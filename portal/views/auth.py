#!/usr/bin/env python3
"""
auth.py

Login, second factor, enrollment and password change.

The login is deliberately split in two requests. The password step never
reveals whether an account exists, and only stores a pending id in the
session; the account is signed in after the TOTP step. An account without a
confirmed authenticator is forced through enrollment before it can reach any
other page, so there is no way to run the portal with a single factor.
"""

import io
import re
from datetime import datetime, timedelta, timezone

import qrcode
import qrcode.image.svg
from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import update

from portal import audit, security
from portal.db import Session
from portal.forms import LoginForm, PasswordForm, StepUpForm, TotpForm
from portal.models import RecoveryCode, User, utcnow
from portal.views.helpers import config, form_errors

bp = Blueprint("auth", __name__)

PENDING_KEY = "pending_user_id"
PENDING_SINCE = "pending_since"
PENDING_MINUTES = 5

# Freigabe fuer ein erneutes Einrichten des zweiten Faktors, gesetzt durch die
# Step-up-Bestaetigung oder durch eine Anmeldung mit Recovery-Code.
REENROLL_KEY = "totp_reenroll_user_id"
REENROLL_SINCE = "totp_reenroll_since"
REENROLL_MINUTES = 10

SETUP_SECRET_KEY = "totp_setup_secret"
RECOVERY_PATTERN = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")


def _aware(value):
    """Return a timezone aware copy of a datetime read from SQLite."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _locked(user):
    """True while the account is inside its lockout window."""
    until = _aware(user.locked_until)
    return bool(until and until > datetime.now(timezone.utc))


def _register_failure(user, cfg, reason):
    """
    Count a failed attempt and lock the account once the limit is reached.

    The counter is raised with a single UPDATE instead of a read, modify and
    write over the ORM session, otherwise parallel attempts overwrite each
    other and the lockout engages later than configured.
    """
    Session.execute(update(User).where(User.id == user.id)
                    .values(failed_logins=User.failed_logins + 1))
    Session.commit()
    Session.refresh(user)
    if user.failed_logins >= cfg.login_max_attempts:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=cfg.lockout_minutes)
        user.failed_logins = 0
        audit.log(Session, "login.locked", actor=user.username, success=False,
                  detail="Konto für %d Minuten gesperrt" % cfg.lockout_minutes,
                  trust_proxy=cfg.trust_proxy, commit=False)
    audit.log(Session, "login.failed", actor=user.username, success=False, detail=reason,
              trust_proxy=cfg.trust_proxy)


@bp.route("/login", methods=["GET", "POST"])
def login():
    """First factor: username and password."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    cfg = config()
    form = LoginForm()

    if form.validate_on_submit():
        username = (form.username.data or "").strip()
        user = Session.query(User).filter(User.username == username).one_or_none()

        if user and not user.is_active:
            audit.log(Session, "login.disabled", actor=username, success=False,
                      trust_proxy=cfg.trust_proxy)
            flash("Anmeldung nicht möglich.", "error")
            return render_template("login.html", form=form), 401

        if user and _locked(user):
            flash("Konto ist vorübergehend gesperrt. Bitte später erneut versuchen.", "error")
            return render_template("login.html", form=form), 429

        if not user or not security.verify_password(user.password_hash, form.password.data):
            if user:
                _register_failure(user, cfg, "Passwort falsch")
                Session.commit()
            else:
                # Same cost as a real check, so the answer does not reveal
                # whether the username exists.
                security.dummy_verify(form.password.data)
                audit.log(Session, "login.unknown", actor=username[:64], success=False,
                          trust_proxy=cfg.trust_proxy)
            flash("Benutzername oder Passwort falsch.", "error")
            return render_template("login.html", form=form), 401

        if security.needs_rehash(user.password_hash):
            user.password_hash = security.hash_password(form.password.data)
        user.failed_logins = 0
        Session.commit()

        session.clear()
        session[PENDING_KEY] = user.id
        session[PENDING_SINCE] = utcnow().isoformat()
        return redirect(url_for("auth.setup_totp") if not user.totp_ready
                        else url_for("auth.verify_totp"))

    form_errors(form)
    return render_template("login.html", form=form)


def _pending_user():
    """Return the user waiting for the second factor, or None when expired."""
    user_id = session.get(PENDING_KEY)
    since = session.get(PENDING_SINCE)
    if not user_id or not since:
        return None
    try:
        started = datetime.fromisoformat(since)
    except ValueError:
        return None
    if _aware(started) + timedelta(minutes=PENDING_MINUTES) < datetime.now(timezone.utc):
        _clear_pending()
        return None
    user = Session.get(User, user_id)
    if user is None or not user.is_active:
        return None
    # The lockout has to bite on the second step as well. Without this check a
    # locked account could still be brute forced for TOTP codes as long as the
    # pending window lasts.
    if _locked(user):
        _clear_pending()
        return None
    return user


def _clear_pending():
    """Drop the half finished login from the session."""
    session.pop(PENDING_KEY, None)
    session.pop(PENDING_SINCE, None)


def _complete_login(user, cfg):
    """Sign the user in and reset the counters, without deciding where to go."""
    _clear_pending()
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    user.last_login_ip = audit.client_ip(cfg.trust_proxy)
    Session.commit()
    login_user(user, remember=False)
    audit.log(Session, "login.ok", actor=user.username, trust_proxy=cfg.trust_proxy)


def _finish_login(user, cfg):
    """Sign the user in and redirect to wherever the account has to go next."""
    _complete_login(user, cfg)
    if user.must_change_password:
        flash("Bitte zuerst ein eigenes Passwort setzen.", "warn")
        return redirect(url_for("auth.change_password"))
    return redirect(url_for("dashboard.index"))


@bp.route("/login/2fa", methods=["GET", "POST"])
def verify_totp():
    """Second factor: the six digit code or one recovery code."""
    cfg = config()
    user = _pending_user()
    if user is None:
        flash("Anmeldung abgelaufen, bitte erneut beginnen.", "error")
        return redirect(url_for("auth.login"))
    if not user.totp_ready:
        return redirect(url_for("auth.setup_totp"))

    form = TotpForm()
    if form.validate_on_submit():
        code = (form.code.data or "").strip()
        secret = security.decrypt_totp_secret(user.totp_secret_enc, cfg.encryption_key,
                                              user.username)
        ok, counter = security.verify_totp(secret, code, user.last_totp_counter or 0)
        if ok and _claim_totp_counter(user, counter):
            return _finish_login(user, cfg)

        if _consume_recovery_code(user, code):
            audit.log(Session, "login.recovery", actor=user.username,
                      detail="Recovery-Code verbraucht", trust_proxy=cfg.trust_proxy)
            response = _finish_login(user, cfg)
            # Wer einen Recovery-Code einloest, hat das verlorene Geraet
            # nachgewiesen und darf den zweiten Faktor sofort neu einrichten.
            _allow_reenrollment(user)
            flash("Recovery-Code verbraucht. Bitte den zweiten Faktor neu einrichten.",
                  "warn")
            return response

        _register_failure(user, cfg, "TOTP falsch")
        Session.commit()
        flash("Code ist ungültig.", "error")
        return render_template("totp_verify.html", form=form), 401

    form_errors(form)
    return render_template("totp_verify.html", form=form)


def _consume_recovery_code(user, code):
    """
    Mark a matching unused recovery code as used and report success.

    The format check comes first on purpose: without it every wrong six digit
    code would run through up to eight Argon2 verifications and turn a guessing
    attempt into a denial of service against the worker threads.

    The row is claimed with a conditional UPDATE so two parallel requests
    cannot spend the same code twice.
    """
    if not RECOVERY_PATTERN.match((code or "").strip().upper()):
        return False
    for entry in user.recovery_codes:
        if entry.used_at is not None:
            continue
        if not security.verify_recovery_code(entry.code_hash, code):
            continue
        claimed = Session.execute(
            update(RecoveryCode)
            .where(RecoveryCode.id == entry.id, RecoveryCode.used_at.is_(None))
            .values(used_at=utcnow())).rowcount
        Session.commit()
        return bool(claimed)
    return False


def _claim_totp_counter(user, counter):
    """
    Store the accepted TOTP counter, but only if it really moved forward.

    Conditional UPDATE instead of an assignment: two requests arriving with the
    same valid code must not both succeed.
    """
    claimed = Session.execute(
        update(User)
        .where(User.id == user.id, User.last_totp_counter < counter)
        .values(last_totp_counter=counter)).rowcount
    Session.commit()
    Session.refresh(user)
    return bool(claimed)


def _allow_reenrollment(user):
    """Open the short window in which an existing authenticator may be replaced."""
    session[REENROLL_KEY] = user.id
    session[REENROLL_SINCE] = utcnow().isoformat()


def _reenrollment_allowed(user):
    """True while a step-up confirmation for this account is still valid."""
    if session.get(REENROLL_KEY) != user.id:
        return False
    try:
        since = _aware(datetime.fromisoformat(session.get(REENROLL_SINCE, "")))
    except ValueError:
        return False
    return since + timedelta(minutes=REENROLL_MINUTES) > datetime.now(timezone.utc)


def _clear_reenrollment():
    """Close the re-enrollment window."""
    session.pop(REENROLL_KEY, None)
    session.pop(REENROLL_SINCE, None)


def _qr_svg(uri):
    """Render the otpauth URI as an inline SVG, so no image endpoint is needed."""
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")


@bp.route("/login/2fa/setup", methods=["GET", "POST"])
def setup_totp():
    """
    Enrollment of the authenticator app.

    Reachable in exactly two situations: an account that has no confirmed
    authenticator yet, and an account that passed the step-up in
    reenroll_totp or redeemed a recovery code. Anything else is turned away.

    Without that guard, knowing the password alone would be enough: an
    attacker could skip the code prompt, call this page, register their own
    authenticator over the victim's and be signed in. The second factor would
    be decorative.
    """
    cfg = config()
    pending = _pending_user()
    user = pending or (current_user if current_user.is_authenticated else None)
    if user is None:
        flash("Anmeldung abgelaufen, bitte erneut beginnen.", "error")
        return redirect(url_for("auth.login"))

    if user.totp_ready and not _reenrollment_allowed(user):
        if pending is not None:
            return redirect(url_for("auth.verify_totp"))
        return redirect(url_for("auth.reenroll_totp"))

    # The secret survives a page reload on purpose: regenerating it would
    # invalidate a QR code the user is halfway through scanning.
    if SETUP_SECRET_KEY not in session:
        session[SETUP_SECRET_KEY] = security.new_totp_secret()
    secret = session[SETUP_SECRET_KEY]

    def enrollment_page(status=200):
        """Render the enrollment page with a QR code for the current secret."""
        return render_template("totp_setup.html", form=form, secret=secret,
                               reenroll=user.totp_ready,
                               qr=_qr_svg(security.totp_uri(secret, user.username,
                                                            cfg.instance_name))), status

    form = TotpForm()
    if form.validate_on_submit():
        ok, counter = security.verify_totp(secret, form.code.data, 0)
        if not ok:
            flash("Code stimmt nicht. Uhrzeit des Geräts prüfen und erneut versuchen.",
                  "error")
            return enrollment_page(400)

        user.totp_secret_enc = security.encrypt_totp_secret(secret, cfg.encryption_key,
                                                            user.username)
        user.totp_confirmed_at = utcnow()
        user.last_totp_counter = counter
        codes = security.new_recovery_codes()
        Session.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).delete()
        for code in codes:
            Session.add(RecoveryCode(user_id=user.id,
                                     code_hash=security.hash_recovery_code(code)))
        Session.commit()
        session.pop(SETUP_SECRET_KEY, None)
        _clear_reenrollment()
        audit.log(Session, "totp.enrolled", actor=user.username, trust_proxy=cfg.trust_proxy)

        if pending is not None:
            _complete_login(user, cfg)
        # The codes are rendered straight into this response. Handing them
        # through the session would write all eight in clear text into the
        # client cookie, which is signed but not encrypted.
        return render_template("recovery_codes.html", codes=codes, remaining=len(codes))

    form_errors(form)
    return enrollment_page()


@bp.route("/account/2fa", methods=["GET", "POST"])
@login_required
def reenroll_totp():
    """
    Step-up before an existing authenticator may be replaced.

    Requires the current password and a currently valid code, so a stolen
    session alone cannot turn itself into permanent access by swapping the
    second factor.
    """
    cfg = config()
    if not current_user.totp_ready:
        return redirect(url_for("auth.setup_totp"))

    if _locked(current_user):
        flash("Konto ist vorübergehend gesperrt. Bitte später erneut versuchen.", "error")
        return render_template("totp_reenroll.html", form=StepUpForm()), 429

    form = StepUpForm()
    if form.validate_on_submit():
        password_ok = security.verify_password(current_user.password_hash,
                                               form.current_password.data)
        secret = security.decrypt_totp_secret(current_user.totp_secret_enc,
                                              cfg.encryption_key, current_user.username)
        code_ok, counter = security.verify_totp(secret, form.code.data,
                                                current_user.last_totp_counter or 0)
        if password_ok and code_ok and _claim_totp_counter(current_user, counter):
            _allow_reenrollment(current_user)
            session.pop(SETUP_SECRET_KEY, None)
            audit.log(Session, "totp.reenroll_allowed", actor=current_user.username,
                      trust_proxy=cfg.trust_proxy)
            return redirect(url_for("auth.setup_totp"))

        audit.log(Session, "totp.reenroll_denied", actor=current_user.username,
                  success=False, trust_proxy=cfg.trust_proxy)
        # Ohne Zaehler liesse sich ueber diesen Pfad unbegrenzt raten, waehrend
        # Login und Code-Pruefung nach cfg.login_max_attempts sperren.
        _register_failure(current_user, cfg, "Step-up 2FA falsch")
        Session.commit()
        flash("Passwort oder Code stimmt nicht.", "error")
        return render_template("totp_reenroll.html", form=form), 400

    form_errors(form)
    return render_template("totp_reenroll.html", form=form)


@bp.route("/account/recovery-codes")
@login_required
def recovery_codes():
    """
    Show how many recovery codes are left.

    The codes themselves appear only once, in the response of the enrollment
    that created them. They are never stored in the session and never rendered
    again.
    """
    remaining = Session.query(RecoveryCode).filter(
        RecoveryCode.user_id == current_user.id, RecoveryCode.used_at.is_(None)).count()
    return render_template("recovery_codes.html", codes=None, remaining=remaining)


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change the password of the signed in account."""
    cfg = config()
    form = PasswordForm()
    if form.validate_on_submit():
        if not security.verify_password(current_user.password_hash, form.current_password.data):
            audit.log(Session, "password.failed", actor=current_user.username, success=False,
                      trust_proxy=cfg.trust_proxy)
            flash("Aktuelles Passwort ist falsch.", "error")
            return render_template("password.html", form=form,
                                   policy=_policy_text(cfg)), 400
        try:
            security.assert_password_policy(form.new_password.data, cfg.password_min_length,
                                            current_user.username, current_user.display_name)
        except security.PolicyError as exc:
            flash(str(exc), "error")
            return render_template("password.html", form=form, policy=_policy_text(cfg)), 400

        current_user.password_hash = security.hash_password(form.new_password.data)
        current_user.password_changed_at = utcnow()
        current_user.must_change_password = False
        Session.commit()
        audit.log(Session, "password.changed", actor=current_user.username,
                  trust_proxy=cfg.trust_proxy)
        flash("Passwort geändert.", "ok")
        return redirect(url_for("dashboard.index"))

    form_errors(form)
    return render_template("password.html", form=form, policy=_policy_text(cfg))


def _policy_text(cfg):
    """Return the password rules as a list for display next to the form."""
    return [
        "mindestens %d Zeichen" % cfg.password_min_length,
        "Gross- und Kleinbuchstaben",
        "mindestens eine Ziffer",
        "mindestens ein Sonderzeichen aus %s" % security.SPECIALS,
        "kein Benutzername, kein leicht erratbares Wort",
        "kein Zeichen mehr als dreimal hintereinander",
    ]


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """End the session."""
    cfg = config()
    audit.log(Session, "logout", actor=current_user.username, trust_proxy=cfg.trust_proxy)
    logout_user()
    session.clear()
    flash("Abgemeldet.", "ok")
    return redirect(url_for("auth.login"))


@bp.before_app_request
def _enforce_password_change():
    """
    Keep an account with a temporary password inside the password page.

    Applies to every blueprint, which is why it lives here as an app wide
    hook instead of on each individual view.
    """
    if not current_user.is_authenticated or not current_user.must_change_password:
        return None
    allowed = ("auth.change_password", "auth.logout", "auth.recovery_codes",
               "auth.setup_totp", "auth.reenroll_totp", "static")
    if request.endpoint in allowed:
        return None
    if request.endpoint and request.endpoint.startswith("prtg."):
        return None
    return redirect(url_for("auth.change_password"))
