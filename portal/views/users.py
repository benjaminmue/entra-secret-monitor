#!/usr/bin/env python3
"""
users.py

Account administration: list, create, edit, reset and delete portal users.

Only administrators reach this blueprint. A new account always starts with a
generated password that is shown exactly once and must be changed at the
first login, and it always has to enrol an authenticator before it can use
the portal.
"""

from flask import (Blueprint, abort, flash, make_response, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import select

from portal import audit, security
from portal.db import Session
from portal.forms import ConfirmForm, UserForm
from portal.models import ROLE_ADMIN, RecoveryCode, User, utcnow
from portal.views.helpers import config, form_errors, get_or_404, require_role

bp = Blueprint("users", __name__, url_prefix="/benutzer")


def _last_admin(user):
    """True when removing or demoting this account would leave no administrator."""
    if user.role != ROLE_ADMIN:
        return False
    others = Session.query(User).filter(User.role == ROLE_ADMIN, User.is_active.is_(True),
                                        User.id != user.id).count()
    return others == 0


def _one_time_password_page(user, password, headline):
    """
    Render a one time password exactly once, with caching switched off.

    Deliberately not a flash message: the Flask session is signed but not
    encrypted, so a flashed password would sit in clear text in the browser
    cookie of the administrator.
    """
    response = make_response(render_template("user_secret.html", user=user,
                                             password=password, headline=headline))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


@bp.route("/")
@login_required
@require_role(ROLE_ADMIN)
def index():
    """List all portal accounts."""
    users = Session.execute(select(User).order_by(User.username.asc())).scalars().all()
    return render_template("users.html", users=users, form=ConfirmForm())


@bp.route("/neu", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def create():
    """Create an account and hand out its one time password."""
    cfg = config()
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        if Session.query(User).filter(User.username == username).count():
            flash("Benutzername ist bereits vergeben.", "error")
            return render_template("user_form.html", form=form, user=None), 400

        password = (form.password.data or "").strip() or security.suggest_password()
        try:
            security.assert_password_policy(password, cfg.password_min_length, username,
                                            form.display_name.data or "")
        except security.PolicyError as exc:
            flash(str(exc), "error")
            return render_template("user_form.html", form=form, user=None), 400

        user = User(
            username=username,
            display_name=(form.display_name.data or "").strip(),
            email=(form.email.data or "").strip(),
            role=form.role.data,
            is_active=bool(form.is_active.data),
            password_hash=security.hash_password(password),
            must_change_password=True,
            created_by=current_user.username,
        )
        Session.add(user)
        Session.commit()
        audit.log(Session, "user.created", actor=current_user.username, target=username,
                  detail="Rolle %s" % user.role, trust_proxy=cfg.trust_proxy)
        return _one_time_password_page(user, password, "Konto angelegt")

    form_errors(form)
    return render_template("user_form.html", form=form, user=None)


@bp.route("/<int:user_id>/bearbeiten", methods=["GET", "POST"])
@login_required
@require_role(ROLE_ADMIN)
def edit(user_id):
    """Change role, contact data or the active state of an account."""
    cfg = config()
    user = get_or_404(User, user_id)
    form = UserForm(obj=user) if request.method == "GET" else UserForm()

    if form.validate_on_submit():
        new_role = form.role.data
        still_active = bool(form.is_active.data)
        if _last_admin(user) and (new_role != ROLE_ADMIN or not still_active):
            flash("Das letzte aktive Administratorkonto kann nicht herabgestuft "
                  "oder deaktiviert werden.", "error")
            return render_template("user_form.html", form=form, user=user), 400

        user.display_name = (form.display_name.data or "").strip()
        user.email = (form.email.data or "").strip()
        user.role = new_role
        user.is_active = still_active
        Session.commit()
        audit.log(Session, "user.updated", actor=current_user.username, target=user.username,
                  detail="Rolle %s, aktiv %s" % (user.role, user.is_active),
                  trust_proxy=cfg.trust_proxy)
        flash("Konto gespeichert.", "ok")
        return redirect(url_for("users.index"))

    if request.method == "GET":
        form.username.data = user.username
        form.password.data = ""
    else:
        form_errors(form)
    return render_template("user_form.html", form=form, user=user)


@bp.route("/<int:user_id>/passwort", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def reset_password(user_id):
    """Issue a new one time password for an account."""
    cfg = config()
    user = get_or_404(User, user_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    password = security.suggest_password()
    user.password_hash = security.hash_password(password)
    user.password_changed_at = utcnow()
    user.must_change_password = True
    user.failed_logins = 0
    user.locked_until = None
    Session.commit()
    audit.log(Session, "user.password_reset", actor=current_user.username,
              target=user.username, trust_proxy=cfg.trust_proxy)
    return _one_time_password_page(user, password, "Passwort zurückgesetzt")


@bp.route("/<int:user_id>/2fa", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def reset_totp(user_id):
    """Clear the second factor so the account enrols a new authenticator."""
    cfg = config()
    user = get_or_404(User, user_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    user.totp_secret_enc = ""
    user.totp_confirmed_at = None
    user.last_totp_counter = 0
    Session.query(RecoveryCode).filter(RecoveryCode.user_id == user.id).delete()
    Session.commit()
    audit.log(Session, "user.totp_reset", actor=current_user.username, target=user.username,
              trust_proxy=cfg.trust_proxy)
    flash("Zweiter Faktor zurückgesetzt. %s richtet beim nächsten Login neu ein."
          % user.username, "warn")
    return redirect(url_for("users.index"))


@bp.route("/<int:user_id>/loeschen", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def delete(user_id):
    """Delete an account, except the last administrator and oneself."""
    cfg = config()
    user = get_or_404(User, user_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    if user.id == current_user.id:
        flash("Das eigene Konto kann nicht gelöscht werden.", "error")
        return redirect(url_for("users.index"))
    if _last_admin(user):
        flash("Das letzte Administratorkonto kann nicht gelöscht werden.", "error")
        return redirect(url_for("users.index"))
    username = user.username
    Session.delete(user)
    Session.commit()
    audit.log(Session, "user.deleted", actor=current_user.username, target=username,
              trust_proxy=cfg.trust_proxy)
    flash("Konto '%s' gelöscht." % username, "ok")
    return redirect(url_for("users.index"))
