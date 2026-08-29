#!/usr/bin/env python3
"""
customers.py

Customer lifecycle: create, edit, inspect, force check and delete.

Creating a customer immediately runs one scan so a wrong tenant id, a
missing admin consent or a mismatched certificate surfaces during
onboarding instead of on the next morning's schedule.
"""

from flask import (Blueprint, abort, flash, redirect, render_template, request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import select

from portal import audit, crypto, scheduler
from portal.db import Session
from portal.forms import ConfirmForm, CustomerForm
from portal.models import (AUTH_CERT, CheckRun, CredentialSnapshot, Customer,
                           ROLE_ADMIN, new_token)
from portal.scanner import data_age_hours, inspect_certificate
from portal.views.docs import base_url
from portal.views.dashboard import customer_state
from portal.views.helpers import (config, form_errors, get_or_404, require_role,
                                  require_write)

bp = Blueprint("customers", __name__, url_prefix="/kunden")


def _apply_credentials(form, customer, cfg, is_new):
    """
    Store the credential that matches the chosen authentication method.

    Leaving the field empty on an edit keeps the stored value, which is what
    lets an operator change thresholds without handling the secret again.
    """
    if form.auth_type.data == AUTH_CERT:
        cert_pem = (form.cert_pem.data or "").strip()
        key_pem = (form.key_pem.data or "").strip()
        if cert_pem or key_pem:
            if not (cert_pem and key_pem):
                raise ValueError("Zertifikat und privater Schlüssel müssen zusammen "
                                 "hinterlegt werden")
            thumbprint, not_after = inspect_certificate(cert_pem, key_pem)
            customer.cert_pem = cert_pem
            customer.key_pem_enc = crypto.encrypt(
                key_pem, cfg.encryption_key,
                crypto.aad_for("customer", customer.key, "key_pem_enc"))
            customer.cert_thumbprint = thumbprint
            customer.cert_not_after = not_after
            customer.client_secret_enc = ""
        elif is_new or not customer.cert_pem:
            raise ValueError("Für die Zertifikatsanmeldung fehlen Zertifikat und Schlüssel")
    else:
        secret = (form.client_secret.data or "").strip()
        if secret:
            customer.client_secret_enc = crypto.encrypt(
                secret, cfg.encryption_key,
                crypto.aad_for("customer", customer.key, "client_secret_enc"))
            customer.cert_pem = ""
            customer.key_pem_enc = ""
            customer.cert_thumbprint = ""
            customer.cert_not_after = None
        elif is_new or not customer.client_secret_enc:
            raise ValueError("Für die Secret-Anmeldung fehlt das Client Secret")
    customer.auth_type = form.auth_type.data


def _apply_settings(form, customer):
    """Copy every non credential field from the form onto the customer."""
    customer.display_name = form.display_name.data.strip()
    customer.tenant_id = form.tenant_id.data.strip().lower()
    customer.client_id = form.client_id.data.strip().lower()
    customer.warn_days = form.warn_days.data
    customer.error_days = form.error_days.data
    customer.max_channels = form.max_channels.data
    customer.include_sp = bool(form.include_sp.data)
    customer.show_expired = bool(form.show_expired.data)
    customer.app_filter = (form.app_filter.data or "").strip()
    customer.app_exclude = (form.app_exclude.data or "").strip()
    customer.notes = (form.notes.data or "").strip()
    customer.is_active = bool(form.is_active.data)


@bp.route("/neu", methods=["GET", "POST"])
@login_required
@require_write
def create():
    """Onboard a new customer tenant and verify the connection right away."""
    cfg = config()
    form = CustomerForm()
    if form.validate_on_submit():
        key = form.key.data.strip().lower()
        if Session.query(Customer).filter(Customer.key == key).count():
            flash("Der Schlüssel '%s' ist bereits vergeben." % key, "error")
            return render_template("customer_form.html", form=form, customer=None), 400

        customer = Customer(key=key, prtg_token=new_token(),
                            created_by=current_user.username)
        try:
            _apply_settings(form, customer)
            _apply_credentials(form, customer, cfg, is_new=True)
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("customer_form.html", form=form, customer=None), 400

        customer.slot_minute = scheduler.assign_slot(Session)
        Session.add(customer)
        Session.commit()
        audit.log(Session, "customer.created", actor=current_user.username, target=key,
                  detail="Anmeldung %s, Slot %s" % (customer.auth_label, customer.slot_label),
                  trust_proxy=cfg.trust_proxy)

        status, error = scheduler.force_check(customer.id, cfg.encryption_key,
                                              current_user.username, cfg.history_runs)
        if status == "ok":
            flash("Kunde angelegt, erste Prüfung erfolgreich.", "ok")
        else:
            flash("Kunde angelegt, die erste Prüfung schlug fehl: %s" % error, "error")
        return redirect(url_for("customers.detail", customer_id=customer.id))

    form_errors(form)
    return render_template("customer_form.html", form=form, customer=None)


@bp.route("/<int:customer_id>/bearbeiten", methods=["GET", "POST"])
@login_required
@require_write
def edit(customer_id):
    """Change the settings or the credential of an existing customer."""
    cfg = config()
    customer = get_or_404(Customer, customer_id)
    form = CustomerForm(obj=customer) if request.method == "GET" else CustomerForm()

    if form.validate_on_submit():
        try:
            _apply_settings(form, customer)
            _apply_credentials(form, customer, cfg, is_new=False)
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("customer_form.html", form=form, customer=customer), 400
        Session.commit()
        audit.log(Session, "customer.updated", actor=current_user.username, target=customer.key,
                  trust_proxy=cfg.trust_proxy)
        flash("Änderungen gespeichert.", "ok")
        return redirect(url_for("customers.detail", customer_id=customer.id))

    if request.method == "GET":
        form.key.data = customer.key
        form.client_secret.data = ""
        form.cert_pem.data = ""
        form.key_pem.data = ""
    else:
        form_errors(form)
    return render_template("customer_form.html", form=form, customer=customer)


@bp.route("/<int:customer_id>")
@login_required
def detail(customer_id):
    """Show the stored credential state of one customer plus its run history."""
    customer = get_or_404(Customer, customer_id)
    credentials = Session.execute(
        select(CredentialSnapshot).where(CredentialSnapshot.customer_id == customer.id)
        .order_by(CredentialSnapshot.days_left.asc())).scalars().all()
    runs = Session.execute(
        select(CheckRun).where(CheckRun.customer_id == customer.id)
        .order_by(CheckRun.started_at.desc()).limit(10)).scalars().all()
    prtg_url = "%s%s" % (base_url(), url_for("prtg.prtg_xml", token=customer.prtg_token))
    return render_template("customer_detail.html", customer=customer,
                           credentials=credentials, runs=runs, form=ConfirmForm(),
                           age_hours=data_age_hours(customer), prtg_url=prtg_url,
                           state=customer_state(customer))


@bp.route("/<int:customer_id>/pruefen", methods=["POST"])
@login_required
@require_write
def force(customer_id):
    """
    Force check: fetch the current state now instead of waiting for the slot.

    This is the answer to a freshly rolled secret. The scheduled run for the
    day is suppressed afterwards because last_check_at then lies behind the
    slot, so a force check costs no extra Graph call later.
    """
    cfg = config()
    customer = get_or_404(Customer, customer_id)
    form = ConfirmForm()
    if not form.validate_on_submit():
        abort(400)
    try:
        status, error = scheduler.force_check(customer.id, cfg.encryption_key,
                                              current_user.username, cfg.history_runs)
    except TimeoutError as exc:
        flash(str(exc), "error")
        return redirect(url_for("customers.detail", customer_id=customer.id))

    audit.log(Session, "customer.checked", actor=current_user.username, target=customer.key,
              success=status == "ok", detail=error or "", trust_proxy=cfg.trust_proxy)
    flash("Prüfung erfolgreich." if status == "ok" else "Prüfung fehlgeschlagen: %s" % error,
          "ok" if status == "ok" else "error")
    return redirect(url_for("customers.detail", customer_id=customer.id))


@bp.route("/<int:customer_id>/token", methods=["POST"])
@login_required
@require_write
def rotate_token(customer_id):
    """Issue a new PRTG token, invalidating the old sensor URL."""
    cfg = config()
    customer = get_or_404(Customer, customer_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    customer.prtg_token = new_token()
    Session.commit()
    audit.log(Session, "customer.token_rotated", actor=current_user.username,
              target=customer.key, trust_proxy=cfg.trust_proxy)
    flash("Neuer PRTG-Token erzeugt. Sensor-URL im PRTG anpassen.", "warn")
    return redirect(url_for("customers.detail", customer_id=customer.id))


@bp.route("/<int:customer_id>/loeschen", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def delete(customer_id):
    """Remove a customer with its history; only administrators may do this."""
    cfg = config()
    customer = get_or_404(Customer, customer_id)
    if not ConfirmForm().validate_on_submit():
        abort(400)
    key = customer.key
    Session.delete(customer)
    Session.commit()
    audit.log(Session, "customer.deleted", actor=current_user.username, target=key,
              trust_proxy=cfg.trust_proxy)
    flash("Kunde '%s' gelöscht." % key, "ok")
    return redirect(url_for("dashboard.index"))


@bp.route("/slots", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def redistribute():
    """Spread every customer evenly over the day again."""
    cfg = config()
    if not ConfirmForm().validate_on_submit():
        abort(400)
    count = scheduler.redistribute_slots(Session)
    audit.log(Session, "schedule.redistributed", actor=current_user.username,
              detail="%d Kunden neu verteilt" % count, trust_proxy=cfg.trust_proxy)
    flash("%d Kunden neu über den Tag verteilt." % count, "ok")
    return redirect(url_for("dashboard.index"))
