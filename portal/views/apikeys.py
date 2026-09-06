#!/usr/bin/env python3
"""
apikeys.py

Einstellungsseite fuer die REST-Schnittstelle: Schluessel ausstellen,
widerrufen und loeschen, dazu das Verzeichnis der Endpunkte.

Getrennt vom Blueprint der Schnittstelle selbst, weil hier das Gegenteil gilt:
Anmeldung ueber die Sitzung, CSRF-Schutz, HTML. Nur Administratoren kommen
herein, denn ein schreibender Schluessel darf so viel wie ein Bedienerkonto,
nur ohne zweiten Faktor.
"""

from flask import (Blueprint, flash, make_response, redirect, render_template,
                   url_for)
from flask_login import current_user, login_required
from sqlalchemy import select

from portal import audit, security
from portal.db import Session
from portal.forms import ApiKeyForm, ConfirmForm
from portal.models import ROLE_ADMIN, ApiKey, new_api_key, utcnow
from portal.views.api import ENDPUNKTE
from portal.views.helpers import config, form_errors, get_or_404, require_role

bp = Blueprint("apikeys", __name__, url_prefix="/einstellungen/api")


@bp.route("/")
@login_required
@require_role(ROLE_ADMIN)
def index():
    """List every API key together with the endpoint directory."""
    schluessel = Session.execute(
        select(ApiKey).order_by(ApiKey.created_at.desc())).scalars().all()
    return render_template("apikeys.html", keys=schluessel, form=ConfirmForm(),
                           new_form=ApiKeyForm(), endpoints=ENDPUNKTE,
                           base_url=config().base_url)


@bp.route("/neu", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def create():
    """
    Issue a new key and show it exactly once.

    Gespeichert wird nur der Hash. Wer den Schluessel verliert, bekommt einen
    neuen; ein Nachschlagen gibt es nicht, sonst waere die Datenbank selbst der
    Generalschluessel zur Schnittstelle.
    """
    form = ApiKeyForm()
    if not form.validate_on_submit():
        form_errors(form)
        return redirect(url_for("apikeys.index"))

    name = form.name.data.strip()
    if Session.execute(select(ApiKey).where(ApiKey.name == name)).scalar_one_or_none():
        flash("Ein Schlüssel mit diesem Namen existiert bereits.", "error")
        return redirect(url_for("apikeys.index"))

    roh, praefix = new_api_key()
    eintrag = ApiKey(name=name, prefix=praefix, key_hash=security.hash_password(roh),
                     scope=form.scope.data, created_by=current_user.username)
    Session.add(eintrag)
    Session.commit()
    audit.log(Session, "apikey.created", actor=current_user.username, target=name,
              detail="Bereich %s" % eintrag.scope_label, trust_proxy=config().trust_proxy)

    # Kein Flash: die Flask-Sitzung ist signiert, aber nicht verschluesselt.
    # Ein geflashter Schluessel laege im Klartext im Browser-Cookie.
    antwort = make_response(render_template("apikey_secret.html", key=eintrag, secret=roh,
                                            base_url=config().base_url))
    antwort.headers["Cache-Control"] = "no-store"
    antwort.headers["Pragma"] = "no-cache"
    return antwort


@bp.route("/<int:key_id>/widerrufen", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def revoke(key_id):
    """Revoke a key without deleting it, so the audit trail stays readable."""
    eintrag = get_or_404(ApiKey, key_id)
    if eintrag.revoked_at is None:
        eintrag.revoked_at = utcnow()
        Session.commit()
        audit.log(Session, "apikey.revoked", actor=current_user.username,
                  target=eintrag.name, trust_proxy=config().trust_proxy)
    flash("Schlüssel '%s' widerrufen." % eintrag.name, "ok")
    return redirect(url_for("apikeys.index"))


@bp.route("/<int:key_id>/loeschen", methods=["POST"])
@login_required
@require_role(ROLE_ADMIN)
def delete(key_id):
    """Remove a key entirely."""
    eintrag = get_or_404(ApiKey, key_id)
    name = eintrag.name
    Session.delete(eintrag)
    Session.commit()
    audit.log(Session, "apikey.deleted", actor=current_user.username, target=name,
              trust_proxy=config().trust_proxy)
    flash("Schlüssel '%s' gelöscht." % name, "ok")
    return redirect(url_for("apikeys.index"))
