#!/usr/bin/env python3
"""
docs.py

Built in documentation: how to create the app registration a customer needs,
which permission it requires, and how the resulting sensor is wired in PRTG.

The page is generated from the running configuration, so the URLs it shows
are the ones that actually work on this instance instead of placeholders
from a README.
"""

from pathlib import Path

from flask import Blueprint, abort, render_template, request, send_file
from flask_login import login_required
from sqlalchemy import select

from portal.db import Session
from portal.models import Customer
from portal.views.helpers import config

bp = Blueprint("docs", __name__, url_prefix="/anleitung")

# One place for the permission the app registration needs. Application.Read.All
# as an application permission is the least that lets Graph return the
# credential collections of every app registration in the tenant.
PERMISSION = {
    "api": "Microsoft Graph",
    "name": "Application.Read.All",
    "type": "Anwendungsberechtigung",
    "id": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
    "consent": "Erfordert Administratorzustimmung im Kundentenant",
}

# The setup script Variante A of the guide refers to. It sits next to the
# package: under <repo>/scripts in the working tree, under /opt/portal/scripts
# in the image. Both are the same two levels above this file, because
# portal/views/ -> portal/ -> root holds either way.
SETUP_SCRIPT = (Path(__file__).resolve().parents[2] / "scripts"
                / "New-MonitorAppRegistration.ps1")


def base_url():
    """Return the externally reachable base URL of this instance."""
    cfg = config()
    return cfg.base_url or request.url_root.rstrip("/")


@bp.route("/")
@login_required
def index():
    """Render the onboarding guide."""
    customers = Session.execute(
        select(Customer).order_by(Customer.display_name.asc())).scalars().all()
    return render_template("docs.html", permission=PERMISSION, base=base_url(),
                           customers=customers, cfg=config())


@bp.route("/skript")
@login_required
def setup_script():
    """
    Hand out the setup script that Variante A of the guide refers to.

    Without this route the file exists only in the repository: the image
    carries app/ and portal/ and nothing else, so the documented call went
    nowhere on a running instance. The script holds no secret, it creates
    them, which is why every signed in account may fetch it.
    """
    if not SETUP_SCRIPT.is_file():
        abort(404, description="Das Einrichtungsskript liegt nicht in diesem Abbild. "
                               "Es stammt aus scripts/ des Projektarchivs.")
    return send_file(SETUP_SCRIPT, mimetype="text/plain",
                     as_attachment=True,
                     download_name="New-MonitorAppRegistration.ps1")
