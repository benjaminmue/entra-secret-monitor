#!/usr/bin/env python3
"""
docs.py

Built in documentation: how to create the app registration a customer needs,
which permission it requires, and how the resulting sensor is wired in PRTG.

The page is generated from the running configuration, so the URLs it shows
are the ones that actually work on this instance instead of placeholders
from a README.
"""

from flask import Blueprint, render_template, request
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
