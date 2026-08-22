#!/usr/bin/env python3
"""
dashboard.py

Overview page: one row per customer with its worst remaining runtime, the
data age and the direct links to the PRTG endpoints.
"""

from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import select

from portal import scheduler
from portal.db import Session
from portal.models import Customer
from portal.scanner import data_age_hours
from portal.views.helpers import config

bp = Blueprint("dashboard", __name__)


def customer_rows():
    """Return all customers with the derived values the overview shows."""
    customers = Session.execute(
        select(Customer).order_by(Customer.display_name.asc())).scalars().all()
    rows = []
    for customer in customers:
        rows.append({
            "customer": customer,
            "age_hours": data_age_hours(customer),
            "state": customer_state(customer),
        })
    return rows


def customer_state(customer, stale_hours=None):
    """
    Classify a customer into ok, warn, error or unknown.

    Stale data outranks a green remaining runtime: numbers from a scan that
    never ran again say nothing about today.
    """
    cfg = config()
    stale_hours = stale_hours if stale_hours is not None else cfg.stale_hours
    if not customer.is_active:
        return "inactive"
    if customer.last_status == "pending" or customer.last_check_at is None:
        return "unknown"
    if customer.last_status == "error":
        return "error"
    age = data_age_hours(customer)
    if age > stale_hours:
        return "stale"
    if customer.count_expired:
        return "error"
    if customer.min_days is None:
        return "unknown"
    if customer.min_days < customer.error_days:
        return "error"
    if customer.min_days < customer.warn_days:
        return "warn"
    return "ok"


@bp.route("/")
@login_required
def index():
    """Render the customer overview."""
    rows = customer_rows()
    totals = {
        "customers": len(rows),
        "active": sum(1 for r in rows if r["customer"].is_active),
        "error": sum(1 for r in rows if r["state"] in ("error", "stale")),
        "warn": sum(1 for r in rows if r["state"] == "warn"),
        "credentials": sum(r["customer"].count_total for r in rows),
    }
    return render_template("dashboard.html", rows=rows, totals=totals,
                           scheduler=scheduler.status())
