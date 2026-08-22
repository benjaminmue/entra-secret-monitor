#!/usr/bin/env python3
"""
prtg.py

Machine readable endpoints for the monitoring system.

Both routes answer from the stored snapshot and never touch Microsoft Graph.
A sensor poll therefore costs nothing at the tenant, which is what allows a
six hour PRTG interval next to a single daily scan.

Authentication is a per customer token in the path. It grants read access to
exactly one customer, can be rotated without touching any account, and is
kept out of the query string so it does not end up in proxy access logs as
readily as a parameter would.
"""

from flask import Blueprint, Response, jsonify, request

import graph
from portal.db import Session
from portal.models import Customer
from portal.scanner import RenderConfig, data_age_hours, filter_result, result_from_db
from portal.views.helpers import config

bp = Blueprint("prtg", __name__)


def _customer_by_token(token):
    """Resolve a PRTG token to an active customer, or None."""
    if not token or len(token) < 20:
        return None
    customer = Session.query(Customer).filter(Customer.prtg_token == token).one_or_none()
    if customer is None or not customer.is_active:
        return None
    return customer


def _age_channel(customer, cfg):
    """
    Build the data age channel.

    Without it a stalled scheduler would look perfectly healthy: the numbers
    would simply stop moving while the sensor stays green.
    """
    age = data_age_hours(customer)
    return ("Datenalter", age if age >= 0 else 9999, "Stunden",
            (None, None, cfg.stale_hours, cfg.stale_hours * 2))


def _int_param(name):
    """Read an optional positive integer from the query string."""
    raw = request.args.get(name)
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("Parameter '%s' ist keine Zahl: %s" % (name, raw[:40])) from exc
    if value < 1 or value > 3650:
        raise ValueError("Parameter '%s' liegt ausserhalb von 1 bis 3650" % name)
    return value


def _scoped_result(customer):
    """
    Build the result for this request, honouring the optional scope parameters.

    app, filter, exclude and type narrow the channel list, warn and error
    override the thresholds. Everything comes from the stored snapshot, so a
    second sensor on the same customer costs no additional Graph call.
    """
    result = result_from_db(Session, customer)
    return filter_result(
        result,
        app=request.args.get("app", "")[:256],
        name_filter=request.args.get("filter", "")[:190],
        exclude=request.args.get("exclude", "")[:190],
        cred_type=request.args.get("type", "")[:32],
        warn_days=_int_param("warn"),
        error_days=_int_param("error"),
        max_channels=_int_param("max_channels"),
    )


@bp.route("/prtg/<token>")
def prtg_xml(token):
    """Serve PRTG XML for one customer from the stored snapshot."""
    cfg = config()
    customer = _customer_by_token(token)
    if customer is None:
        return Response(graph.render_prtg_error("Unbekannter oder deaktivierter Token"),
                        mimetype="text/xml", status=200)

    if customer.last_status == "error" and customer.last_check_at is None:
        return Response(graph.render_prtg_error(
            "Noch keine erfolgreiche Prüfung: %s" % (customer.last_error or "unbekannt")),
            mimetype="text/xml", status=200)

    try:
        result = _scoped_result(customer)
    except ValueError as exc:
        return Response(graph.render_prtg_error(str(exc)), mimetype="text/xml", status=200)

    render_cfg = RenderConfig(warn_days=result["warn_days"], error_days=result["error_days"],
                              max_channels=customer.max_channels)
    xml = graph.render_prtg(result, render_cfg, extra_channels=[_age_channel(customer, cfg)])
    return Response(xml, mimetype="text/xml")


@bp.route("/json/<token>")
def prtg_json(token):
    """Serve the same data as JSON, for anything that is not PRTG."""
    customer = _customer_by_token(token)
    if customer is None:
        return jsonify({"error": "Unbekannter oder deaktivierter Token"}), 404
    try:
        return jsonify(_scoped_result(customer))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@bp.route("/healthz")
def healthz():
    """Liveness probe; never requires a token and never touches the database."""
    return Response("ok", mimetype="text/plain")
