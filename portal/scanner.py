#!/usr/bin/env python3
"""
scanner.py

Bridge between the database and the Graph logic in app/graph.py.

Turns a Customer row into a graph.TenantConfig, runs one scan, and writes
the result back as a CheckRun plus a fresh credential snapshot. Nothing else
in the portal talks to Microsoft Graph.
"""

import time
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from sqlalchemy import delete, select

import graph
from portal import crypto
from portal.models import (AUTH_CERT, TRIGGER_SCHEDULE, CheckRun, CredentialSnapshot,
                           utcnow)


@dataclass
class RenderConfig:
    """Minimal stand in for a TenantConfig when only thresholds are needed."""

    warn_days: int = 30
    error_days: int = 14
    max_channels: int = 45


def customer_to_config(customer, encryption_key):
    """
    Build the graph.TenantConfig for one customer, decrypting its credential.

    Certificate material stays in memory: the private key is never written to
    disk, which is why graph.TenantConfig accepts PEM strings.
    """
    # Decrypt before constructing: TenantConfig validates in __post_init__ and
    # would reject a config whose credential is only attached afterwards.
    secret, cert_pem, key_pem = "", "", ""
    if customer.auth_type == AUTH_CERT:
        cert_pem = customer.cert_pem or ""
        key_pem = crypto.decrypt(customer.key_pem_enc, encryption_key,
                                 crypto.aad_for("customer", customer.key, "key_pem_enc"))
    else:
        secret = crypto.decrypt(customer.client_secret_enc, encryption_key,
                                crypto.aad_for("customer", customer.key,
                                               "client_secret_enc"))
    if not (secret or (cert_pem and key_pem)):
        raise graph.GraphError("Kunde '%s' hat keine hinterlegten Zugangsdaten" % customer.key)

    return graph.TenantConfig(
        key=customer.key,
        tenant_id=customer.tenant_id,
        client_id=customer.client_id,
        display_name=customer.display_name,
        client_secret=secret,
        cert_pem=cert_pem,
        key_pem=key_pem,
        include_sp=customer.include_sp,
        app_filter=customer.app_filter or "",
        app_exclude=customer.app_exclude or "",
        show_expired=customer.show_expired,
        warn_days=customer.warn_days,
        error_days=customer.error_days,
        max_channels=customer.max_channels,
    )


def inspect_certificate(cert_pem, key_pem):
    """
    Validate an uploaded key pair and return (thumbprint, not_after).

    Rejects a certificate whose public key does not belong to the private
    key, which is the mistake that otherwise only shows up as a Graph error
    hours later during the first scheduled scan.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_pub != key_pub:
        raise ValueError("Zertifikat und privater Schlüssel gehören nicht zusammen")
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") \
        else cert.not_valid_after.replace(tzinfo=timezone.utc)
    return thumbprint, not_after


def run_check(session, customer, encryption_key, trigger=TRIGGER_SCHEDULE, actor="system",
              history_runs=30):
    """
    Execute one scan for a customer and persist the outcome.

    Returns the CheckRun. A failure is stored as a run with status 'error'
    and leaves the previous snapshot untouched, so the PRTG sensor keeps
    delivering the last known values plus a rising data age instead of
    silently dropping to zero.
    """
    run = CheckRun(customer_id=customer.id, trigger=trigger, triggered_by=actor,
                   started_at=utcnow())
    session.add(run)
    session.flush()

    started = time.monotonic()
    try:
        cfg = customer_to_config(customer, encryption_key)
        result = graph.scan_tenant(cfg)
    except Exception as exc:                              # noqa: BLE001
        run.status = "error"
        run.error_message = "%s: %s" % (type(exc).__name__, exc)
        run.finished_at = utcnow()
        run.duration_ms = int((time.monotonic() - started) * 1000)
        customer.last_status = "error"
        customer.last_error = run.error_message[:2000]
        customer.last_check_at = run.finished_at
        _trim_history(session, customer.id, history_runs)
        session.commit()
        return run

    summary = result["summary"]
    run.status = "ok"
    run.finished_at = utcnow()
    run.duration_ms = int((time.monotonic() - started) * 1000)
    run.min_days = summary["minimum"]
    run.count_total = summary["total"]
    run.count_critical = summary["critical"]
    run.count_expired = summary["expired"]

    session.execute(delete(CredentialSnapshot).where(
        CredentialSnapshot.customer_id == customer.id))
    for entry in result["channels"]:
        session.add(CredentialSnapshot(
            customer_id=customer.id,
            check_run_id=run.id,
            app_name=entry["app"][:256],
            app_id=entry["app_id"][:64],
            object_type=entry["object_type"],
            cred_type=entry["type"],
            cred_name=entry["cred_name"][:256],
            end_date=datetime.strptime(entry["expires"], "%Y-%m-%d").replace(
                tzinfo=timezone.utc),
            days_left=entry["days"],
            sibling_count=entry["count"],
        ))

    customer.last_status = "ok"
    customer.last_error = ""
    customer.last_check_at = run.finished_at
    customer.min_days = summary["minimum"]
    customer.count_total = summary["total"]
    customer.count_critical = summary["critical"]
    customer.count_expired = summary["expired"]

    _trim_history(session, customer.id, history_runs)
    session.commit()
    return run


def _trim_history(session, customer_id, keep):
    """Delete check runs beyond the configured history depth."""
    ids = session.execute(
        select(CheckRun.id).where(CheckRun.customer_id == customer_id)
        .order_by(CheckRun.started_at.desc()).offset(keep)).scalars().all()
    if ids:
        session.execute(delete(CheckRun).where(CheckRun.id.in_(ids)))


def result_from_db(session, customer, max_channels=None):
    """
    Rebuild the renderer result structure from the stored snapshot.

    A PRTG poll must never trigger a Graph call, otherwise 50 sensors would
    hammer the same tenants and defeat the whole point of the daily schedule.
    """
    rows = session.execute(
        select(CredentialSnapshot).where(CredentialSnapshot.customer_id == customer.id)
        .order_by(CredentialSnapshot.days_left.asc())).scalars().all()

    channels = []
    for row in rows:
        label = "Secret" if row.cred_type == "secret" else "Zertifikat"
        channels.append({
            "name": "%s (%s)" % (row.app_name, label),
            "app": row.app_name,
            "days": row.days_left,
            "expires": row.end_date.strftime("%Y-%m-%d"),
            "cred_name": row.cred_name,
            "app_id": row.app_id,
            "type": row.cred_type,
            "object_type": row.object_type,
            "count": row.sibling_count,
        })

    checked = customer.last_check_at
    return {
        "tenant": customer.key,
        "display_name": customer.display_name,
        "warn_days": customer.warn_days,
        "error_days": customer.error_days,
        "checked": checked.strftime("%Y-%m-%d %H:%M:%S UTC") if checked else "nie",
        "age_hours": data_age_hours(customer),
        "status": customer.last_status,
        "error": customer.last_error or "",
        "summary": {
            "minimum": customer.min_days if customer.min_days is not None else 9999,
            "critical": customer.count_critical,
            "expired": customer.count_expired,
            "total": customer.count_total,
        },
        "channels": channels[:max_channels] if max_channels else channels,
    }


def data_age_hours(customer):
    """Whole hours since the last successful scan, -1 when never scanned."""
    if not customer.last_check_at:
        return -1
    checked = customer.last_check_at
    if checked.tzinfo is None:
        checked = checked.replace(tzinfo=timezone.utc)
    return int((datetime.now(timezone.utc) - checked).total_seconds() // 3600)


def filter_result(result, app="", name_filter="", exclude="", cred_type="",
                  warn_days=None, error_days=None, max_channels=None):
    """
    Narrow a stored result down to a subset of its channels.

    Used by the PRTG endpoint so one customer token can feed several sensors:
    the full picture with the customer thresholds, plus a dedicated sensor per
    application with its own limits. The summary is recomputed over the
    remaining channels, otherwise the minimum would still describe the whole
    tenant instead of the sensor's own scope.
    """
    channels = result["channels"]
    if app:
        wanted = app.strip().lower()
        channels = [c for c in channels if c["app"].lower() == wanted]
    if name_filter:
        needle = name_filter.strip().lower()
        channels = [c for c in channels if needle in c["app"].lower()]
    for stem in [e.strip().lower() for e in (exclude or "").split(",") if e.strip()]:
        channels = [c for c in channels if stem not in c["app"].lower()]
    if cred_type:
        wanted_type = "cert" if cred_type.strip().lower() in ("cert", "zertifikat",
                                                              "certificate") else "secret"
        channels = [c for c in channels if c["type"] == wanted_type]

    warn = warn_days if warn_days is not None else result["warn_days"]
    error = error_days if error_days is not None else result["error_days"]

    narrowed = dict(result)
    narrowed["warn_days"] = warn
    narrowed["error_days"] = error
    narrowed["channels"] = channels[:max_channels] if max_channels else channels
    narrowed["summary"] = {
        "minimum": min((c["days"] for c in channels), default=9999),
        "critical": sum(1 for c in channels if 0 <= c["days"] < warn),
        "expired": sum(1 for c in channels if c["days"] < 0),
        "total": len(channels),
    }
    return narrowed
