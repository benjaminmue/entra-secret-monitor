#!/usr/bin/env python3
"""
audit.py

Append only audit trail.

Every write in the portal and every authentication decision produces one
row. Reads are not logged: they would drown the interesting events without
adding evidence, since the portal never shows a secret in clear.
"""

from flask import has_request_context, request

from portal.models import AuditEvent


def client_ip(trust_proxy=False):
    """Return the caller address, honouring X-Forwarded-For only when trusted."""
    if not has_request_context():
        return ""
    if trust_proxy:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return (request.remote_addr or "")[:64]


def log(session, action, actor="system", target="", detail="", success=True,
        trust_proxy=False, commit=True):
    """Write one audit row; never raises so logging cannot break a request."""
    try:
        session.add(AuditEvent(
            action=action[:48],
            actor=(actor or "system")[:64],
            target=str(target)[:128],
            detail=str(detail)[:2000],
            success=bool(success),
            ip=client_ip(trust_proxy),
        ))
        if commit:
            session.commit()
    except Exception as exc:                              # noqa: BLE001
        print("audit fehlgeschlagen (%s): %s" % (action, exc), flush=True)
