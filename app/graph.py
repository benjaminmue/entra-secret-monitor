#!/usr/bin/env python3
"""
graph.py

Core library for the Entra ID credential expiry monitor.

Talks to Microsoft Graph with an app-only token, flattens the credentials of
app registrations and service principals, aggregates them per app and renders
them as PRTG XML, JSON or text. Used by cli.py and server.py.

Only stdlib plus `cryptography` (needed for certificate authentication).
"""

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
SELECT_FIELDS = "id,appId,displayName,passwordCredentials,keyCredentials"


class GraphError(RuntimeError):
    """Raised when Graph or the token endpoint returns an unusable response."""


class NoTenantsConfigured(GraphError):
    """Raised when no tenant is configured at all, as opposed to a broken one."""


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

@dataclass
class TenantConfig:
    """Everything needed to query one tenant and judge its credentials."""

    key: str
    tenant_id: str
    client_id: str
    display_name: str = ""
    client_secret: str = ""
    cert_path: str = ""
    key_path: str = ""
    include_sp: bool = False
    app_filter: str = ""
    app_exclude: str = ""
    show_expired: bool = False
    warn_days: int = 30
    error_days: int = 14
    max_channels: int = 45
    push_url: str = ""

    def __post_init__(self):
        """Fill in the display name and validate the credential configuration."""
        if not self.display_name:
            self.display_name = self.key
        if not self.tenant_id or not self.client_id:
            raise GraphError("Tenant '%s': TENANT_ID oder CLIENT_ID fehlt" % self.key)
        if not self.client_secret and not (self.cert_path and self.key_path):
            raise GraphError("Tenant '%s': weder CLIENT_SECRET noch CERT_PATH/KEY_PATH gesetzt"
                             % self.key)


def _as_bool(value, default=False):
    """Interpret common truthy strings from environment variables."""
    if value is None or value == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "ja", "on")


def _as_int(value, default):
    """Parse an integer from an environment variable, falling back on default."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _env_prefix(key):
    """Turn a tenant key into its environment variable prefix."""
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in key)
    return cleaned.upper() + "_"


def tenant_from_env(key, env=None):
    """Build a TenantConfig from prefixed environment variables."""
    env = env if env is not None else os.environ
    p = _env_prefix(key)

    def get(name, fallback=""):
        """Read a prefixed variable, falling back to the unprefixed one."""
        return env.get(p + name, env.get(name, fallback))

    return TenantConfig(
        key=key,
        tenant_id=get("TENANT_ID"),
        client_id=get("CLIENT_ID"),
        display_name=get("DISPLAY_NAME", ""),
        client_secret=get("CLIENT_SECRET"),
        cert_path=get("CERT_PATH"),
        key_path=get("KEY_PATH"),
        include_sp=_as_bool(get("INCLUDE_SP"), False),
        app_filter=get("APP_FILTER"),
        app_exclude=get("APP_EXCLUDE"),
        show_expired=_as_bool(get("SHOW_EXPIRED"), False),
        warn_days=_as_int(get("WARN_DAYS"), 30),
        error_days=_as_int(get("ERROR_DAYS"), 14),
        max_channels=_as_int(get("MAX_CHANNELS"), 45),
        push_url=get("PUSH_URL"),
    )


def tenant_from_dict(key, data):
    """Build a TenantConfig from one entry of tenants.json."""
    return TenantConfig(
        key=key,
        tenant_id=data.get("tenant_id", ""),
        client_id=data.get("client_id", ""),
        display_name=data.get("display_name", ""),
        client_secret=data.get("client_secret", ""),
        cert_path=data.get("cert_path", ""),
        key_path=data.get("key_path", ""),
        include_sp=bool(data.get("include_sp", False)),
        app_filter=data.get("app_filter", ""),
        app_exclude=data.get("app_exclude", ""),
        show_expired=bool(data.get("show_expired", False)),
        warn_days=int(data.get("warn_days", 30)),
        error_days=int(data.get("error_days", 14)),
        max_channels=int(data.get("max_channels", 45)),
        push_url=data.get("push_url", ""),
    )


def load_tenants(env=None, config_path=None):
    """
    Assemble all configured tenants.

    Sources, later ones win: TENANTS=<keys> with prefixed env vars, a single
    unprefixed tenant when TENANTS is unset, and an optional tenants.json.
    """
    env = env if env is not None else os.environ
    tenants = {}

    keys = [k.strip() for k in env.get("TENANTS", "").split(",") if k.strip()]
    if keys:
        for key in keys:
            tenants[key] = tenant_from_env(key, env)
    elif env.get("TENANT_ID"):
        tenants["default"] = tenant_from_env("default", env)

    path = config_path or env.get("TENANTS_FILE", "/config/tenants.json")
    if path and Path(path).is_file():
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for key, entry in data.items():
            tenants[key] = tenant_from_dict(key, entry)

    if not tenants:
        raise NoTenantsConfigured(
            "Keine Tenants konfiguriert (TENANTS/TENANT_ID oder tenants.json)")
    return tenants


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def _post_token(tenant_id, data):
    """POST to the tenant token endpoint and return the access token."""
    url = "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % tenant_id
    req = urllib.request.Request(
        url, data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        raise GraphError("Token-Endpoint HTTP %s: %s" % (exc.code, detail)) from exc
    except urllib.error.URLError as exc:
        raise GraphError("Token-Endpoint nicht erreichbar: %s" % exc.reason) from exc
    if "access_token" not in payload:
        raise GraphError("Token-Antwort ohne access_token: %s" % payload)
    return payload["access_token"]


def _client_assertion(cfg):
    """Build a signed JWT client assertion from the configured certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    cert = x509.load_pem_x509_certificate(Path(cfg.cert_path).read_bytes())
    key = serialization.load_pem_private_key(Path(cfg.key_path).read_bytes(), password=None)
    thumb = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA1())).decode().rstrip("=")

    def segment(obj):
        """Base64url encode one JWT segment without padding."""
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": thumb}
    claims = {
        "aud": "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % cfg.tenant_id,
        "iss": cfg.client_id,
        "sub": cfg.client_id,
        "jti": str(uuid.uuid4()),
        "nbf": now - 60,
        "exp": now + 600,
    }
    signing_input = segment(header) + b"." + segment(claims)
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()


def get_token(cfg):
    """Acquire an app-only Graph token, certificate first, secret as fallback."""
    if cfg.cert_path and cfg.key_path:
        return _post_token(cfg.tenant_id, {
            "client_id": cfg.client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _client_assertion(cfg),
            "scope": GRAPH_SCOPE,
            "grant_type": "client_credentials",
        })
    return _post_token(cfg.tenant_id, {
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "scope": GRAPH_SCOPE,
        "grant_type": "client_credentials",
    })


# --------------------------------------------------------------------------
# Graph queries
# --------------------------------------------------------------------------

@dataclass
class Credential:
    """One secret or certificate belonging to an app registration."""

    app_name: str
    app_id: str
    object_type: str          # "application" or "servicePrincipal"
    cred_type: str            # "secret" or "cert"
    display_name: str
    key_id: str
    end_date: datetime

    @property
    def days_left(self):
        """Whole days until expiry; negative when already expired."""
        return int((self.end_date - datetime.now(timezone.utc)).total_seconds() // 86400)


def graph_get_all(token, path):
    """Follow @odata.nextLink and return all items of a Graph collection."""
    items = []
    url = GRAPH_BASE + path
    while url:
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:300]
            raise GraphError("Graph HTTP %s auf %s: %s" % (exc.code, path, detail)) from exc
        except urllib.error.URLError as exc:
            raise GraphError("Graph nicht erreichbar: %s" % exc.reason) from exc
        items.extend(payload.get("value", []))
        url = payload.get("@odata.nextLink")
    return items


def parse_date(value):
    """Parse a Graph ISO 8601 timestamp into a timezone aware datetime."""
    cleaned = value.replace("Z", "+00:00")
    if "." in cleaned:
        head, _, tail = cleaned.partition(".")
        frac, sign, offset = tail.partition("+")
        cleaned = head + "." + frac[:6] + (sign + offset if sign else "")
    return datetime.fromisoformat(cleaned).astimezone(timezone.utc)


def collect_credentials(token, include_sp):
    """Fetch app registrations (and optionally SPs) and flatten their credentials."""
    objects = [("application", o) for o in
               graph_get_all(token, "/applications?$select=%s&$top=999" % SELECT_FIELDS)]
    if include_sp:
        objects += [("servicePrincipal", o) for o in
                    graph_get_all(token, "/servicePrincipals?$select=%s&$top=999" % SELECT_FIELDS)]

    creds = []
    for obj_type, obj in objects:
        for cred_type, field_name in (("secret", "passwordCredentials"),
                                      ("cert", "keyCredentials")):
            for cred in obj.get(field_name) or []:
                end = cred.get("endDateTime")
                if not end:
                    continue
                creds.append(Credential(
                    app_name=obj.get("displayName") or obj.get("appId", "?"),
                    app_id=obj.get("appId", ""),
                    object_type=obj_type,
                    cred_type=cred_type,
                    display_name=cred.get("displayName") or "(ohne Name)",
                    key_id=cred.get("keyId", ""),
                    end_date=parse_date(end),
                ))
    return creds


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

def build_channels(creds, cfg):
    """
    Group credentials per app and type and keep the longest remaining runtime.

    A freshly rolled secret makes the old one irrelevant, so the maximum per
    group is the value that actually describes the risk for that app.

    app_filter keeps only matching apps, app_exclude drops them. Both match on a
    lowercased substring of the display name; app_exclude takes a comma separated
    list and wins over app_filter.
    """
    excludes = [e.strip().lower() for e in (cfg.app_exclude or "").split(",") if e.strip()]

    groups = {}
    for cred in creds:
        name = cred.app_name.lower()
        if cfg.app_filter and cfg.app_filter.lower() not in name:
            continue
        if any(e in name for e in excludes):
            continue
        groups.setdefault((cred.app_name, cred.cred_type), []).append(cred)

    channels = []
    for (app_name, cred_type), items in groups.items():
        best = max(items, key=lambda c: c.days_left)
        if best.days_left < 0 and not cfg.show_expired:
            continue
        label = "Secret" if cred_type == "secret" else "Zertifikat"
        channels.append({
            "name": "%s (%s)" % (app_name, label),
            "app": app_name,
            "days": best.days_left,
            "expires": best.end_date.strftime("%Y-%m-%d"),
            "cred_name": best.display_name,
            "app_id": best.app_id,
            "type": cred_type,
            "object_type": best.object_type,
            "count": len(items),
        })
    channels.sort(key=lambda c: c["days"])
    return channels


def summarize(channels, cfg):
    """Compute the three headline numbers used by PRTG and the web GUI."""
    return {
        "minimum": min((c["days"] for c in channels), default=9999),
        "critical": sum(1 for c in channels if 0 <= c["days"] < cfg.warn_days),
        "expired": sum(1 for c in channels if c["days"] < 0),
        "total": len(channels),
    }


def fetch_credentials(cfg):
    """
    Authenticate and return the raw credential list for one tenant.

    Kept separate from rendering so a caller can cache the expensive Graph
    round trip and still apply different filters and thresholds per request.
    Only include_sp changes what is fetched; everything else is post-processing.
    """
    return collect_credentials(get_token(cfg), cfg.include_sp)


def build_result(creds, cfg):
    """Turn raw credentials into the result structure used by every renderer."""
    channels = build_channels(creds, cfg)
    return {
        "tenant": cfg.key,
        "display_name": cfg.display_name,
        "warn_days": cfg.warn_days,
        "error_days": cfg.error_days,
        "checked": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "summary": summarize(channels, cfg),
        "channels": channels,
    }


def scan_tenant(cfg):
    """Run a full scan for one tenant and return channels plus summary."""
    return build_result(fetch_credentials(cfg), cfg)


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------

def render_prtg(result, cfg):
    """Render PRTG XML: three summary channels plus one channel per app."""
    channels = result["channels"]
    shown = channels[:cfg.max_channels]
    truncated = len(channels) - len(shown)
    summary = result["summary"]
    out = ['<?xml version="1.0" encoding="UTF-8" ?>', "<prtg>"]

    def channel(name, value, unit, limits=None):
        """Append one <result> block, optionally with static limits."""
        out.append("  <result>")
        out.append("    <channel>%s</channel>" % escape(name))
        out.append("    <value>%d</value>" % value)
        out.append("    <unit>Custom</unit>")
        out.append("    <customunit>%s</customunit>" % escape(unit))
        if limits:
            lo_warn, lo_err, hi_warn, hi_err = limits
            out.append("    <limitmode>1</limitmode>")
            if lo_warn is not None:
                out.append("    <limitminwarning>%d</limitminwarning>" % lo_warn)
            if lo_err is not None:
                out.append("    <limitminerror>%d</limitminerror>" % lo_err)
            if hi_warn is not None:
                out.append("    <limitmaxwarning>%d</limitmaxwarning>" % hi_warn)
            if hi_err is not None:
                out.append("    <limitmaxerror>%d</limitmaxerror>" % hi_err)
        out.append("  </result>")

    day_limits = (cfg.warn_days, cfg.error_days, None, None)
    channel("Minimale Restlaufzeit", summary["minimum"], "Tage", day_limits)
    channel("Kritisch unter Warngrenze", summary["critical"], "Anzahl", (None, None, 0, None))
    channel("Abgelaufen", summary["expired"], "Anzahl", (None, None, None, 0))
    for entry in shown:
        channel(entry["name"], entry["days"], "Tage", day_limits)

    if channels:
        worst = channels[0]
        text = "Naechster Ablauf: %s am %s (%d Tage)" % (
            worst["name"], worst["expires"], worst["days"])
    else:
        text = "Keine Credentials gefunden"
    if truncated > 0:
        text += " | %d weitere Kanaele nicht dargestellt" % truncated
    out.append("  <text>%s</text>" % escape(text[:2000]))
    out.append("</prtg>")
    return "\n".join(out)


def render_prtg_error(message):
    """Render a PRTG error response so the sensor turns red instead of staying silent."""
    return ('<?xml version="1.0" encoding="UTF-8" ?>\n<prtg>\n  <error>1</error>\n'
            '  <text>%s</text>\n</prtg>' % escape(str(message)[:2000]))


def render_text(result, cfg):
    """Render a readable table for manual runs on the shell."""
    lines = ["Tenant: %s (%s)" % (result["display_name"], result["tenant"]),
             "Stand:  %s" % result["checked"], ""]
    lines.append("%12s     %-12s %-8s %s" % ("Restlaufzeit", "Ablauf", "Typ", "App / Credential"))
    lines.append("-" * 100)
    for entry in result["channels"]:
        flag = "!!" if entry["days"] < cfg.error_days else (
            "! " if entry["days"] < cfg.warn_days else "  ")
        lines.append("%10d d %s %-12s %-8s %s / %s" % (
            entry["days"], flag, entry["expires"], entry["type"],
            entry["app"], entry["cred_name"]))
    lines.append("-" * 100)
    summary = result["summary"]
    lines.append("%d Eintraege, %d abgelaufen, %d unter %d Tagen" % (
        summary["total"], summary["expired"], summary["critical"], cfg.warn_days))
    return "\n".join(lines)


def push_to_prtg(url, xml):
    """Send the XML to a PRTG HTTP Push Data Advanced sensor."""
    req = urllib.request.Request(
        url, data=urllib.parse.urlencode({"content": xml}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()
