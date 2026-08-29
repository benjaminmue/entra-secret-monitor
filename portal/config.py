#!/usr/bin/env python3
"""
config.py

Central configuration of the portal, read once from the environment.

Everything the portal needs at runtime is resolved here so no other module
touches os.environ. Missing security relevant values are a hard error: a
portal that silently starts with a random key would log every user out on
restart and would lose access to every stored customer credential.
"""

import base64
import os
from dataclasses import dataclass, field

# Dieselben Konventionen fuer Umgebungsvariablen wie der klassische
# Dienst; frueher lagen hier wortgleiche Kopien.
from graph import as_bool, as_int

# Environment variables that must be present, mapped to a short explanation
# used in the error message when they are missing.
REQUIRED = {
    "PORTAL_SECRET_KEY": "Signiert die Session-Cookies. Beliebiger langer Zufallswert.",
    "PORTAL_ENCRYPTION_KEY": "Base64 von 32 Zufallsbytes. Verschlüsselt Kunden-Credentials.",
}


class ConfigError(RuntimeError):
    """Raised when the environment does not describe a usable portal."""


@dataclass
class PortalConfig:
    """Immutable runtime configuration of one portal instance."""

    secret_key: str
    encryption_key: bytes
    database_url: str = "sqlite:////data/portal.db"

    # Session and login hardening
    session_minutes: int = 60
    cookie_secure: bool = True
    login_max_attempts: int = 5
    lockout_minutes: int = 15
    password_min_length: int = 12

    # Scan scheduling
    scheduler_enabled: bool = True
    tick_seconds: int = 60
    gap_seconds: int = 10
    stale_hours: int = 30
    history_runs: int = 30
    default_warn_days: int = 30
    default_error_days: int = 14

    # Bootstrap of the very first administrator
    bootstrap_user: str = ""
    bootstrap_password: str = ""

    # Presentation
    listen_addr: str = "0.0.0.0"
    listen_port: int = 8099
    base_url: str = ""
    instance_name: str = "Entra Credential Monitor"
    trust_proxy: bool = False

    warnings: list = field(default_factory=list)


def _read_encryption_key(raw):
    """Decode and validate the base64 master key used for credential encryption."""
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:                              # noqa: BLE001
        raise ConfigError("PORTAL_ENCRYPTION_KEY ist kein gültiges Base64: %s" % exc) from exc
    if len(key) != 32:
        raise ConfigError("PORTAL_ENCRYPTION_KEY muss 32 Bytes ergeben, sind %d" % len(key))
    return key


def load_config(env=None):
    """
    Build the PortalConfig from the environment.

    Raises ConfigError with a copy-pasteable hint when a required value is
    missing, because the two keys cannot be regenerated without data loss.
    """
    env = env if env is not None else os.environ

    missing = [name for name in REQUIRED if not env.get(name)]
    if missing:
        lines = ["Fehlende Umgebungsvariablen:"]
        lines += ["  %s  %s" % (name, REQUIRED[name]) for name in missing]
        lines.append("")
        lines.append("Erzeugen mit:")
        lines.append('  python3 -c "import secrets,base64;'
                     'print(secrets.token_urlsafe(64));'
                     'print(base64.b64encode(secrets.token_bytes(32)).decode())"')
        raise ConfigError("\n".join(lines))

    cfg = PortalConfig(
        secret_key=env["PORTAL_SECRET_KEY"],
        encryption_key=_read_encryption_key(env["PORTAL_ENCRYPTION_KEY"]),
        database_url=env.get("PORTAL_DATABASE_URL", "sqlite:////data/portal.db"),
        session_minutes=as_int(env.get("PORTAL_SESSION_MINUTES"), 60),
        cookie_secure=as_bool(env.get("PORTAL_COOKIE_SECURE"), True),
        login_max_attempts=as_int(env.get("PORTAL_LOGIN_MAX_ATTEMPTS"), 5),
        lockout_minutes=as_int(env.get("PORTAL_LOCKOUT_MINUTES"), 15),
        password_min_length=as_int(env.get("PORTAL_PASSWORD_MIN_LENGTH"), 12),
        scheduler_enabled=as_bool(env.get("PORTAL_SCHEDULER"), True),
        tick_seconds=as_int(env.get("PORTAL_TICK_SECONDS"), 60),
        gap_seconds=as_int(env.get("PORTAL_GAP_SECONDS"), 10),
        stale_hours=as_int(env.get("PORTAL_STALE_HOURS"), 30),
        history_runs=as_int(env.get("PORTAL_HISTORY_RUNS"), 30),
        default_warn_days=as_int(env.get("PORTAL_WARN_DAYS"), 30),
        default_error_days=as_int(env.get("PORTAL_ERROR_DAYS"), 14),
        bootstrap_user=env.get("PORTAL_BOOTSTRAP_USER", ""),
        bootstrap_password=env.get("PORTAL_BOOTSTRAP_PASSWORD", ""),
        listen_addr=env.get("LISTEN_ADDR", "0.0.0.0"),
        listen_port=as_int(env.get("LISTEN_PORT"), 8099),
        base_url=env.get("PORTAL_BASE_URL", "").rstrip("/"),
        instance_name=env.get("PORTAL_INSTANCE_NAME", "Entra Credential Monitor"),
        trust_proxy=as_bool(env.get("PORTAL_TRUST_PROXY"), False),
    )

    if cfg.password_min_length < 12:
        cfg.password_min_length = 12
        cfg.warnings.append("PORTAL_PASSWORD_MIN_LENGTH unter 12, auf 12 angehoben")
    if not cfg.base_url:
        cfg.warnings.append("PORTAL_BASE_URL nicht gesetzt: die angezeigten Sensor-URLs "
                            "stammen dann aus dem Host-Header des Aufrufers und lassen "
                            "sich von aussen fälschen")
    if not cfg.cookie_secure:
        cfg.warnings.append("PORTAL_COOKIE_SECURE=0: Session-Cookie auch über HTTP gültig, "
                            "nur für lokale Tests verwenden")
    return cfg
