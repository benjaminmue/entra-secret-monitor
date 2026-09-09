#!/usr/bin/env python3
"""
models.py

Database schema of the portal.

Six tables: users and their recovery codes, customers (one monitored Entra
tenant each), the check runs against them, the credential snapshot a run
produced, and an append only audit log.

The snapshot is what the GUI and the PRTG endpoint read. Microsoft Graph is
only touched by the scheduler and by an explicit force check, never by a
sensor poll.
"""

import secrets
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, ForeignKey, Index, Integer, String, Text)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from portal.db import Base

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"
ROLES = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_VIEWER)

ROLE_LABELS = {
    ROLE_ADMIN: "Administrator",
    ROLE_OPERATOR: "Operator",
    ROLE_VIEWER: "Leser",
}

AUTH_SECRET = "secret"
AUTH_CERT = "certificate"

# Welche Eingabefelder zu welcher Anmeldeart gehoeren, und was die jeweils
# andere ist. Steht hier neben den Konstanten, weil drei Stellen dieselbe
# Kenntnis brauchen: die Pruefung und die Uebernahme in der Schnittstelle und
# die Uebernahme in der Oberflaeche. Als drei Kopien hat genau das schon dazu
# gefuehrt, dass eine Stelle nachgezogen wurde und die andere nicht.
CREDENTIAL_FELDER = {
    AUTH_SECRET: ("client_secret",),
    AUTH_CERT: ("cert_pem", "key_pem"),
}
GEGENSTUECK = {AUTH_SECRET: AUTH_CERT, AUTH_CERT: AUTH_SECRET}

TRIGGER_SCHEDULE = "schedule"
TRIGGER_MANUAL = "manual"
TRIGGER_STARTUP = "startup"


def utcnow():
    """Timezone aware current time, used as default for every timestamp."""
    return datetime.now(timezone.utc)


def new_token(length=32):
    """Return a URL safe random token, used for the PRTG endpoints."""
    return secrets.token_urlsafe(length)


class User(Base):
    """A portal account. Authentication is password plus mandatory TOTP."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(190), default="")
    role: Mapped[str] = mapped_column(String(16), default=ROLE_VIEWER, nullable=False)

    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    password_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)

    totp_secret_enc: Mapped[str] = mapped_column(Text, default="")
    totp_confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_totp_counter: Mapped[int] = mapped_column(Integer, default=0)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[str] = mapped_column(String(64), default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="")

    recovery_codes: Mapped[list["RecoveryCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan")

    @property
    def totp_ready(self):
        """True when the account finished TOTP enrollment."""
        return bool(self.totp_secret_enc and self.totp_confirmed_at)

    @property
    def role_label(self):
        """German label of the role for display."""
        return ROLE_LABELS.get(self.role, self.role)

    def has_role(self, *roles):
        """True when the account holds one of the given roles."""
        return self.role in roles

    @property
    def is_authenticated(self):
        """Flask-Login interface; a loaded user always counts as authenticated."""
        return True

    @property
    def is_anonymous(self):
        """Flask-Login interface."""
        return False

    def get_id(self):
        """Flask-Login interface; the session stores the primary key."""
        return str(self.id)


class RecoveryCode(Base):
    """One single use fallback code for a lost authenticator app."""

    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"),
                                         nullable=False)
    code_hash: Mapped[str] = mapped_column(Text, nullable=False)
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["User"] = relationship(back_populates="recovery_codes")


class Customer(Base):
    """
    One monitored customer tenant.

    Credentials are stored encrypted; auth_type decides which of the two
    columns is filled. slot_minute holds the assigned minute of the day for
    the automatic scan so all tenants are spread over 24 hours.
    """

    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(48), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="")

    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(16), default=AUTH_SECRET, nullable=False)
    client_secret_enc: Mapped[str] = mapped_column(Text, default="")
    cert_pem: Mapped[str] = mapped_column(Text, default="")
    key_pem_enc: Mapped[str] = mapped_column(Text, default="")
    cert_thumbprint: Mapped[str] = mapped_column(String(64), default="")
    cert_not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    warn_days: Mapped[int] = mapped_column(Integer, default=30)
    error_days: Mapped[int] = mapped_column(Integer, default=14)
    include_sp: Mapped[bool] = mapped_column(Boolean, default=False)
    show_expired: Mapped[bool] = mapped_column(Boolean, default=False)
    app_filter: Mapped[str] = mapped_column(String(190), default="")
    app_exclude: Mapped[str] = mapped_column(String(190), default="")
    max_channels: Mapped[int] = mapped_column(Integer, default=45)

    prtg_token: Mapped[str] = mapped_column(String(64), unique=True, default=new_token)
    slot_minute: Mapped[int] = mapped_column(Integer, default=0)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    last_check_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    # Getrennt vom letzten Versuch: last_check_at treibt den Zeitplan und muss
    # deshalb auch bei einem Fehlschlag weiterruecken, sonst liefe der Kunde
    # bei jedem Tick erneut. Das Alter der Daten haengt aber am letzten
    # Erfolg. Ueber last_check_at gerechnet sah ein Kunde, dessen Scans
    # dauerhaft scheitern, taggenau frisch aus, und genau den Fall soll der
    # Kanal Datenalter im Sensor melden.
    last_success_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                      nullable=True)
    last_status: Mapped[str] = mapped_column(String(16), default="pending")
    last_error: Mapped[str] = mapped_column(Text, default="")
    min_days: Mapped[int] = mapped_column(Integer, nullable=True)
    count_total: Mapped[int] = mapped_column(Integer, default=0)
    count_critical: Mapped[int] = mapped_column(Integer, default=0)
    count_expired: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow,
                                                 onupdate=utcnow)

    runs: Mapped[list["CheckRun"]] = relationship(
        back_populates="customer", cascade="all, delete-orphan")
    credentials: Mapped[list["CredentialSnapshot"]] = relationship(
        back_populates="customer", cascade="all, delete-orphan")

    @property
    def slot_label(self):
        """Assigned scan time of day as HH:MM in UTC."""
        return "%02d:%02d" % (self.slot_minute // 60, self.slot_minute % 60)

    @property
    def auth_label(self):
        """German label of the configured authentication method."""
        return "Zertifikat" if self.auth_type == AUTH_CERT else "Client Secret"

    @property
    def has_credential(self):
        """
        True when material for the *chosen* method is stored.

        Bewusst an auth_type gebunden, dieselbe Verzweigung wie im Scanner. Eine
        methodenblinde Pruefung auf "irgendein Feld ist gefuellt" meldete einen
        Kunden als bereit, dessen Lauf dann an der leeren Haelfte scheiterte,
        etwa nach einem Import oder einer Aenderung von Hand.

        Geprueft wird, ob etwas hinterlegt ist, nicht ob es sich lesen laesst:
        der Schluessel zum Entschluesseln liegt in der Umgebung und nicht am
        Datensatz. Ein Datensatz, der mit einem anderen PORTAL_ENCRYPTION_KEY
        geschrieben wurde, meldet hier True und scheitert trotzdem im Lauf.
        """
        if self.auth_type == AUTH_CERT:
            return bool(self.cert_pem and self.key_pem_enc)
        return bool(self.client_secret_enc)


class CheckRun(Base):
    """One scan attempt against one customer, successful or not."""

    __tablename__ = "check_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"),
                                             nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="ok")
    trigger: Mapped[str] = mapped_column(String(16), default=TRIGGER_SCHEDULE)
    triggered_by: Mapped[str] = mapped_column(String(64), default="")
    error_message: Mapped[str] = mapped_column(Text, default="")

    min_days: Mapped[int] = mapped_column(Integer, nullable=True)
    count_total: Mapped[int] = mapped_column(Integer, default=0)
    count_critical: Mapped[int] = mapped_column(Integer, default=0)
    count_expired: Mapped[int] = mapped_column(Integer, default=0)

    customer: Mapped["Customer"] = relationship(back_populates="runs")

    __table_args__ = (Index("ix_runs_customer_started", "customer_id", "started_at"),)


class CredentialSnapshot(Base):
    """
    One credential of one customer as seen by the last successful run.

    Rows are replaced wholesale per successful scan, so the table always
    mirrors the current state and never grows unbounded.
    """

    __tablename__ = "credential_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"),
                                             nullable=False)
    check_run_id: Mapped[int] = mapped_column(Integer, nullable=True)

    app_name: Mapped[str] = mapped_column(String(256), default="")
    app_id: Mapped[str] = mapped_column(String(64), default="")
    object_type: Mapped[str] = mapped_column(String(24), default="application")
    cred_type: Mapped[str] = mapped_column(String(16), default="secret")
    cred_name: Mapped[str] = mapped_column(String(256), default="")
    key_id: Mapped[str] = mapped_column(String(64), default="")
    end_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    days_left: Mapped[int] = mapped_column(Integer, default=0)
    sibling_count: Mapped[int] = mapped_column(Integer, default=1)

    customer: Mapped["Customer"] = relationship(back_populates="credentials")

    __table_args__ = (Index("ix_snapshot_customer_days", "customer_id", "days_left"),)

    @property
    def type_label(self):
        """German label of the credential type."""
        return "Secret" if self.cred_type == "secret" else "Zertifikat"

    @property
    def object_label(self):
        """German label of the owning directory object."""
        return "App-Registrierung" if self.object_type == "application" else "Enterprise App"


class AuditEvent(Base):
    """Append only record of every change and every security relevant event."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(64), default="system")
    ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    target: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    success: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (Index("ix_audit_created", "created_at"),)


# Rechte eines API-Schluessels. Lesen deckt Abfragen ab, Schreiben zusaetzlich
# das Anlegen und Aendern von Kunden sowie das Ausloesen einer Pruefung.
API_SCOPE_READ = "read"
API_SCOPE_WRITE = "write"
API_SCOPES = (API_SCOPE_READ, API_SCOPE_WRITE)

# Der sichtbare Anfang eines Schluessels. Er steht im Klartext in der Datenbank,
# damit eine Anfrage ohne Durchprobieren aller Hashes zugeordnet werden kann,
# und er erlaubt es, einen Schluessel in einer Liste wiederzuerkennen.
API_KEY_PREFIX_LENGTH = 8


def new_api_key():
    """
    Return (vollstaendiger Schluessel, Praefix) for a fresh API key.

    Das Format esm_<praefix>_<geheimnis> macht den Schluessel in Protokollen als
    solchen erkennbar, was Werkzeuge zur Geheimnissuche brauchen, und trennt den
    nachschlagbaren Teil vom geheimen.
    """
    praefix = secrets.token_hex(API_KEY_PREFIX_LENGTH // 2)
    return "esm_%s_%s" % (praefix, secrets.token_urlsafe(32)), praefix


class ApiKey(Base):
    """
    A machine account for the REST interface.

    Bewusst kein User: ein Programm hat kein Passwort zu wechseln und keinen
    zweiten Faktor. Gespeichert wird nur der Hash, der Schluessel selbst ist
    nach dem Erzeugen nicht mehr herstellbar.
    """

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    key_hash: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(String(16), default=API_SCOPE_READ, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def is_active(self):
        """True while the key has not been revoked."""
        return self.revoked_at is None

    @property
    def may_write(self):
        """True when the key is allowed to change anything."""
        return self.is_active and self.scope == API_SCOPE_WRITE

    @property
    def scope_label(self):
        """German label of the scope for display."""
        return "Lesen und Schreiben" if self.scope == API_SCOPE_WRITE else "Nur Lesen"


class SchemaInfo(Base):
    """Single row marker so a future migration can detect the schema level."""

    __tablename__ = "schema_info"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
