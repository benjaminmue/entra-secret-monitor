#!/usr/bin/env python3
"""
api.py

REST-Schnittstelle des Portals, gedacht fuer die Ansteuerung aus einem
uebergeordneten System wie dem Business Portal.

Bewusst getrennt von der Weboberflaeche: keine Sitzung, kein CSRF, keine
Weiterleitungen. Authentifiziert wird mit einem API-Schluessel im
Authorization-Kopf, und jede Antwort ist JSON, auch im Fehlerfall. Ein
Programm bekommt sonst eine HTML-Seite und meldet einen Parserfehler statt der
Ursache.

Zugangsdaten der Kunden nimmt die Schnittstelle entgegen, gibt sie aber nie
heraus. Zurueck kommt nur, ob etwas hinterlegt ist und wann ein Zertifikat
ablaeuft. Ein API-Schluessel ist damit kein Generalschluessel fuer die Tenants
der Kunden.
"""

import re
from datetime import timezone
from functools import wraps

from flask import Blueprint, g, jsonify, request, url_for
from flask_login import current_user
from sqlalchemy import select

from portal import audit, crypto, openapi, scheduler, security
from portal.db import Session
from portal.forms import GUID, KEY_PATTERN
from portal.models import (API_SCOPE_WRITE, AUTH_CERT, AUTH_SECRET, ApiKey,
                           CredentialSnapshot, Customer, new_token, utcnow)
from portal.scanner import inspect_certificate
from portal.views.helpers import base_url, config

bp = Blueprint("api", __name__, url_prefix="/api/v1")

# Version der Schnittstelle. Sie steht im Pfad, damit eine spaetere,
# unvertraegliche Fassung danebenlaufen kann statt bestehende Aufrufer zu
# brechen.
API_VERSION = "1.0"


# Verzeichnis der Endpunkte. Es steht hier und nicht im Template, damit die
# Einstellungsseite und die Wurzel derselben Quelle folgen und eine neue Route
# nicht an einer der beiden Stellen vergessen wird.
ENDPUNKTE = [
    {"methode": "GET", "pfad": "/api/v1/", "bereich": "read",
     "zweck": "Version, Instanzname und dieses Verzeichnis"},
    {"methode": "GET", "pfad": "/api/v1/openapi.json", "bereich": "read",
     "zweck": "Maschinenlesbare Beschreibung dieser Schnittstelle"},
    {"methode": "GET", "pfad": "/api/v1/customers", "bereich": "read",
     "zweck": "Alle Kunden mit Zusammenfassung und Sensor-URLs"},
    {"methode": "POST", "pfad": "/api/v1/customers", "bereich": "write",
     "zweck": "Kunde anlegen mit Tenant-ID, Client-ID und Secret oder Zertifikat"},
    {"methode": "GET", "pfad": "/api/v1/customers/<key>", "bereich": "read",
     "zweck": "Ein Kunde samt seiner Zugangsdaten-Laufzeiten"},
    {"methode": "PATCH", "pfad": "/api/v1/customers/<key>", "bereich": "write",
     "zweck": "Kunde ändern, weggelassene Felder bleiben stehen"},
    {"methode": "DELETE", "pfad": "/api/v1/customers/<key>", "bereich": "write",
     "zweck": "Kunde mit Verlauf entfernen"},
    {"methode": "POST", "pfad": "/api/v1/customers/<key>/check", "bereich": "write",
     "zweck": "Prüfung sofort auslösen, Antwort enthält das Ergebnis"},
    {"methode": "GET", "pfad": "/api/v1/customers/<key>/credentials", "bereich": "read",
     "zweck": "Zugangsdaten des Kunden, kürzeste Restlaufzeit zuerst"},
    {"methode": "GET", "pfad": "/api/v1/customers/<key>/urls", "bereich": "read",
     "zweck": "Sensor-URLs für PRTG und JSON"},
    {"methode": "POST", "pfad": "/api/v1/customers/<key>/token", "bereich": "write",
     "zweck": "Neues Sensor-Token, die bisherige URL liefert danach nichts mehr"},
]


# --------------------------------------------------------------------------
# Fehler und Authentifizierung
# --------------------------------------------------------------------------

def fehler(status, code, meldung, felder=None):
    """
    Render one error response.

    Immer dieselbe Form, damit ein Aufrufer nicht raten muss: ein maschinen-
    lesbarer Code und ein Satz fuer den Menschen, der davorsitzt.
    """
    koerper = {"error": {"code": code, "message": meldung}}
    if felder:
        koerper["error"]["fields"] = felder
    return jsonify(koerper), status


def schluessel_aus_anfrage():
    """Read the bearer token from the Authorization header, or None."""
    kopf = request.headers.get("Authorization", "").strip()
    if kopf[:7].lower() == "bearer ":
        return kopf[7:].strip()
    return None


def finde_schluessel(roh):
    """
    Resolve a presented key to its record, or None.

    Der Praefix macht das Nachschlagen zu einer Abfrage statt zu einem
    Durchprobieren aller Hashes. Verglichen wird trotzdem ueber den Hash, der
    Praefix allein berechtigt zu nichts.
    """
    if not roh or not roh.startswith("esm_"):
        return None
    teile = roh.split("_", 2)
    if len(teile) != 3:
        return None
    eintrag = Session.execute(
        select(ApiKey).where(ApiKey.prefix == teile[1])).scalar_one_or_none()
    if eintrag is None or not eintrag.is_active:
        return None
    if not security.verify_password(eintrag.key_hash, roh):
        return None
    return eintrag


def benoetigt_schluessel(schreibend=False):
    """
    Decorator: require a valid API key, optionally one that may write.

    Setzt g.api_key, damit die Sicht dahinter weiss, wer aufgerufen hat, und
    schreibt den Zeitpunkt der letzten Nutzung fort. Das ist die einzige
    Stelle, an der ein Schluessel Spuren hinterlaesst.
    """
    def dekorator(sicht):
        @wraps(sicht)
        def huelle(*args, **kwargs):
            roh = schluessel_aus_anfrage()
            if not roh:
                return fehler(401, "unauthenticated",
                              "Kein API-Schlüssel. Erwartet wird der Kopf "
                              "'Authorization: Bearer <schlüssel>'.")
            eintrag = finde_schluessel(roh)
            if eintrag is None:
                # Nur mit passendem Praefix protokolliert. Sonst schriebe jeder
                # Portscanner, der /api/v1 anfaesst, eine Zeile ins Protokoll.
                if roh.startswith("esm_"):
                    audit.log(Session, "apikey.rejected", actor="api",
                              target=roh.split("_")[1][:16], success=False,
                              detail="Unbekannter oder widerrufener Schlüssel",
                              trust_proxy=config().trust_proxy)
                return fehler(401, "invalid_key",
                              "Der API-Schlüssel ist unbekannt oder widerrufen.")
            if schreibend and not eintrag.may_write:
                audit.log(Session, "apikey.denied", actor="apikey:%s" % eintrag.name,
                          target=request.path, success=False,
                          detail="Schreibzugriff mit lesendem Schlüssel",
                          trust_proxy=config().trust_proxy)
                return fehler(403, "read_only",
                              "Dieser Schlüssel darf nur lesen.")
            eintrag.last_used_at = utcnow()
            Session.commit()
            g.api_key = eintrag
            return sicht(*args, **kwargs)
        return huelle
    return dekorator


# --------------------------------------------------------------------------
# Darstellung
# --------------------------------------------------------------------------

def zeitstempel(wert):
    """ISO 8601 in UTC, oder None."""
    if wert is None:
        return None
    if wert.tzinfo is None:
        wert = wert.replace(tzinfo=timezone.utc)
    return wert.astimezone(timezone.utc).isoformat()


def sensor_urls(kunde):
    """The externally reachable sensor URLs of one customer."""
    basis = base_url()
    return {
        "prtg_xml": basis + url_for("prtg.prtg_xml", token=kunde.prtg_token),
        "json": basis + url_for("prtg.prtg_json", token=kunde.prtg_token),
        "hinweis": "Anhängbar sind ?app=, ?filter=, ?exclude=, ?type=secret|cert, "
                   "?warn= und ?error= für eigene Schwellen.",
    }


def kunde_als_json(kunde, mit_credentials=False):
    """
    Render one customer.

    Enthaelt bewusst kein Client Secret und keinen privaten Schluessel. Was ein
    Aufrufer erfaehrt, ist ob etwas hinterlegt ist und wann es ablaeuft.
    """
    daten = {
        "key": kunde.key,
        "display_name": kunde.display_name,
        "tenant_id": kunde.tenant_id,
        "client_id": kunde.client_id,
        "auth_type": kunde.auth_type,
        "has_credential": bool(kunde.client_secret_enc or kunde.key_pem_enc),
        "certificate": {
            "thumbprint": kunde.cert_thumbprint or None,
            "not_after": zeitstempel(kunde.cert_not_after),
        } if kunde.auth_type == AUTH_CERT else None,
        "is_active": bool(kunde.is_active),
        "thresholds": {"warn_days": kunde.warn_days, "error_days": kunde.error_days},
        "scan": {
            "last_check_at": zeitstempel(kunde.last_check_at),
            "status": kunde.last_status,
            "error": kunde.last_error or None,
            "slot_minute": kunde.slot_minute,
        },
        "summary": {
            "min_days": kunde.min_days,
            "count_total": kunde.count_total,
            "count_critical": kunde.count_critical,
            "count_expired": kunde.count_expired,
        },
        "urls": sensor_urls(kunde),
    }
    if mit_credentials:
        daten["credentials"] = [credential_als_json(c) for c in
                                Session.execute(
                                    select(CredentialSnapshot)
                                    .where(CredentialSnapshot.customer_id == kunde.id)
                                    .order_by(CredentialSnapshot.days_left.asc())
                                ).scalars().all()]
    return daten


def credential_als_json(eintrag):
    """Render one stored credential. Never carries a secret value."""
    return {
        "app_name": eintrag.app_name,
        "app_id": eintrag.app_id,
        "object_type": eintrag.object_type,
        "type": eintrag.cred_type,
        "credential_name": eintrag.cred_name,
        "key_id": eintrag.key_id,
        "end_date": zeitstempel(eintrag.end_date),
        "days_left": eintrag.days_left,
        "sibling_count": eintrag.sibling_count,
    }


def hole_kunde(schluessel):
    """Load a customer by its key, or None."""
    return Session.execute(
        select(Customer).where(Customer.key == schluessel)).scalar_one_or_none()


# --------------------------------------------------------------------------
# Eingaben pruefen
# --------------------------------------------------------------------------

# Dieselben Muster wie im Formular der Oberflaeche. Bewusst importiert statt
# nachgebaut: zwei Kopien laufen frueher oder spaeter auseinander, und dann
# nimmt die Schnittstelle an, was die Oberflaeche ablehnt.
SCHLUESSEL_MUSTER = re.compile(KEY_PATTERN)
GUID_MUSTER = GUID


# Was ein Feld sein darf. Eine Tabelle statt verstreuter Einzelpruefungen,
# damit Anlage und Aenderung dieselben Grenzen anwenden: POST und PATCH liefen
# vorher auseinander, und ein PATCH konnte Werte setzen, die ein POST ablehnte.
TEXTFELDER = ("key", "display_name", "notes", "app_filter", "app_exclude",
              "client_secret", "cert_pem", "key_pem", "auth_type")
GUID_FELDER = ("tenant_id", "client_id")
BOOLFELDER = ("include_sp", "show_expired", "is_active")
ZAHLENFELDER = {"warn_days": (1, 3650), "error_days": (1, 3650),
                "max_channels": (1, 200)}


def als_ganzzahl(wert):
    """
    Read one integer from the request, or None when it is not one.

    Ein Boolean ist in Python eine Ganzzahl, hier aber keine: True als
    warn_days waere ein Tag. Ziffernfolgen als Text sind erlaubt, weil manche
    Clients jedes Feld als Zeichenkette senden.
    """
    if isinstance(wert, bool):
        return None
    if isinstance(wert, int):
        return wert
    if isinstance(wert, str) and wert.strip().lstrip("-").isdigit():
        return int(wert.strip())
    return None


def text(daten, feld, kunde=None, standard=""):
    """Read one text field, falling back to the stored value."""
    if feld in daten and daten[feld] is not None:
        return str(daten[feld]).strip()
    if kunde is not None and hasattr(kunde, feld):
        return getattr(kunde, feld) or standard
    return standard


def zahl(daten, feld, standard):
    """Read one integer field, falling back to the given default."""
    return als_ganzzahl(daten[feld]) if feld in daten else standard


def pruefe_typen(daten):
    """
    Reject fields whose type cannot be used, before anything touches them.

    Ohne diese Runde erzeugte eine Zahl in einem Textfeld einen Serverfehler,
    weil strip() sie nicht kennt, und die Zeichenkette "false" wurde als wahr
    gelesen.
    """
    fehler_felder = {}
    for feld in TEXTFELDER:
        if feld in daten and daten[feld] is not None and not isinstance(daten[feld], str):
            fehler_felder[feld] = "Muss Text sein"
    for feld in GUID_FELDER:
        if feld in daten and not (isinstance(daten[feld], str)
                                  and GUID_MUSTER.match(daten[feld].strip())):
            fehler_felder[feld] = "Muss eine GUID sein"
    for feld in BOOLFELDER:
        if feld in daten and not isinstance(daten[feld], bool):
            fehler_felder[feld] = "Muss true oder false sein"
    for feld, (kleinster, groesster) in ZAHLENFELDER.items():
        if feld not in daten:
            continue
        wert = als_ganzzahl(daten[feld])
        if wert is None:
            fehler_felder[feld] = "Muss eine ganze Zahl sein"
        elif not kleinster <= wert <= groesster:
            fehler_felder[feld] = "Zwischen %d und %d" % (kleinster, groesster)
    return fehler_felder


def pruefe_schwellen(daten, kunde=None):
    """
    Check the pair of thresholds in the state it would end up in.

    Beide Werte einzeln zu pruefen genuegt nicht: wer nur warn_days sendet,
    stellt es gegen den Standardwert oder den gespeicherten error_days, und
    genau dabei entstand eine Warnung nach dem Fehler.
    """
    cfg = config()
    warn = als_ganzzahl(daten.get("warn_days"))
    fehl = als_ganzzahl(daten.get("error_days"))
    if warn is None:
        warn = kunde.warn_days if kunde else cfg.default_warn_days
    if fehl is None:
        fehl = kunde.error_days if kunde else cfg.default_error_days
    if fehl > warn:
        return {"error_days": "Muss kleiner oder gleich warn_days sein, "
                              "hier %d gegen %d" % (fehl, warn)}
    return {}


def pruefe_zugangsdaten(daten, kunde=None):
    """
    Check that the resulting authentication method has usable material.

    Geprueft wird der Zustand nach der Aenderung, nicht die Anfrage: ein
    Wechsel auf Zertifikat ohne Zertifikat hinterliesse einen Kunden, der erst
    beim naechsten Lauf auffaellt.
    """
    if "auth_type" in daten:
        art = daten["auth_type"].strip() if isinstance(daten["auth_type"], str) else ""
    else:
        art = kunde.auth_type if kunde else AUTH_SECRET
    if art not in (AUTH_SECRET, AUTH_CERT):
        return {"auth_type": "Erlaubt sind 'secret' und 'certificate'"}

    if art == AUTH_SECRET:
        gesendet = (daten.get("client_secret") or "").strip() if isinstance(
            daten.get("client_secret"), str) else ""
        gespeichert = bool(kunde and kunde.auth_type == AUTH_SECRET
                           and kunde.client_secret_enc)
        if not gesendet and not gespeichert:
            return {"client_secret": "Pflichtfeld bei auth_type 'secret'"}
        return {}

    cert = daten.get("cert_pem") if isinstance(daten.get("cert_pem"), str) else ""
    key = daten.get("key_pem") if isinstance(daten.get("key_pem"), str) else ""
    if cert.strip() or key.strip():
        fehler_felder = {}
        if not cert.strip():
            fehler_felder["cert_pem"] = "Gehört zum privaten Schlüssel dazu"
        if not key.strip():
            fehler_felder["key_pem"] = "Gehört zum Zertifikat dazu"
        return fehler_felder
    if kunde and kunde.auth_type == AUTH_CERT and kunde.cert_pem and kunde.key_pem_enc:
        return {}
    return {"cert_pem": "Pflichtfeld bei auth_type 'certificate'",
            "key_pem": "Pflichtfeld bei auth_type 'certificate'"}


def pruefe_anlage(daten):
    """Validate the body of a create request, returning a dict of field errors."""
    fehler_felder = pruefe_typen(daten)
    if not isinstance(daten.get("key"), str) or not SCHLUESSEL_MUSTER.match(
            daten.get("key", "").strip()):
        fehler_felder.setdefault(
            "key", "Kleinbuchstaben, Ziffern und Bindestrich, 2 bis 48 Zeichen, "
                   "beginnend mit Buchstabe oder Ziffer")
    if not text(daten, "display_name"):
        fehler_felder.setdefault("display_name", "Pflichtfeld")
    for feld in GUID_FELDER:
        if feld not in daten:
            fehler_felder.setdefault(feld, "Pflichtfeld")
    if not {"warn_days", "error_days"} & set(fehler_felder):
        fehler_felder.update(pruefe_schwellen(daten))
    fehler_felder.update(pruefe_zugangsdaten(daten))
    return fehler_felder


def pruefe_aenderung(daten, kunde):
    """Validate a change against the state the customer would end up in."""
    fehler_felder = pruefe_typen(daten)
    if not {"warn_days", "error_days"} & set(fehler_felder):
        fehler_felder.update(pruefe_schwellen(daten, kunde))
    fehler_felder.update(pruefe_zugangsdaten(daten, kunde))
    return fehler_felder


def uebernehme_zugangsdaten(kunde, daten, schluesselmaterial):
    """
    Store the credential that matches the chosen method.

    Wirft ValueError mit einem lesbaren Satz, wenn das Paar nicht zusammenpasst.
    Dieselbe Pruefung wie in der Oberflaeche, damit ein falsches Paar hier
    auffaellt und nicht erst beim naechsten Lauf.
    """
    art = (daten.get("auth_type") or kunde.auth_type or AUTH_SECRET).strip()
    if art == AUTH_CERT:
        cert = (daten.get("cert_pem") or "").strip()
        key = (daten.get("key_pem") or "").strip()
        if cert or key:
            if not (cert and key):
                raise ValueError("Zertifikat und privater Schlüssel gehören zusammen")
            fingerabdruck, laeuft_ab = inspect_certificate(cert, key)
            kunde.cert_pem = cert
            kunde.key_pem_enc = crypto.encrypt(
                key, schluesselmaterial,
                crypto.aad_for("customer", kunde.key, "key_pem_enc"))
            kunde.cert_thumbprint = fingerabdruck
            kunde.cert_not_after = laeuft_ab
            kunde.client_secret_enc = ""
    else:
        geheim = (daten.get("client_secret") or "").strip()
        if geheim:
            kunde.client_secret_enc = crypto.encrypt(
                geheim, schluesselmaterial,
                crypto.aad_for("customer", kunde.key, "client_secret_enc"))
            kunde.cert_pem = ""
            kunde.key_pem_enc = ""
            kunde.cert_thumbprint = ""
            kunde.cert_not_after = None
    kunde.auth_type = art


# --------------------------------------------------------------------------
# Endpunkte
# --------------------------------------------------------------------------

@bp.route("/", methods=["GET"])
@benoetigt_schluessel()
def wurzel():
    """Entry point: version and the available endpoints."""
    return jsonify({
        "version": API_VERSION,
        "instance": config().instance_name,
        "scope": g.api_key.scope,
        "endpoints": [{"method": e["methode"], "path": e["pfad"],
                       "scope": e["bereich"], "purpose": e["zweck"]}
                      for e in ENDPUNKTE],
    })


@bp.route("/openapi.json", methods=["GET"])
def openapi_document():
    """
    The machine readable description of this instance.

    Die einzige Route, die auch eine angemeldete Sitzung akzeptiert. Ein
    Generator holt sie mit Schluessel, ein Administrator klickt sie aus der
    Einstellungsseite heraus auf, und beide brauchen dasselbe Dokument. Sie
    enthaelt keine Daten, nur die Form der Schnittstelle.
    """
    if not current_user.is_authenticated and finde_schluessel(
            schluessel_aus_anfrage() or "") is None:
        return fehler(401, "unauthenticated",
                      "Weder ein API-Schlüssel noch eine angemeldete Sitzung.")
    return jsonify(openapi.build(base_url(), config().instance_name, ENDPUNKTE))


@bp.route("/customers", methods=["GET"])
@benoetigt_schluessel()
def kunden_liste():
    """List every customer with its current summary."""
    kunden = Session.execute(
        select(Customer).order_by(Customer.display_name.asc())).scalars().all()
    return jsonify({"count": len(kunden),
                    "customers": [kunde_als_json(k) for k in kunden]})


@bp.route("/customers", methods=["POST"])
@benoetigt_schluessel(schreibend=True)
def kunde_anlegen():
    """Create a customer, store its credential and schedule a daily slot."""
    daten = request.get_json(silent=True)
    if not isinstance(daten, dict):
        return fehler(400, "invalid_body", "Erwartet wird ein JSON-Objekt.")

    felder = pruefe_anlage(daten)
    if felder:
        return fehler(422, "validation_failed", "Eingaben unvollständig.", felder)
    if hole_kunde(daten["key"].strip()) is not None:
        return fehler(409, "duplicate", "Ein Kunde mit diesem Schlüssel existiert bereits.")

    cfg = config()
    kunde = Customer(
        key=daten["key"].strip(),
        display_name=text(daten, "display_name"),
        tenant_id=daten["tenant_id"].strip(),
        client_id=daten["client_id"].strip(),
        auth_type=text(daten, "auth_type", standard=AUTH_SECRET) or AUTH_SECRET,
        prtg_token=new_token(),
        warn_days=zahl(daten, "warn_days", cfg.default_warn_days),
        error_days=zahl(daten, "error_days", cfg.default_error_days),
        max_channels=zahl(daten, "max_channels", 45),
        include_sp=bool(daten.get("include_sp", False)),
        show_expired=bool(daten.get("show_expired", False)),
        app_filter=text(daten, "app_filter"),
        app_exclude=text(daten, "app_exclude"),
        notes=text(daten, "notes"),
        is_active=bool(daten.get("is_active", True)))
    Session.add(kunde)
    Session.flush()

    try:
        uebernehme_zugangsdaten(kunde, daten, cfg.encryption_key)
    except ValueError as exc:
        Session.rollback()
        return fehler(422, "invalid_credential", str(exc))

    kunde.slot_minute = scheduler.assign_slot(Session)
    Session.commit()
    audit.log(Session, "api.customer_created", actor="apikey:%s" % g.api_key.name,
              target=kunde.key, trust_proxy=cfg.trust_proxy)
    return jsonify(kunde_als_json(kunde)), 201


@bp.route("/customers/<key>", methods=["GET"])
@benoetigt_schluessel()
def kunde_lesen(key):
    """One customer including its stored credentials."""
    kunde = hole_kunde(key)
    if kunde is None:
        return fehler(404, "not_found", "Kein Kunde mit diesem Schlüssel.")
    return jsonify(kunde_als_json(kunde, mit_credentials=True))


@bp.route("/customers/<key>", methods=["PATCH"])
@benoetigt_schluessel(schreibend=True)
def kunde_aendern(key):
    """Change a customer. Fields left out keep their value."""
    kunde = hole_kunde(key)
    if kunde is None:
        return fehler(404, "not_found", "Kein Kunde mit diesem Schlüssel.")
    daten = request.get_json(silent=True)
    if not isinstance(daten, dict):
        return fehler(400, "invalid_body", "Erwartet wird ein JSON-Objekt.")

    felder = pruefe_aenderung(daten, kunde)
    if felder:
        return fehler(422, "validation_failed", "Eingaben unvollständig.", felder)

    for feld in ("display_name", "notes", "app_filter", "app_exclude"):
        if feld in daten:
            setattr(kunde, feld, text(daten, feld))
    for feld in GUID_FELDER:
        if feld in daten:
            setattr(kunde, feld, daten[feld].strip())
    for feld in ZAHLENFELDER:
        if feld in daten:
            setattr(kunde, feld, als_ganzzahl(daten[feld]))
    for feld in BOOLFELDER:
        if feld in daten:
            setattr(kunde, feld, daten[feld])

    cfg = config()
    try:
        uebernehme_zugangsdaten(kunde, daten, cfg.encryption_key)
    except ValueError as exc:
        Session.rollback()
        return fehler(422, "invalid_credential", str(exc))

    Session.commit()
    audit.log(Session, "api.customer_updated", actor="apikey:%s" % g.api_key.name,
              target=kunde.key, trust_proxy=cfg.trust_proxy)
    return jsonify(kunde_als_json(kunde))


@bp.route("/customers/<key>", methods=["DELETE"])
@benoetigt_schluessel(schreibend=True)
def kunde_loeschen(key):
    """Remove a customer with its history."""
    kunde = hole_kunde(key)
    if kunde is None:
        return fehler(404, "not_found", "Kein Kunde mit diesem Schlüssel.")
    cfg = config()
    Session.delete(kunde)
    Session.commit()
    audit.log(Session, "api.customer_deleted", actor="apikey:%s" % g.api_key.name,
              target=key, trust_proxy=cfg.trust_proxy)
    return "", 204


@bp.route("/customers/<key>/check", methods=["POST"])
@benoetigt_schluessel(schreibend=True)
def kunde_pruefen(key):
    """
    Run a scan for this customer right now.

    Laeuft synchron und wartet auf die gemeinsame Sperre, damit eine manuelle
    Pruefung sich hinter einen laufenden Durchgang stellt statt die Abfragerate
    gegen denselben Tenant zu verdoppeln.
    """
    kunde = hole_kunde(key)
    if kunde is None:
        return fehler(404, "not_found", "Kein Kunde mit diesem Schlüssel.")
    cfg = config()
    try:
        status, meldung = scheduler.force_check(
            kunde.id, cfg.encryption_key, "apikey:%s" % g.api_key.name,
            cfg.history_runs)
    except TimeoutError as exc:
        return fehler(409, "busy", str(exc))
    except LookupError:
        return fehler(404, "not_found", "Kein Kunde mit diesem Schlüssel.")

    # force_check schreibt in einer eigenen Sitzung. Ohne das Verwerfen liefe
    # die Antwort aus dem Zwischenspeicher dieser Sitzung und zeigte die Zahlen
    # von vor dem Lauf.
    Session.expire_all()
    audit.log(Session, "api.customer_checked", actor="apikey:%s" % g.api_key.name,
              target=key, success=status == "ok", detail=meldung or "",
              trust_proxy=cfg.trust_proxy)
    return jsonify({"status": status, "error": meldung or None,
                    "customer": kunde_als_json(hole_kunde(key), mit_credentials=True)})


@bp.route("/customers/<key>/credentials", methods=["GET"])
@benoetigt_schluessel()
def kunde_credentials(key):
    """The stored credentials of one customer, shortest runtime first."""
    kunde = hole_kunde(key)
    if kunde is None:
        return fehler(404, "not_found", "Kein Kunde mit diesem Schlüssel.")
    eintraege = Session.execute(
        select(CredentialSnapshot)
        .where(CredentialSnapshot.customer_id == kunde.id)
        .order_by(CredentialSnapshot.days_left.asc())).scalars().all()
    return jsonify({"customer": kunde.key, "count": len(eintraege),
                    "last_check_at": zeitstempel(kunde.last_check_at),
                    "credentials": [credential_als_json(e) for e in eintraege]})


@bp.route("/customers/<key>/urls", methods=["GET"])
@benoetigt_schluessel()
def kunde_urls(key):
    """The sensor URLs of one customer."""
    kunde = hole_kunde(key)
    if kunde is None:
        return fehler(404, "not_found", "Kein Kunde mit diesem Schlüssel.")
    return jsonify(sensor_urls(kunde))


@bp.route("/customers/<key>/token", methods=["POST"])
@benoetigt_schluessel(schreibend=True)
def kunde_token(key):
    """Issue a new PRTG token; the previous sensor URL stops serving data."""
    kunde = hole_kunde(key)
    if kunde is None:
        return fehler(404, "not_found", "Kein Kunde mit diesem Schlüssel.")
    cfg = config()
    kunde.prtg_token = new_token()
    Session.commit()
    audit.log(Session, "api.token_rotated", actor="apikey:%s" % g.api_key.name,
              target=kunde.key, trust_proxy=cfg.trust_proxy)
    return jsonify(sensor_urls(kunde))
