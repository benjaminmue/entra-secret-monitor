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

from datetime import timezone
from functools import wraps

from flask import Blueprint, g, jsonify, request, url_for
from flask_login import current_user
from sqlalchemy import select

from portal import audit, crypto, diagnose, openapi, ratelimit, scheduler, security
from portal.db import Session
from portal.forms import GUID, schluessel_hinweis
from portal.models import (API_SCOPE_WRITE, AUTH_CERT, AUTH_SECRET,
                           CREDENTIAL_FELDER, GEGENSTUECK, ApiKey,
                           CredentialSnapshot, Customer, new_token, utcnow)
from portal.scanner import data_age_hours, inspect_certificate
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
    {"methode": "GET", "pfad": "/api/v1/problems", "bereich": "read",
     "zweck": "Nur die Kunden, bei denen etwas nicht stimmt, mit lesbarem Befund"},
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
# Drosselung
# --------------------------------------------------------------------------

# Drei Grenzen, weil drei verschiedene Dinge schiefgehen koennen: jemand
# probiert Schluessel durch, ein fehlerhafter Aufrufer haemmert in einer
# Schleife, oder eine Pruefung wird so oft ausgeloest, dass der Kundentenant
# die Last sieht. Eine einzige Zahl wuerde entweder das Durchprobieren
# erlauben oder den normalen Betrieb behindern.

def _grenzen():
    """Build the three limits from the running configuration."""
    cfg = config()
    return (
        ratelimit.Grenze("api", cfg.api_rate_per_minute, 60),
        ratelimit.Grenze("apikey", cfg.api_key_attempts_per_minute, 60),
        ratelimit.Grenze("check", cfg.api_check_per_hour, 3600),
        ratelimit.Grenze("anon", cfg.api_anon_attempts_per_minute, 60),
    )


def _praefix(roh):
    """The lookup prefix of a presented key, or empty when it has no shape."""
    teile = (roh or "").split("_", 2)
    return teile[1][:16] if len(teile) == 3 and teile[0] == "esm" else ""


def _fehlversuch_kennung(roh):
    """
    Identify what a failed authentication is counted against.

    Bewusst der Praefix und nicht die Adresse. Wer den Praefix eines
    Schluessels kennt und dessen Geheimnis raten will, laeuft damit gegen
    genau diesen Zaehler, und andere Schluessel bleiben davon unberuehrt.

    Seit der Umstellung auf einen schnellen Hash kostet ein Fehlversuch kaum
    noch Rechenzeit. Der Zaehler bleibt trotzdem: er begrenzt die Menge, macht
    das Durchprobieren im Protokoll sichtbar und ist die einzige Stelle, an der
    ein solcher Versuch ueberhaupt auffaellt.

    Nach der Adresse zu zaehlen waere hier falsch: hinter einem Reverse Proxy
    teilen sich alle Aufrufer eine Adresse, und zehn Fehlversuche eines
    Dritten wuerden das Cloudportal aussperren. Genau das ist in der Pruefung
    aufgefallen.

    Was bleibt: wer den Praefix eines Schluessels kennt, kann genau diesen
    Schluessel fuer die Dauer des Fensters sperren. Das ist dieselbe Abwaegung
    wie beim Kontologin, wo `login_max_attempts` das Konto sperrt. Der
    Wirkungskreis ist ein Schluessel, nicht die Instanz, und ein Ersatz ist
    in einer Minute ausgestellt.
    """
    praefix = _praefix(roh)
    return "prefix:%s" % praefix if praefix else "form:ungueltig"


def zu_schnell(wartezeit, meldung):
    """One 429 with the header a well behaved client honours."""
    antwort = jsonify({"error": {"code": "rate_limited", "message": meldung}})
    antwort.headers["Retry-After"] = str(wartezeit)
    return antwort, 429


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
    if not security.verify_api_key(eintrag.key_hash, roh):
        return None
    # Schluessel aus der Zeit vor dem schnellen Hash beim ersten richtigen
    # Gebrauch umstellen. Ein Neuausstellen waere sonst noetig, nur damit die
    # Anfrage nicht weiter 45 ms Argon2 kostet.
    if security.api_key_needs_upgrade(eintrag.key_hash):
        eintrag.key_hash = security.hash_api_key(roh)
    return eintrag


def authentifiziere(schreibend=False):
    """
    Resolve and authorise the presented key, or return a ready error response.

    Gibt (eintrag, fehlerantwort) zurueck, genau eines davon gefuellt. Als
    eigene Funktion und nicht nur im Dekorator, weil /openapi.json ebenfalls
    einen Schluessel annimmt: als der Weg dort an der Drosselung vorbeilief,
    liess sich die Schluesselpruefung ueber diese eine Route unbegrenzt
    ausloesen, waehrend jede andere Route laengst 429 lieferte.

    **Die Zaehler werden erst nach der Pruefung angefasst.** Zuerst lief es
    andersherum, und dann sperrten fremde Fehlversuche von derselben Adresse
    auch einen Aufrufer aus, der einen gueltigen Schluessel mitschickte. Genau
    das schliesst docs/SECURITY-GATE.md aus, und die Zusicherung war damit
    falsch. Seit der Schluesselvergleich kein Argon2 mehr ist, kostet eine
    Suche ohnehin fast nichts, es gibt also keinen Grund mehr, vorab zu sperren.
    """
    allgemein, versuche, _, anonym = _grenzen()
    roh = schluessel_aus_anfrage()
    if not roh:
        return None, fehler(401, "unauthenticated",
                            "Kein API-Schlüssel. Erwartet wird der Kopf "
                            "'Authorization: Bearer <schlüssel>'.")

    eintrag = finde_schluessel(roh)

    if eintrag is None or (schreibend and not eintrag.may_write):
        # Zwei Zaehler, weil zwei verschiedene Angriffe dahinterstehen: das
        # Raten des Geheimnisses zu einem bekannten Praefix, und das
        # Durchprobieren wechselnder Praefixe. Beide sehen nur Fehlversuche.
        adresse = "ip:%s" % audit.client_ip(config().trust_proxy)
        gebremst = [ratelimit.pruefe(versuche, _fehlversuch_kennung(roh)),
                    ratelimit.pruefe(anonym, adresse)]
        wartezeiten = [warten for erlaubt, warten in gebremst if not erlaubt]

        if eintrag is None:
            if _praefix(roh):
                audit.log(Session, "apikey.rejected", actor="api",
                          target=_praefix(roh), success=False,
                          detail="Unbekannter oder widerrufener Schlüssel",
                          trust_proxy=config().trust_proxy)
            if wartezeiten:
                return None, zu_schnell(max(wartezeiten),
                                        "Zu viele fehlgeschlagene Anmeldungen. "
                                        "Bitte %d Sekunden warten."
                                        % max(wartezeiten))
            return None, fehler(401, "invalid_key",
                                "Der API-Schlüssel ist unbekannt oder widerrufen.")

        audit.log(Session, "apikey.denied", actor="apikey:%s" % eintrag.name,
                  target=request.path, success=False,
                  detail="Schreibzugriff mit lesendem Schlüssel",
                  trust_proxy=config().trust_proxy)
        if wartezeiten:
            return None, zu_schnell(max(wartezeiten),
                                    "Zu viele abgewiesene Zugriffe. Bitte %d "
                                    "Sekunden warten." % max(wartezeiten))
        return None, fehler(403, "read_only", "Dieser Schlüssel darf nur lesen.")

    eintrag.last_used_at = utcnow()
    Session.commit()

    erlaubt, warten = ratelimit.pruefe(allgemein, "key:%s" % eintrag.prefix)
    if not erlaubt:
        return None, zu_schnell(warten, "Zu viele Anfragen. Bitte %d Sekunden "
                                        "warten." % warten)
    return eintrag, None


def benoetigt_schluessel(schreibend=False):
    """
    Decorator: require a valid API key, optionally one that may write.

    Setzt g.api_key, damit die Sicht dahinter weiss, wer aufgerufen hat.
    """
    def dekorator(sicht):
        @wraps(sicht)
        def huelle(*args, **kwargs):
            eintrag, antwort = authentifiziere(schreibend)
            if antwort is not None:
                return antwort
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


def lade_credentials(kunden_ids):
    """
    Load the stored credentials of many customers in one query.

    Gibt eine Zuordnung von Kunden-ID auf die Liste zurueck, je Kunde nach
    kuerzester Restlaufzeit sortiert. Eine Abfrage statt einer je Kunde: die
    Kundenliste faehrt sonst ueber alle und fragt fuenfzig Mal nach.
    """
    if not kunden_ids:
        return {}
    zeilen = Session.execute(
        select(CredentialSnapshot)
        .where(CredentialSnapshot.customer_id.in_(kunden_ids))
        .order_by(CredentialSnapshot.customer_id.asc(),
                  CredentialSnapshot.days_left.asc())).scalars().all()
    nach_kunde = {kid: [] for kid in kunden_ids}
    for zeile in zeilen:
        nach_kunde.setdefault(zeile.customer_id, []).append(zeile)
    return nach_kunde


def zustand_und_befunde(kunde, credentials):
    """
    The overall state plus the readable findings for one customer.

    Der Zustand kommt aus derselben Funktion wie in der Oberflaeche. Ein
    anbindendes System soll ihn nicht nachbauen muessen, und vor allem soll es
    die Veraltungsregel nicht uebersehen: frische Zahlen sind Teil der Aussage.
    """
    from portal.views.dashboard import customer_state

    stale_hours = config().stale_hours
    return (customer_state(kunde, stale_hours),
            diagnose.befunde(kunde, credentials, stale_hours))


def kunde_als_json(kunde, mit_credentials=False, credentials=None):
    """
    Render one customer.

    Enthaelt bewusst kein Client Secret und keinen privaten Schluessel. Was ein
    Aufrufer erfaehrt, ist ob etwas hinterlegt ist und wann es ablaeuft.
    """
    # Die Zugangsdaten braucht sowohl die Befundung als auch die Ausgabe. Der
    # Aufrufer kann sie mitgeben; die Listen tun das, weil sonst je Kunde eine
    # eigene Abfrage entstuende. Gemessen bei 50 Kunden: 53 Abfragen statt 4.
    gespeicherte = credentials if credentials is not None else lade_credentials(
        [kunde.id]).get(kunde.id, [])
    zustand, probleme = zustand_und_befunde(kunde, gespeicherte)
    alter = data_age_hours(kunde)

    daten = {
        "key": kunde.key,
        "display_name": kunde.display_name,
        "tenant_id": kunde.tenant_id,
        "client_id": kunde.client_id,
        "auth_type": kunde.auth_type,
        "has_credential": kunde.has_credential,
        "certificate": {
            "thumbprint": kunde.cert_thumbprint or None,
            "not_after": zeitstempel(kunde.cert_not_after),
        } if kunde.auth_type == AUTH_CERT else None,
        "is_active": bool(kunde.is_active),
        "thresholds": {"warn_days": kunde.warn_days, "error_days": kunde.error_days},
        "state": zustand,
        "problems": probleme,
        "scan": {
            "last_check_at": zeitstempel(kunde.last_check_at),
            "last_success_at": zeitstempel(kunde.last_success_at),
            "status": kunde.last_status,
            "error": kunde.last_error or None,
            "age_hours": alter if alter >= 0 else None,
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
        daten["credentials"] = [credential_als_json(c) for c in gespeicherte]
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

# Dieselben Pruefungen wie im Formular der Oberflaeche. Bewusst importiert
# statt nachgebaut: zwei Kopien laufen frueher oder spaeter auseinander, und
# dann nimmt die Schnittstelle an, was die Oberflaeche ablehnt. Der Schluessel
# kommt als Funktion herein, damit die Schnittstelle denselben Satz zur
# Grossschreibung ausgibt wie das Formular.
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

    # Zugangsdaten der jeweils anderen Anmeldeart abweisen statt sie zu
    # verwerfen. Vorher nahm die Schnittstelle ein client_secret fuer einen
    # Zertifikatskunden mit 200 entgegen und legte es nirgends ab: ein
    # Rotations-Script meldete Erfolg, ohne dass etwas rotiert war.
    #
    # Gesammelt statt sofort zurueckgegeben: sonst verdeckt das ueberzaehlige
    # Feld ein fehlendes Pflichtfeld, und der Aufrufer erfaehrt erst im zweiten
    # Anlauf, dass ihm auch die Haelfte des Paares fehlt.
    fehler_felder = {}
    for feld in CREDENTIAL_FELDER[GEGENSTUECK[art]]:
        wert = daten.get(feld)
        if isinstance(wert, str) and wert.strip():
            fehler_felder[feld] = ("Gehört nicht zu auth_type '%s'. Feld "
                                   "weglassen oder leer senden." % art)

    if art == AUTH_SECRET:
        gesendet = (daten.get("client_secret") or "").strip() if isinstance(
            daten.get("client_secret"), str) else ""
        gespeichert = bool(kunde and kunde.auth_type == AUTH_SECRET
                           and kunde.client_secret_enc)
        if not gesendet and not gespeichert:
            fehler_felder["client_secret"] = "Pflichtfeld bei auth_type 'secret'"
        return fehler_felder

    cert = daten.get("cert_pem") if isinstance(daten.get("cert_pem"), str) else ""
    key = daten.get("key_pem") if isinstance(daten.get("key_pem"), str) else ""
    if cert.strip() or key.strip():
        if not cert.strip():
            fehler_felder["cert_pem"] = "Gehört zum privaten Schlüssel dazu"
        if not key.strip():
            fehler_felder["key_pem"] = "Gehört zum Zertifikat dazu"
        return fehler_felder
    if kunde and kunde.auth_type == AUTH_CERT and kunde.cert_pem and kunde.key_pem_enc:
        return fehler_felder
    fehler_felder.setdefault("cert_pem", "Pflichtfeld bei auth_type 'certificate'")
    fehler_felder.setdefault("key_pem", "Pflichtfeld bei auth_type 'certificate'")
    return fehler_felder


def pruefe_anlage(daten):
    """Validate the body of a create request, returning a dict of field errors."""
    fehler_felder = pruefe_typen(daten)
    if not isinstance(daten.get("key"), str):
        fehler_felder.setdefault("key", "Pflichtfeld, Zeichenkette erwartet")
    else:
        meldung = schluessel_hinweis(daten.get("key", "").strip())
        if meldung:
            fehler_felder.setdefault("key", meldung)
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
    if not current_user.is_authenticated:
        _, antwort = authentifiziere()
        if antwort is not None:
            return antwort
    return jsonify(openapi.build(base_url(), config().instance_name, ENDPUNKTE))


@bp.route("/customers", methods=["GET"])
@benoetigt_schluessel()
def kunden_liste():
    """List every customer with its current summary."""
    kunden = Session.execute(
        select(Customer).order_by(Customer.display_name.asc())).scalars().all()
    je_kunde = lade_credentials([k.id for k in kunden])
    return jsonify({"count": len(kunden),
                    "customers": [kunde_als_json(k, credentials=je_kunde.get(k.id, []))
                                  for k in kunden]})


@bp.route("/problems", methods=["GET"])
@benoetigt_schluessel()
def probleme():
    """
    Only the customers that need attention, with a readable finding each.

    Der Weg fuer ein uebergeordnetes System, das nicht alle Kunden durchgehen
    und selbst bewerten will. Die Reihenfolge ist die der Dringlichkeit, damit
    der erste Eintrag der ist, den jemand zuerst ansehen sollte.

    ?severity=error liefert nur das, was schon weh tut, ohne die Warnungen.
    """
    gewuenscht = (request.args.get("severity") or "").strip().lower()
    if gewuenscht and gewuenscht not in ("error", "warn", "info"):
        return fehler(422, "validation_failed", "Eingaben unvollständig.",
                      {"severity": "Erlaubt sind 'error', 'warn' und 'info'"})

    kunden = Session.execute(
        select(Customer).order_by(Customer.display_name.asc())).scalars().all()
    je_kunde = lade_credentials([k.id for k in kunden])
    # Sortiert wird nach der Schwere der Befunde, nicht nach dem Zustandswort.
    # Ueber den Zustand lief es zuerst, und dabei landete ein Kunde mit
    # veralteten Daten hinter einem mit einer blossen Warnung, weil "stale" in
    # der Rangfolge fehlte. Die Befunde tragen die Dringlichkeit ohnehin.
    rang = {"error": 0, "warn": 1, "info": 2}
    betroffen = []
    for kunde in kunden:
        daten = kunde_als_json(kunde, credentials=je_kunde.get(kunde.id, []))
        if not daten["problems"]:
            continue
        if gewuenscht and not any(b["severity"] == gewuenscht for b in daten["problems"]):
            continue
        betroffen.append({
            "key": daten["key"],
            "display_name": daten["display_name"],
            "state": daten["state"],
            "min_days": daten["summary"]["min_days"],
            "problems": daten["problems"],
            "urls": daten["urls"],
        })

    betroffen.sort(key=lambda e: (min(rang.get(b["severity"], 3) for b in e["problems"]),
                                  e["min_days"] if e["min_days"] is not None else 9999))
    return jsonify({"count": len(betroffen),
                    "checked_customers": len(kunden),
                    "customers": betroffen})


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

    # Eigene, engere Grenze je Kunde: hinter diesem Aufruf steht eine echte
    # Abfrage im Tenant des Kunden, nicht nur Arbeit im Portal.
    erlaubt, warten = ratelimit.pruefe(_grenzen()[2], key)
    if not erlaubt:
        return zu_schnell(warten, "Für diesen Kunden wurden zu viele Prüfungen "
                                  "ausgelöst. Der Tagesplan läuft weiter, die "
                                  "nächste manuelle Prüfung ist in %d Sekunden "
                                  "möglich." % warten)

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
