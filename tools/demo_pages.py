#!/usr/bin/env python3
"""
demo_pages.py

Rendert die Seiten der Oberflaeche mit Beispieldaten als HTML-Dateien, damit
die Screenshots der Dokumentation reproduzierbar sind und ohne echte
Kundendaten entstehen.

Warum gerendert und nicht abfotografiert: ein Screenshot aus einer laufenden
Instanz zeigt zwangslaeufig den Datenbestand dieser Instanz. Fuer die
oeffentliche Dokumentation braucht es das Gegenteil, naemlich einen Bestand,
der erfunden, vollstaendig und in jedem Durchlauf identisch ist. Die Daten
hier sind frei erfunden und decken bewusst alle Zustaende ab: gruen, Warnung,
Fehler, abgelaufen und ein Kunde, dessen Lauf scheiterte.

Aufruf:

    PYTHONPATH=app python3 tools/demo_pages.py [Zielverzeichnis]

Erzeugt im Zielverzeichnis eine HTML-Datei pro Seite plus portal.css. Die
Dateien sind statisch und lassen sich direkt im Browser oeffnen.
"""

import base64
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone

BOOTSTRAP_PASSWORD = "Vorlage-Start-7431-Kanton"
NEUES_PASSWORT = "Vorlage-Weiter-9182-Kanton"

# Erfundene Kunden. Namen aus den ueblichen Beispielfirmen, damit niemand sie
# fuer echte Mandanten haelt.
KUNDEN = [
    {"key": "contoso", "name": "Contoso AG", "tage": 5, "status": "error"},
    {"key": "fabrikam", "name": "Fabrikam GmbH", "tage": 23, "status": "warn"},
    {"key": "nordwind", "name": "Nordwind Logistik", "tage": 88, "status": "ok"},
    {"key": "alpina-treuhand", "name": "Alpina Treuhand", "tage": 210, "status": "ok"},
    {"key": "seewerk", "name": "Seewerk Industrie", "tage": 0, "status": "fehler"},
]

# Anwendungen pro Kunde. Der erste Eintrag bestimmt die minimale Restlaufzeit.
ANWENDUNGEN = {
    "contoso": [
        ("SVC-Backup Veeam", "secret", 5, 1),
        ("ConnectSyncProvisioning", "cert", 86, 2),
        ("SVC-Monitoring", "cert", 1204, 1),
    ],
    "fabrikam": [
        ("Intune Automation", "secret", 23, 1),
        ("KeyCloak SSO", "secret", 708, 1),
        ("SVC-Reporting", "cert", 2193, 1),
    ],
    "nordwind": [
        ("SVC-Sync Sage", "cert", 88, 1),
        ("Power Automate Connector", "secret", 412, 1),
    ],
    "alpina-treuhand": [
        ("Abacus Schnittstelle", "cert", 210, 1),
        ("SVC-Archiv", "cert", 3634, 1),
    ],
    "seewerk": [],
}


def baue_app(datenbank):
    """Create the portal app on a throwaway database with the scheduler off."""
    os.environ.update({
        "PORTAL_SECRET_KEY": "demo-key-demo-key-demo-key-demo",
        "PORTAL_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
        "PORTAL_DATABASE_URL": "sqlite:///" + datenbank.replace("\\", "/"),
        "PORTAL_SCHEDULER": "0",
        "PORTAL_COOKIE_SECURE": "0",
        "PORTAL_BASE_URL": "https://entra-portal.example.com",
        "PORTAL_INSTANCE_NAME": "Entra Credential Portal",
        "PORTAL_BOOTSTRAP_USER": "admin",
        "PORTAL_BOOTSTRAP_PASSWORD": BOOTSTRAP_PASSWORD,
    })
    import portal.db as db
    db._engine = None                                                   # noqa: SLF001
    db.Session.remove()
    from portal.factory import create_app
    return create_app()


def csrf(client, pfad):
    """Read the CSRF token from a rendered form."""
    koerper = client.get(pfad).get_data(as_text=True)
    treffer = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', koerper)
    if not treffer:
        raise RuntimeError("kein CSRF-Token auf %s" % pfad)
    return treffer.group(1)


def melde_an(client):
    """Walk the bootstrap account through enrollment so pages render signed in."""
    import pyotp

    client.post("/login", data={"csrf_token": csrf(client, "/login"),
                                "username": "admin", "password": BOOTSTRAP_PASSWORD})
    token = csrf(client, "/login/2fa/setup")
    with client.session_transaction() as sitzung:
        secret = sitzung["totp_setup_secret"]
    client.post("/login/2fa/setup", data={"csrf_token": token,
                                          "code": pyotp.TOTP(secret).now()})
    client.post("/account/password", data={
        "csrf_token": csrf(client, "/account/password"),
        "current_password": BOOTSTRAP_PASSWORD,
        "new_password": NEUES_PASSWORT, "confirm_password": NEUES_PASSWORT})


def fuelle_daten(app):
    """Insert the invented customers, their credentials and one failed run."""
    from portal import crypto
    from portal.config import load_config
    from portal.db import Session
    from portal.models import CheckRun, CredentialSnapshot, Customer, new_token

    # Ohne hinterlegtes Zugangsdatum meldet die Diagnose bei jedem Kunden
    # "kein Zugangsdatum hinterlegt", und /problems zeigte in der Anleitung
    # einen Befund, den ein eingerichteter Kunde nie hat.
    schluessel = load_config(os.environ).encryption_key

    jetzt = datetime.now(timezone.utc)
    for platz, eintrag in enumerate(KUNDEN):
        anwendungen = ANWENDUNGEN[eintrag["key"]]
        kunde = Customer(
            key=eintrag["key"], display_name=eintrag["name"],
            tenant_id="%08d-1111-2222-3333-444444444444" % (platz + 1),
            client_id="%08d-5555-6666-7777-888888888888" % (platz + 1),
            auth_type="secret",
            client_secret_enc=crypto.encrypt(
                "Beispieldaten, kein echtes Secret", schluessel,
                crypto.aad_for("customer", eintrag["key"], "client_secret_enc")),
            warn_days=30, error_days=14, max_channels=45,
            include_sp=False, show_expired=False,
            prtg_token=new_token(), slot_minute=platz * 240, is_active=True,
            notes="Beispieldaten der Dokumentation, kein echter Mandant.")

        if eintrag["status"] == "fehler":
            kunde.last_status = "error"
            kunde.last_error = ("AADSTS7000215: Ungültiges Client Secret. "
                                "Secret abgelaufen oder falsch hinterlegt.")
            kunde.last_check_at = jetzt - timedelta(hours=6)
        else:
            kunde.last_status = "ok"
            kunde.last_check_at = jetzt - timedelta(hours=platz + 1)
            kunde.last_success_at = kunde.last_check_at
            kunde.min_days = eintrag["tage"]
            kunde.count_total = sum(zahl for _, _, _, zahl in anwendungen)
            kunde.count_critical = sum(1 for _, _, tage, _ in anwendungen
                                       if tage < kunde.warn_days)
            kunde.count_expired = 0

        Session.add(kunde)
        Session.flush()

        if anwendungen:
            lauf = CheckRun(customer_id=kunde.id, started_at=kunde.last_check_at,
                            status="ok", trigger="scheduler")
            Session.add(lauf)
            Session.flush()
            for nummer, (name, art, tage, geschwister) in enumerate(anwendungen):
                Session.add(CredentialSnapshot(
                    customer_id=kunde.id, check_run_id=lauf.id,
                    app_name=name, app_id="%08d-aaaa-bbbb-cccc-%012d" % (platz + 1, nummer),
                    object_type="application", cred_type=art,
                    cred_name="prod" if art == "secret" else "monitoring",
                    key_id="%08d-dddd-eeee-ffff-%012d" % (platz + 1, nummer),
                    end_date=jetzt + timedelta(days=tage),
                    days_left=tage, sibling_count=geschwister))
    Session.commit()


def schreibe(ziel, name, inhalt):
    """
    Write one rendered page with its asset links pointing next to the file.

    Das Skript bleibt bewusst eingebunden: das Umschalten der Anmeldeart ist
    genau das, was der Screenshot des Formulars zeigen soll.
    """
    inhalt = inhalt.replace('href="/static/portal.css"', 'href="portal.css"')
    inhalt = inhalt.replace('src="/static/customer-form.js"', 'src="customer-form.js"')
    pfad = pathlib.Path(ziel) / name
    pfad.write_text(inhalt, encoding="utf-8")
    print("  %s (%d Bytes)" % (name, len(inhalt)))


def sammle_api_antworten(app, ziel):
    """
    Call every documented endpoint once and write the real answers as JSON.

    Beispiele in einer Anleitung veralten genau dann, wenn sie von Hand
    geschrieben sind. Diese hier stammen aus der Schnittstelle selbst, ein
    Feld weniger oder ein umbenannter Schluessel faellt beim naechsten Lauf
    sofort auf.
    """
    from portal.db import Session
    from portal.models import ApiKey, new_api_key
    from portal import security

    roh, praefix = new_api_key()
    with app.app_context():
        Session.add(ApiKey(name="Dokumentation", prefix=praefix,
                           key_hash=security.hash_api_key(roh), scope="write",
                           created_by="demo"))
        Session.commit()

    client = app.test_client()
    kopf = {"Authorization": "Bearer " + roh}
    aufrufe = [
        ("api-wurzel", "GET", "/api/v1/", None),
        ("api-kunden", "GET", "/api/v1/customers", None),
        ("api-probleme", "GET", "/api/v1/problems", None),
        ("api-kunde", "GET", "/api/v1/customers/contoso", None),
        ("api-credentials", "GET", "/api/v1/customers/contoso/credentials", None),
        ("api-urls", "GET", "/api/v1/customers/contoso/urls", None),
        ("api-anlegen", "POST", "/api/v1/customers", {
            "key": "musterag", "display_name": "Muster AG",
            "tenant_id": "99999999-1111-2222-3333-444444444444",
            "client_id": "88888888-5555-6666-7777-888888888888",
            "auth_type": "secret", "client_secret": "beispiel-secret-aus-der-app"}),
        ("api-fehler-schluessel", "POST", "/api/v1/customers", {
            "key": "MusterAG", "display_name": "Muster AG",
            "tenant_id": "99999999-1111-2222-3333-444444444444",
            "client_id": "88888888-5555-6666-7777-888888888888",
            "auth_type": "secret", "client_secret": "beispiel-secret-aus-der-app"}),
        ("api-fehler-unbekannt", "GET", "/api/v1/customers/gibtesnicht", None),
    ]

    # Ein zweiter Schluessel nur mit Leserecht, fuer den Nachweis von 403.
    roh_lesend, praefix_lesend = new_api_key()
    with app.app_context():
        Session.add(ApiKey(name="Dokumentation lesend", prefix=praefix_lesend,
                           key_hash=security.hash_api_key(roh_lesend), scope="read",
                           created_by="demo"))
        Session.commit()

    print("API-Antworten:")
    for name, methode, pfad, koerper in aufrufe:
        antwort = client.open(pfad, method=methode, headers=kopf, json=koerper)
        daten = {"request": {"method": methode, "path": pfad},
                 "status": antwort.status_code,
                 "body": antwort.get_json()}
        if koerper is not None:
            daten["request"]["body"] = koerper
        pfad_datei = pathlib.Path(ziel) / (name + ".json")
        pfad_datei.write_text(json.dumps(daten, indent=2, ensure_ascii=False),
                              encoding="utf-8")
        print("  %-24s %s" % (name + ".json", antwort.status_code))

    # Die Statuscodes der Anleitung, jeder einmal wirklich ausgeloest. Eine
    # Tabelle mit behaupteten Codes veraltet lautlos, diese Zeilen nicht.
    kopf_lesend = {"Authorization": "Bearer " + roh_lesend}
    neuanlage = {"key": "musterag", "display_name": "Muster AG",
                 "tenant_id": "99999999-1111-2222-3333-444444444444",
                 "client_id": "88888888-5555-6666-7777-888888888888",
                 "auth_type": "secret", "client_secret": "beispiel-secret-aus-der-app"}
    codes = {
        "ohne Schluessel (401)": client.get("/api/v1/customers"),
        "falscher Schluessel (401)": client.get(
            "/api/v1/customers", headers={"Authorization": "Bearer esm_falsch_00000"}),
        "nur lesend auf POST (403)": client.post(
            "/api/v1/customers", headers=kopf_lesend, json=neuanlage),
        "Schluessel doppelt (409)": client.post(
            "/api/v1/customers", headers=kopf, json=neuanlage),
    }
    belege = {}
    for was, antwort in codes.items():
        koerper = antwort.get_json()
        belege[was] = {"status": antwort.status_code, "body": koerper}
        print("  %-30s %s  %s" % (was, antwort.status_code,
                                  (koerper or {}).get("error", {}).get("code", "")))
    (pathlib.Path(ziel) / "api-statuscodes.json").write_text(
        json.dumps(belege, indent=2, ensure_ascii=False), encoding="utf-8")

    # Das PRTG-XML eines Kunden, so wie der Sensor es bekommt. Der Token steht
    # im Pfad und identifiziert den Kunden, es gibt keinen zweiten Parameter.
    from portal.models import Customer
    from sqlalchemy import select

    with app.app_context():
        kunde = Session.execute(
            select(Customer).where(Customer.key == "contoso")).scalar_one()
        token = kunde.prtg_token
    xml = client.get("/prtg/" + token)
    (pathlib.Path(ziel) / "prtg.xml").write_text(xml.get_data(as_text=True),
                                                 encoding="utf-8")
    print("  %-24s %s" % ("prtg.xml", xml.status_code))


def main():
    """Render every documented page into the target directory."""
    ziel = sys.argv[1] if len(sys.argv) > 1 else "demo-pages"
    pathlib.Path(ziel).mkdir(parents=True, exist_ok=True)

    handle, datenbank = tempfile.mkstemp(suffix=".db")
    os.close(handle)
    try:
        app = baue_app(datenbank)
        with app.app_context():
            fuelle_daten(app)
        client = app.test_client()
        melde_an(client)

        # Ein erster Abruf verbraucht die Flash-Meldung des Passwortwechsels.
        # Sonst klebt sie im Screenshot und gehoert dort nicht hin.
        client.get("/")

        print("Seiten:")
        schreibe(ziel, "dashboard.html", client.get("/").get_data(as_text=True))
        schreibe(ziel, "kunde-neu.html", client.get("/kunden/neu").get_data(as_text=True))
        schreibe(ziel, "kunde-detail.html", client.get("/kunden/1").get_data(as_text=True))
        # Zwei Schluessel, damit die Liste beide Bereiche zeigt statt leer zu sein.
        for name, bereich in (("PRTG Leserechte", "read"), ("Cloud Portal", "write")):
            client.post("/einstellungen/api/neu", data={
                "csrf_token": csrf(client, "/einstellungen/api/"),
                "name": name, "scope": bereich})
        schreibe(ziel, "api-schluessel.html",
                 client.get("/einstellungen/api/").get_data(as_text=True))

        # Der Fehlerfall des Schluessels, so wie ihn die Oberflaeche zeigt.
        antwort = client.post("/kunden/neu", data={
            "csrf_token": csrf(client, "/kunden/neu"),
            "key": "Contoso", "display_name": "Contoso AG",
            "tenant_id": "11111111-2222-3333-4444-555555555555",
            "client_id": "66666666-7777-8888-9999-000000000000",
            "auth_type": "secret", "client_secret": "beispiel",
            "warn_days": 30, "error_days": 14, "max_channels": 45, "is_active": "y"})
        schreibe(ziel, "kunde-neu-fehler.html", antwort.get_data(as_text=True))

        quelle = pathlib.Path(__file__).resolve().parent.parent / "portal" / "static"
        for datei in ("portal.css", "customer-form.js"):
            shutil.copy(quelle / datei, pathlib.Path(ziel) / datei)
            print("  %s" % datei)

        sammle_api_antworten(app, ziel)
        print("Fertig in %s" % pathlib.Path(ziel).resolve())
    finally:
        try:
            os.unlink(datenbank)
        except OSError:
            pass


if __name__ == "__main__":
    main()
