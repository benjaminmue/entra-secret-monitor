#!/usr/bin/env python3
"""
portal_sandbox.py

Eine Portal-Instanz auf einer Wegwerfdatenbank, plus die zwei Handgriffe, die
jeder Aufrufer danach braucht: ein CSRF-Token von einer Seite lesen und das
Erstkonto durch Zweitfaktor und Passwortwechsel fuehren.

Warum das hier liegt und nicht in tests/: es wird von beiden Seiten gebraucht.
Die Testsuite baut damit ihre Instanzen, und tools/demo_pages.py rendert damit
die Screenshots der Dokumentation. Vorher stand dieselbe Mechanik zweimal im
Repository, einmal in tests/support.py und einmal nachgebaut im Doku-Werkzeug.
Zwei Kopien laufen frueher oder spaeter auseinander, und dann zeigt die
Dokumentation einen Anmeldeweg, den die Anwendung nicht mehr hat.

Die Abhaengigkeit zeigt bewusst in diese Richtung: die Tests haengen am
Werkzeug, nicht das Werkzeug an den Tests. Ausgeliefert wird keines von beiden,
Dockerfile.portal kopiert nur app/ und portal/.
"""

import base64
import os
import re
import tempfile

# Vorgaben der Testsuite. Beide erfuellen die Passwortrichtlinie des Portals,
# enthalten also kein Wort aus FORBIDDEN_PATTERNS.
BOOTSTRAP_PASSWORD = "Start!Passwort2026x"
NEW_PASSWORD = "Zaun#Kies7Vogel!Lampe"


def build_app(bootstrap_password=BOOTSTRAP_PASSWORD, **zusatz):
    """
    Create a portal app on a throwaway SQLite file with the scheduler off.

    Gibt (app, datenbankpfad) zurueck. Der Pfad gehoert dem Aufrufer, er muss
    ihn selbst wieder loeschen. Ueber zusatz lassen sich weitere
    PORTAL_-Variablen setzen, etwa PORTAL_BASE_URL fuer stabile Sensor-URLs
    in der Dokumentation.
    """
    handle, pfad = tempfile.mkstemp(suffix=".db")
    os.close(handle)
    umgebung = {
        "PORTAL_SECRET_KEY": "unit-test-key-unit-test-key",
        "PORTAL_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
        "PORTAL_DATABASE_URL": "sqlite:///" + pfad.replace("\\", "/"),
        "PORTAL_SCHEDULER": "0",
        "PORTAL_COOKIE_SECURE": "0",
        "PORTAL_BOOTSTRAP_USER": "admin",
        "PORTAL_BOOTSTRAP_PASSWORD": bootstrap_password,
    }
    umgebung.update(zusatz)
    os.environ.update(umgebung)

    import portal.db as db
    db._engine = None                                                   # noqa: SLF001
    db.Session.remove()
    from portal.factory import create_app
    return create_app(), pfad


def csrf_token(client, path):
    """
    Read the CSRF token from a rendered form.

    Das Token haengt an der Sitzung, und die Sitzung wird zwischen Passwort-
    und Codeschritt geleert. Es muss deshalb von genau der Seite gelesen
    werden, die abgeschickt wird.
    """
    body = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', body)
    assert match, "kein CSRF-Token auf %s" % path
    return match.group(1)


def sign_in_admin(client, bootstrap_password=BOOTSTRAP_PASSWORD,
                  new_password=NEW_PASSWORD):
    """Walk the bootstrap account through TOTP enrollment and password change."""
    import pyotp

    client.post("/login", data={"csrf_token": csrf_token(client, "/login"),
                                "username": "admin", "password": bootstrap_password})
    token = csrf_token(client, "/login/2fa/setup")
    # Das Geheimnis liegt waehrend der Einrichtung in der Sitzung, nicht im HTML.
    with client.session_transaction() as session:
        secret = session["totp_setup_secret"]
    client.post("/login/2fa/setup", data={"csrf_token": token,
                                          "code": pyotp.TOTP(secret).now()})
    client.post("/account/password", data={
        "csrf_token": csrf_token(client, "/account/password"),
        "current_password": bootstrap_password,
        "new_password": new_password, "confirm_password": new_password})
