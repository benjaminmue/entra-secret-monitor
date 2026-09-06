#!/usr/bin/env python3
"""
test_api.py

Die REST-Schnittstelle, so wie das Cloudportal sie ansteuert.

Zwei Zusagen stehen hier im Mittelpunkt, weil ihr Bruch nicht auffiele: ein
lesender Schluessel darf nichts veraendern, und keine Antwort enthaelt je ein
Client Secret oder einen privaten Schluessel. Der Rest deckt Anlage, Aenderung,
Pruefung und die Fehlerformen ab.

Run with:  python -m unittest discover -s tests
"""

import json
import os
import re
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app"))

from tests.support import needs_portal                                   # noqa: E402

TENANT = "00000000-0000-0000-0000-0000000000aa"
CLIENT = "00000000-0000-0000-0000-0000000000bb"
GEHEIM = "streng-geheimes-client-secret"


def anlage(**overrides):
    """A create body that passes validation, overridable per test."""
    koerper = {"key": "musterag", "display_name": "Muster AG",
               "tenant_id": TENANT, "client_id": CLIENT,
               "auth_type": "secret", "client_secret": GEHEIM}
    koerper.update(overrides)
    return koerper


@needs_portal
class ApiTests(unittest.TestCase):
    """Every endpoint, driven the way an integration would drive it."""

    @classmethod
    def setUpClass(cls):
        """One app, one writing key and one read only key."""
        from tests.test_portal import build_app

        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        cls.context = cls.app.app_context()
        cls.context.push()

        from portal import security
        from portal.db import Session
        from portal.models import API_SCOPE_READ, API_SCOPE_WRITE, ApiKey, new_api_key

        cls.keys = {}
        for name, scope in (("schreibend", API_SCOPE_WRITE), ("lesend", API_SCOPE_READ)):
            roh, praefix = new_api_key()
            Session.add(ApiKey(name=name, prefix=praefix, scope=scope,
                               key_hash=security.hash_password(roh), created_by="test"))
            cls.keys[name] = roh
        Session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.context.pop()
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def setUp(self):
        """Start every test from an empty customer table and a clear limiter."""
        from portal import ratelimit
        from portal.db import Session
        from portal.models import Customer

        for kunde in Session.query(Customer).all():
            Session.delete(kunde)
        Session.commit()
        # Sonst misst ein spaeterer Test die Drosselung des frueheren.
        ratelimit.zuruecksetzen()

    # ------------------------------------------------------------------
    # Hilfen
    # ------------------------------------------------------------------

    def ruf(self, methode, pfad, schluessel="schreibend", koerper=None, roh=None):
        """One API call, returning (status, parsed body)."""
        kopf = {}
        token = roh if roh is not None else self.keys.get(schluessel)
        if token:
            kopf["Authorization"] = "Bearer " + token
        antwort = self.client.open(pfad, method=methode, headers=kopf, json=koerper)
        try:
            return antwort.status_code, antwort.get_json()
        except Exception:                                # pragma: no cover
            return antwort.status_code, None

    def lege_an(self, **overrides):
        """Create one customer through the API and assert it worked."""
        status, koerper = self.ruf("POST", "/api/v1/customers", koerper=anlage(**overrides))
        self.assertEqual(201, status, koerper)
        return koerper

    # ------------------------------------------------------------------
    # Authentifizierung
    # ------------------------------------------------------------------

    def test_without_a_key_nothing_is_reachable(self):
        """Ohne Kopf gibt es 401, und zwar als JSON, nicht als HTML-Seite."""
        status, koerper = self.ruf("GET", "/api/v1/customers", roh="")
        self.assertEqual(401, status)
        self.assertEqual("unauthenticated", koerper["error"]["code"])

    def test_an_unknown_key_is_refused(self):
        """Ein erfundener Schluessel im richtigen Format kommt nicht durch."""
        status, koerper = self.ruf("GET", "/api/v1/customers", roh="esm_deadbeef_" + "x" * 40)
        self.assertEqual(401, status)
        self.assertEqual("invalid_key", koerper["error"]["code"])

    def test_a_key_with_the_right_prefix_but_wrong_secret_is_refused(self):
        """
        Der Praefix allein berechtigt zu nichts.

        Er dient nur dem Nachschlagen. Waere er die Berechtigung, genuegten
        acht bekannte Zeichen aus einem Protokoll fuer den Vollzugriff.
        """
        praefix = self.keys["schreibend"].split("_")[1]
        status, _ = self.ruf("GET", "/api/v1/customers",
                             roh="esm_%s_%s" % (praefix, "f" * 43))
        self.assertEqual(401, status)

    def test_a_malformed_header_is_refused(self):
        """Alles, was nicht 'Bearer <schluessel>' ist, gilt als kein Schluessel."""
        for kopf in ("", "Basic abc", "Bearer", "esm_abc_def", "Bearer   "):
            with self.subTest(kopf=kopf):
                antwort = self.client.get("/api/v1/customers",
                                          headers={"Authorization": kopf})
                self.assertEqual(401, antwort.status_code)

    def test_a_revoked_key_stops_working(self):
        """Widerrufen wirkt sofort, ohne Neustart."""
        from portal.db import Session
        from portal.models import ApiKey, utcnow

        eintrag = Session.query(ApiKey).filter_by(name="lesend").one()
        eintrag.revoked_at = utcnow()
        Session.commit()
        try:
            status, _ = self.ruf("GET", "/api/v1/customers", "lesend")
            self.assertEqual(401, status)
        finally:
            eintrag.revoked_at = None
            Session.commit()

    def test_using_a_key_records_the_time(self):
        """last_used_at macht einen vergessenen Schluessel im Portal sichtbar."""
        from portal.db import Session
        from portal.models import ApiKey

        self.ruf("GET", "/api/v1/customers", "lesend")
        Session.expire_all()
        eintrag = Session.query(ApiKey).filter_by(name="lesend").one()
        self.assertIsNotNone(eintrag.last_used_at)

    def test_a_rejected_key_lands_in_the_audit_log(self):
        """Ein Zugriffsversuch mit unbekanntem Schluessel muss sichtbar sein."""
        from portal.db import Session
        from portal.models import AuditEvent

        vorher = Session.query(AuditEvent).filter_by(action="apikey.rejected").count()
        self.ruf("GET", "/api/v1/customers", roh="esm_cafebabe_" + "z" * 40)
        self.assertEqual(vorher + 1,
                         Session.query(AuditEvent).filter_by(action="apikey.rejected").count())

    def test_a_scan_of_the_path_does_not_flood_the_audit_log(self):
        """Ohne das Praefix esm_ ist es kein Angriff auf einen Schluessel."""
        from portal.db import Session
        from portal.models import AuditEvent

        vorher = Session.query(AuditEvent).filter_by(action="apikey.rejected").count()
        self.ruf("GET", "/api/v1/customers", roh="irgendwas")
        self.assertEqual(vorher,
                         Session.query(AuditEvent).filter_by(action="apikey.rejected").count())

    # ------------------------------------------------------------------
    # Bereiche
    # ------------------------------------------------------------------

    def test_a_read_only_key_may_read(self):
        """Lesende Endpunkte stehen dem lesenden Schluessel offen."""
        status, koerper = self.ruf("GET", "/api/v1/customers", "lesend")
        self.assertEqual(200, status)
        self.assertEqual(0, koerper["count"])

    def test_a_read_only_key_may_not_write(self):
        """Jeder schreibende Endpunkt weist den lesenden Schluessel ab."""
        self.lege_an()
        faelle = [
            ("POST", "/api/v1/customers", anlage(key="zweite")),
            ("PATCH", "/api/v1/customers/musterag", {"display_name": "Neu"}),
            ("DELETE", "/api/v1/customers/musterag", None),
            ("POST", "/api/v1/customers/musterag/check", None),
            ("POST", "/api/v1/customers/musterag/token", None),
        ]
        for methode, pfad, koerper in faelle:
            with self.subTest(pfad="%s %s" % (methode, pfad)):
                status, antwort = self.ruf(methode, pfad, "lesend", koerper)
                self.assertEqual(403, status)
                self.assertEqual("read_only", antwort["error"]["code"])

    def test_a_denied_write_lands_in_the_audit_log(self):
        """Ein Schreibversuch mit lesendem Schluessel ist eine Fehlkonfiguration."""
        from portal.db import Session
        from portal.models import AuditEvent

        self.ruf("POST", "/api/v1/customers", "lesend", anlage())
        self.assertEqual(1, Session.query(AuditEvent).filter_by(action="apikey.denied").count())

    # ------------------------------------------------------------------
    # Kunde anlegen
    # ------------------------------------------------------------------

    def test_creating_a_customer_returns_its_sensor_urls(self):
        """Das Cloudportal braucht die URLs sofort, nicht erst nach einem Abruf."""
        koerper = self.lege_an()
        self.assertEqual("musterag", koerper["key"])
        self.assertIn("/prtg/", koerper["urls"]["prtg_xml"])
        self.assertIn("/json/", koerper["urls"]["json"])

    def test_the_stored_secret_is_encrypted_and_never_returned(self):
        """
        Die zentrale Zusage: entgegennehmen, nie herausgeben.

        Geprueft an beiden Enden, in der Datenbank und in jeder Antwort, die
        den Kunden ausgibt.
        """
        from portal.db import Session
        from portal.models import Customer

        self.lege_an()
        kunde = Session.query(Customer).filter_by(key="musterag").one()
        self.assertNotIn(GEHEIM, kunde.client_secret_enc)
        self.assertTrue(kunde.client_secret_enc)

        for pfad in ("/api/v1/customers", "/api/v1/customers/musterag",
                     "/api/v1/customers/musterag/credentials",
                     "/api/v1/customers/musterag/urls"):
            with self.subTest(pfad=pfad):
                _, antwort = self.ruf("GET", pfad)
                self.assertNotIn(GEHEIM, json.dumps(antwort))

    def test_a_created_customer_reports_that_a_credential_is_stored(self):
        """Statt des Secrets kommt die Auskunft, dass eines hinterlegt ist."""
        koerper = self.lege_an()
        self.assertTrue(koerper["has_credential"])
        self.assertIsNone(koerper["certificate"])

    def test_a_created_customer_gets_a_daily_slot(self):
        """Ohne Slot liefe der Kunde nie im taeglichen Durchgang mit."""
        koerper = self.lege_an()
        self.assertIsInstance(koerper["scan"]["slot_minute"], int)

    def test_a_duplicate_key_is_refused(self):
        """Zweimal derselbe Kurzname waere zweimal dieselbe Sensor-URL."""
        self.lege_an()
        status, koerper = self.ruf("POST", "/api/v1/customers", koerper=anlage())
        self.assertEqual(409, status)
        self.assertEqual("duplicate", koerper["error"]["code"])

    def test_invalid_input_names_the_offending_fields(self):
        """
        Der Aufrufer muss wissen, was er falsch gemacht hat.

        Ein blosses 'ungueltig' zwingt den Integrator zum Raten, und geraten
        wird am Ende beim Kunden.
        """
        status, koerper = self.ruf("POST", "/api/v1/customers", koerper={
            "key": "Gross Und Falsch", "display_name": "",
            "tenant_id": "keine-guid", "client_id": CLIENT})
        self.assertEqual(422, status)
        self.assertEqual("validation_failed", koerper["error"]["code"])
        self.assertEqual({"key", "display_name", "tenant_id", "client_secret"},
                         set(koerper["error"]["fields"]))

    def test_a_body_that_is_not_an_object_is_refused(self):
        """Eine Liste oder eine Zahl ist kein Kunde."""
        for koerper in ([], 42, "text"):
            with self.subTest(koerper=koerper):
                status, antwort = self.ruf("POST", "/api/v1/customers", koerper=koerper)
                self.assertEqual(400, status)
                self.assertEqual("invalid_body", antwort["error"]["code"])

    def test_thresholds_have_to_be_ordered(self):
        """error_days ueber warn_days ergaebe eine Warnung nach dem Fehler."""
        status, koerper = self.ruf("POST", "/api/v1/customers",
                                   koerper=anlage(warn_days=10, error_days=30))
        self.assertEqual(422, status)
        self.assertIn("error_days", koerper["error"]["fields"])

    def test_a_secret_customer_without_a_secret_is_refused(self):
        """Ein Kunde ohne Zugangsdaten scheitert sonst erst beim ersten Lauf."""
        koerper = anlage()
        del koerper["client_secret"]
        status, antwort = self.ruf("POST", "/api/v1/customers", koerper=koerper)
        self.assertEqual(422, status)
        self.assertIn("client_secret", antwort["error"]["fields"])

    def test_a_certificate_customer_needs_both_halves(self):
        """Zertifikat ohne Schluessel ist kein Zugang."""
        status, koerper = self.ruf("POST", "/api/v1/customers", koerper=anlage(
            auth_type="certificate", client_secret=None, cert_pem="-----BEGIN..."))
        self.assertEqual(422, status)
        self.assertIn("key_pem", koerper["error"]["fields"])

    def test_a_mismatched_key_pair_is_refused(self):
        """Zertifikat und Schluessel muessen zusammengehoeren."""
        from tests.support import make_certificate

        cert_a, _ = make_certificate()
        _, key_b = make_certificate()
        status, koerper = self.ruf("POST", "/api/v1/customers", koerper=anlage(
            auth_type="certificate", client_secret=None,
            cert_pem=cert_a, key_pem=key_b))
        self.assertEqual(422, status)
        self.assertEqual("invalid_credential", koerper["error"]["code"])

    def test_a_matching_key_pair_is_accepted_and_only_its_expiry_returned(self):
        """Vom Zertifikat kommt der Fingerabdruck zurueck, nie der Schluessel."""
        from tests.support import make_certificate

        cert, key = make_certificate()
        koerper = self.lege_an(auth_type="certificate", client_secret=None,
                               cert_pem=cert, key_pem=key)
        self.assertEqual("certificate", koerper["auth_type"])
        self.assertTrue(koerper["certificate"]["thumbprint"])
        self.assertNotIn(key, json.dumps(koerper))

    def test_a_rejected_creation_leaves_no_half_customer_behind(self):
        """Scheitert das Zugangsdatum, darf der Kunde nicht ohne es stehen bleiben."""
        from portal.db import Session
        from portal.models import Customer
        from tests.support import make_certificate

        cert_a, _ = make_certificate()
        _, key_b = make_certificate()
        self.ruf("POST", "/api/v1/customers", koerper=anlage(
            auth_type="certificate", client_secret=None, cert_pem=cert_a, key_pem=key_b))
        Session.expire_all()
        self.assertIsNone(Session.query(Customer).filter_by(key="musterag").one_or_none())

    # ------------------------------------------------------------------
    # Lesen, aendern, loeschen
    # ------------------------------------------------------------------

    def test_listing_returns_every_customer(self):
        """Das Cloudportal holt die Liste, um seine eigene Sicht zu fuellen."""
        self.lege_an()
        self.lege_an(key="zweite", display_name="Zweite AG")
        status, koerper = self.ruf("GET", "/api/v1/customers", "lesend")
        self.assertEqual(200, status)
        self.assertEqual(2, koerper["count"])

    def test_an_unknown_customer_is_a_clean_404(self):
        """Auf jedem Pfad dieselbe Form, damit der Aufrufer eine Regel hat."""
        for methode, pfad in (("GET", "/api/v1/customers/gibtsnicht"),
                              ("PATCH", "/api/v1/customers/gibtsnicht"),
                              ("DELETE", "/api/v1/customers/gibtsnicht"),
                              ("POST", "/api/v1/customers/gibtsnicht/check"),
                              ("GET", "/api/v1/customers/gibtsnicht/credentials"),
                              ("GET", "/api/v1/customers/gibtsnicht/urls"),
                              ("POST", "/api/v1/customers/gibtsnicht/token")):
            with self.subTest(pfad=pfad):
                status, koerper = self.ruf(methode, pfad,
                                           koerper={} if methode == "PATCH" else None)
                self.assertEqual(404, status)
                self.assertEqual("not_found", koerper["error"]["code"])

    def test_an_unknown_path_answers_json_not_html(self):
        """
        Sonst meldet der Aufrufer einen Parserfehler statt der Ursache.

        Ein Routing-404 trifft keinen Blueprint, deshalb muss die App-Ebene
        anhand des Pfads entscheiden.
        """
        antwort = self.client.get("/api/v1/gibtsnicht",
                                  headers={"Authorization": "Bearer " + self.keys["lesend"]})
        self.assertEqual(404, antwort.status_code)
        self.assertEqual("not_found", antwort.get_json()["error"]["code"])

    def test_a_wrong_method_answers_json(self):
        """Auch 405 muss maschinenlesbar sein."""
        antwort = self.client.delete(
            "/api/v1/customers", headers={"Authorization": "Bearer " + self.keys["lesend"]})
        self.assertEqual(405, antwort.status_code)
        self.assertEqual("method_not_allowed", antwort.get_json()["error"]["code"])

    def test_patching_changes_only_what_was_sent(self):
        """Weggelassene Felder bleiben stehen, sonst raeumte ein Teil-Update auf."""
        self.lege_an(notes="wichtig")
        status, koerper = self.ruf("PATCH", "/api/v1/customers/musterag",
                                   koerper={"display_name": "Muster Holding"})
        self.assertEqual(200, status)
        self.assertEqual("Muster Holding", koerper["display_name"])

        _, voll = self.ruf("GET", "/api/v1/customers/musterag")
        self.assertEqual(TENANT, voll["tenant_id"])

    def test_patching_can_replace_the_secret(self):
        """Ein rotiertes Secret muss ohne Neuanlage ankommen."""
        from portal.db import Session
        from portal.models import Customer

        self.lege_an()
        vorher = Session.query(Customer).filter_by(key="musterag").one().client_secret_enc
        status, _ = self.ruf("PATCH", "/api/v1/customers/musterag",
                             koerper={"client_secret": "neues-secret"})
        self.assertEqual(200, status)
        Session.expire_all()
        nachher = Session.query(Customer).filter_by(key="musterag").one().client_secret_enc
        self.assertNotEqual(vorher, nachher)

    def test_patching_rejects_a_broken_guid(self):
        """Eine kaputte Tenant-ID faellt hier auf, nicht erst beim naechsten Lauf."""
        self.lege_an()
        status, koerper = self.ruf("PATCH", "/api/v1/customers/musterag",
                                   koerper={"tenant_id": "nicht-guid"})
        self.assertEqual(422, status)
        self.assertIn("tenant_id", koerper["error"]["fields"])

    def test_patching_keeps_the_thresholds_ordered(self):
        """Auch beim Aendern darf error_days nicht ueber warn_days steigen."""
        self.lege_an(warn_days=30, error_days=14)
        status, _ = self.ruf("PATCH", "/api/v1/customers/musterag",
                             koerper={"error_days": 60})
        self.assertEqual(422, status)

    def test_a_non_numeric_threshold_is_refused(self):
        """Text in einem Zahlenfeld darf keinen 500er ausloesen."""
        self.lege_an()
        status, koerper = self.ruf("PATCH", "/api/v1/customers/musterag",
                                   koerper={"warn_days": "dreissig"})
        self.assertEqual(422, status)
        self.assertIn("warn_days", koerper["error"]["fields"])

    def test_deleting_removes_the_customer(self):
        """Loeschen antwortet ohne Koerper und entfernt den Kunden wirklich."""
        self.lege_an()
        antwort = self.client.delete(
            "/api/v1/customers/musterag",
            headers={"Authorization": "Bearer " + self.keys["schreibend"]})
        self.assertEqual(204, antwort.status_code)
        status, _ = self.ruf("GET", "/api/v1/customers/musterag")
        self.assertEqual(404, status)

    # ------------------------------------------------------------------
    # Pruefung, Zugangsdaten, Token
    # ------------------------------------------------------------------

    def test_a_forced_check_returns_the_fresh_numbers(self):
        """
        Nach dem Lauf muessen die neuen Zahlen in der Antwort stehen.

        force_check schreibt in einer eigenen Sitzung. Ohne das Verwerfen des
        Zwischenspeichers antwortete der Endpunkt mit dem Stand von vorher.
        """
        from tests.test_portal import fake_scan

        self.lege_an()
        with mock.patch("portal.scanner.graph.scan_tenant", side_effect=fake_scan):
            status, koerper = self.ruf("POST", "/api/v1/customers/musterag/check")
        self.assertEqual(200, status)
        self.assertEqual("ok", koerper["status"])
        self.assertEqual(2, koerper["customer"]["summary"]["count_total"])
        self.assertEqual(9, koerper["customer"]["summary"]["min_days"])
        self.assertEqual(2, len(koerper["customer"]["credentials"]))

    def test_a_failing_check_reports_the_reason(self):
        """Ein fehlgeschlagener Lauf ist kein Serverfehler, sondern eine Auskunft."""
        self.lege_an()
        with mock.patch("portal.scanner.graph.scan_tenant",
                        side_effect=RuntimeError("Tenant nicht erreichbar")):
            status, koerper = self.ruf("POST", "/api/v1/customers/musterag/check")
        self.assertEqual(200, status)
        self.assertEqual("error", koerper["status"])
        self.assertIn("Tenant", koerper["error"])

    def test_a_blocked_check_answers_409_instead_of_hanging(self):
        """Laeuft ein anderer Scan zu lange, bekommt der Aufrufer eine Antwort."""
        from portal import scheduler

        self.lege_an()
        with mock.patch.object(scheduler, "force_check",
                               side_effect=TimeoutError("blockiert")):
            status, koerper = self.ruf("POST", "/api/v1/customers/musterag/check")
        self.assertEqual(409, status)
        self.assertEqual("busy", koerper["error"]["code"])

    def test_credentials_are_listed_shortest_runtime_first(self):
        """Das Cloudportal zeigt oben, was zuerst ablaeuft."""
        from tests.test_portal import fake_scan

        self.lege_an()
        with mock.patch("portal.scanner.graph.scan_tenant", side_effect=fake_scan):
            self.ruf("POST", "/api/v1/customers/musterag/check")
        status, koerper = self.ruf("GET", "/api/v1/customers/musterag/credentials", "lesend")
        self.assertEqual(200, status)
        tage = [c["days_left"] for c in koerper["credentials"]]
        self.assertEqual(sorted(tage), tage)
        self.assertEqual("SVC-Backup", koerper["credentials"][0]["app_name"])

    def test_rotating_the_token_changes_the_sensor_url(self):
        """
        Nach dem Wechsel liefert die alte URL keine Daten mehr.

        Sie antwortet weiterhin mit 200, aber mit einer Fehlermeldung im XML:
        PRTG zeigt bei einem HTTP-Fehler nur "Verbindung fehlgeschlagen",
        waehrend die Meldung im Koerper im Sensor lesbar ist.
        """
        altes_token = self.lege_an()["urls"]["prtg_xml"].rsplit("/", 1)[1]
        status, koerper = self.ruf("POST", "/api/v1/customers/musterag/token")
        self.assertEqual(200, status)
        self.assertNotEqual(altes_token, koerper["prtg_xml"].rsplit("/", 1)[1])

        antwort = self.client.get("/prtg/" + altes_token)
        self.assertEqual(200, antwort.status_code)
        self.assertIn("Unbekannter oder deaktivierter Token",
                      antwort.get_data(as_text=True))

    # ------------------------------------------------------------------
    # Eingaben, die aus einem Review stammen
    # ------------------------------------------------------------------

    def test_a_threshold_is_checked_against_the_default_of_the_other(self):
        """
        Nur warn_days zu senden darf die Reihenfolge nicht kippen.

        Der Standardwert fuer error_days liegt bei 14. Ein warn_days von 1
        wurde frueher angenommen, weil nur gegeneinander geprueft wurde, was
        beide in derselben Anfrage standen. Der Kunde war danach nicht einmal
        mehr aenderbar, weil jeder PATCH an derselben Pruefung scheiterte.
        """
        status, koerper = self.ruf("POST", "/api/v1/customers",
                                   koerper=anlage(warn_days=1))
        self.assertEqual(422, status)
        self.assertIn("error_days", koerper["error"]["fields"])

    def test_a_threshold_is_checked_against_the_stored_value_on_patch(self):
        """Dasselbe beim Aendern, dort gegen den gespeicherten Wert."""
        self.lege_an(warn_days=30, error_days=14)
        status, koerper = self.ruf("PATCH", "/api/v1/customers/musterag",
                                   koerper={"warn_days": 5})
        self.assertEqual(422, status)
        self.assertIn("error_days", koerper["error"]["fields"])

    def test_patching_respects_the_same_ranges_as_creating(self):
        """
        Die Grenzen aus der Anlage gelten auch beim Aendern.

        Sie fehlten dort ganz: negative Schwellen wurden gespeichert, und eine
        Zahl jenseits des Wertebereichs von SQLite endete im Serverfehler.
        """
        self.lege_an()
        faelle = [{"warn_days": -1}, {"error_days": 0}, {"max_channels": 0},
                  {"max_channels": 500}, {"max_channels": 10 ** 100},
                  {"warn_days": 4000}]
        for koerper in faelle:
            with self.subTest(koerper=koerper):
                status, antwort = self.ruf("PATCH", "/api/v1/customers/musterag",
                                           koerper=koerper)
                self.assertEqual(422, status)
                self.assertEqual(set(koerper), set(antwort["error"]["fields"]))

    def test_a_wrong_type_is_a_field_error_not_a_server_error(self):
        """
        Ein falscher Typ darf keinen 500er ausloesen.

        strip() auf einer Zahl warf frueher einen AttributeError, und der
        Aufrufer bekam eine Fehlerseite statt der Auskunft, welches Feld er
        falsch belegt hat.
        """
        self.lege_an()
        faelle = [("POST", {"key": 123}), ("POST", {"display_name": []}),
                  ("PATCH", {"notes": 123}), ("PATCH", {"app_filter": {"a": 1}}),
                  ("PATCH", {"warn_days": "dreissig"}), ("PATCH", {"is_active": "false"}),
                  ("PATCH", {"tenant_id": 5}), ("PATCH", {"include_sp": 1})]
        for methode, teil in faelle:
            with self.subTest(fall="%s %s" % (methode, teil)):
                pfad = ("/api/v1/customers" if methode == "POST"
                        else "/api/v1/customers/musterag")
                koerper = anlage(**teil) if methode == "POST" else teil
                status, antwort = self.ruf(methode, pfad, koerper=koerper)
                self.assertEqual(422, status)
                self.assertEqual(set(teil), set(antwort["error"]["fields"]))

    def test_a_boolean_is_never_read_from_a_string(self):
        """
        Die Zeichenkette "false" waere sonst wahr.

        bool("false") ist True, und ein Kunde, den das Cloudportal deaktivieren
        wollte, waere aktiv geblieben.
        """
        self.lege_an()
        status, _ = self.ruf("PATCH", "/api/v1/customers/musterag",
                             koerper={"is_active": "false"})
        self.assertEqual(422, status)
        _, koerper = self.ruf("PATCH", "/api/v1/customers/musterag",
                              koerper={"is_active": False})
        self.assertFalse(koerper["is_active"])

    def test_switching_to_certificates_needs_a_certificate(self):
        """
        Die Anmeldeart darf nur wechseln, wenn das Material mitkommt.

        Ein blosses auth_type 'certificate' wurde frueher gespeichert. Der
        Kunde meldete danach weiterhin ein hinterlegtes Zugangsdatum, weil das
        alte Secret noch dalag, und der naechste Lauf scheiterte.
        """
        self.lege_an()
        status, koerper = self.ruf("PATCH", "/api/v1/customers/musterag",
                                   koerper={"auth_type": "certificate"})
        self.assertEqual(422, status)
        self.assertIn("cert_pem", koerper["error"]["fields"])

        _, unveraendert = self.ruf("GET", "/api/v1/customers/musterag")
        self.assertEqual("secret", unveraendert["auth_type"])

    def test_switching_to_a_secret_needs_a_secret(self):
        """Dasselbe in die andere Richtung."""
        from tests.support import make_certificate

        cert, key = make_certificate()
        self.lege_an(auth_type="certificate", client_secret=None,
                     cert_pem=cert, key_pem=key)
        status, koerper = self.ruf("PATCH", "/api/v1/customers/musterag",
                                   koerper={"auth_type": "secret"})
        self.assertEqual(422, status)
        self.assertIn("client_secret", koerper["error"]["fields"])

    def test_an_unknown_auth_type_is_refused(self):
        """Ein erfundener Wert darf nicht als Anmeldeart durchgehen."""
        self.lege_an()
        for koerper in ({"auth_type": "bogus"}, {"auth_type": ""}):
            with self.subTest(koerper=koerper):
                status, antwort = self.ruf("PATCH", "/api/v1/customers/musterag",
                                           koerper=koerper)
                self.assertEqual(422, status)
                self.assertIn("auth_type", antwort["error"]["fields"])

    def test_switching_the_method_with_material_works(self):
        """Mit Material ist der Wechsel erlaubt und raeumt das alte Zugangsdatum weg."""
        from portal.db import Session
        from portal.models import Customer
        from tests.support import make_certificate

        cert, key = make_certificate()
        self.lege_an()
        status, koerper = self.ruf("PATCH", "/api/v1/customers/musterag", koerper={
            "auth_type": "certificate", "cert_pem": cert, "key_pem": key})
        self.assertEqual(200, status)
        self.assertEqual("certificate", koerper["auth_type"])
        Session.expire_all()
        self.assertEqual("", Session.query(Customer).filter_by(
            key="musterag").one().client_secret_enc)

    def test_a_password_protected_private_key_is_a_field_error(self):
        """
        Ein verschluesselter PEM-Schluessel ist eine Eingabe, kein Serverfehler.

        load_pem_private_key wirft dabei TypeError statt ValueError, was
        frueher ungefiltert bis zur Fehlerseite durchschlug.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from tests.support import make_certificate

        cert, _ = make_certificate()
        schluessel = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        geschuetzt = schluessel.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"geheim")).decode()

        status, koerper = self.ruf("POST", "/api/v1/customers", koerper=anlage(
            auth_type="certificate", client_secret=None,
            cert_pem=cert, key_pem=geschuetzt))
        self.assertEqual(422, status)
        self.assertEqual("invalid_credential", koerper["error"]["code"])
        self.assertIn("Passwort", koerper["error"]["message"])

    def test_unreadable_pem_input_is_a_field_error(self):
        """Auch Text, der kein PEM ist, endet in einer 422 statt in einem 500er."""
        status, koerper = self.ruf("POST", "/api/v1/customers", koerper=anlage(
            auth_type="certificate", client_secret=None,
            cert_pem="kein zertifikat", key_pem="kein schluessel"))
        self.assertEqual(422, status)
        self.assertEqual("invalid_credential", koerper["error"]["code"])

    # ------------------------------------------------------------------
    # Verzeichnis und Beschreibung
    # ------------------------------------------------------------------

    def test_the_root_lists_every_endpoint(self):
        """Der Einstieg sagt, was es gibt, ohne dass jemand die Doku sucht."""
        status, koerper = self.ruf("GET", "/api/v1/", "lesend")
        self.assertEqual(200, status)
        self.assertEqual("1.0", koerper["version"])
        pfade = {e["path"] for e in koerper["endpoints"]}
        self.assertIn("/api/v1/customers", pfade)

    def test_every_endpoint_of_the_directory_is_described(self):
        """
        Verzeichnis und OpenAPI duerfen nicht auseinanderlaufen.

        Ein neuer Endpunkt ohne Eintrag faellt in build() still unter den
        Tisch. Dieser Test ist die Bremse dafuer.
        """
        from portal.openapi import BESONDERHEITEN
        from portal.views.api import ENDPUNKTE

        fehlend = ["%s %s" % (e["methode"], e["pfad"]) for e in ENDPUNKTE
                   if "%s %s" % (e["methode"], e["pfad"]) not in BESONDERHEITEN]
        self.assertEqual([], fehlend)

    def test_every_described_endpoint_actually_exists(self):
        """Und umgekehrt: nichts beschreiben, was es nicht gibt."""
        from portal.openapi import BESONDERHEITEN
        from portal.views.api import ENDPUNKTE

        vorhanden = {"%s %s" % (e["methode"], e["pfad"]) for e in ENDPUNKTE}
        self.assertEqual([], sorted(set(BESONDERHEITEN) - vorhanden))

    def test_the_openapi_document_is_complete_enough_to_generate_a_client(self):
        """Server, Sicherheitsschema und Schemas muessen darin stehen."""
        status, koerper = self.ruf("GET", "/api/v1/openapi.json", "lesend")
        self.assertEqual(200, status)
        self.assertEqual("3.0.3", koerper["openapi"])
        self.assertTrue(koerper["servers"][0]["url"])
        self.assertIn("bearerAuth", koerper["components"]["securitySchemes"])
        self.assertIn("/api/v1/customers/{key}", koerper["paths"])
        self.assertIn("post", koerper["paths"]["/api/v1/customers"])

    def test_every_reference_in_the_openapi_document_resolves(self):
        """
        Ein toter Verweis bricht jeden Generator.

        Geprueft wird der ganze Baum, nicht nur die oberste Ebene, weil die
        Verweise tief in den Antwortobjekten stehen.
        """
        _, dokument = self.ruf("GET", "/api/v1/openapi.json", "lesend")

        def verweise(knoten):
            """Yield every $ref value in the document."""
            if isinstance(knoten, dict):
                for schluessel, wert in knoten.items():
                    if schluessel == "$ref":
                        yield wert
                    else:
                        yield from verweise(wert)
            elif isinstance(knoten, list):
                for eintrag in knoten:
                    yield from verweise(eintrag)

        for verweis in verweise(dokument):
            with self.subTest(verweis=verweis):
                ziel = dokument
                for teil in verweis.lstrip("#/").split("/"):
                    self.assertIn(teil, ziel, verweis)
                    ziel = ziel[teil]

    def test_the_openapi_document_is_also_reachable_from_the_browser(self):
        """Ein Administrator hat keinen Schluessel im Kopf, nur eine Sitzung."""
        antwort = self.client.get("/api/v1/openapi.json")
        self.assertEqual(401, antwort.status_code)
        self.assertEqual("unauthenticated", antwort.get_json()["error"]["code"])

    # ------------------------------------------------------------------
    # Feindliche Eingaben
    # ------------------------------------------------------------------

    def test_injection_payloads_are_treated_as_plain_text(self):
        """
        SQL und Script gehen durch die ORM-Bindung, nicht in eine Anweisung.

        Geprueft am Anzeigenamen, weil der als einziges Feld freien Text
        annimmt und spaeter in der Oberflaeche landet.
        """
        from portal.db import Session
        from portal.models import Customer

        nutzlasten = ["Muster'; DROP TABLE customers; --",
                      "<script>alert(1)</script>",
                      "Muster\" OR \"1\"=\"1"]
        for index, nutzlast in enumerate(nutzlasten):
            with self.subTest(nutzlast=nutzlast):
                koerper = self.lege_an(key="kunde%d" % index, display_name=nutzlast)
                self.assertEqual(nutzlast, koerper["display_name"])
        self.assertEqual(len(nutzlasten), Session.query(Customer).count())

    def test_a_traversal_attempt_in_the_key_finds_nothing(self):
        """Der Kurzname ist ein Pfadsegment, also wird er auch so behandelt."""
        for schluessel in ("..%2f..%2fetc%2fpasswd", "%00", "' OR '1'='1"):
            with self.subTest(schluessel=schluessel):
                status, _ = self.ruf("GET", "/api/v1/customers/" + schluessel, "lesend")
                self.assertEqual(404, status)

    def test_an_oversized_body_is_refused_before_it_is_parsed(self):
        """MAX_CONTENT_LENGTH schuetzt vor dem Speicherfresser."""
        antwort = self.client.post(
            "/api/v1/customers",
            headers={"Authorization": "Bearer " + self.keys["schreibend"],
                     "Content-Type": "application/json"},
            data=b'{"key":"x","notes":"' + b"a" * (2 * 1024 * 1024) + b'"}')
        self.assertEqual(413, antwort.status_code)
        self.assertEqual("payload_too_large", antwort.get_json()["error"]["code"])

    def test_api_answers_are_never_cached(self):
        """Zwischengespeicherte Laufzeiten waeren schlimmer als keine."""
        antwort = self.client.get("/api/v1/customers",
                                  headers={"Authorization": "Bearer " + self.keys["lesend"]})
        self.assertEqual("no-store", antwort.headers.get("Cache-Control"))


if __name__ == "__main__":
    unittest.main()


@needs_portal
class ApiKeyAdministrationTests(unittest.TestCase):
    """
    Die Einstellungsseite, ueber die ein Schluessel entsteht und vergeht.

    Sie gibt Vollzugriff auf jeden Kundentenant weiter, deshalb steht hier vor
    allem, wer sie nicht bedienen darf und was nach dem Anlegen sichtbar bleibt.
    """

    @classmethod
    def setUpClass(cls):
        from tests.support import sign_in_admin
        from tests.test_portal import build_app

        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        sign_in_admin(cls.client)
        cls.context = cls.app.app_context()
        cls.context.push()

    @classmethod
    def tearDownClass(cls):
        cls.context.pop()
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def _csrf(self, pfad="/einstellungen/api/"):
        from tests.support import csrf_token

        return csrf_token(self.client, pfad)

    def _ausstellen(self, name, scope="read"):
        """Issue one key through the form and return the response."""
        return self.client.post("/einstellungen/api/neu", data={
            "csrf_token": self._csrf(), "name": name, "scope": scope})

    def test_the_page_lists_the_endpoints(self):
        """Der Integrator soll nicht im Quellcode nachsehen muessen."""
        seite = self.client.get("/einstellungen/api/").get_data(as_text=True)
        self.assertIn("/api/v1/customers", seite)
        self.assertIn("Authorization", seite)

    def test_a_new_key_is_shown_once_and_only_hashed_afterwards(self):
        """
        Die Datenbank darf nie der Generalschluessel zur Schnittstelle sein.

        Der Klartext erscheint genau in dieser Antwort, danach steht nur noch
        der Hash in der Tabelle.
        """
        from portal.db import Session
        from portal.models import ApiKey

        antwort = self._ausstellen("Cloudportal")
        self.assertEqual(200, antwort.status_code)
        seite = antwort.get_data(as_text=True)
        treffer = re.search(r"esm_[0-9a-f]{8}_[A-Za-z0-9_-]{20,}", seite)
        self.assertIsNotNone(treffer, "kein Schlüssel in der Antwort")

        eintrag = Session.query(ApiKey).filter_by(name="Cloudportal").one()
        self.assertNotIn(treffer.group(0), eintrag.key_hash)
        self.assertNotIn(treffer.group(0),
                         self.client.get("/einstellungen/api/").get_data(as_text=True))

    def test_the_one_time_page_is_never_cached(self):
        """Sonst holt der Zurueck-Knopf den Schluessel aus dem Browserspeicher."""
        antwort = self._ausstellen("Einmalig")
        self.assertEqual("no-store", antwort.headers.get("Cache-Control"))

    def test_a_duplicate_name_is_refused(self):
        """Zwei gleich benannte Schluessel waeren im Protokoll nicht zu trennen."""
        from portal.db import Session
        from portal.models import ApiKey

        self._ausstellen("Doppelt")
        self._ausstellen("Doppelt")
        self.assertEqual(1, Session.query(ApiKey).filter_by(name="Doppelt").count())

    def test_a_rejected_name_creates_nothing(self):
        """Das Formular laesst nur harmlose Zeichen zu."""
        from portal.db import Session
        from portal.models import ApiKey

        vorher = Session.query(ApiKey).count()
        self.client.post("/einstellungen/api/neu", data={
            "csrf_token": self._csrf(), "name": "<script>alert(1)</script>",
            "scope": "read"})
        self.assertEqual(vorher, Session.query(ApiKey).count())

    def test_an_unknown_scope_is_refused(self):
        """Ein erfundener Bereich darf nicht als schreibend durchgehen."""
        from portal.db import Session
        from portal.models import ApiKey

        vorher = Session.query(ApiKey).count()
        self.client.post("/einstellungen/api/neu", data={
            "csrf_token": self._csrf(), "name": "Erfunden", "scope": "admin"})
        self.assertEqual(vorher, Session.query(ApiKey).count())

    def test_revoking_keeps_the_row_for_the_audit_trail(self):
        """Widerrufen loescht nicht, sonst fehlte spaeter der Bezug im Protokoll."""
        from portal.db import Session
        from portal.models import ApiKey

        self._ausstellen("Zu widerrufen")
        eintrag = Session.query(ApiKey).filter_by(name="Zu widerrufen").one()
        self.client.post("/einstellungen/api/%d/widerrufen" % eintrag.id,
                         data={"csrf_token": self._csrf()})
        Session.expire_all()
        eintrag = Session.query(ApiKey).filter_by(name="Zu widerrufen").one()
        self.assertIsNotNone(eintrag.revoked_at)
        self.assertFalse(eintrag.is_active)

    def test_deleting_removes_the_key(self):
        """Ein geloeschter Schluessel verschwindet ganz."""
        from portal.db import Session
        from portal.models import ApiKey

        self._ausstellen("Zu loeschen")
        eintrag = Session.query(ApiKey).filter_by(name="Zu loeschen").one()
        self.client.post("/einstellungen/api/%d/loeschen" % eintrag.id,
                         data={"csrf_token": self._csrf()})
        self.assertIsNone(Session.query(ApiKey).filter_by(name="Zu loeschen").one_or_none())

    def test_every_route_needs_the_csrf_token(self):
        """Ohne Token wird nichts ausgestellt, widerrufen oder geloescht."""
        from portal.db import Session
        from portal.models import ApiKey

        self._ausstellen("Geschuetzt")
        eintrag = Session.query(ApiKey).filter_by(name="Geschuetzt").one()
        for pfad in ("/einstellungen/api/neu",
                     "/einstellungen/api/%d/widerrufen" % eintrag.id,
                     "/einstellungen/api/%d/loeschen" % eintrag.id):
            with self.subTest(pfad=pfad):
                self.assertEqual(400, self.client.post(pfad, data={"name": "X"}).status_code)

    def test_a_missing_key_is_a_404(self):
        """Eine erfundene Kennung fuehrt nicht in einen Serverfehler."""
        for pfad in ("/einstellungen/api/9999/widerrufen",
                     "/einstellungen/api/9999/loeschen"):
            with self.subTest(pfad=pfad):
                self.assertEqual(404, self.client.post(
                    pfad, data={"csrf_token": self._csrf()}).status_code)

    def test_a_viewer_may_not_manage_keys(self):
        """
        Ein schreibender Schluessel wiegt so schwer wie ein Bedienerkonto.

        Deshalb reicht die Leseberechtigung im Portal nicht, um einen
        auszustellen. Geprueft am angemeldeten Konto, dessen Rolle kurz
        heruntergestuft wird: die Rolle wird bei jedem Zugriff frisch aus der
        Datenbank gelesen, ein zweiter Login mit zweitem Faktor waere nur
        Umweg.
        """
        from portal.db import Session
        from portal.models import ROLE_ADMIN, ROLE_VIEWER, User

        # Das Token noch als Administrator holen: CSRF greift vor der
        # Rollenpruefung, sonst bewiese der POST unten nur den fehlenden Token.
        token = self._csrf()

        konto = Session.query(User).filter_by(username="admin").one()
        konto.role = ROLE_VIEWER
        Session.commit()
        try:
            # Eigener Anwendungskontext: der Kontext dieser Klasse haelt in g
            # den bereits geladenen Benutzer, und Flask-Login liest ihn von
            # dort statt neu aus der Datenbank.
            with self.app.app_context():
                self.assertEqual(403, self.client.get("/einstellungen/api/").status_code)
                self.assertEqual(403, self.client.post(
                    "/einstellungen/api/neu",
                    data={"csrf_token": token, "name": "Verboten",
                          "scope": "write"}).status_code)
        finally:
            konto.role = ROLE_ADMIN
            Session.commit()


@needs_portal
class RateLimitTests(unittest.TestCase):
    """
    Die Drosselung der Schnittstelle.

    Sie kam aus einem Sicherheitsdurchgang: ein Schlüssel liess sich unbegrenzt
    durchprobieren, und `/check` löste bei jedem Aufruf eine Graph-Abfrage im
    Kundentenant aus. Beides ohne Bremse.
    """

    @classmethod
    def setUpClass(cls):
        from tests.test_portal import build_app

        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        cls.context = cls.app.app_context()
        cls.context.push()

        from portal import security
        from portal.db import Session
        from portal.models import API_SCOPE_READ, API_SCOPE_WRITE, ApiKey, new_api_key

        cls.keys = {}
        for name, scope in (("schreibend", API_SCOPE_WRITE), ("lesend", API_SCOPE_READ)):
            roh, praefix = new_api_key()
            Session.add(ApiKey(name=name, prefix=praefix, scope=scope,
                               key_hash=security.hash_password(roh), created_by="test"))
            cls.keys[name] = roh
        Session.commit()

    @classmethod
    def tearDownClass(cls):
        cls.context.pop()
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def setUp(self):
        from portal import ratelimit

        ratelimit.zuruecksetzen()

    def _kopf(self, name="schreibend"):
        return {"Authorization": "Bearer " + self.keys[name]}

    def test_guessing_the_secret_of_a_known_key_is_throttled(self):
        """
        Das Raten des Geheimnisses zu einem bekannten Präfix läuft in die Sperre.

        Gezählt wird je Präfix, nicht je Adresse. Nach der Adresse zu zählen
        hatte einen Fehler: hinter einem Reverse Proxy teilen sich alle
        Aufrufer eine Adresse, und zehn Fehlversuche eines Dritten sperrten
        das anbindende System aus.
        """
        praefix = self.keys["lesend"].split("_")[1]
        codes = [self.client.get("/api/v1/customers", headers={
            "Authorization": "Bearer esm_%s_%s" % (praefix, "y" * 43)}).status_code
            for i in range(14)]
        self.assertIn(429, codes, codes)
        self.assertEqual(10, codes.count(401), codes)

    def test_a_valid_key_is_never_locked_out_by_failed_attempts(self):
        """
        Die Zusicherung aus docs/SECURITY-GATE.md, jetzt vollständig.

        Zwei Fassungen davor waren schwächer. Die erste zählte je Adresse, dann
        sperrten fremde Fehlversuche hinter einem Reverse Proxy jeden mit.
        Die zweite zählte je Präfix, prüfte aber **vor** der Authentifizierung,
        also sperrte das Raten am eigenen Schlüssel dessen Inhaber aus. Jetzt
        werden die Zähler erst nach der Prüfung angefasst, und ein gültiger
        Schlüssel kommt immer durch.
        """
        angegriffen = self.keys["lesend"].split("_")[1]
        for _ in range(20):
            self.client.get("/api/v1/customers", headers={
                "Authorization": "Bearer esm_%s_%s" % (angegriffen, "z" * 43)})
        for _ in range(70):
            self.client.get("/api/v1/customers", headers={
                "Authorization": "Bearer esm_deadbeef_%s" % ("y" * 43)})

        self.assertEqual(200, self.client.get("/api/v1/customers",
                                              headers=self._kopf("lesend")).status_code,
                         "der angegriffene Schlüssel selbst muss durchkommen")
        self.assertEqual(200, self.client.get("/api/v1/customers",
                                              headers=self._kopf()).status_code,
                         "ein anderer Schlüssel erst recht")

    def test_walking_through_prefixes_is_throttled_by_address(self):
        """
        Wechselnde Präfixe umgehen den Präfixzähler, deshalb ein zweiter.

        Je Versuch ist das nur eine indizierte Abfrage, in der Menge trotzdem
        Last. Gezählt werden auch hier ausschliesslich Fehlversuche.
        """
        codes = [self.client.get("/api/v1/customers", headers={
            "Authorization": "Bearer esm_%08x_%s" % (i, "x" * 43)}).status_code
            for i in range(70)]
        self.assertIn(429, codes, sorted(set(codes)))
        self.assertEqual(60, codes.count(401), sorted(set(codes)))

    def test_a_valid_key_never_spends_the_failure_budget(self):
        """
        Sonst sperrte sich ein fleissiger Aufrufer selbst aus.

        Genau das war die erste, verworfene Fassung: sie zählte jede Anfrage
        und liess die Testsuite nach hundert Aufrufen auflaufen.
        """
        for _ in range(15):
            self.assertEqual(200, self.client.get("/api/v1/customers",
                                                  headers=self._kopf()).status_code)

    def test_a_throttled_answer_says_when_to_come_back(self):
        """Ohne Retry-After rät ein Client die Wartezeit."""
        praefix = self.keys["lesend"].split("_")[1]
        antwort = None
        for _ in range(14):
            antwort = self.client.get("/api/v1/customers", headers={
                "Authorization": "Bearer esm_%s_%s" % (praefix, "y" * 43)})
        self.assertEqual(429, antwort.status_code)
        self.assertEqual("rate_limited", antwort.get_json()["error"]["code"])
        self.assertTrue(antwort.headers.get("Retry-After", "").isdigit())

    def test_a_read_only_key_spends_the_budget_on_denied_writes(self):
        """
        Ein Schlüssel, der dauernd schreiben will, verhält sich wie ein Angriff.

        Der abgewiesene Schreibzugriff zählt als Fehlversuch, weil der Schlüssel
        dabei nie freigegeben wird. Das trifft nur diesen einen Schlüssel.
        """
        codes = [self.client.post("/api/v1/customers", headers=self._kopf("lesend"),
                                  json={}).status_code for _ in range(14)]
        self.assertIn(429, codes, codes)
        # Der schreibende Schlüssel bleibt davon unberührt.
        self.assertEqual(200, self.client.get("/api/v1/customers",
                                              headers=self._kopf()).status_code)

    def test_the_openapi_route_is_throttled_like_every_other(self):
        """
        Sie nahm einen Schlüssel entgegen und ging an der Drosselung vorbei.

        Aufgefallen in der Gegenprüfung: die Route rief die Schlüsselsuche
        direkt auf, statt durch die gemeinsame Authentifizierung zu gehen.
        Damit liess sich der Argon2-Vergleich über diesen einen Pfad
        unbegrenzt auslösen, während jede andere Route längst 429 lieferte.
        """
        praefix = self.keys["lesend"].split("_")[1]
        codes = [self.client.get("/api/v1/openapi.json", headers={
            "Authorization": "Bearer esm_%s_%s" % (praefix, "y" * 43)}).status_code
            for _ in range(14)]
        self.assertIn(429, codes, codes)

    def test_forced_checks_are_limited_per_customer(self):
        """
        Hinter /check steht eine echte Abfrage im Tenant des Kunden.

        Ohne eigene, engere Grenze liesse sich der Tenant über das Portal
        belasten, und zwar mit einem Schlüssel, der sonst alles richtig macht.
        """
        from unittest import mock

        from tests.test_portal import fake_scan

        self.client.post("/api/v1/customers", headers=self._kopf(),
                         json=anlage(key="gebremst"))
        with mock.patch("portal.scanner.graph.scan_tenant", side_effect=fake_scan):
            codes = [self.client.post("/api/v1/customers/gebremst/check",
                                      headers=self._kopf()).status_code
                     for _ in range(14)]
        self.assertIn(429, codes, codes)
        self.assertEqual(12, codes.count(200), codes)

    def test_the_check_limit_is_per_customer_not_global(self):
        """Ein vielgeprüfter Kunde darf keinen anderen blockieren."""
        from unittest import mock

        from tests.test_portal import fake_scan

        for kurz in ("erster", "zweiter"):
            self.client.post("/api/v1/customers", headers=self._kopf(),
                             json=anlage(key=kurz))
        with mock.patch("portal.scanner.graph.scan_tenant", side_effect=fake_scan):
            for _ in range(13):
                self.client.post("/api/v1/customers/erster/check", headers=self._kopf())
            zweiter = self.client.post("/api/v1/customers/zweiter/check",
                                       headers=self._kopf())
        self.assertEqual(200, zweiter.status_code)

    def test_the_limiter_forgets_after_the_window(self):
        """Eine Sperre, die nie endet, wäre eine Selbstblockade."""
        from portal import ratelimit

        grenze = ratelimit.Grenze("test", 2, 60)
        self.assertEqual((True, 0), ratelimit.pruefe(grenze, "x"))
        self.assertEqual((True, 0), ratelimit.pruefe(grenze, "x"))
        erlaubt, warten = ratelimit.pruefe(grenze, "x")
        self.assertFalse(erlaubt)
        self.assertTrue(0 < warten <= 61)

        # Die Uhr vorstellen statt zu warten: der Zähler nutzt monotonic().
        with mock.patch.object(ratelimit, "_jetzt",
                               side_effect=lambda: ratelimit.time.monotonic() + 61):
            self.assertEqual((True, 0), ratelimit.pruefe(grenze, "x"))

    def test_the_limiter_does_not_grow_without_bound(self):
        """
        Wechselnde Kennungen dürfen den Speicher nicht füllen.

        Sonst wäre die Bremse gegen Durchprobieren selbst der Hebel für eine
        Überlastung.
        """
        from portal import ratelimit

        grenze = ratelimit.Grenze("wachstum", 5, 60)
        for i in range(ratelimit.MAX_EIMER + 500):
            ratelimit.pruefe(grenze, "kennung-%d" % i)
        self.assertLessEqual(len(ratelimit._EIMER), ratelimit.MAX_EIMER)

    def test_two_callers_are_counted_separately(self):
        """Sonst sperrt ein Angreifer den echten Aufrufer aus."""
        from portal import ratelimit

        grenze = ratelimit.Grenze("getrennt", 1, 60)
        self.assertTrue(ratelimit.pruefe(grenze, "a")[0])
        self.assertTrue(ratelimit.pruefe(grenze, "b")[0])
        self.assertFalse(ratelimit.pruefe(grenze, "a")[0])

    def test_an_active_block_survives_a_flood_of_other_keys(self):
        """
        Die Speichergrenze darf keine laufende Sperre wegräumen.

        Sonst wäre die Bremse selbst der Hebel, sie aufzuheben: Tabelle mit
        erfundenen Kennungen fluten, und der gesperrte Kunde ist wieder frei.
        Genau das liess die erste Fassung zu.
        """
        from portal import ratelimit

        grenze = ratelimit.Grenze("kunde", 2, 3600)
        ratelimit.pruefe(grenze, "wichtig")
        ratelimit.pruefe(grenze, "wichtig")
        self.assertFalse(ratelimit.pruefe(grenze, "wichtig")[0])

        fuellen = ratelimit.Grenze("fuellen", 5, 60)
        for i in range(ratelimit.MAX_EIMER + 200):
            ratelimit.pruefe(fuellen, "muell-%d" % i)

        self.assertFalse(ratelimit.pruefe(grenze, "wichtig")[0],
                         "die Sperre wurde von der Speichergrenze geraeumt")
        self.assertLessEqual(ratelimit.belegung(), ratelimit.MAX_EIMER)

    def test_a_full_table_refuses_new_identities_instead_of_forgetting_old(self):
        """Voll und nichts abgelaufen heisst abweisen, nicht vergessen."""
        from portal import ratelimit

        grenze = ratelimit.Grenze("voll", 5, 3600)
        for i in range(ratelimit.MAX_EIMER):
            ratelimit.pruefe(grenze, "belegt-%d" % i)
        erlaubt, warten = ratelimit.pruefe(grenze, "neu")
        self.assertFalse(erlaubt)
        self.assertGreaterEqual(warten, 1)

    def test_a_limit_below_one_is_refused_when_it_is_built(self):
        """
        Ein Grenzwert von 0 lief früher erst beim ersten Zugriff auf.

        Als IndexError aus einer leeren deque, also als Serverfehler statt als
        Konfigurationsfehler beim Start.
        """
        from portal import ratelimit

        for anzahl, fenster in ((0, 60), (-1, 60), (5, 0)):
            with self.subTest(anzahl=anzahl, fenster=fenster):
                with self.assertRaises(ValueError):
                    ratelimit.Grenze("kaputt", anzahl, fenster)

    def test_the_config_refuses_a_limit_below_one(self):
        """Und der Konfigurationslader fängt es ab, bevor das Portal startet."""
        import base64
        import os

        from portal.config import ConfigError, load_config

        basis = {"PORTAL_SECRET_KEY": "x" * 40,
                 "PORTAL_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode()}
        for variable in ("PORTAL_API_RATE_PER_MINUTE",
                         "PORTAL_API_KEY_ATTEMPTS_PER_MINUTE",
                         "PORTAL_API_ANON_ATTEMPTS_PER_MINUTE",
                         "PORTAL_API_CHECK_PER_HOUR"):
            with self.subTest(variable=variable):
                with self.assertRaises(ConfigError) as gefangen:
                    load_config(dict(basis, **{variable: "0"}))
                self.assertIn(variable, str(gefangen.exception))

    def test_retry_after_is_never_zero(self):
        """Ein Retry-After von 0 lädt zum sofortigen Wiederholen ein."""
        from unittest import mock

        from portal import ratelimit

        grenze = ratelimit.Grenze("knapp", 1, 1)
        ratelimit.pruefe(grenze, "x")
        # Kurz vor Ablauf des Fensters: die Restzeit rundet sonst auf 0.
        with mock.patch.object(ratelimit, "_jetzt",
                               side_effect=lambda: ratelimit.time.monotonic() + 0.99):
            erlaubt, warten = ratelimit.pruefe(grenze, "x")
        self.assertFalse(erlaubt)
        self.assertGreaterEqual(warten, 1)

    def test_the_gui_check_button_is_throttled_too(self):
        """
        Ein Knopf lässt sich so oft drücken wie ein Endpunkt aufrufen.

        Die Grenze sass zuerst nur an der Schnittstelle; über die Oberfläche
        liess sich derselbe Tenant-Scan unbegrenzt auslösen.

        Eigene App statt der gemeinsamen: der Anwendungskontext dieser Klasse
        bleibt gepusht, und eine Anmeldung über den Testclient scheitert dann
        am CSRF-Schutz.
        """
        from unittest import mock

        from tests.support import csrf_token, sign_in_admin
        from tests.test_portal import build_app, fake_scan

        app, dbpfad = build_app()
        try:
            with app.app_context():
                from portal import crypto, ratelimit
                from portal.db import Session
                from portal.models import Customer, new_token

                ratelimit.zuruecksetzen()
                cfg = app.config["PORTAL"]
                kunde = Customer(key="ueberdiegui", display_name="Über die GUI",
                                 tenant_id=TENANT, client_id=CLIENT,
                                 auth_type="secret", prtg_token=new_token())
                kunde.client_secret_enc = crypto.encrypt(
                    "s", cfg.encryption_key,
                    crypto.aad_for("customer", kunde.key, "client_secret_enc"))
                Session.add(kunde)
                Session.commit()
                kunde_id = kunde.id

            browser = app.test_client()
            sign_in_admin(browser)
            with mock.patch("portal.scanner.graph.scan_tenant", side_effect=fake_scan):
                for _ in range(cfg.api_check_per_hour + 1):
                    letzte = browser.post(
                        "/kunden/%d/pruefen" % kunde_id,
                        data={"csrf_token": csrf_token(browser, "/")},
                        follow_redirects=True)
            self.assertIn("zu viele Prüfungen", letzte.get_data(as_text=True))
        finally:
            try:
                os.unlink(dbpfad)
            except OSError:
                pass


@needs_portal
class DiagnoseTests(unittest.TestCase):
    """
    Die lesbaren Befunde und der Endpunkt, der nur die Auffälligen liefert.

    Anlass war, dass die Schnittstelle bei einem Fehler nur den Rohtext von
    Microsoft herausgab. `AADSTS7000215` sagt einem anbindenden System nichts
    und einem Techniker erst nach dem Nachschlagen.
    """

    @classmethod
    def setUpClass(cls):
        from tests.test_portal import build_app

        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        cls.context = cls.app.app_context()
        cls.context.push()

        from portal import security
        from portal.db import Session
        from portal.models import API_SCOPE_WRITE, ApiKey, new_api_key

        roh, praefix = new_api_key()
        Session.add(ApiKey(name="diag", prefix=praefix, scope=API_SCOPE_WRITE,
                           key_hash=security.hash_password(roh), created_by="test"))
        Session.commit()
        cls.kopf = {"Authorization": "Bearer " + roh}

    @classmethod
    def tearDownClass(cls):
        cls.context.pop()
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def setUp(self):
        from portal import ratelimit
        from portal.db import Session
        from portal.models import Customer

        for kunde in Session.query(Customer).all():
            Session.delete(kunde)
        Session.commit()
        ratelimit.zuruecksetzen()

    # ------------------------------------------------------------------
    # Hilfen
    # ------------------------------------------------------------------

    def _kunde(self, key="musterag", **felder):
        """Create a customer through the API and return the stored model."""
        self.client.post("/api/v1/customers", headers=self.kopf, json=anlage(key=key))
        from portal.db import Session
        from portal.models import Customer

        kunde = Session.query(Customer).filter_by(key=key).one()
        for name, wert in felder.items():
            setattr(kunde, name, wert)
        Session.commit()
        return kunde

    def _credential(self, kunde, tage, app_name="SVC-Backup", cred_name="prod"):
        """
        Attach one stored credential and refresh the customer summary.

        Die Zusammenfassung am Kunden gehoert dazu, weil im Betrieb run_check
        beides in einem Zug schreibt. Ohne sie stuende min_days auf None, und
        der Zustand waere "unknown" statt dessen, was der Test meint.
        """
        from datetime import timedelta

        from portal.db import Session
        from portal.models import CredentialSnapshot, utcnow

        Session.add(CredentialSnapshot(
            customer_id=kunde.id, app_name=app_name, app_id="a", object_type="application",
            cred_type="secret", cred_name=cred_name, key_id="k",
            end_date=utcnow() + timedelta(days=tage, hours=6), days_left=tage))
        Session.flush()

        alle = Session.query(CredentialSnapshot).filter_by(customer_id=kunde.id).all()
        kunde.count_total = len(alle)
        kunde.min_days = min(c.days_left for c in alle)
        kunde.count_expired = sum(1 for c in alle if c.days_left < 0)
        kunde.count_critical = sum(1 for c in alle
                                   if 0 <= c.days_left < kunde.error_days)
        Session.commit()

    def _befunde(self, key="musterag"):
        """The findings of one customer, as the API renders them."""
        antwort = self.client.get("/api/v1/customers/" + key, headers=self.kopf)
        self.assertEqual(200, antwort.status_code)
        return antwort.get_json()

    # ------------------------------------------------------------------
    # Übersetzung der Microsoft-Fehler
    # ------------------------------------------------------------------

    def test_a_known_entra_code_becomes_a_sentence_and_a_next_step(self):
        """
        Der eigentliche Zweck: aus AADSTS7000215 wird ein Satz.

        Der Rohtext bleibt erhalten, weil er bei einer Rückfrage an Microsoft
        gebraucht wird.
        """
        from portal.models import utcnow

        self._kunde(last_status="error", last_check_at=utcnow(),
                    last_error="GraphError: Token-Endpoint HTTP 401: {\"error\":"
                               "\"invalid_client\",\"error_description\":\"AADSTS7000215: "
                               "Invalid client secret provided.\"}")
        daten = self._befunde()
        befund = next(b for b in daten["problems"] if b["code"] == "scan_failed")
        self.assertEqual("AADSTS7000215", befund["entra_code"])
        self.assertIn("Client Secret", befund["message"])
        self.assertIn("neues Secret", befund["action"])
        self.assertIn("AADSTS7000215", befund["detail"])

    def test_every_known_entra_code_is_translated(self):
        """Jede Kennung in der Tabelle muss auch greifen."""
        from portal.diagnose import AADSTS
        from portal.models import utcnow

        for kennung in AADSTS:
            with self.subTest(kennung=kennung):
                self._kunde(key="k" + kennung.lower(), last_status="error",
                            last_check_at=utcnow(),
                            last_error="Token-Endpoint HTTP 401: %s: irgendwas" % kennung)
                daten = self._befunde("k" + kennung.lower())
                befund = next(b for b in daten["problems"] if b["code"] == "scan_failed")
                self.assertEqual(kennung, befund["entra_code"])
                self.assertTrue(befund["action"])

    def test_an_unknown_error_still_yields_a_finding(self):
        """
        Ein Fehler ohne Kennung darf nicht stillschweigend verschwinden.

        Dann eben ohne Übersetzung, aber mit dem Rohtext im Feld detail.
        """
        from portal.models import utcnow

        self._kunde(last_status="error", last_check_at=utcnow(),
                    last_error="ValueError: irgendetwas ganz Neues")
        befund = next(b for b in self._befunde()["problems"] if b["code"] == "scan_failed")
        self.assertIn("fehlgeschlagen", befund["message"])
        self.assertIn("ganz Neues", befund["detail"])

    def test_a_network_failure_names_the_ports(self):
        """Der häufigste Fall beim ersten Aufsetzen: die Firewall."""
        from portal.models import utcnow

        self._kunde(last_status="error", last_check_at=utcnow(),
                    last_error="GraphError: Token-Endpoint nicht erreichbar: timed out")
        befund = next(b for b in self._befunde()["problems"] if b["code"] == "scan_failed")
        self.assertIn("443", befund["action"])

    def test_a_wrong_encryption_key_is_named_as_such(self):
        """
        Sonst sucht jemand den Fehler beim Kunden statt in der Umgebung.

        Ein gewechselter PORTAL_ENCRYPTION_KEY macht jedes gespeicherte
        Zugangsdatum unlesbar, und die Meldung sagt das auch.
        """
        from portal.models import utcnow

        self._kunde(last_status="error", last_check_at=utcnow(),
                    last_error="CryptoError: InvalidTag")
        befund = next(b for b in self._befunde()["problems"] if b["code"] == "scan_failed")
        self.assertIn("PORTAL_ENCRYPTION_KEY", befund["action"])

    # ------------------------------------------------------------------
    # Befunde aus den Zahlen
    # ------------------------------------------------------------------

    def test_a_single_expired_credential_is_named_in_the_singular(self):
        """
        "1 Zugangsdaten sind abgelaufen" wäre falsches Deutsch.

        Bei einem einzelnen Eintrag steht der Name im Satz, bei mehreren die
        Anzahl mit der Aufzählung dahinter.
        """
        from portal.models import utcnow

        kunde = self._kunde(last_status="ok", last_check_at=utcnow())
        self._credential(kunde, -12, "SVC-Backup", "prod")
        befund = next(b for b in self._befunde()["problems"]
                      if b["code"] == "credential_expired")
        self.assertEqual("SVC-Backup (prod) ist bereits abgelaufen.", befund["message"])
        self.assertEqual(1, befund["count"])

    def test_several_expired_credentials_are_counted_and_listed(self):
        """Bei mehreren zählt der Satz und nennt sie danach."""
        from portal.models import utcnow

        kunde = self._kunde(last_status="ok", last_check_at=utcnow())
        self._credential(kunde, -12, "SVC-Backup", "prod")
        self._credential(kunde, -3, "APP-Lohn", "cred-2")
        befund = next(b for b in self._befunde()["problems"]
                      if b["code"] == "credential_expired")
        self.assertIn("2 Zugangsdaten sind bereits abgelaufen", befund["message"])
        self.assertEqual(["APP-Lohn (cred-2)", "SVC-Backup (prod)"], befund["applications"])

    def test_the_thresholds_of_the_customer_decide_the_severity(self):
        """Kritisch und Warnung richten sich nach den Werten des Kunden, nicht nach festen."""
        from portal.models import utcnow

        kunde = self._kunde(last_status="ok", last_check_at=utcnow(),
                            warn_days=30, error_days=14)
        self._credential(kunde, 5, "APP-Kritisch", "a")
        self._credential(kunde, 20, "APP-Warnung", "b")
        self._credential(kunde, 200, "APP-Ruhig", "c")
        codes = {b["code"]: b for b in self._befunde()["problems"]}
        self.assertIn("APP-Kritisch", codes["credential_critical"]["message"])
        self.assertIn("APP-Warnung", codes["credential_warning"]["message"])
        self.assertEqual("warn", codes["credential_warning"]["severity"])
        self.assertNotIn("APP-Ruhig", str(codes))

    def test_stale_data_is_a_finding_of_its_own(self):
        """
        Alte Zahlen sind kein grüner Zustand.

        Der Sensor bekäme sonst weiterhin die letzten Werte, und niemand merkt,
        dass der Scheduler steht.
        """
        from datetime import timedelta

        from portal.models import utcnow

        self._kunde(last_status="ok", last_check_at=utcnow() - timedelta(hours=100))
        befund = next(b for b in self._befunde()["problems"] if b["code"] == "data_stale")
        self.assertEqual("error", befund["severity"])
        self.assertGreaterEqual(befund["age_hours"], 99)

    def test_a_customer_never_checked_says_so(self):
        """Kein Fehler, aber auch keine Aussage."""
        self._kunde()
        codes = [b["code"] for b in self._befunde()["problems"]]
        self.assertIn("never_checked", codes)

    def test_an_inactive_customer_reports_only_that(self):
        """
        Bei abgeschalteter Überwachung sind die alten Zahlen bedeutungslos.

        Sonst meldete ein pausierter Kunde jahrelang abgelaufene Secrets.
        """
        from datetime import timedelta

        from portal.models import utcnow

        kunde = self._kunde(is_active=False, last_status="ok",
                            last_check_at=utcnow() - timedelta(hours=500))
        self._credential(kunde, -300)
        befunde = self._befunde()["problems"]
        self.assertEqual(["inactive"], [b["code"] for b in befunde])
        self.assertEqual("inactive", self._befunde()["state"])

    def test_a_stored_certificate_date_survives_a_reload(self):
        """
        SQLite gibt Datumswerte ohne Zeitzone zurück, sobald neu geladen wird.

        Der Test daneben hielt das Objekt in der Sitzung und sah deshalb nie
        den Wert, wie er aus der Datenbank kommt. Ohne die Umrechnung stürzte
        jede Kundenliste ab, bei der ein Kunde ein Zertifikat hinterlegt hat.
        """
        from datetime import timedelta

        from portal.db import Session
        from portal.models import utcnow

        kunde = self._kunde(last_status="ok", last_check_at=utcnow())
        kunde.cert_not_after = utcnow() + timedelta(days=10, hours=6)
        Session.commit()
        Session.remove()                       # erzwingt echtes Neuladen

        for pfad in ("/api/v1/customers", "/api/v1/problems",
                     "/api/v1/customers/musterag"):
            with self.subTest(pfad=pfad):
                self.assertEqual(200, self.client.get(pfad, headers=self.kopf).status_code)

    def test_a_longer_code_is_not_mistaken_for_a_known_one(self):
        """
        "AADSTS70002150" enthält "AADSTS7000215" und bekäme sonst dessen Text.

        Ein falscher Rat schickt jemanden in die falsche Richtung und kostet
        mehr als gar kein Rat.
        """
        from portal.models import utcnow

        self._kunde(last_status="error", last_check_at=utcnow(),
                    last_error="Token-Endpoint HTTP 401: AADSTS70002150: etwas anderes")
        befund = next(b for b in self._befunde()["problems"] if b["code"] == "scan_failed")
        self.assertNotIn("entra_code", befund)
        self.assertIn("fehlgeschlagen", befund["message"])

    def test_the_expiry_finding_does_not_claim_an_outage(self):
        """
        Ob etwas ausgefallen ist, sagt der gespeicherte Stand nicht.

        Die Anwendung kann bereits ein zweites, gültiges Zugangsdatum
        verwenden. Der Text sagt deshalb, was zu prüfen ist, statt zu behaupten.
        """
        from portal.models import utcnow

        kunde = self._kunde(last_status="ok", last_check_at=utcnow())
        self._credential(kunde, -12)
        befund = next(b for b in self._befunde()["problems"]
                      if b["code"] == "credential_expired")
        self.assertNotIn("funktioniert bereits nicht mehr", befund["action"])
        self.assertIn("prüfen", befund["action"])

    def test_an_expiring_own_certificate_is_a_finding(self):
        """
        Läuft das Zertifikat des Portals ab, endet die Überwachung leise.

        Der Kunde wird dabei nicht rot, weil seine eigenen Zugangsdaten in
        Ordnung sind. Deshalb ein eigener Befund.
        """
        from datetime import timedelta

        from portal.models import utcnow

        kunde = self._kunde(last_status="ok", last_check_at=utcnow())
        kunde.cert_not_after = utcnow() + timedelta(days=10, hours=6)
        from portal.db import Session
        Session.commit()
        befund = next(b for b in self._befunde()["problems"]
                      if b["code"] == "own_certificate_expiring")
        self.assertEqual(10, befund["days_left"])

    def test_a_customer_without_a_credential_cannot_be_checked(self):
        """Ohne Zugangsdatum läuft kein Scan, das gehört gesagt."""
        from portal.db import Session

        kunde = self._kunde()
        kunde.client_secret_enc = ""
        Session.commit()
        codes = [b["code"] for b in self._befunde()["problems"]]
        self.assertIn("no_credential", codes)

    def test_a_healthy_customer_has_no_findings(self):
        """Der Normalfall muss leer sein, sonst ist die Liste wertlos."""
        from portal.models import utcnow

        kunde = self._kunde(last_status="ok", last_check_at=utcnow())
        self._credential(kunde, 200)
        daten = self._befunde()
        self.assertEqual([], daten["problems"])
        self.assertEqual("ok", daten["state"])

    def test_findings_are_ordered_by_severity(self):
        """Der erste Eintrag muss der sein, den jemand zuerst ansehen sollte."""
        from portal.models import utcnow

        kunde = self._kunde(last_status="ok", last_check_at=utcnow())
        self._credential(kunde, 20, "APP-Warnung", "a")
        self._credential(kunde, -5, "APP-Abgelaufen", "b")
        schweren = [b["severity"] for b in self._befunde()["problems"]]
        self.assertEqual(sorted(schweren, key=lambda s: {"error": 0, "warn": 1}[s]), schweren)

    # ------------------------------------------------------------------
    # Der Endpunkt
    # ------------------------------------------------------------------

    def test_the_problem_list_holds_only_customers_that_need_attention(self):
        """Der Zweck: nicht alle durchgehen und selbst bewerten müssen."""
        from portal.models import utcnow

        gesund = self._kunde("gesund", last_status="ok", last_check_at=utcnow())
        self._credential(gesund, 300)
        krank = self._kunde("krank", last_status="ok", last_check_at=utcnow())
        self._credential(krank, -5)

        daten = self.client.get("/api/v1/problems", headers=self.kopf).get_json()
        self.assertEqual(1, daten["count"])
        self.assertEqual(2, daten["checked_customers"])
        self.assertEqual("krank", daten["customers"][0]["key"])
        self.assertIn("urls", daten["customers"][0])

    def test_the_problem_list_puts_the_worst_first(self):
        """Sortiert nach Zustand, dann nach kürzester Restlaufzeit."""
        from portal.models import utcnow

        for key, tage in (("mild", 20), ("schlimm", -30), ("mittel", 3)):
            kunde = self._kunde(key, last_status="ok", last_check_at=utcnow())
            self._credential(kunde, tage)
        daten = self.client.get("/api/v1/problems", headers=self.kopf).get_json()
        self.assertEqual(["schlimm", "mittel", "mild"],
                         [k["key"] for k in daten["customers"]])

    def test_the_problem_list_can_be_narrowed_to_errors(self):
        """Wer nur wissen will, was schon weh tut, filtert auf error."""
        from portal.models import utcnow

        warnend = self._kunde("warnend", last_status="ok", last_check_at=utcnow())
        self._credential(warnend, 20)
        schlimm = self._kunde("schlimm", last_status="ok", last_check_at=utcnow())
        self._credential(schlimm, -5)

        daten = self.client.get("/api/v1/problems?severity=error",
                                headers=self.kopf).get_json()
        self.assertEqual(["schlimm"], [k["key"] for k in daten["customers"]])

    def test_stale_data_outranks_a_mere_warning_in_the_list(self):
        """
        Sortiert wird nach der Schwere der Befunde, nicht nach dem Zustandswort.

        Über den Zustand lief es zuerst, und dabei landete ein Kunde mit
        veralteten Daten hinter einem mit einer blossen Warnung, weil "stale"
        in der Rangfolge fehlte.
        """
        from datetime import timedelta

        from portal.models import utcnow

        warnend = self._kunde("warnend", last_status="ok", last_check_at=utcnow())
        self._credential(warnend, 20)
        veraltet = self._kunde("veraltet", last_status="ok",
                               last_check_at=utcnow() - timedelta(hours=200))
        self._credential(veraltet, 300)

        daten = self.client.get("/api/v1/problems", headers=self.kopf).get_json()
        self.assertEqual(["veraltet", "warnend"], [k["key"] for k in daten["customers"]])

    def test_a_critical_finding_on_an_otherwise_healthy_customer_comes_first(self):
        """
        Ein ablaufendes eigenes Zertifikat macht den Kunden nicht rot.

        Der Zustand bleibt "ok", weil seine eigenen Zugangsdaten in Ordnung
        sind. Über den Zustand sortiert wäre er hinten gelandet.
        """
        from datetime import timedelta

        from portal.db import Session
        from portal.models import utcnow

        warnend = self._kunde("warnend", last_status="ok", last_check_at=utcnow())
        self._credential(warnend, 20)
        zert = self._kunde("zertifikat", last_status="ok", last_check_at=utcnow())
        self._credential(zert, 300)
        zert.cert_not_after = utcnow() - timedelta(days=5)
        Session.commit()

        daten = self.client.get("/api/v1/problems", headers=self.kopf).get_json()
        self.assertEqual("zertifikat", daten["customers"][0]["key"])

    def test_an_unknown_severity_is_refused(self):
        """Ein Tippfehler im Filter darf nicht stillschweigend alles liefern."""
        antwort = self.client.get("/api/v1/problems?severity=schlimm", headers=self.kopf)
        self.assertEqual(422, antwort.status_code)
        self.assertIn("severity", antwort.get_json()["error"]["fields"])

    def test_the_problem_list_is_readable_for_a_read_only_key(self):
        """Ein anbindendes System, das nur beobachtet, braucht keinen Schreibzugriff."""
        from portal import security
        from portal.db import Session
        from portal.models import API_SCOPE_READ, ApiKey, new_api_key

        roh, praefix = new_api_key()
        Session.add(ApiKey(name="nurlesen", prefix=praefix, scope=API_SCOPE_READ,
                           key_hash=security.hash_password(roh), created_by="test"))
        Session.commit()
        antwort = self.client.get("/api/v1/problems",
                                  headers={"Authorization": "Bearer " + roh})
        self.assertEqual(200, antwort.status_code)

    def test_no_finding_leaks_a_credential(self):
        """
        Die Zusage gilt auch hier.

        Ein Befund nennt Anwendungsnamen und Restlaufzeiten, nie einen Wert.
        """
        from portal.models import utcnow

        kunde = self._kunde(last_status="error", last_check_at=utcnow(),
                            last_error="GraphError: irgendwas")
        self._credential(kunde, -5)
        roh = json.dumps(self.client.get("/api/v1/problems",
                                         headers=self.kopf).get_json())
        self.assertNotIn(GEHEIM, roh)
        self.assertNotIn("client_secret_enc", roh)


@needs_portal
class LeistungTests(unittest.TestCase):
    """
    Zwei Eigenschaften, die sich leise wieder verschlechtern.

    Gemessen bei 50 Kunden mit je 20 Zugangsdaten: die Kundenliste brauchte
    53 Abfragen und 57 ms, ein einzelner Kunde 49 ms. Die 49 ms waren fast
    vollständig Argon2 auf dem API-Schlüssel.
    """

    @classmethod
    def setUpClass(cls):
        from tests.test_portal import build_app

        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        cls.context = cls.app.app_context()
        cls.context.push()

    @classmethod
    def tearDownClass(cls):
        cls.context.pop()
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def setUp(self):
        from portal import ratelimit
        from portal.db import Session
        from portal.models import ApiKey, Customer

        for modell in (Customer, ApiKey):
            for zeile in Session.query(modell).all():
                Session.delete(zeile)
        Session.commit()
        ratelimit.zuruecksetzen()

    def _schluessel(self, hasher=None):
        """Issue one API key, optionally with the old slow hash."""
        from portal import security
        from portal.db import Session
        from portal.models import API_SCOPE_WRITE, ApiKey, new_api_key

        roh, praefix = new_api_key()
        hasher = hasher or security.hash_api_key
        Session.add(ApiKey(name="k" + praefix, prefix=praefix, scope=API_SCOPE_WRITE,
                           key_hash=hasher(roh), created_by="test"))
        Session.commit()
        return roh

    def _kunden(self, anzahl, credentials_je_kunde=5):
        """Create customers with stored credentials, without going through Graph."""
        from datetime import timedelta

        from portal import crypto
        from portal.db import Session
        from portal.models import CredentialSnapshot, Customer, new_token, utcnow

        cfg = self.app.config["PORTAL"]
        jetzt = utcnow()
        for i in range(anzahl):
            kunde = Customer(
                key="kunde%03d" % i, display_name="Kunde %03d" % i,
                tenant_id="%08d-0001-4000-8000-%012d" % (i, i),
                client_id="%08d-0002-4000-8000-%012d" % (i, i),
                auth_type="secret", prtg_token=new_token(),
                last_status="ok", last_check_at=jetzt - timedelta(hours=1))
            kunde.client_secret_enc = crypto.encrypt(
                "s", cfg.encryption_key,
                crypto.aad_for("customer", kunde.key, "client_secret_enc"))
            Session.add(kunde)
            Session.flush()
            tage = [(j * 37 + i) % 300 - 10 for j in range(credentials_je_kunde)]
            for j, rest in enumerate(tage):
                Session.add(CredentialSnapshot(
                    customer_id=kunde.id, app_name="APP-%02d" % j, app_id="a",
                    object_type="application", cred_type="secret", cred_name="c%d" % j,
                    key_id="k%d" % j, end_date=jetzt + timedelta(days=rest, hours=6),
                    days_left=rest))
            kunde.count_total = len(tage)
            kunde.min_days = min(tage)
            kunde.count_expired = sum(1 for t in tage if t < 0)
        Session.commit()

    def _zaehle_abfragen(self, pfad, kopf):
        """Count the SQL statements one request produces."""
        from sqlalchemy import event

        import portal.db as db

        zaehler = {"n": 0}

        def mitzaehlen(*args, **kwargs):
            zaehler["n"] += 1

        event.listen(db._engine, "before_cursor_execute", mitzaehlen)   # noqa: SLF001
        try:
            self.client.get(pfad, headers=kopf)                          # aufwaermen
            zaehler["n"] = 0
            antwort = self.client.get(pfad, headers=kopf)
        finally:
            event.remove(db._engine, "before_cursor_execute", mitzaehlen)  # noqa: SLF001
        self.assertEqual(200, antwort.status_code)
        return zaehler["n"], antwort.get_json()

    # ------------------------------------------------------------------

    def test_the_customer_list_does_not_query_once_per_customer(self):
        """
        Die Zahl der Abfragen darf nicht mit der Kundenzahl wachsen.

        Vorher: 53 Abfragen bei 50 Kunden, weil jeder Kunde seine Zugangsdaten
        einzeln nachlud. Der Test vergleicht zwei Grössen statt einer festen
        Zahl, damit er nicht bei jeder harmlosen Änderung anschlägt.
        """
        kopf = {"Authorization": "Bearer " + self._schluessel()}

        self._kunden(3)
        wenige, _ = self._zaehle_abfragen("/api/v1/customers", kopf)
        self.setUp()
        kopf = {"Authorization": "Bearer " + self._schluessel()}
        self._kunden(30)
        viele, daten = self._zaehle_abfragen("/api/v1/customers", kopf)

        self.assertEqual(30, daten["count"])
        self.assertEqual(wenige, viele,
                         "3 Kunden brauchten %d Abfragen, 30 Kunden %d"
                         % (wenige, viele))

    def test_the_problem_list_does_not_query_once_per_customer(self):
        """Dasselbe für den Endpunkt, der die Befunde sammelt."""
        kopf = {"Authorization": "Bearer " + self._schluessel()}

        self._kunden(3)
        wenige, _ = self._zaehle_abfragen("/api/v1/problems", kopf)
        self.setUp()
        kopf = {"Authorization": "Bearer " + self._schluessel()}
        self._kunden(30)
        viele, _ = self._zaehle_abfragen("/api/v1/problems", kopf)

        self.assertEqual(wenige, viele,
                         "3 Kunden brauchten %d Abfragen, 30 Kunden %d"
                         % (wenige, viele))

    def test_the_list_still_returns_the_credentials_of_the_right_customer(self):
        """
        Eine Sammelabfrage kann Zeilen dem falschen Kunden zuordnen.

        Deshalb nicht nur zählen, sondern prüfen: jeder Kunde muss genau seine
        eigenen Zugangsdaten tragen.
        """
        kopf = {"Authorization": "Bearer " + self._schluessel()}
        self._kunden(5, credentials_je_kunde=4)

        _, liste = self._zaehle_abfragen("/api/v1/customers", kopf)
        for eintrag in liste["customers"]:
            einzeln = self.client.get("/api/v1/customers/" + eintrag["key"],
                                      headers=kopf).get_json()
            self.assertEqual(eintrag["summary"], einzeln["summary"], eintrag["key"])
            self.assertEqual(eintrag["problems"], einzeln["problems"], eintrag["key"])
            self.assertEqual(4, len(einzeln["credentials"]))

    # ------------------------------------------------------------------

    def test_an_api_key_is_not_hashed_like_a_password(self):
        """
        Argon2 macht ein Passwort teuer, weil ein Mensch wenig Entropie wählt.

        Ein Schlüssel aus `secrets.token_urlsafe(32)` trägt 256 Bit. Die Kosten
        träfen nur den, der den Schlüssel richtig mitschickt: gemessen 45 ms je
        Anfrage.
        """
        from portal import security

        roh = "esm_deadbeef_" + "x" * 43
        gespeichert = security.hash_api_key(roh)
        self.assertTrue(gespeichert.startswith("sha256$"))
        self.assertNotIn(roh, gespeichert)
        self.assertTrue(security.verify_api_key(gespeichert, roh))
        self.assertFalse(security.verify_api_key(gespeichert, roh + "x"))
        self.assertFalse(security.verify_api_key("", roh))

    def test_a_key_from_before_the_change_still_works(self):
        """Ein Neuausstellen aller Schlüssel wäre der Preis gewesen."""
        from portal import security

        roh = self._schluessel(hasher=security.hash_password)
        antwort = self.client.get("/api/v1/customers",
                                  headers={"Authorization": "Bearer " + roh})
        self.assertEqual(200, antwort.status_code)

    def test_an_old_key_is_upgraded_on_first_use(self):
        """
        Sonst zahlte ein bestehender Schlüssel die 45 ms für immer weiter.

        Umgestellt wird erst nach erfolgreicher Prüfung, ein Fehlversuch darf
        nichts schreiben.
        """
        from portal import security
        from portal.db import Session
        from portal.models import ApiKey

        roh = self._schluessel(hasher=security.hash_password)
        eintrag = Session.query(ApiKey).one()
        self.assertTrue(security.api_key_needs_upgrade(eintrag.key_hash))

        self.client.get("/api/v1/customers",
                        headers={"Authorization": "Bearer " + roh})
        Session.expire_all()
        eintrag = Session.query(ApiKey).one()
        self.assertFalse(security.api_key_needs_upgrade(eintrag.key_hash))
        self.assertTrue(security.verify_api_key(eintrag.key_hash, roh))

    def test_a_failed_attempt_does_not_upgrade_anything(self):
        """Ein falscher Schlüssel darf den gespeicherten Hash nicht anfassen."""
        from portal import security
        from portal.db import Session
        from portal.models import ApiKey

        roh = self._schluessel(hasher=security.hash_password)
        vorher = Session.query(ApiKey).one().key_hash
        praefix = roh.split("_")[1]
        self.client.get("/api/v1/customers", headers={
            "Authorization": "Bearer esm_%s_%s" % (praefix, "y" * 43)})
        Session.expire_all()
        self.assertEqual(vorher, Session.query(ApiKey).one().key_hash)

    def test_passwords_keep_the_slow_hash(self):
        """
        Die Umstellung gilt nur für Schlüssel.

        Ein Passwort hat wenig Entropie, dort ist der Aufwand der Sinn der
        Sache.
        """
        from portal import security

        gespeichert = security.hash_password("Zaun#Kies7Vogel!Lampe")
        self.assertTrue(gespeichert.startswith("$argon2"))
        self.assertTrue(security.verify_password(gespeichert, "Zaun#Kies7Vogel!Lampe"))
