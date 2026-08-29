"""
Tests for portal/views/customers.py and portal/scheduler.py.

The customer blueprint holds the monitored tenants and their credentials, so its
promises are that secrets are stored encrypted and never rendered back, that a
viewer cannot change anything, that only an administrator deletes, and that a
rotated PRTG token really invalidates the previous sensor URL.
"""
import os
import re
import unittest

from .support import make_certificate, needs_portal

try:
    import pyotp
except ImportError:
    pyotp = None

from tests.test_portal import BOOTSTRAP_PASSWORD, NEW_PASSWORD, build_app

TENANT_GUID = "11111111-2222-3333-4444-555555555555"
CLIENT_GUID = "66666666-7777-8888-9999-000000000000"
SECRET = "streng-geheimes-client-secret-4711"


@needs_portal
class CustomerAdministrationTests(unittest.TestCase):
    """One signed in administrator, one customer, exercised through the forms."""

    @classmethod
    def setUpClass(cls):
        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        cls._sign_in(cls.client)

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    @classmethod
    def _csrf_for(cls, client, path):
        body = client.get(path).get_data(as_text=True)
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', body)
        assert match, "kein CSRF-Token auf %s" % path
        return match.group(1)

    @classmethod
    def _sign_in(cls, client):
        client.post("/login", data={"csrf_token": cls._csrf_for(client, "/login"),
                                    "username": "admin",
                                    "password": BOOTSTRAP_PASSWORD})
        token = cls._csrf_for(client, "/login/2fa/setup")
        with client.session_transaction() as session:
            secret = session["totp_setup_secret"]
        client.post("/login/2fa/setup", data={"csrf_token": token,
                                              "code": pyotp.TOTP(secret).now()})
        client.post("/account/password", data={
            "csrf_token": cls._csrf_for(client, "/account/password"),
            "current_password": BOOTSTRAP_PASSWORD,
            "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})

    def _create(self, key, secret=SECRET):
        """Create one customer through the form and return the stored model."""
        self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf_for(self.client, "/kunden/neu"),
            "key": key, "display_name": key.title(), "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "secret",
            "client_secret": secret, "warn_days": 30, "error_days": 14,
            "max_channels": 45, "is_active": "y"})
        return self._reload(key)

    @staticmethod
    def _reload(key):
        from portal.db import Session
        from portal.models import Customer
        return Session.query(Customer).filter(Customer.key == key).one_or_none()

    # -- credential storage ------------------------------------------------

    def test_client_secret_is_stored_encrypted(self):
        customer = self._create("kryptokunde")
        self.assertIsNotNone(customer, "Kunde wurde nicht angelegt")
        self.assertTrue(customer.client_secret_enc)
        self.assertNotIn(SECRET, customer.client_secret_enc)

    def test_stored_secret_decrypts_with_the_record_bound_associated_data(self):
        from portal import crypto

        customer = self._create("aadkunde")
        key = self.app.config["PORTAL"].encryption_key
        self.assertEqual(SECRET, crypto.decrypt(
            customer.client_secret_enc, key,
            crypto.aad_for("customer", customer.key, "client_secret_enc")))

    def test_secret_is_never_rendered_back_into_the_page(self):
        customer = self._create("anzeigekunde")
        for path in ("/kunden/%d" % customer.id,
                     "/kunden/%d/bearbeiten" % customer.id):
            body = self.client.get(path).get_data(as_text=True)
            self.assertNotIn(SECRET, body, path)

    def test_editing_without_a_secret_keeps_the_stored_one(self):
        # Otherwise changing a threshold would force handling the secret again.
        customer = self._create("behaltkunde")
        stored = customer.client_secret_enc
        self.client.post("/kunden/%d/bearbeiten" % customer.id, data={
            "csrf_token": self._csrf_for(self.client,
                                         "/kunden/%d/bearbeiten" % customer.id),
            "key": "behaltkunde", "display_name": "Neuer Name",
            "tenant_id": TENANT_GUID, "client_id": CLIENT_GUID,
            "auth_type": "secret", "client_secret": "",
            "warn_days": 60, "error_days": 14, "max_channels": 45, "is_active": "y"})
        reloaded = self._reload("behaltkunde")
        self.assertEqual(stored, reloaded.client_secret_enc)
        self.assertEqual(60, reloaded.warn_days)

    def test_new_customer_without_a_credential_is_refused(self):
        self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf_for(self.client, "/kunden/neu"),
            "key": "ohnegeheimnis", "display_name": "Ohne", "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "secret", "client_secret": "",
            "warn_days": 30, "error_days": 14, "max_channels": 45, "is_active": "y"})
        self.assertIsNone(self._reload("ohnegeheimnis"))

    def test_a_certificate_pair_is_stored_with_key_encrypted(self):
        cert_pem, key_pem = make_certificate()
        self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf_for(self.client, "/kunden/neu"),
            "key": "zertkunde", "display_name": "Zert", "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "certificate",
            "cert_pem": cert_pem, "key_pem": key_pem,
            "warn_days": 30, "error_days": 14, "max_channels": 45, "is_active": "y"})
        customer = self._reload("zertkunde")
        self.assertIsNotNone(customer, "Zertifikatskunde wurde nicht angelegt")
        # The certificate is public and stored as is; the private key is not.
        self.assertIn("BEGIN CERTIFICATE", customer.cert_pem)
        self.assertNotIn("PRIVATE KEY", customer.key_pem_enc)
        self.assertTrue(customer.cert_thumbprint)
        self.assertIsNotNone(customer.cert_not_after)

    def test_the_stored_private_key_decrypts_back(self):
        from portal import crypto

        cert_pem, key_pem = make_certificate()
        self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf_for(self.client, "/kunden/neu"),
            "key": "zertrueck", "display_name": "Zert", "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "certificate",
            "cert_pem": cert_pem, "key_pem": key_pem,
            "warn_days": 30, "error_days": 14, "max_channels": 45, "is_active": "y"})
        customer = self._reload("zertrueck")
        restored = crypto.decrypt(
            customer.key_pem_enc, self.app.config["PORTAL"].encryption_key,
            crypto.aad_for("customer", customer.key, "key_pem_enc"))
        # Beim Speichern wird getrimmt, der Inhalt muss aber gleich sein.
        self.assertEqual(key_pem.strip(), restored.strip())

    def test_a_mismatched_pair_is_refused(self):
        # Otherwise the mistake only surfaces as a Graph error hours later.
        from cryptography.hazmat.primitives.asymmetric import rsa

        cert_pem, _ = make_certificate(key=rsa.generate_private_key(
            public_exponent=65537, key_size=2048))
        _, other_key = make_certificate()
        self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf_for(self.client, "/kunden/neu"),
            "key": "falschespaar", "display_name": "Falsch", "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "certificate",
            "cert_pem": cert_pem, "key_pem": other_key,
            "warn_days": 30, "error_days": 14, "max_channels": 45, "is_active": "y"})
        self.assertIsNone(self._reload("falschespaar"))

    def test_switching_to_a_secret_clears_the_certificate(self):
        cert_pem, key_pem = make_certificate()
        self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf_for(self.client, "/kunden/neu"),
            "key": "wechselkunde", "display_name": "Wechsel", "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "certificate",
            "cert_pem": cert_pem, "key_pem": key_pem,
            "warn_days": 30, "error_days": 14, "max_channels": 45, "is_active": "y"})
        customer = self._reload("wechselkunde")
        self.client.post("/kunden/%d/bearbeiten" % customer.id, data={
            "csrf_token": self._csrf_for(self.client,
                                         "/kunden/%d/bearbeiten" % customer.id),
            "key": "wechselkunde", "display_name": "Wechsel", "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "secret", "client_secret": SECRET,
            "warn_days": 30, "error_days": 14, "max_channels": 45, "is_active": "y"})
        reloaded = self._reload("wechselkunde")
        self.assertTrue(reloaded.client_secret_enc)
        self.assertEqual("", reloaded.cert_pem, "das alte Zertifikat blieb stehen")
        self.assertEqual("", reloaded.key_pem_enc)

    def test_certificate_half_a_pair_is_refused(self):
        self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf_for(self.client, "/kunden/neu"),
            "key": "halbzert", "display_name": "Halb", "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "certificate",
            "cert_pem": "-----BEGIN CERTIFICATE-----", "key_pem": "",
            "warn_days": 30, "error_days": 14, "max_channels": 45, "is_active": "y"})
        self.assertIsNone(self._reload("halbzert"))

    # -- PRTG token --------------------------------------------------------

    def _sensor(self, token):
        """
        Fetch a sensor document and report whether it is an error document.

        The route answers 200 even for a rejected token, deliberately: PRTG
        evaluates <error> and would otherwise fail on a parse error instead of
        turning the sensor red. The status code therefore says nothing here.
        """
        body = self.client.get("/prtg/%s" % token).get_data(as_text=True)
        return "<error>1</error>" in body

    def test_rotating_the_token_invalidates_the_previous_sensor_url(self):
        self._create("rotationskunde")
        stored = self._reload("rotationskunde")
        customer_id, old_token = stored.id, stored.prtg_token
        self.assertFalse(self._sensor(old_token), "der frische Sensor-Link antwortet nicht")

        self.client.post("/kunden/%d/token" % customer_id, data={
            "csrf_token": self._csrf_for(self.client, "/kunden/%d" % customer_id)})
        new_token = self._reload("rotationskunde").prtg_token
        self.assertNotEqual(old_token, new_token, "der Token wurde nicht gewechselt")
        self.assertTrue(self._sensor(old_token),
                        "die alte Sensor-URL liefert weiterhin Daten")
        self.assertFalse(self._sensor(new_token), "die neue Sensor-URL liefert nichts")

    def test_an_unknown_token_never_yields_data(self):
        self.assertTrue(self._sensor("voellig-erfundener-token-mit-genug-laenge"))
        self.assertTrue(self._sensor("kurz"))

    def test_rotation_without_a_csrf_token_is_refused(self):
        customer = self._create("csrfkunde")
        before = customer.prtg_token
        self.assertEqual(400,
                         self.client.post("/kunden/%d/token" % customer.id).status_code)
        self.assertEqual(before, self._reload("csrfkunde").prtg_token)

    # -- authorisation -----------------------------------------------------

    def test_a_viewer_cannot_change_anything(self):
        from portal.db import Session
        from portal.models import ROLE_VIEWER, User

        customer = self._create("leserkunde")
        token = self._csrf_for(self.client, "/kunden/%d" % customer.id)

        admin = Session.query(User).filter(User.username == "admin").one()
        admin.role = ROLE_VIEWER
        Session.commit()
        try:
            self.assertEqual(403, self.client.get("/kunden/neu").status_code)
            for route in ("token", "pruefen", "loeschen"):
                response = self.client.post("/kunden/%d/%s" % (customer.id, route),
                                            data={"csrf_token": token})
                self.assertEqual(403, response.status_code, route)
            # Reading stays allowed for a viewer.
            self.assertEqual(200, self.client.get("/kunden/%d" % customer.id).status_code)
        finally:
            restored = Session.query(User).filter(User.username == "admin").one()
            restored.role = "admin"
            Session.commit()

    def test_deletion_removes_the_customer(self):
        customer = self._create("wegkunde")
        self.client.post("/kunden/%d/loeschen" % customer.id, data={
            "csrf_token": self._csrf_for(self.client, "/kunden/%d" % customer.id)})
        self.assertIsNone(self._reload("wegkunde"))

    def test_unknown_customer_yields_404(self):
        self.assertEqual(404, self.client.get("/kunden/999999").status_code)

    def test_a_forced_check_runs_the_scan_and_reports_the_outcome(self):
        from unittest import mock

        from portal import scheduler

        customer = self._create("sofortkunde")
        with mock.patch.object(scheduler, "force_check",
                               return_value=("ok", "")) as forced:
            response = self.client.post("/kunden/%d/pruefen" % customer.id, data={
                "csrf_token": self._csrf_for(self.client, "/kunden/%d" % customer.id)})
        self.assertEqual(302, response.status_code)
        forced.assert_called_once()
        self.assertEqual(customer.id, forced.call_args[0][0])

    def test_a_blocked_forced_check_reports_instead_of_hanging(self):
        # force_check waits for the shared lock and gives up; the page has to
        # say so rather than presenting a silent failure.
        from unittest import mock

        from portal import scheduler

        customer = self._create("blockierterkunde")
        with mock.patch.object(scheduler, "force_check",
                               side_effect=TimeoutError("blockiert seit 120 s")):
            response = self.client.post("/kunden/%d/pruefen" % customer.id, data={
                "csrf_token": self._csrf_for(self.client, "/kunden/%d" % customer.id)},
                follow_redirects=True)
        self.assertIn("blockiert", response.get_data(as_text=True))

    def test_a_forced_check_needs_a_csrf_token(self):
        customer = self._create("csrfpruefkunde")
        self.assertEqual(400,
                         self.client.post("/kunden/%d/pruefen" % customer.id).status_code)

    def test_slots_can_be_redistributed_over_the_endpoint(self):
        self._create("verteilkunde1")
        self._create("verteilkunde2")
        response = self.client.post("/kunden/slots", data={
            "csrf_token": self._csrf_for(self.client, "/")}, follow_redirects=True)
        self.assertEqual(200, response.status_code)
        self.assertIn("verteilt", response.get_data(as_text=True))

    def test_redistribution_needs_a_csrf_token(self):
        self.assertEqual(400, self.client.post("/kunden/slots").status_code)


@needs_portal
class SchedulerTests(unittest.TestCase):
    """Slot handling decides when a tenant is scanned, and how evenly."""

    @classmethod
    def setUpClass(cls):
        cls.app, cls.db_path = build_app()

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def _customer(self, key, slot=None):
        from portal.db import Session
        from portal.models import Customer

        customer = Customer(key=key, display_name=key, tenant_id=TENANT_GUID,
                            client_id=CLIENT_GUID, auth_type="secret",
                            client_secret_enc="x", prtg_token=key + "-token")
        if slot is not None:
            customer.slot_minute = slot
        Session.add(customer)
        Session.commit()
        return customer

    def setUp(self):
        from portal.db import Session
        from portal.models import Customer

        Session.query(Customer).delete()
        Session.commit()

    def test_assigned_slots_stay_inside_a_day(self):
        from portal.db import Session
        from portal.scheduler import assign_slot

        for index in range(5):
            self._customer("kunde%d" % index)
            slot = assign_slot(Session)
            self.assertGreaterEqual(slot, 0)
            self.assertLess(slot, 24 * 60)

    def test_assigned_slots_do_not_collide(self):
        from portal.db import Session
        from portal.scheduler import assign_slot

        slots = []
        for index in range(6):
            slot = assign_slot(Session)
            self._customer("kunde%d" % index, slot=slot)
            slots.append(slot)
        self.assertEqual(len(slots), len(set(slots)))

    def test_redistribution_spreads_customers_over_the_day(self):
        from portal.db import Session
        from portal.models import Customer
        from portal.scheduler import redistribute_slots

        for index in range(4):
            self._customer("kunde%d" % index, slot=0)   # alle auf derselben Minute
        redistribute_slots(Session)
        slots = sorted(c.slot_minute for c in Session.query(Customer).all())
        self.assertEqual(len(slots), len(set(slots)), "Slots kollidieren weiterhin")
        self.assertGreater(max(slots) - min(slots), 60,
                           "Slots liegen weiterhin dicht beieinander")

    def test_status_reports_without_a_running_thread(self):
        from portal import scheduler

        state = scheduler.status()
        self.assertIsInstance(state, dict)
        self.assertIn("running", state)
        self.assertFalse(state["running"])

    def test_stop_is_harmless_when_nothing_runs(self):
        from portal import scheduler

        scheduler.stop()
        self.assertFalse(scheduler.status()["running"])

    def test_thread_starts_and_stops(self):
        from types import SimpleNamespace

        from portal import scheduler

        config = SimpleNamespace(encryption_key=b"\x00" * 32, tick_seconds=60,
                                 gap_seconds=1, history_runs=5)
        thread = scheduler.start(config)
        try:
            self.assertTrue(thread.is_alive())
            self.assertTrue(scheduler.status()["active"])
        finally:
            scheduler.stop()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "der Scheduler-Thread endet nicht")
        self.assertFalse(scheduler.status()["active"])

    def test_start_is_idempotent(self):
        from types import SimpleNamespace

        from portal import scheduler

        config = SimpleNamespace(encryption_key=b"\x00" * 32, tick_seconds=60,
                                 gap_seconds=1, history_runs=5)
        first = scheduler.start(config)
        try:
            # A second call must not spawn a competing thread against the same
            # tenants, it returns the running one.
            self.assertIs(first, scheduler.start(config))
        finally:
            scheduler.stop()
            first.join(timeout=5)

    def test_force_check_reports_an_unknown_customer(self):
        from portal import scheduler

        with self.assertRaises(LookupError):
            scheduler.force_check(999999, b"\x00" * 32, actor="test")

    def test_the_due_run_skips_customers_whose_slot_has_not_come(self):
        from unittest import mock

        from portal import scheduler

        self._customer("spaeter", slot=23 * 60 + 59)
        stop = mock.Mock(is_set=mock.Mock(return_value=False))
        with mock.patch.object(scheduler, "run_check") as ran:
            scheduler._run_due(b"\x00" * 32, 0, 5, stop)
        ran.assert_not_called()

    def test_the_due_run_stops_when_asked_to(self):
        # A shutdown must not wait for every remaining tenant.
        from unittest import mock

        from portal import scheduler

        for index in range(3):
            self._customer("kunde%d" % index, slot=0)
        stop = mock.Mock(is_set=mock.Mock(return_value=True))
        with mock.patch.object(scheduler, "run_check") as ran:
            scheduler._run_due(b"\x00" * 32, 0, 5, stop)
        ran.assert_not_called()

    def test_a_failing_scan_does_not_stop_the_others(self):
        from unittest import mock

        from portal import scheduler
        from portal.db import Session
        from portal.models import Customer

        for index in range(2):
            customer = self._customer("fehlerkunde%d" % index, slot=0)
            customer.last_check_at = None
            customer.is_active = True
        Session.commit()
        self.assertGreaterEqual(Session.query(Customer).count(), 2)

        stop = mock.Mock(is_set=mock.Mock(return_value=False))
        with mock.patch.object(scheduler, "run_check",
                               side_effect=RuntimeError("Graph weg")) as ran, \
             mock.patch("builtins.print") as printed:
            scheduler._run_due(b"\x00" * 32, 0, 5, stop)
        self.assertGreaterEqual(ran.call_count, 2, "der Lauf brach beim ersten Fehler ab")
        self.assertIn("abgebrochen", str(printed.call_args_list))

    def test_force_check_gives_up_when_a_run_holds_the_lock(self):
        # Queueing behind a scheduled run is intended; blocking forever is not.
        from portal import scheduler

        self.assertTrue(scheduler.SCAN_LOCK.acquire(timeout=5))
        try:
            with self.assertRaises(TimeoutError):
                scheduler.force_check(1, b"\x00" * 32, actor="test", wait_seconds=0)
        finally:
            scheduler.SCAN_LOCK.release()


if __name__ == "__main__":
    unittest.main()
