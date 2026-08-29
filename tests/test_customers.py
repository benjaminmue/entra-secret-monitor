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

from .support import needs_portal

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

    def test_certificate_half_a_pair_is_refused(self):
        self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf_for(self.client, "/kunden/neu"),
            "key": "halbzert", "display_name": "Halb", "tenant_id": TENANT_GUID,
            "client_id": CLIENT_GUID, "auth_type": "cert",
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


if __name__ == "__main__":
    unittest.main()
