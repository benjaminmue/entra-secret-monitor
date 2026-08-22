#!/usr/bin/env python3
"""
test_portal.py

End to end tests of the portal without touching Microsoft Graph.

Covers the parts that must not regress silently: the password policy, the
encryption of stored credentials, the two step login with TOTP, the customer
lifecycle including the PRTG endpoint, the daily slot distribution, CSRF
protection and the behaviour on hostile input.

Run with:  python -m unittest discover -s tests
"""

import base64
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "app"))

import pyotp                                                            # noqa: E402

BOOTSTRAP_PASSWORD = "Start!Passwort2026x"
NEW_PASSWORD = "Zaun#Kies7Vogel!Lampe"


def build_app():
    """Create a portal app on a throwaway SQLite file with the scheduler off."""
    handle, path = tempfile.mkstemp(suffix=".db")
    os.close(handle)
    os.environ.update({
        "PORTAL_SECRET_KEY": "unit-test-key-unit-test-key",
        "PORTAL_ENCRYPTION_KEY": base64.b64encode(os.urandom(32)).decode(),
        "PORTAL_DATABASE_URL": "sqlite:///" + path.replace("\\", "/"),
        "PORTAL_SCHEDULER": "0",
        "PORTAL_COOKIE_SECURE": "0",
        "PORTAL_BOOTSTRAP_USER": "admin",
        "PORTAL_BOOTSTRAP_PASSWORD": BOOTSTRAP_PASSWORD,
    })
    import portal.db as db
    db._engine = None                                                   # noqa: SLF001
    db.Session.remove()
    from portal.factory import create_app
    return create_app(), path


FAKE_CHANNELS = [
    {"name": "SVC-Backup (Secret)", "app": "SVC-Backup", "days": 9,
     "expires": "2026-08-30", "cred_name": "prod", "app_id": "1111",
     "type": "secret", "object_type": "application", "count": 2},
    {"name": "SVC-Sync (Zertifikat)", "app": "SVC-Sync", "days": 400,
     "expires": "2027-09-25", "cred_name": "cert", "app_id": "2222",
     "type": "cert", "object_type": "application", "count": 1},
]


def fake_scan(cfg):
    """Stand in for graph.scan_tenant so no test ever calls Microsoft."""
    return {
        "tenant": cfg.key,
        "display_name": cfg.display_name,
        "warn_days": cfg.warn_days,
        "error_days": cfg.error_days,
        "checked": "2026-08-21 09:00:00 UTC",
        "summary": {"minimum": 9, "critical": 1, "expired": 0, "total": 2},
        "channels": FAKE_CHANNELS,
    }


class SecurityUnitTests(unittest.TestCase):
    """Password policy and credential encryption, without a running app."""

    def test_policy_rejects_weak_passwords(self):
        """Every rule of the policy must actually reject something."""
        from portal import security
        cases = ["kurz1!A", "alleklein123!", "ALLEGROSS123!", "KeineZiffer!Hier",
                 "KeinSonderzeichen1", "Passwort2026!Aaa", "AAAAaaaa1111!!!!"]
        for candidate in cases:
            with self.subTest(candidate=candidate):
                self.assertTrue(security.check_password_policy(candidate, 12, "admin", ""))

    def test_policy_accepts_a_strong_password(self):
        """A password with all four classes and no stem passes."""
        from portal import security
        self.assertEqual([], security.check_password_policy(NEW_PASSWORD, 12, "admin", ""))

    def test_generated_password_satisfies_the_policy(self):
        """suggest_password must never produce something the policy rejects."""
        from portal import security
        for _ in range(25):
            self.assertEqual([], security.check_password_policy(security.suggest_password(), 12))

    def test_password_hash_is_not_reversible(self):
        """The stored hash must not contain the password."""
        from portal import security
        stored = security.hash_password(NEW_PASSWORD)
        self.assertNotIn(NEW_PASSWORD, stored)
        self.assertTrue(security.verify_password(stored, NEW_PASSWORD))
        self.assertFalse(security.verify_password(stored, NEW_PASSWORD + "x"))

    def test_encryption_roundtrip_and_wrong_key(self):
        """A value survives a roundtrip and fails loudly under a different key."""
        from portal import crypto
        key = os.urandom(32)
        blob = crypto.encrypt("super-secret-value", key)
        self.assertNotIn("super-secret-value", blob)
        self.assertEqual("super-secret-value", crypto.decrypt(blob, key))
        with self.assertRaises(crypto.CryptoError):
            crypto.decrypt(blob, os.urandom(32))

    def test_totp_code_cannot_be_replayed(self):
        """The same code must not be accepted twice."""
        from portal import security
        secret = security.new_totp_secret()
        code = pyotp.TOTP(secret).now()
        ok, counter = security.verify_totp(secret, code, 0)
        self.assertTrue(ok)
        again, _ = security.verify_totp(secret, code, counter)
        self.assertFalse(again)


class SchedulingTests(unittest.TestCase):
    """Slot distribution and the once per day rule."""

    def test_is_due_only_once_per_day(self):
        """A customer already scanned after its slot is not due again today."""
        from portal.models import Customer
        from portal.scheduler import is_due
        now = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
        customer = Customer(key="k", display_name="K", tenant_id="t", client_id="c",
                            slot_minute=8 * 60, is_active=True)

        customer.last_check_at = None
        self.assertTrue(is_due(customer, now))

        customer.last_check_at = now - timedelta(hours=1)
        self.assertFalse(is_due(customer, now))

        customer.last_check_at = now - timedelta(days=1)
        self.assertTrue(is_due(customer, now))

        customer.slot_minute = 23 * 60
        customer.last_check_at = None
        self.assertFalse(is_due(customer, now))

        customer.slot_minute = 8 * 60
        customer.is_active = False
        customer.last_check_at = None
        self.assertFalse(is_due(customer, now))


class PortalFlowTests(unittest.TestCase):
    """The full path from first login to a working PRTG sensor."""

    @classmethod
    def setUpClass(cls):
        """Build one app and sign the bootstrap account in."""
        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        """Drop the temporary database file."""
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def _csrf(self, path):
        """Extract the CSRF token from a rendered form."""
        return self._csrf_for(self.client, path)

    def _csrf_for(self, client, path):
        """
        Extract the CSRF token as seen by one specific client.

        The token is bound to the session, and the session is cleared between
        the password step and the code step, so it has to be read again from
        the page that is actually being submitted.
        """
        body = client.get(path).get_data(as_text=True)
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', body)
        self.assertIsNotNone(match, "kein CSRF-Token auf %s" % path)
        return match.group(1)

    def test_01_login_rejects_wrong_password(self):
        """A wrong password must not sign anyone in."""
        response = self.client.post("/login", data={
            "csrf_token": self._csrf("/login"),
            "username": "admin", "password": "falsch"}, follow_redirects=False)
        self.assertEqual(401, response.status_code)

    def test_02_sql_injection_in_login_is_harmless(self):
        """A classic injection payload must be treated as an ordinary string."""
        payload = "admin' OR '1'='1' --"
        response = self.client.post("/login", data={
            "csrf_token": self._csrf("/login"),
            "username": payload, "password": "x"}, follow_redirects=False)
        self.assertEqual(401, response.status_code)
        from portal.db import Session
        from portal.models import User
        self.assertEqual(1, Session.query(User).count())

    def test_03_missing_csrf_token_is_refused(self):
        """A POST without the token must never be processed."""
        response = self.client.post("/login", data={"username": "admin",
                                                    "password": BOOTSTRAP_PASSWORD})
        self.assertEqual(400, response.status_code)

    def test_04_login_enrols_second_factor_and_forces_password_change(self):
        """First login: password, TOTP enrollment, then the password page."""
        response = self.client.post("/login", data={
            "csrf_token": self._csrf("/login"),
            "username": "admin", "password": BOOTSTRAP_PASSWORD})
        self.assertEqual(302, response.status_code)
        self.assertIn("/login/2fa/setup", response.headers["Location"])

        token = self._csrf("/login/2fa/setup")
        with self.client.session_transaction() as session:
            secret = session["totp_setup_secret"]
        response = self.client.post("/login/2fa/setup", data={
            "csrf_token": token, "code": pyotp.TOTP(secret).now()})
        self.assertEqual(200, response.status_code)

        # The recovery codes arrive in this very response and never touch the
        # session cookie, which is signed but readable by anyone.
        body = response.get_data(as_text=True)
        self.assertIn("Recovery-Codes", body)
        with self.client.session_transaction() as session:
            self.assertNotIn("fresh_recovery_codes", session)

        # A revisit shows only the remaining count, not the codes again.
        again = self.client.get("/account/recovery-codes").get_data(as_text=True)
        self.assertNotIn("Einmalig sichtbar", again)
        self.assertEqual(302, self.client.get("/").status_code)

        response = self.client.post("/account/password", data={
            "csrf_token": self._csrf("/account/password"),
            "current_password": BOOTSTRAP_PASSWORD,
            "new_password": NEW_PASSWORD,
            "confirm_password": NEW_PASSWORD})
        self.assertEqual(302, response.status_code)
        self.assertEqual(200, self.client.get("/").status_code)

    def test_04b_setup_page_cannot_replace_a_confirmed_authenticator(self):
        """
        Regression for the 2FA bypass found in the Codex review.

        Knowing the password used to be enough: skip the code prompt, call the
        enrollment page directly, register your own authenticator over the
        victim's and be signed in. The setup page must now turn that away.
        """
        from portal.db import Session
        from portal.models import User
        admin = Session.query(User).filter(User.username == "admin").one()
        stored_before = admin.totp_secret_enc

        attacker = self.app.test_client()
        response = attacker.post("/login", data={
            "csrf_token": self._csrf_for(attacker, "/login"),
            "username": "admin", "password": NEW_PASSWORD})
        self.assertEqual(302, response.status_code)
        self.assertIn("/login/2fa", response.headers["Location"])

        # Straight to the enrollment page, ignoring the code prompt.
        setup = attacker.get("/login/2fa/setup")
        self.assertEqual(302, setup.status_code)
        self.assertIn("/login/2fa", setup.headers["Location"])
        self.assertNotIn("/setup", setup.headers["Location"])
        with attacker.session_transaction() as session:
            self.assertNotIn("totp_setup_secret", session)

        # Posting a code to it must not enrol anything either.
        forced = attacker.post("/login/2fa/setup", data={
            "csrf_token": self._csrf_for(attacker, "/login/2fa"), "code": "123456"})
        self.assertEqual(302, forced.status_code)
        reloaded = Session.query(User).filter(User.username == "admin").one()
        self.assertEqual(stored_before, reloaded.totp_secret_enc,
                         "das gespeicherte TOTP-Secret wurde ersetzt")
        self.assertEqual(302, attacker.get("/").status_code, "Angreifer ist angemeldet")

    def test_04c_lockout_applies_to_the_totp_step(self):
        """A locked account must not keep accepting TOTP guesses."""
        from portal.db import Session
        from portal.models import User
        admin = Session.query(User).filter(User.username == "admin").one()
        admin.failed_logins = 0
        admin.locked_until = None
        Session.commit()

        guesser = self.app.test_client()
        guesser.post("/login", data={"csrf_token": self._csrf_for(guesser, "/login"),
                                     "username": "admin", "password": NEW_PASSWORD})
        token = self._csrf_for(guesser, "/login/2fa")

        limit = self.app.config["PORTAL"].login_max_attempts
        statuses = []
        for _ in range(limit + 3):
            statuses.append(guesser.post("/login/2fa", data={
                "csrf_token": token, "code": "000000"}).status_code)

        # Once the limit is hit the pending login is dropped and further
        # attempts land back on the login page instead of being evaluated.
        self.assertIn(302, statuses, "Sperre greift auf der TOTP-Stufe nicht: %s" % statuses)
        self.assertLessEqual(statuses.index(302), limit)

        reloaded = Session.query(User).filter(User.username == "admin").one()
        reloaded.failed_logins = 0
        reloaded.locked_until = None
        Session.commit()

    def test_05_weak_password_is_refused_on_change(self):
        """The policy is enforced on the change form, not only on creation."""
        response = self.client.post("/account/password", data={
            "csrf_token": self._csrf("/account/password"),
            "current_password": NEW_PASSWORD,
            "new_password": "passwort123",
            "confirm_password": "passwort123"})
        self.assertEqual(400, response.status_code)

    def test_06_customer_lifecycle_and_prtg_endpoint(self):
        """Create a customer with a stubbed scan and read the sensor output."""
        import graph
        original = graph.scan_tenant
        graph.scan_tenant = fake_scan
        try:
            response = self.client.post("/kunden/neu", data={
                "csrf_token": self._csrf("/kunden/neu"),
                "key": "testkunde",
                "display_name": "Test Kunde AG",
                "tenant_id": "11111111-2222-3333-4444-555555555555",
                "client_id": "66666666-7777-8888-9999-000000000000",
                "auth_type": "secret",
                "client_secret": "ein-geheimes-secret",
                "warn_days": "30", "error_days": "14", "max_channels": "45",
                "is_active": "y"}, follow_redirects=True)
            self.assertEqual(200, response.status_code)
            body = response.get_data(as_text=True)
            self.assertIn("Test Kunde AG", body)
            self.assertIn("SVC-Backup", body)

            from portal.db import Session
            from portal.models import Customer
            customer = Session.query(Customer).filter(Customer.key == "testkunde").one()
            self.assertNotIn("ein-geheimes-secret", customer.client_secret_enc)
            self.assertEqual("ok", customer.last_status)
            self.assertEqual(9, customer.min_days)

            xml = self.client.get("/prtg/%s" % customer.prtg_token)
            self.assertEqual(200, xml.status_code)
            text = xml.get_data(as_text=True)
            self.assertIn("<channel>Datenalter</channel>", text)
            self.assertIn("<channel>Minimale Restlaufzeit</channel>", text)
            self.assertIn("SVC-Backup", text)

            data = self.client.get("/json/%s" % customer.prtg_token).get_json()
            self.assertEqual(2, data["summary"]["total"])
        finally:
            graph.scan_tenant = original

    def test_06b_prtg_scope_parameters_narrow_the_sensor(self):
        """One token must be able to feed a sensor for a single application."""
        from portal.db import Session
        from portal.models import Customer
        customer = Session.query(Customer).filter(Customer.key == "testkunde").one()
        base = "/prtg/%s" % customer.prtg_token

        full = self.client.get(base).get_data(as_text=True)
        self.assertIn("SVC-Backup", full)
        self.assertIn("SVC-Sync", full)

        # Exactly one application, with its own thresholds.
        single = self.client.get(base + "?app=SVC-Backup&type=secret&warn=10&error=5")
        text = single.get_data(as_text=True)
        self.assertIn("SVC-Backup", text)
        self.assertNotIn("SVC-Sync", text)
        self.assertIn("<limitminwarning>10</limitminwarning>", text)
        self.assertIn("<limitminerror>5</limitminerror>", text)

        # The summary describes the narrowed scope, not the whole tenant.
        scoped = self.client.get("/json/%s?app=SVC-Sync" % customer.prtg_token).get_json()
        self.assertEqual(1, scoped["summary"]["total"])
        self.assertEqual(400, scoped["summary"]["minimum"])

        # exclude drops an application, a bad number is refused.
        excluded = self.client.get(base + "?exclude=SVC-Backup").get_data(as_text=True)
        self.assertNotIn("SVC-Backup (Secret)", excluded)
        broken = self.client.get(base + "?warn=viele").get_data(as_text=True)
        self.assertIn("<error>1</error>", broken)

    def test_07_prtg_token_must_match(self):
        """An unknown token yields a PRTG error document, never customer data."""
        response = self.client.get("/prtg/%s" % ("x" * 40))
        self.assertEqual(200, response.status_code)
        body = response.get_data(as_text=True)
        self.assertIn("<error>1</error>", body)
        self.assertNotIn("SVC-Backup", body)

    def test_08_invalid_guid_is_refused(self):
        """The tenant id is validated before anything is stored."""
        response = self.client.post("/kunden/neu", data={
            "csrf_token": self._csrf("/kunden/neu"),
            "key": "boese-ag",
            "display_name": "Böse AG",
            "tenant_id": "'; DROP TABLE customers; --",
            "client_id": "66666666-7777-8888-9999-000000000000",
            "auth_type": "secret", "client_secret": "x",
            "warn_days": "30", "error_days": "14", "max_channels": "45"})
        self.assertEqual(200, response.status_code)
        from portal.db import Session
        from portal.models import Customer
        self.assertEqual(0, Session.query(Customer).filter(
            Customer.key == "boese-ag").count())
        self.assertGreaterEqual(Session.query(Customer).count(), 1)

    def test_09_slots_are_spread_over_the_day(self):
        """Ten customers must not share the same scan minute."""
        from portal.db import Session
        from portal.models import Customer
        from portal.scheduler import assign_slot, redistribute_slots
        for index in range(9):
            Session.add(Customer(key="slot%d" % index, display_name="Slot %d" % index,
                                 tenant_id="11111111-2222-3333-4444-555555555555",
                                 client_id="66666666-7777-8888-9999-000000000000",
                                 client_secret_enc="", slot_minute=assign_slot(Session),
                                 prtg_token="token-slot-%d" % index))
            Session.commit()
        slots = sorted(c.slot_minute for c in Session.query(Customer).all())
        self.assertEqual(len(slots), len(set(slots)), "Slots doppelt vergeben")

        redistribute_slots(Session)
        slots = sorted(c.slot_minute for c in Session.query(Customer).all())
        gaps = [b - a for a, b in zip(slots, slots[1:])]
        self.assertTrue(all(gap >= 100 for gap in gaps), "Slots liegen zu dicht: %s" % gaps)

    def test_10_viewer_cannot_create_customers(self):
        """The role guard must block a read only account."""
        from portal.db import Session
        from portal.models import ROLE_VIEWER, User
        admin = Session.query(User).filter(User.username == "admin").one()
        admin.role = ROLE_VIEWER
        Session.commit()
        try:
            self.assertEqual(403, self.client.get("/kunden/neu").status_code)
            self.assertEqual(403, self.client.get("/benutzer/").status_code)
        finally:
            admin.role = "admin"
            Session.commit()


if __name__ == "__main__":
    unittest.main(verbosity=2)
