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

try:                                                                    # noqa: E402
    import pyotp
    PORTAL_DEPS_AVAILABLE = True
except ImportError:                     # Flask, argon2 und pyotp sind Extras,
    pyotp = None                        # der Dienst in app/ bleibt reine stdlib.
    PORTAL_DEPS_AVAILABLE = False

needs_portal = unittest.skipUnless(
    PORTAL_DEPS_AVAILABLE,
    "Portal-Abhaengigkeiten fehlen, siehe requirements-portal.txt")

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


@needs_portal
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

    def test_dummy_verify_costs_the_same_as_a_real_check(self):
        """
        A missing account must not be distinguishable by response time.

        Asserted structurally rather than by the clock: dummy_verify must not
        hash, because hashing on top of the verify made the unknown user twice
        as slow, which is exactly what leaked the username.
        """
        from unittest import mock

        from portal import security

        with mock.patch.object(security, "hash_password") as hashed:
            self.assertFalse(security.dummy_verify("irgendein Passwort"))
        hashed.assert_not_called()

    def test_dummy_verify_is_within_the_same_order_as_a_real_check(self):
        """Guards the structural test above with a generous timing bound."""
        import statistics
        import time

        from portal import security

        stored = security.hash_password("richtiges-passwort")

        def median(call):
            samples = []
            for _ in range(7):
                started = time.perf_counter()
                call()
                samples.append(time.perf_counter() - started)
            return statistics.median(samples)

        real = median(lambda: security.verify_password(stored, "falsch"))
        dummy = median(lambda: security.dummy_verify("falsch"))
        self.assertLess(max(real, dummy) / min(real, dummy), 1.5,
                        "Antwortzeit verraet, ob der Benutzer existiert")

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


@needs_portal
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


@needs_portal
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

    def test_05b_step_up_locks_out_after_repeated_failures(self):
        """
        Replacing the second factor must not be brute forceable.

        Login and the code step both count failures and lock the account. The
        step-up guarding the authenticator swap only wrote an audit entry, so a
        stolen session could guess password and code indefinitely and turn a
        temporary hijack into permanent access.
        """
        from portal.db import Session
        from portal.models import User

        admin = Session.query(User).filter(User.username == "admin").one()
        admin.failed_logins = 0
        admin.locked_until = None
        Session.commit()

        limit = self.app.config["PORTAL"].login_max_attempts
        statuses = []
        for _ in range(limit + 2):
            token = self._csrf("/account/2fa")
            statuses.append(self.client.post("/account/2fa", data={
                "csrf_token": token,
                "current_password": "definitiv-falsch",
                "code": "000000"}).status_code)

        self.assertIn(429, statuses,
                      "Step-up laesst unbegrenztes Raten zu: %s" % statuses)
        self.assertLessEqual(statuses.index(429), limit)

        reloaded = Session.query(User).filter(User.username == "admin").one()
        reloaded.failed_logins = 0
        reloaded.locked_until = None
        Session.commit()

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


@needs_portal
class UserAdministrationTests(unittest.TestCase):
    """
    The account administration carries the role separation of the portal.

    Its guarantees were unasserted: every endpoint is admin only, the last
    administrator cannot be removed or demoted, and nobody deletes themselves.
    A regression here hands out privileges rather than merely misreporting.
    """

    @classmethod
    def setUpClass(cls):
        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        cls._sign_in_admin(cls.client)

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    @classmethod
    def _csrf_for(cls, client, path):
        """Read the CSRF token from a rendered form."""
        body = client.get(path).get_data(as_text=True)
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', body)
        assert match, "kein CSRF-Token auf %s" % path
        return match.group(1)

    @classmethod
    def _sign_in_admin(cls, client):
        """Walk the bootstrap account through TOTP enrollment and password change."""
        client.post("/login", data={"csrf_token": cls._csrf_for(client, "/login"),
                                    "username": "admin",
                                    "password": BOOTSTRAP_PASSWORD})
        token = cls._csrf_for(client, "/login/2fa/setup")
        # The secret lives in the session during enrollment, not in the markup.
        with client.session_transaction() as session:
            secret = session["totp_setup_secret"]
        client.post("/login/2fa/setup", data={"csrf_token": token,
                                              "code": pyotp.TOTP(secret).now()})
        client.post("/account/password", data={
            "csrf_token": cls._csrf_for(client, "/account/password"),
            "current_password": BOOTSTRAP_PASSWORD,
            "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})

    @staticmethod
    def _reload(username):
        """Fetch an account fresh; refresh() fails on instances detached by a commit."""
        from portal.db import Session
        from portal.models import User
        return Session.query(User).filter(User.username == username).one_or_none()

    def _create_user(self, username, role="viewer"):
        """Create an account through the form and return the stored model."""
        self.client.post("/benutzer/neu", data={
            "csrf_token": self._csrf_for(self.client, "/benutzer/neu"),
            "username": username, "email": "%s@example.com" % username,
            "role": role})
        user = self._reload(username)
        self.assertIsNotNone(user, "Konto '%s' wurde nicht angelegt" % username)
        return user

    def _edit(self, user, **fields):
        """Submit the edit form; UserForm requires username even when unchanged."""
        data = {"csrf_token": self._csrf_for(self.client,
                                             "/benutzer/%d/bearbeiten" % user.id),
                "username": user.username,
                "email": "%s@example.com" % user.username,
                "role": user.role, "is_active": "y"}
        data.update(fields)
        return self.client.post("/benutzer/%d/bearbeiten" % user.id, data=data)

    # -- access control ----------------------------------------------------

    def test_anonymous_access_is_redirected_to_the_login(self):
        anonymous = self.app.test_client()
        for path in ("/benutzer/", "/benutzer/neu"):
            self.assertIn(anonymous.get(path).status_code, (302, 401), path)

    def test_every_administration_route_rejects_a_viewer(self):
        from portal.db import Session
        from portal.models import ROLE_VIEWER

        target = self._create_user("rollenopfer")
        # Read the token while still an administrator: a missing CSRF token
        # answers 400 before the role is ever checked, proving nothing.
        token = self._csrf_for(self.client, "/benutzer/")

        admin = self._reload("admin")
        admin.role = ROLE_VIEWER
        Session.commit()
        try:
            self.assertEqual(403, self.client.get("/benutzer/").status_code)
            self.assertEqual(403, self.client.get("/benutzer/neu").status_code)
            for route in ("passwort", "2fa", "loeschen"):
                response = self.client.post("/benutzer/%d/%s" % (target.id, route),
                                            data={"csrf_token": token})
                self.assertEqual(403, response.status_code, route)
        finally:
            restored = self._reload("admin")
            restored.role = "admin"
            Session.commit()
        self.assertEqual("admin", self._reload("admin").role)

    # -- creation ----------------------------------------------------------

    def test_new_account_starts_without_a_usable_second_factor(self):
        user = self._create_user("neuling")
        self.assertFalse(user.totp_ready)
        self.assertTrue(user.must_change_password)

    def test_one_time_password_page_is_not_cached(self):
        response = self.client.post("/benutzer/neu", data={
            "csrf_token": self._csrf_for(self.client, "/benutzer/neu"),
            "username": "einmalig", "email": "einmalig@example.com",
            "role": "viewer"})
        # The generated password is on this page; a cached copy would outlive it.
        self.assertEqual("no-store", response.headers.get("Cache-Control"))

    def test_duplicate_username_is_refused(self):
        from portal.db import Session
        from portal.models import User

        self._create_user("doppelt")
        self.client.post("/benutzer/neu", data={
            "csrf_token": self._csrf_for(self.client, "/benutzer/neu"),
            "username": "doppelt", "email": "doppelt@example.com", "role": "viewer"})
        self.assertEqual(1, Session.query(User).filter(User.username == "doppelt").count())

    # -- the last administrator -------------------------------------------

    def test_last_administrator_cannot_be_deleted(self):
        admin = self._reload("admin")
        self.client.post("/benutzer/%d/loeschen" % admin.id, data={
            "csrf_token": self._csrf_for(self.client, "/benutzer/")})
        self.assertIsNotNone(self._reload("admin"),
                             "das letzte Administratorkonto wurde geloescht")

    def test_last_administrator_cannot_be_demoted(self):
        from portal.models import ROLE_VIEWER

        self._edit(self._reload("admin"), role=ROLE_VIEWER)
        self.assertEqual("admin", self._reload("admin").role,
                         "das letzte Administratorkonto wurde degradiert")

    def test_last_administrator_cannot_be_deactivated(self):
        admin = self._reload("admin")
        self._edit(admin, is_active="")
        self.assertTrue(self._reload("admin").is_active,
                        "das letzte Administratorkonto wurde deaktiviert")

    def test_a_second_administrator_may_be_demoted(self):
        from portal.models import ROLE_VIEWER

        other = self._create_user("zweitadmin", role="admin")
        self._edit(other, role=ROLE_VIEWER)
        self.assertEqual(ROLE_VIEWER, self._reload("zweitadmin").role)

    def test_own_account_cannot_be_deleted(self):
        self._create_user("mitadmin", role="admin")   # so the guard is not "last admin"
        admin = self._reload("admin")
        self.client.post("/benutzer/%d/loeschen" % admin.id, data={
            "csrf_token": self._csrf_for(self.client, "/benutzer/")})
        self.assertIsNotNone(self._reload("admin"), "das eigene Konto wurde geloescht")

    def test_another_account_can_be_deleted(self):
        victim = self._create_user("wegdamit")
        self.client.post("/benutzer/%d/loeschen" % victim.id, data={
            "csrf_token": self._csrf_for(self.client, "/benutzer/")})
        self.assertIsNone(self._reload("wegdamit"))

    def test_deletion_without_a_csrf_token_is_refused(self):
        victim = self._create_user("bleibtda")
        self.assertEqual(400,
                         self.client.post("/benutzer/%d/loeschen" % victim.id).status_code)
        self.assertIsNotNone(self._reload("bleibtda"))

    # -- resets ------------------------------------------------------------

    def test_password_reset_issues_a_new_secret_and_forces_a_change(self):
        user = self._create_user("resetkandidat")
        before = user.password_hash
        response = self.client.post("/benutzer/%d/passwort" % user.id, data={
            "csrf_token": self._csrf_for(self.client, "/benutzer/")})
        reloaded = self._reload("resetkandidat")
        self.assertNotEqual(before, reloaded.password_hash)
        self.assertTrue(reloaded.must_change_password)
        self.assertEqual("no-store", response.headers.get("Cache-Control"))

    def test_totp_reset_clears_the_second_factor(self):
        from datetime import datetime, timezone

        from portal.db import Session

        user = self._create_user("totpkandidat")
        # totp_ready is derived from these two columns, there is no setter.
        user.totp_secret_enc = "irgendein-verschluesseltes-geheimnis"
        user.totp_confirmed_at = datetime.now(timezone.utc)
        Session.commit()
        self.assertTrue(self._reload("totpkandidat").totp_ready)

        user_id = self._reload("totpkandidat").id
        self.client.post("/benutzer/%d/2fa" % user_id, data={
            "csrf_token": self._csrf_for(self.client, "/benutzer/")})
        self.assertFalse(self._reload("totpkandidat").totp_ready)

    def test_unknown_account_yields_404(self):
        self.assertEqual(404, self.client.get("/benutzer/999999/bearbeiten").status_code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
