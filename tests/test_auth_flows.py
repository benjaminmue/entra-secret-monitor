"""
The authentication paths that the main flow test does not reach.

Recovery codes, session expiry, logout and the guards around enrollment. These
decide what happens when someone loses their authenticator or leaves a session
lying around, which is exactly when an account is worth attacking.
"""
import os
import re
import unittest
from datetime import datetime, timedelta, timezone

from .support import needs_portal

try:
    import pyotp
except ImportError:
    pyotp = None

from tests.test_portal import BOOTSTRAP_PASSWORD, NEW_PASSWORD, build_app


@needs_portal
class RecoveryCodeTest(unittest.TestCase):
    """A recovery code stands in for the authenticator exactly once."""

    @classmethod
    def setUpClass(cls):
        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        cls.codes = cls._enrol(cls.client)

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    @classmethod
    def _csrf(cls, client, path):
        body = client.get(path).get_data(as_text=True)
        match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', body)
        assert match, "kein CSRF-Token auf %s" % path
        return match.group(1)

    @classmethod
    def _enrol(cls, client):
        """Run the first login and return the recovery codes shown once."""
        client.post("/login", data={"csrf_token": cls._csrf(client, "/login"),
                                    "username": "admin",
                                    "password": BOOTSTRAP_PASSWORD})
        token = cls._csrf(client, "/login/2fa/setup")
        with client.session_transaction() as session:
            secret = session["totp_setup_secret"]
        cls.secret = secret
        body = client.post("/login/2fa/setup", data={
            "csrf_token": token, "code": pyotp.TOTP(secret).now()}).get_data(as_text=True)
        client.post("/account/password", data={
            "csrf_token": cls._csrf(client, "/account/password"),
            "current_password": BOOTSTRAP_PASSWORD,
            "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
        return re.findall(r"\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b", body)

    def _password_step(self, client):
        """Get a client to the point where a second factor is asked for."""
        client.post("/login", data={"csrf_token": self._csrf(client, "/login"),
                                    "username": "admin", "password": NEW_PASSWORD})

    def test_enrollment_hands_out_codes(self):
        self.assertGreaterEqual(len(self.codes), 4,
                                "keine Recovery-Codes ausgegeben: %r" % self.codes)

    def test_a_recovery_code_signs_in_and_cannot_be_reused(self):
        code = self.codes[0]
        first = self.app.test_client()
        self._password_step(first)
        response = first.post("/login/2fa", data={
            "csrf_token": self._csrf(first, "/login/2fa"), "code": code})
        self.assertEqual(302, response.status_code, "Recovery-Code wurde nicht akzeptiert")

        second = self.app.test_client()
        self._password_step(second)
        again = second.post("/login/2fa", data={
            "csrf_token": self._csrf(second, "/login/2fa"), "code": code})
        self.assertEqual(401, again.status_code, "der Code liess sich zweimal einloesen")

    def test_a_wrong_recovery_code_is_refused(self):
        client = self.app.test_client()
        self._password_step(client)
        response = client.post("/login/2fa", data={
            "csrf_token": self._csrf(client, "/login/2fa"), "code": "ZZZZ-ZZZZ"})
        self.assertEqual(401, response.status_code)

    def test_the_remaining_count_is_shown_without_the_codes(self):
        body = self.client.get("/account/recovery-codes").get_data(as_text=True)
        self.assertNotIn(self.codes[1], body,
                         "ein ungenutzter Code wird erneut angezeigt")


@needs_portal
class SessionTest(unittest.TestCase):
    """Half finished and expired logins must not survive."""

    @classmethod
    def setUpClass(cls):
        cls.app, cls.db_path = build_app()
        cls.client = cls.app.test_client()
        RecoveryCodeTest._enrol(cls.client)

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def _csrf(self, client, path):
        return RecoveryCodeTest._csrf(client, path)

    def test_logout_ends_the_session(self):
        self.assertEqual(200, self.client.get("/").status_code)
        self.client.post("/logout", data={"csrf_token": self._csrf(self.client, "/")})
        self.assertIn(self.client.get("/").status_code, (302, 401))

    def test_the_code_step_is_unreachable_without_the_password_step(self):
        # Otherwise the second factor alone would be enough.
        fresh = self.app.test_client()
        self.assertIn(fresh.get("/login/2fa").status_code, (302, 401))

    def test_an_expired_pending_login_is_dropped(self):
        client = self.app.test_client()
        client.post("/login", data={"csrf_token": self._csrf(client, "/login"),
                                    "username": "admin", "password": NEW_PASSWORD})
        with client.session_transaction() as session:
            stale = datetime.now(timezone.utc) - timedelta(hours=2)
            session["pending_since"] = stale.isoformat()
        self.assertIn(client.get("/login/2fa").status_code, (302, 401),
                      "ein abgelaufener halbfertiger Login wird noch akzeptiert")

    def test_a_confirmed_authenticator_cannot_be_replaced_without_step_up(self):
        # This client already finished enrollment. Calling the setup page again
        # must not hand out a fresh secret without the step-up confirmation.
        response = self.client.get("/login/2fa/setup")
        self.assertIn(response.status_code, (302, 400, 403),
                      "der zweite Faktor laesst sich ohne Bestaetigung tauschen")


if __name__ == "__main__":
    unittest.main()
