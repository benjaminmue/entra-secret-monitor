"""
Tests for portal/audit.py: the append only audit trail.

Two promises carry weight here. An untrusted X-Forwarded-For must not decide
what address ends up in the trail, otherwise anyone can forge their own
provenance. And writing a row must never raise, because the trail sits inside
login and every write path, where an exception would turn a logging problem into
an outage.
"""
import unittest
from unittest import mock

from .support import needs_portal

try:
    from flask import Flask

    from portal import audit
except ImportError:                     # ohne die Extras uebernimmt needs_portal
    audit = None
    Flask = None


@needs_portal
class ClientIpTest(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    def test_no_request_context_yields_an_empty_address(self):
        # Scheduler runs write audit rows without any request in flight.
        self.assertEqual("", audit.client_ip())

    def test_remote_address_is_used_by_default(self):
        with self.app.test_request_context(environ_base={"REMOTE_ADDR": "10.1.2.3"}):
            self.assertEqual("10.1.2.3", audit.client_ip())

    def test_forwarded_header_is_ignored_unless_the_proxy_is_trusted(self):
        with self.app.test_request_context(
                headers={"X-Forwarded-For": "1.2.3.4"},
                environ_base={"REMOTE_ADDR": "10.1.2.3"}):
            self.assertEqual("10.1.2.3", audit.client_ip(trust_proxy=False))

    def test_forwarded_header_is_honoured_when_the_proxy_is_trusted(self):
        with self.app.test_request_context(
                headers={"X-Forwarded-For": "1.2.3.4"},
                environ_base={"REMOTE_ADDR": "10.1.2.3"}):
            self.assertEqual("1.2.3.4", audit.client_ip(trust_proxy=True))

    def test_only_the_first_hop_of_a_forwarded_chain_is_taken(self):
        with self.app.test_request_context(
                headers={"X-Forwarded-For": "1.2.3.4, 10.0.0.1, 10.0.0.2"},
                environ_base={"REMOTE_ADDR": "10.1.2.3"}):
            self.assertEqual("1.2.3.4", audit.client_ip(trust_proxy=True))

    def test_an_overlong_forwarded_value_is_truncated(self):
        with self.app.test_request_context(
                headers={"X-Forwarded-For": "9" * 500},
                environ_base={"REMOTE_ADDR": "10.1.2.3"}):
            self.assertLessEqual(len(audit.client_ip(trust_proxy=True)), 64)

    def test_an_empty_forwarded_header_falls_back_to_the_remote_address(self):
        with self.app.test_request_context(
                headers={"X-Forwarded-For": ""},
                environ_base={"REMOTE_ADDR": "10.1.2.3"}):
            self.assertEqual("10.1.2.3", audit.client_ip(trust_proxy=True))


@needs_portal
class LogTest(unittest.TestCase):
    def test_a_row_is_added_and_committed(self):
        session = mock.Mock()
        audit.log(session, "user.created", actor="admin", target="neuling")
        session.add.assert_called_once()
        session.commit.assert_called_once()

    def test_commit_can_be_deferred_to_the_caller(self):
        # Lockout writes its row inside a transaction the caller finishes.
        session = mock.Mock()
        audit.log(session, "login.locked", commit=False)
        session.add.assert_called_once()
        session.commit.assert_not_called()

    def test_overlong_values_are_truncated_to_the_column_widths(self):
        session = mock.Mock()
        audit.log(session, "a" * 100, actor="b" * 200, target="c" * 500,
                  detail="d" * 5000)
        event = session.add.call_args[0][0]
        self.assertLessEqual(len(event.action), 48)
        self.assertLessEqual(len(event.actor), 64)
        self.assertLessEqual(len(event.target), 128)
        self.assertLessEqual(len(event.detail), 2000)

    def test_a_missing_actor_becomes_system(self):
        session = mock.Mock()
        audit.log(session, "scheduler.run", actor="")
        self.assertEqual("system", session.add.call_args[0][0].actor)

    def test_a_failing_session_does_not_raise(self):
        # The trail sits inside login; an exception here would be an outage.
        session = mock.Mock()
        session.commit.side_effect = RuntimeError("Datenbank weg")
        with mock.patch("builtins.print"):
            audit.log(session, "login.failed")      # must not raise

    def test_the_failure_is_reported_on_stdout(self):
        session = mock.Mock()
        session.add.side_effect = RuntimeError("Datenbank weg")
        with mock.patch("builtins.print") as printed:
            audit.log(session, "login.failed")
        self.assertTrue(printed.called, "ein verlorener Audit-Eintrag bleibt unbemerkt")
        self.assertIn("login.failed", str(printed.call_args))


if __name__ == "__main__":
    unittest.main()
