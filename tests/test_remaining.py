"""
The paths left over after the main suites: status logic, config, probe, forced runs.

Nothing exotic here, but each of these decides something visible. The dashboard
status is what an operator glances at, the config loader is what refuses to
start, and the health probe is what tells Docker whether to restart the
container.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from .support import needs_portal

try:
    import pyotp
except ImportError:
    pyotp = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class HealthProbeTest(unittest.TestCase):
    """
    The probe Docker runs to decide whether the container is alive.

    It is a script, not a module: importing it fires the request. Both outcomes
    are therefore exercised in a subprocess.
    """

    def _run(self, port):
        env = dict(os.environ, LISTEN_PORT=str(port))
        return subprocess.run([sys.executable, os.path.join(ROOT, "app", "healthcheck.py")],
                              capture_output=True, env=env, check=False).returncode

    def test_a_closed_port_reports_unhealthy(self):
        # Port 1 is reserved and never listening.
        self.assertEqual(1, self._run(1))

    def test_a_serving_endpoint_reports_healthy(self):
        from .support import LiveServer, make_config

        server = LiveServer(tenants={"demo": make_config()}).start()
        try:
            self.assertEqual(0, self._run(server.port))
        finally:
            server.stop()


@needs_portal
class ConfigLoaderTest(unittest.TestCase):
    """What the portal refuses to start with, and what it merely warns about."""

    # Base64 von "0123456789abcdef0123456789abcdef": 32 Bytes der richtigen
    # Laenge, damit der Loader zufrieden ist, und offensichtlich kein echter
    # Schluessel.
    BASE = {"PORTAL_SECRET_KEY": "x" * 40,                             # gitleaks:allow
            "PORTAL_ENCRYPTION_KEY":
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}        # gitleaks:allow

    def test_missing_keys_are_reported_with_a_usable_hint(self):
        from portal.config import ConfigError, load_config

        with self.assertRaises(ConfigError) as caught:
            load_config({})
        message = str(caught.exception)
        self.assertIn("PORTAL_SECRET_KEY", message)
        # The hint has to be copy-pasteable: the keys cannot be regenerated
        # later without losing every stored credential.
        self.assertIn("python3", message)

    def test_a_key_that_is_not_base64_is_refused(self):
        from portal.config import ConfigError, load_config

        with self.assertRaises(ConfigError):
            load_config(dict(self.BASE, PORTAL_ENCRYPTION_KEY="kein base64!"))

    def test_a_key_of_the_wrong_length_is_refused(self):
        from portal.config import ConfigError, load_config

        with self.assertRaises(ConfigError) as caught:
            load_config(dict(self.BASE, PORTAL_ENCRYPTION_KEY="YWJj"))   # 3 Bytes
        self.assertIn("32", str(caught.exception))

    def test_a_valid_environment_yields_a_config(self):
        from portal.config import load_config

        cfg = load_config(dict(self.BASE, PORTAL_WARN_DAYS="45"))
        self.assertEqual(45, cfg.default_warn_days)
        self.assertEqual(32, len(cfg.encryption_key))

    def test_a_short_password_minimum_is_raised_with_a_warning(self):
        from portal.config import load_config

        cfg = load_config(dict(self.BASE, PORTAL_PASSWORD_MIN_LENGTH="4"))
        self.assertEqual(12, cfg.password_min_length)
        self.assertTrue(any("PASSWORD_MIN_LENGTH" in w for w in cfg.warnings))

    def test_a_missing_base_url_warns_about_forgeable_sensor_links(self):
        from portal.config import load_config

        cfg = load_config(dict(self.BASE))
        self.assertTrue(any("PORTAL_BASE_URL" in w for w in cfg.warnings))

    def test_an_insecure_cookie_warns(self):
        from portal.config import load_config

        cfg = load_config(dict(self.BASE, PORTAL_COOKIE_SECURE="0"))
        self.assertTrue(any("COOKIE_SECURE" in w for w in cfg.warnings))

    def test_a_trailing_slash_on_the_base_url_is_dropped(self):
        from portal.config import load_config

        cfg = load_config(dict(self.BASE, PORTAL_BASE_URL="https://portal.example/"))
        self.assertEqual("https://portal.example", cfg.base_url)


@needs_portal
class DashboardStatusTest(unittest.TestCase):
    """
    The single word an operator reads per customer.

    Order matters: an inactive customer is not "error", and a stale one is not
    quietly "ok" just because its last numbers looked fine.
    """

    @classmethod
    def setUpClass(cls):
        # customer_state reads the app config for its default staleness bound,
        # so it needs an application context even when the bound is passed in.
        from tests.test_portal import build_app

        cls.app, cls.db_path = build_app()
        cls.context = cls.app.app_context()
        cls.context.push()

    @classmethod
    def tearDownClass(cls):
        cls.context.pop()
        try:
            os.unlink(cls.db_path)
        except OSError:
            pass

    def _customer(self, **fields):
        jetzt = datetime.now(timezone.utc)
        values = dict(is_active=True, last_status="ok",
                      last_check_at=jetzt, last_success_at=jetzt,
                      count_expired=0, min_days=100, warn_days=30, error_days=14)
        values.update(fields)
        return mock.Mock(**values)

    def _status(self, customer, stale_hours=30):
        from portal.views.dashboard import customer_state

        return customer_state(customer, stale_hours)

    def test_a_healthy_customer_is_ok(self):
        self.assertEqual("ok", self._status(self._customer()))

    def test_an_inactive_customer_is_not_judged_at_all(self):
        self.assertEqual("inactive", self._status(
            self._customer(is_active=False, count_expired=5)))

    def test_a_customer_never_scanned_is_unknown(self):
        self.assertEqual("unknown", self._status(self._customer(last_check_at=None)))
        self.assertEqual("unknown", self._status(self._customer(last_status="pending")))

    def test_a_failed_scan_is_an_error(self):
        self.assertEqual("error", self._status(self._customer(last_status="error")))

    def test_old_data_is_stale_even_when_the_numbers_look_good(self):
        # Otherwise a stalled scheduler stays green while the numbers freeze.
        old = datetime.now(timezone.utc) - timedelta(hours=100)
        self.assertEqual("stale", self._status(
            self._customer(last_check_at=old, last_success_at=old)))

    def test_a_failed_scan_does_not_make_old_data_look_fresh(self):
        """
        Der Fehlschlag rückt den Versuch weiter, nicht die Daten.

        Über last_check_at gerechnet sah ein Kunde, dessen Scans dauerhaft
        scheitern, taggenau frisch aus, und der Sensor bekam ein Datenalter
        von null. Genau diesen Fall soll der Kanal melden.
        """
        alt = datetime.now(timezone.utc) - timedelta(hours=100)
        kunde = self._customer(last_status="error",
                               last_check_at=datetime.now(timezone.utc),
                               last_success_at=alt)
        from portal.scanner import data_age_hours

        self.assertGreaterEqual(data_age_hours(kunde), 99)

    def test_an_expired_credential_is_an_error(self):
        self.assertEqual("error", self._status(self._customer(count_expired=1)))

    def test_the_thresholds_decide_between_error_warn_and_ok(self):
        self.assertEqual("error", self._status(self._customer(min_days=10)))
        self.assertEqual("warn", self._status(self._customer(min_days=20)))
        self.assertEqual("ok", self._status(self._customer(min_days=90)))

    def test_a_missing_minimum_is_unknown_rather_than_ok(self):
        self.assertEqual("unknown", self._status(self._customer(min_days=None)))


if __name__ == "__main__":
    unittest.main()


@needs_portal
class SchemaMigrationTest(unittest.TestCase):
    """
    Eine neue Spalte an einer bestehenden Tabelle.

    `create_all` legt nur fehlende Tabellen an. Eine neue Tabelle, wie
    `api_keys`, ging deshalb gut. Die erste neue Spalte hätte jede Abfrage
    darauf auflaufen lassen, und zwar erst im Betrieb beim Kunden.
    """

    def setUp(self):
        handle, self.pfad = tempfile.mkstemp(suffix=".db")
        os.close(handle)

    def tearDown(self):
        for endung in ("", "-wal", "-shm"):
            try:
                os.unlink(self.pfad + endung)
            except OSError:
                pass

    def _neu_verbinden(self):
        """Point the session at the throwaway database."""
        import portal.db as db

        db.Session.remove()
        db._engine = None                                              # noqa: SLF001
        db.init_engine("sqlite:///" + self.pfad.replace("\\", "/"))
        return db

    def test_a_column_missing_from_an_existing_table_is_added(self):
        """Der Fall, der sonst erst beim Kunden aufgefallen wäre."""
        import sqlalchemy

        db = self._neu_verbinden()
        db.create_all()

        # Zustand vor der Erweiterung nachstellen
        with db._engine.begin() as verbindung:                         # noqa: SLF001
            verbindung.execute(sqlalchemy.text(
                "ALTER TABLE customers DROP COLUMN last_success_at"))
        spalten = {s["name"] for s in
                   sqlalchemy.inspect(db._engine).get_columns("customers")}  # noqa: SLF001
        self.assertNotIn("last_success_at", spalten)

        db.create_all()
        spalten = {s["name"] for s in
                   sqlalchemy.inspect(db._engine).get_columns("customers")}  # noqa: SLF001
        self.assertIn("last_success_at", spalten)

    def test_existing_rows_survive_the_added_column(self):
        """Eine Migration, die Daten verliert, wäre schlimmer als keine."""
        import sqlalchemy

        from portal.models import Customer, new_token

        db = self._neu_verbinden()
        db.create_all()
        db.Session.add(Customer(key="alt", display_name="Alt AG",
                                tenant_id="00000000-0000-0000-0000-0000000000aa",
                                client_id="00000000-0000-0000-0000-0000000000bb",
                                auth_type="secret", prtg_token=new_token(),
                                min_days=42))
        db.Session.commit()

        with db._engine.begin() as verbindung:                         # noqa: SLF001
            verbindung.execute(sqlalchemy.text(
                "ALTER TABLE customers DROP COLUMN last_success_at"))
        db.Session.remove()
        db.create_all()

        kunde = db.Session.query(Customer).filter_by(key="alt").one()
        self.assertEqual("Alt AG", kunde.display_name)
        self.assertEqual(42, kunde.min_days)
        self.assertIsNone(kunde.last_success_at)

    def test_running_it_twice_changes_nothing(self):
        """Der Start darf beliebig oft passieren."""
        db = self._neu_verbinden()
        db.create_all()
        db.create_all()
        db.create_all()

    def test_a_column_that_cannot_be_added_is_refused_loudly(self):
        """
        Eine Spalte ohne nullable liesse sich in SQLite nicht nachtragen.

        Dann braucht es ein Migrationswerkzeug, und das soll beim Start
        auffallen statt später an einer Abfrage.
        """
        import sqlalchemy

        from portal.db import Base

        db = self._neu_verbinden()
        db.create_all()

        tabelle = Base.metadata.tables["customers"]
        pflicht = sqlalchemy.Column("pflichtfeld", sqlalchemy.String(8), nullable=False)
        tabelle.append_column(pflicht)
        try:
            with self.assertRaises(RuntimeError) as gefangen:
                db.create_all()
            self.assertIn("pflichtfeld", str(gefangen.exception))
        finally:
            tabelle._columns.remove(pflicht)                           # noqa: SLF001
