"""
Tests for portal/serve.py: the entry point and its exit codes.

Nothing here starts a real server. What matters is that a misconfigured or
incompletely installed portal fails with a distinguishable exit code and a
message, rather than a traceback that a container log turns into noise.
"""
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from .support import needs_portal

try:
    from portal import serve
    from portal.config import ConfigError
except ImportError:                     # ohne die Extras uebernimmt needs_portal
    serve = None
    ConfigError = None


@needs_portal
class MainTest(unittest.TestCase):
    def test_configuration_error_exits_with_two_and_explains(self):
        err = io.StringIO()
        with mock.patch.object(serve, "load_config",
                               side_effect=ConfigError("PORTAL_SECRET_KEY fehlt")), \
             redirect_stderr(err):
            self.assertEqual(2, serve.main())
        self.assertIn("PORTAL_SECRET_KEY fehlt", err.getvalue())

    def test_missing_waitress_exits_with_three_and_names_the_fix(self):
        err = io.StringIO()
        with mock.patch.object(serve, "load_config", return_value=mock.Mock()), \
             mock.patch.dict("sys.modules", {"waitress": None}), \
             redirect_stderr(err):
            self.assertEqual(3, serve.main())
        message = err.getvalue()
        self.assertIn("waitress", message)
        self.assertIn("requirements-portal.txt", message)

    def test_a_working_setup_serves_the_app_on_the_configured_socket(self):
        cfg = mock.Mock(listen_addr="10.0.0.5", listen_port=8099)
        app = object()
        served = mock.Mock()
        with mock.patch.object(serve, "load_config", return_value=cfg), \
             mock.patch.object(serve, "create_app", return_value=app) as factory, \
             mock.patch.dict("sys.modules", {"waitress": mock.Mock(serve=served)}), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(0, serve.main())

        factory.assert_called_once_with(cfg)
        self.assertIs(served.call_args[0][0], app)
        self.assertEqual("10.0.0.5", served.call_args[1]["host"])
        self.assertEqual(8099, served.call_args[1]["port"])

    def test_the_listening_address_is_announced_on_stdout(self):
        # The container log is the only place an operator sees this.
        cfg = mock.Mock(listen_addr="0.0.0.0", listen_port=8099)
        out = io.StringIO()
        with mock.patch.object(serve, "load_config", return_value=cfg), \
             mock.patch.object(serve, "create_app", return_value=object()), \
             mock.patch.dict("sys.modules", {"waitress": mock.Mock(serve=mock.Mock())}), \
             redirect_stdout(out):
            serve.main()
        self.assertIn("0.0.0.0", out.getvalue())
        self.assertIn("8099", out.getvalue())


if __name__ == "__main__":
    unittest.main()
