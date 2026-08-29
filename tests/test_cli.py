"""Tests for app/cli.py: argument parsing, overrides, tenant selection, exit codes."""
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import cli
import graph

from .support import make_config, make_credential


class ParseArgsTest(unittest.TestCase):
    def test_defaults_are_none_so_the_config_wins(self):
        args = cli.parse_args([])
        for name in ("tenant", "warn", "error", "filter", "exclude",
                     "include_sp", "show_expired", "max_channels", "push"):
            self.assertIsNone(getattr(args, name), name)

    def test_output_format_defaults_to_prtg(self):
        self.assertEqual(cli.parse_args([]).format, "prtg")

    def test_unknown_format_is_rejected(self):
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            cli.parse_args(["--format", "yaml"])

    def test_values_are_parsed_into_their_types(self):
        args = cli.parse_args(["--warn", "60", "--max-channels", "20",
                               "--filter", "alpha", "--include-sp"])
        self.assertEqual((args.warn, args.max_channels, args.filter), (60, 20, "alpha"))
        self.assertTrue(args.include_sp)


class ApplyOverridesTest(unittest.TestCase):
    def _args(self, **overrides):
        fields = dict(warn=None, error=None, filter=None, exclude=None,
                      include_sp=None, show_expired=None, max_channels=None, push=None)
        fields.update(overrides)
        return mock.Mock(**fields)

    def test_without_arguments_the_config_is_returned_unchanged(self):
        cfg = make_config()
        self.assertIs(cli.apply_overrides(cfg, self._args()), cfg)

    def test_each_argument_reaches_its_field(self):
        cfg = cli.apply_overrides(make_config(), self._args(
            warn=60, error=7, filter="alpha", exclude="beta",
            include_sp=True, show_expired=True, push="https://push"))
        self.assertEqual(
            (cfg.warn_days, cfg.error_days, cfg.app_filter, cfg.app_exclude,
             cfg.include_sp, cfg.show_expired, cfg.push_url),
            (60, 7, "alpha", "beta", True, True, "https://push"))

    def test_channel_limit_holds_for_the_cli_too(self):
        # Regression: assigning fields skipped __post_init__ and its invariants.
        self.assertEqual(
            cli.apply_overrides(make_config(), self._args(max_channels=500)).max_channels,
            graph.MAX_APP_CHANNELS)
        self.assertEqual(
            cli.apply_overrides(make_config(), self._args(max_channels=-3)).max_channels, 1)

    def test_the_passed_config_is_not_mutated(self):
        cfg = make_config()
        cli.apply_overrides(cfg, self._args(warn=60))
        self.assertEqual(cfg.warn_days, 30)


class SelectTenantTest(unittest.TestCase):
    def test_named_tenant_is_returned(self):
        tenants = {"a": make_config(key="a"), "b": make_config(key="b")}
        self.assertEqual(cli.select_tenant(tenants, "b").key, "b")

    def test_unknown_name_lists_the_available_ones(self):
        with self.assertRaises(graph.GraphError) as caught:
            cli.select_tenant({"a": make_config(key="a")}, "zzz")
        self.assertIn("a", str(caught.exception))

    def test_a_single_tenant_needs_no_name(self):
        self.assertEqual(cli.select_tenant({"a": make_config(key="a")}, None).key, "a")

    def test_several_tenants_without_a_name_is_an_error(self):
        with self.assertRaises(graph.GraphError):
            cli.select_tenant({"a": make_config(key="a"), "b": make_config(key="b")}, None)


class MainTest(unittest.TestCase):
    """The exit code is what a scheduled task or PRTG evaluates."""

    def _run(self, argv, **patches):
        defaults = dict(load_tenants=mock.DEFAULT, scan_tenant=mock.DEFAULT)
        defaults.update(patches)
        out = io.StringIO()
        with mock.patch.multiple(graph, **defaults) as mocks, redirect_stdout(out):
            mocks["load_tenants"].return_value = {"demo": make_config()}
            if "scan_tenant" in mocks and mocks["scan_tenant"] is not None:
                mocks["scan_tenant"].return_value = graph.build_result(
                    [make_credential(app_name="Alpha")], make_config())
            code = cli.main(argv)
        return code, out.getvalue()

    def test_list_tenants_prints_and_succeeds(self):
        code, output = self._run(["--list-tenants"])
        self.assertEqual(code, 0)
        self.assertIn("demo", output)

    def test_json_output_is_parsable(self):
        code, output = self._run(["--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["tenant"], "demo")

    def test_text_output_is_human_readable(self):
        code, output = self._run(["--format", "text"])
        self.assertEqual(code, 0)
        self.assertIn("Alpha", output)

    def test_prtg_output_is_xml(self):
        code, output = self._run([])
        self.assertEqual(code, 0)
        self.assertIn("<prtg>", output)

    def test_scan_failure_still_yields_prtg_error_xml_and_exit_zero(self):
        # PRTG must receive parsable XML, otherwise it reports a parse error
        # instead of the credential problem the sensor is meant to show.
        out = io.StringIO()
        with mock.patch.object(graph, "load_tenants",
                               side_effect=graph.GraphError("kaputt")), \
             redirect_stdout(out):
            code = cli.main([])
        self.assertEqual(code, 0)
        self.assertIn("<error>1</error>", out.getvalue())

    def test_scan_failure_in_other_formats_exits_nonzero(self):
        err = io.StringIO()
        with mock.patch.object(graph, "load_tenants",
                               side_effect=graph.GraphError("kaputt")), \
             redirect_stderr(err), redirect_stdout(io.StringIO()):
            code = cli.main(["--format", "json"])
        self.assertEqual(code, 2)
        self.assertIn("kaputt", err.getvalue())

    def test_failed_push_exits_nonzero(self):
        err = io.StringIO()
        with mock.patch.object(graph, "load_tenants",
                               return_value={"demo": make_config(push_url="https://p")}), \
             mock.patch.object(graph, "scan_tenant",
                               return_value=graph.build_result([], make_config())), \
             mock.patch.object(graph, "push_to_prtg",
                               side_effect=OSError("Netz weg")), \
             redirect_stderr(err), redirect_stdout(io.StringIO()):
            code = cli.main([])
        self.assertEqual(code, 2)
        self.assertIn("Push fehlgeschlagen", err.getvalue())


if __name__ == "__main__":
    unittest.main()
