"""Tests for app/server.py: caching, request overrides, rendering, routing."""
import json
import unittest
from unittest import mock
from xml.etree import ElementTree

import graph
import server

from .support import LiveServer, make_config, make_credential


class CacheTest(unittest.TestCase):
    """Only the Graph round trip is cached, so filters stay free per request."""

    def setUp(self):
        server._cache.clear()
        self.addCleanup(server._cache.clear)

    def test_second_call_within_the_ttl_is_served_from_cache(self):
        with mock.patch.object(graph, "fetch_credentials",
                               return_value=[make_credential()]) as fetch:
            cfg = make_config()
            server.get_credentials(cfg)
            server.get_credentials(cfg)
        self.assertEqual(fetch.call_count, 1)

    def test_force_bypasses_the_cache(self):
        with mock.patch.object(graph, "fetch_credentials",
                               return_value=[make_credential()]) as fetch:
            cfg = make_config()
            server.get_credentials(cfg)
            server.get_credentials(cfg, force=True)
        self.assertEqual(fetch.call_count, 2)

    def test_expired_entries_are_refetched(self):
        with mock.patch.object(graph, "fetch_credentials",
                               return_value=[make_credential()]) as fetch, \
             mock.patch.object(server, "CACHE_TTL", 0):
            cfg = make_config()
            server.get_credentials(cfg)
            server.get_credentials(cfg)
        self.assertEqual(fetch.call_count, 2)

    def test_tenants_are_cached_independently(self):
        with mock.patch.object(graph, "fetch_credentials",
                               return_value=[make_credential()]) as fetch:
            server.get_credentials(make_config(key="a"))
            server.get_credentials(make_config(key="b"))
        self.assertEqual(fetch.call_count, 2)

    def test_get_result_builds_from_the_cached_credentials(self):
        with mock.patch.object(graph, "fetch_credentials",
                               return_value=[make_credential()]):
            self.assertEqual(server.get_result(make_config())["summary"]["total"], 1)


class GetResultSafeTest(unittest.TestCase):
    def setUp(self):
        server._cache.clear()
        self.addCleanup(server._cache.clear)

    def test_failures_become_an_error_result_instead_of_an_exception(self):
        # One broken tenant must not take the whole overview page down.
        with mock.patch.object(graph, "fetch_credentials",
                               side_effect=graph.GraphError("kaputt")):
            result = server.get_result_safe(make_config())
        self.assertIn("kaputt", result["error"])
        self.assertEqual(result["channels"], [])
        self.assertEqual(result["summary"]["total"], 0)

    def test_successful_scans_carry_no_error_key(self):
        with mock.patch.object(graph, "fetch_credentials", return_value=[]):
            self.assertNotIn("error", server.get_result_safe(make_config()))


class ApplyOverridesTest(unittest.TestCase):
    def test_no_parameters_returns_the_same_object(self):
        cfg = make_config()
        self.assertIs(server.apply_overrides(cfg, {}), cfg)

    def test_text_parameters_are_copied(self):
        cfg = server.apply_overrides(make_config(),
                                     {"filter": ["alpha"], "exclude": ["beta"]})
        self.assertEqual((cfg.app_filter, cfg.app_exclude), ("alpha", "beta"))

    def test_numeric_parameters_are_parsed(self):
        cfg = server.apply_overrides(make_config(), {"warn": ["60"], "error": ["7"]})
        self.assertEqual((cfg.warn_days, cfg.error_days), (60, 7))

    def test_boolean_parameter_accepts_the_documented_spellings(self):
        for value in ("1", "true", "yes"):
            self.assertTrue(server.apply_overrides(
                make_config(), {"show_expired": [value]}).show_expired)
        self.assertFalse(server.apply_overrides(
            make_config(), {"show_expired": ["0"]}).show_expired)

    def test_non_numeric_values_are_rejected_with_the_parameter_name(self):
        with self.assertRaises(ValueError) as caught:
            server.apply_overrides(make_config(), {"warn": ["abc"]})
        self.assertIn("warn", str(caught.exception))

    def test_out_of_range_channel_count_is_rejected_rather_than_clamped(self):
        # A deliberate request deserves an answer, unlike a config typo.
        for value in ("0", "-1", str(graph.MAX_APP_CHANNELS + 1)):
            with self.assertRaises(ValueError, msg=value):
                server.apply_overrides(make_config(), {"max_channels": [value]})

    def test_channel_count_inside_the_range_is_accepted(self):
        cfg = server.apply_overrides(make_config(), {"max_channels": ["20"]})
        self.assertEqual(cfg.max_channels, 20)

    def test_the_original_config_is_left_untouched(self):
        cfg = make_config()
        server.apply_overrides(cfg, {"warn": ["60"]})
        self.assertEqual(cfg.warn_days, 30)

    def test_include_sp_is_deliberately_not_overridable(self):
        # It would change what the shared cache holds for other requests.
        cfg = server.apply_overrides(make_config(), {"include_sp": ["1"]})
        self.assertFalse(cfg.include_sp)


class BadgeTest(unittest.TestCase):
    def test_classes_follow_the_thresholds(self):
        self.assertIn("b-err", server.badge(5, 30, 14))
        self.assertIn("b-warn", server.badge(20, 30, 14))
        self.assertIn("b-ok", server.badge(300, 30, 14))

    def test_expired_values_are_labelled_as_such(self):
        self.assertIn("abgelaufen", server.badge(-3, 30, 14))

    def test_boundaries_belong_to_the_calmer_class(self):
        self.assertIn("b-warn", server.badge(14, 30, 14))
        self.assertIn("b-ok", server.badge(30, 30, 14))


class RenderTest(unittest.TestCase):
    def _result(self, **cfg_kwargs):
        cfg = make_config(**cfg_kwargs)
        return graph.build_result([make_credential(app_name="Alpha")], cfg)

    def test_tenant_block_shows_name_and_credentials(self):
        html_out = server.render_tenant_block(self._result(display_name="Contoso"), "")
        self.assertIn("Contoso", html_out)
        self.assertIn("Alpha", html_out)

    def test_tenant_block_shows_the_error_instead_of_a_table(self):
        result = self._result()
        result["error"] = "GraphError: kaputt"
        html_out = server.render_tenant_block(result, "")
        self.assertIn("kaputt", html_out)
        self.assertNotIn("<table", html_out)

    def test_setup_card_names_both_configuration_paths(self):
        html_out = server.render_setup_block()
        self.assertIn("Kein Tenant eingerichtet", html_out)
        self.assertIn("TENANTS=", html_out)
        self.assertIn("tenants.json", html_out)
        self.assertIn("Application.Read.All", html_out)

    def test_page_without_tenants_shows_the_setup_card(self):
        html_out = server.render_page([], "", "host:8099")
        self.assertIn("Kein Tenant eingerichtet", html_out)

    def test_page_with_a_broken_config_shows_the_error_not_the_setup_card(self):
        html_out = server.render_page([], "", "host:8099", "GraphError: kaputt")
        self.assertIn("Konfigurationsfehler", html_out)
        self.assertNotIn("Kein Tenant eingerichtet", html_out)

    def test_page_with_results_renders_them(self):
        html_out = server.render_page([self._result()], "", "host:8099")
        self.assertIn("Alpha", html_out)
        self.assertNotIn("Kein Tenant eingerichtet", html_out)


class RoutingTest(unittest.TestCase):
    """
    Every route against a real server, with a working configuration.

    The security suite covers what happens when a request is rejected; this one
    covers what a caller gets when everything is in order, which is the half a
    monitoring service is actually judged on.
    """

    @classmethod
    def setUpClass(cls):
        cls.server = LiveServer(
            tenants={"demo": make_config(key="demo"),
                     "zweit": make_config(key="zweit")},
            result=lambda cfg: graph.build_result(
                [make_credential(app_name="Alpha", days=5)], cfg)).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_health_endpoint_answers_without_touching_the_configuration(self):
        status, _, body = self.server.get("/healthz")
        self.assertEqual(200, status)
        self.assertIn("ok", body.lower())

    def test_overview_lists_every_configured_tenant(self):
        status, headers, body = self.server.get("/")
        self.assertEqual(200, status)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertIn("demo", body)
        self.assertIn("zweit", body)

    def test_refresh_renders_the_same_page(self):
        status, _, body = self.server.get("/refresh")
        self.assertEqual(200, status)
        self.assertIn("Alpha", body)

    def test_json_returns_a_list_for_all_tenants(self):
        status, headers, body = self.server.get("/json")
        self.assertEqual(200, status)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        payload = json.loads(body)
        self.assertIsInstance(payload, list)
        self.assertEqual(2, len(payload))

    def test_json_returns_one_object_for_a_named_tenant(self):
        _, _, body = self.server.get("/json?tenant=demo")
        payload = json.loads(body)
        self.assertIsInstance(payload, dict)
        self.assertEqual("demo", payload["tenant"])

    def test_prtg_needs_a_tenant_when_several_are_configured(self):
        # Otherwise the sensor would silently describe only one of them.
        _, _, body = self.server.get("/prtg")
        self.assertIn("<error>1</error>", body)
        self.assertIn("tenant=", body)

    def test_prtg_renders_channels_for_a_named_tenant(self):
        status, headers, body = self.server.get("/prtg?tenant=demo")
        self.assertEqual(200, status)
        self.assertTrue(headers["Content-Type"].startswith("text/xml"))
        self.assertIn("Alpha", body)
        self.assertNotIn("<error>1</error>", body)
        ElementTree.fromstring(body)

    def test_prtg_reports_a_bad_override_as_a_red_sensor(self):
        _, _, body = self.server.get("/prtg?tenant=demo&warn=viele")
        self.assertIn("<error>1</error>", body)
        ElementTree.fromstring(body)

    def test_prtg_honours_a_threshold_override(self):
        _, _, body = self.server.get("/prtg?tenant=demo&warn=90&error=60")
        self.assertIn("<limitminwarning>90</limitminwarning>", body)
        self.assertIn("<limitminerror>60</limitminerror>", body)

    def test_an_unknown_route_is_a_404(self):
        status, _, _ = self.server.get("/gibtesnicht")
        self.assertEqual(404, status)


class EmptyResultTest(unittest.TestCase):
    """A tenant with nothing to report must not look like a broken one."""

    @classmethod
    def setUpClass(cls):
        cls.server = LiveServer(
            tenants={"leer": make_config(key="leer")},
            result=lambda cfg: graph.build_result([], cfg)).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_the_page_says_so_instead_of_rendering_an_empty_table(self):
        _, _, body = self.server.get("/")
        self.assertIn("Keine Credentials gefunden", body)

    def test_prtg_still_yields_a_parsable_document(self):
        _, _, body = self.server.get("/prtg?tenant=leer")
        ElementTree.fromstring(body)
        self.assertNotIn("<error>1</error>", body)


class TokenRejectionFormatTest(unittest.TestCase):
    """A rejected sensor request must stay parsable for PRTG."""

    @classmethod
    def setUpClass(cls):
        cls.server = LiveServer(tenants={"demo": make_config()},
                                token="RICHTIG").start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_prtg_answers_a_wrong_token_with_error_xml_not_a_status_code(self):
        # PRTG evaluates <error>; a bare 401 shows up as a parse failure instead.
        status, _, body = self.server.get("/prtg?tenant=demo&token=falsch")
        self.assertEqual(200, status)
        self.assertIn("<error>1</error>", body)
        ElementTree.fromstring(body)

    def test_other_routes_answer_a_wrong_token_with_401(self):
        for path in ("/", "/json"):
            self.assertEqual(401, self.server.get("%s?token=falsch" % path)[0], path)


class PushLoopTest(unittest.TestCase):
    """The push thread must survive every failure it can meet."""

    def test_a_tenant_without_a_push_url_is_skipped(self):
        cfg = make_config(push_url="")
        with mock.patch.object(graph, "load_tenants", return_value={"demo": cfg}), \
             mock.patch.object(graph, "push_to_prtg") as pushed, \
             mock.patch.object(server.time, "sleep", side_effect=StopIteration), \
             mock.patch("builtins.print"):
            with self.assertRaises(StopIteration):
                server.push_loop()
        pushed.assert_not_called()

    def test_a_configured_tenant_is_pushed(self):
        cfg = make_config(push_url="https://prtg.example/push")
        with mock.patch.object(graph, "load_tenants", return_value={"demo": cfg}), \
             mock.patch.object(server, "get_result",
                               return_value=graph.build_result([], cfg)), \
             mock.patch.object(graph, "push_to_prtg") as pushed, \
             mock.patch.object(server.time, "sleep", side_effect=StopIteration), \
             mock.patch("builtins.print"):
            with self.assertRaises(StopIteration):
                server.push_loop()
        pushed.assert_called_once()
        self.assertEqual("https://prtg.example/push", pushed.call_args[0][0])

    def test_a_failing_push_does_not_end_the_loop(self):
        # One unreachable PRTG must not stop the other tenants from being pushed.
        cfg = make_config(push_url="https://prtg.example/push")
        with mock.patch.object(graph, "load_tenants", return_value={"demo": cfg}), \
             mock.patch.object(server, "get_result",
                               return_value=graph.build_result([], cfg)), \
             mock.patch.object(graph, "push_to_prtg", side_effect=OSError("Netz weg")), \
             mock.patch.object(server.time, "sleep", side_effect=StopIteration), \
             mock.patch("builtins.print") as printed:
            with self.assertRaises(StopIteration):
                server.push_loop()
        self.assertIn("push fehlgeschlagen", str(printed.call_args_list))

    def test_a_broken_configuration_does_not_end_the_loop(self):
        with mock.patch.object(graph, "load_tenants",
                               side_effect=graph.GraphError("kaputt")), \
             mock.patch.object(server.time, "sleep", side_effect=StopIteration), \
             mock.patch("builtins.print") as printed:
            with self.assertRaises(StopIteration):
                server.push_loop()
        self.assertIn("push loop", str(printed.call_args_list))


class MainTest(unittest.TestCase):
    """The entry point announces its state and starts serving."""

    def _run_main(self, **patches):
        served = mock.MagicMock()
        defaults = {"serve_forever": served}
        defaults.update(patches)
        with mock.patch.object(server, "ThreadingHTTPServer") as http, \
             mock.patch("builtins.print") as printed:
            http.return_value.serve_forever = defaults["serve_forever"]
            with mock.patch.object(graph, "load_tenants",
                                   defaults.get("load_tenants",
                                                mock.Mock(return_value={"demo": None}))):
                server.main()
        return http, printed, served

    def test_the_configured_tenants_are_announced(self):
        _, printed, served = self._run_main()
        self.assertIn("Tenants: demo", str(printed.call_args_list))
        served.assert_called_once()

    def test_a_broken_configuration_warns_but_still_serves(self):
        # The GUI is reachable without tenants and explains what to configure,
        # so refusing to start here would only hide that page.
        _, printed, served = self._run_main(
            load_tenants=mock.Mock(side_effect=graph.GraphError("keine Tenants")))
        self.assertIn("WARNUNG", str(printed.call_args_list))
        served.assert_called_once()

    def test_the_push_thread_starts_only_when_an_interval_is_set(self):
        with mock.patch.object(server, "PUSH_INTERVAL", 0), \
             mock.patch.object(server.threading, "Thread") as thread:
            self._run_main()
        thread.assert_not_called()

        with mock.patch.object(server, "PUSH_INTERVAL", 300), \
             mock.patch.object(server.threading, "Thread") as thread:
            self._run_main()
        thread.assert_called_once()


class ConfigurationFailureTest(unittest.TestCase):
    """What the endpoints answer while the service has no usable configuration."""

    @classmethod
    def setUpClass(cls):
        def broken(_handler):
            raise graph.NoTenantsConfigured("Keine Tenants konfiguriert")

        cls.server = LiveServer(tenants=None).start()
        cls._patch = mock.patch.object(server.Handler, "_tenants", broken)
        cls._patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._patch.stop()
        cls.server.stop()

    def test_the_gui_explains_what_to_configure(self):
        status, _, body = self.server.get("/")
        self.assertEqual(200, status)
        self.assertIn("Kein Tenant eingerichtet", body)

    def test_prtg_turns_the_sensor_red_rather_than_failing_to_parse(self):
        status, _, body = self.server.get("/prtg")
        self.assertEqual(200, status)
        self.assertIn("<error>1</error>", body)
        ElementTree.fromstring(body)

    def test_json_reports_the_problem_as_a_server_error(self):
        status, _, body = self.server.get("/json")
        self.assertEqual(500, status)
        self.assertIn("Konfigurationsfehler", body)


class BrokenConfigurationTest(unittest.TestCase):
    """A configured but unusable tenant differs from none at all."""

    @classmethod
    def setUpClass(cls):
        def broken(_handler):
            raise graph.GraphError("tenants.json ist kaputt")

        cls.server = LiveServer(tenants=None).start()
        cls._patch = mock.patch.object(server.Handler, "_tenants", broken)
        cls._patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._patch.stop()
        cls.server.stop()

    def test_the_gui_shows_the_error_not_the_setup_card(self):
        _, _, body = self.server.get("/")
        self.assertIn("Konfigurationsfehler", body)
        self.assertNotIn("Kein Tenant eingerichtet", body)


if __name__ == "__main__":
    unittest.main()
