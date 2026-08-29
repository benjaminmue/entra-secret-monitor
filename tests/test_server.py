"""Tests for app/server.py: caching, request overrides, HTML rendering."""
import unittest
from unittest import mock

import graph
import server

from .support import make_config, make_credential


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


if __name__ == "__main__":
    unittest.main()
