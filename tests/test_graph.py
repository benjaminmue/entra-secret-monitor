"""Tests for app/graph.py: configuration, Graph access, aggregation, renderers."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import graph

from .support import VALID_CLIENT, VALID_TENANT, graph_object, make_config, make_credential


# --------------------------------------------------------------------------
# Value parsing
# --------------------------------------------------------------------------

class AsBoolTest(unittest.TestCase):
    def test_truthy_spellings(self):
        for value in ("1", "true", "TRUE", " yes ", "ja", "on"):
            self.assertTrue(graph._as_bool(value), value)

    def test_falsy_and_unknown_values(self):
        for value in ("0", "false", "nein", "off", "vielleicht"):
            self.assertFalse(graph._as_bool(value), value)

    def test_empty_and_none_fall_back_to_default(self):
        self.assertTrue(graph._as_bool("", default=True))
        self.assertTrue(graph._as_bool(None, default=True))
        self.assertFalse(graph._as_bool("", default=False))


class AsIntTest(unittest.TestCase):
    def test_parses_surrounding_whitespace(self):
        self.assertEqual(graph._as_int(" 42 ", 7), 42)

    def test_falls_back_on_garbage(self):
        for value in ("abc", "", None, "1.5"):
            self.assertEqual(graph._as_int(value, 7), 7, value)


class ClampChannelsTest(unittest.TestCase):
    """The PRTG sensor breaks above 50 channels, three of which are the summary."""

    def test_values_in_range_pass_through(self):
        for value in (1, 20, graph.MAX_APP_CHANNELS):
            self.assertEqual(graph._clamp_channels(value), value)

    def test_above_limit_is_capped(self):
        self.assertEqual(graph._clamp_channels(graph.MAX_APP_CHANNELS + 1),
                         graph.MAX_APP_CHANNELS)
        self.assertEqual(graph._clamp_channels(10_000), graph.MAX_APP_CHANNELS)

    def test_zero_and_negative_become_one(self):
        # A negative value would slice the channel list from the end.
        self.assertEqual(graph._clamp_channels(0), 1)
        self.assertEqual(graph._clamp_channels(-5), 1)

    def test_garbage_falls_back_to_default(self):
        self.assertEqual(graph._clamp_channels("abc"), 45)
        self.assertEqual(graph._clamp_channels(None), 45)

    def test_summary_channels_still_fit_under_the_prtg_limit(self):
        self.assertLessEqual(graph.MAX_APP_CHANNELS + graph.SUMMARY_CHANNELS,
                             graph.PRTG_CHANNEL_LIMIT)


class EnvPrefixTest(unittest.TestCase):
    def test_uppercases_and_replaces_non_alphanumerics(self):
        self.assertEqual(graph._env_prefix("demo"), "DEMO_")
        self.assertEqual(graph._env_prefix("my-tenant"), "MY_TENANT_")
        self.assertEqual(graph._env_prefix("a.b c"), "A_B_C_")


class ParseDateTest(unittest.TestCase):
    def test_zulu_suffix_becomes_utc(self):
        parsed = graph.parse_date("2026-01-15T10:00:00Z")
        self.assertEqual(parsed.tzinfo, timezone.utc)
        self.assertEqual(parsed.hour, 10)

    def test_offset_is_normalised_to_utc(self):
        self.assertEqual(graph.parse_date("2026-01-15T12:00:00+02:00").hour, 10)

    def test_seven_digit_fraction_from_graph_is_truncated(self):
        # Graph sends 7 fractional digits, fromisoformat accepts at most 6.
        parsed = graph.parse_date("2026-01-15T10:00:00.1234567Z")
        self.assertEqual(parsed.microsecond, 123456)


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

class TenantConfigTest(unittest.TestCase):
    def test_display_name_defaults_to_key(self):
        self.assertEqual(make_config(key="demo").display_name, "demo")

    def test_explicit_display_name_is_kept(self):
        self.assertEqual(make_config(display_name="Contoso").display_name, "Contoso")

    def test_missing_identifiers_are_rejected(self):
        with self.assertRaises(graph.GraphError):
            make_config(tenant_id="")
        with self.assertRaises(graph.GraphError):
            make_config(client_id="")

    def test_missing_credentials_are_rejected(self):
        with self.assertRaises(graph.GraphError):
            make_config(client_secret="")

    def test_certificate_pair_is_accepted_without_a_secret(self):
        cfg = make_config(client_secret="", cert_path="/c.crt", key_path="/c.key")
        self.assertEqual(cfg.cert_path, "/c.crt")

    def test_half_a_certificate_pair_is_not_enough(self):
        with self.assertRaises(graph.GraphError):
            make_config(client_secret="", cert_path="/c.crt")

    def test_channel_limit_is_an_invariant_of_the_config(self):
        # Whatever route builds the config, the value must stay renderable.
        self.assertEqual(make_config(max_channels=10_000).max_channels,
                         graph.MAX_APP_CHANNELS)
        self.assertEqual(make_config(max_channels=-1).max_channels, 1)


class TenantFromEnvTest(unittest.TestCase):
    def test_reads_prefixed_variables(self):
        cfg = graph.tenant_from_env("demo", {
            "DEMO_TENANT_ID": VALID_TENANT, "DEMO_CLIENT_ID": VALID_CLIENT,
            "DEMO_CLIENT_SECRET": "s", "DEMO_WARN_DAYS": "60",
            "DEMO_INCLUDE_SP": "true"})
        self.assertEqual(cfg.warn_days, 60)
        self.assertTrue(cfg.include_sp)

    def test_unprefixed_variable_is_the_fallback(self):
        cfg = graph.tenant_from_env("demo", {
            "TENANT_ID": VALID_TENANT, "CLIENT_ID": VALID_CLIENT,
            "CLIENT_SECRET": "s", "WARN_DAYS": "21"})
        self.assertEqual(cfg.warn_days, 21)

    def test_prefixed_wins_over_unprefixed(self):
        cfg = graph.tenant_from_env("demo", {
            "TENANT_ID": VALID_TENANT, "CLIENT_ID": VALID_CLIENT,
            "CLIENT_SECRET": "s", "WARN_DAYS": "21", "DEMO_WARN_DAYS": "60"})
        self.assertEqual(cfg.warn_days, 60)


class TenantFromDictTest(unittest.TestCase):
    def test_reads_all_documented_keys(self):
        cfg = graph.tenant_from_dict("demo", {
            "tenant_id": VALID_TENANT, "client_id": VALID_CLIENT,
            "client_secret": "s", "display_name": "Contoso",
            "warn_days": 60, "include_sp": True})
        self.assertEqual((cfg.display_name, cfg.warn_days, cfg.include_sp),
                         ("Contoso", 60, True))

    def test_missing_optional_keys_use_defaults(self):
        cfg = graph.tenant_from_dict("demo", {
            "tenant_id": VALID_TENANT, "client_id": VALID_CLIENT, "client_secret": "s"})
        self.assertEqual((cfg.warn_days, cfg.error_days), (30, 14))


class LoadTenantsTest(unittest.TestCase):
    ENV = {"TENANT_ID": VALID_TENANT, "CLIENT_ID": VALID_CLIENT, "CLIENT_SECRET": "s"}

    def test_tenants_list_creates_one_config_per_key(self):
        env = {"TENANTS": "a, b", **self.ENV}
        self.assertEqual(sorted(graph.load_tenants(env, config_path="")), ["a", "b"])

    def test_single_unprefixed_tenant_is_named_default(self):
        self.assertEqual(list(graph.load_tenants(self.ENV, config_path="")), ["default"])

    def test_empty_configuration_raises_the_distinguishable_error(self):
        # The GUI tells "nothing configured" apart from "configured but broken".
        with self.assertRaises(graph.NoTenantsConfigured):
            graph.load_tenants({}, config_path="")
        self.assertTrue(issubclass(graph.NoTenantsConfigured, graph.GraphError))

    def test_json_file_is_merged_and_wins_over_the_environment(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tenants.json"
            path.write_text(json.dumps({
                "default": {"tenant_id": VALID_TENANT, "client_id": VALID_CLIENT,
                            "client_secret": "s", "display_name": "Aus Datei"},
                "extra": {"tenant_id": VALID_TENANT, "client_id": VALID_CLIENT,
                          "client_secret": "s"}}), encoding="utf-8")
            tenants = graph.load_tenants(self.ENV, config_path=str(path))
        self.assertEqual(sorted(tenants), ["default", "extra"])
        self.assertEqual(tenants["default"].display_name, "Aus Datei")


# --------------------------------------------------------------------------
# Authentication and Graph access
# --------------------------------------------------------------------------

class GetTokenTest(unittest.TestCase):
    def test_secret_configuration_sends_the_secret(self):
        with mock.patch.object(graph, "_post_token", return_value="tok") as post:
            self.assertEqual(graph.get_token(make_config()), "tok")
        self.assertEqual(post.call_args[0][1]["client_secret"], "secret")

    def test_certificate_configuration_sends_an_assertion(self):
        cfg = make_config(client_secret="", cert_path="/c.crt", key_path="/c.key")
        with mock.patch.object(graph, "_client_assertion", return_value="jwt"), \
             mock.patch.object(graph, "_post_token", return_value="tok") as post:
            graph.get_token(cfg)
        data = post.call_args[0][1]
        self.assertEqual(data["client_assertion"], "jwt")
        self.assertNotIn("client_secret", data)

    def test_certificate_wins_when_both_are_configured(self):
        cfg = make_config(cert_path="/c.crt", key_path="/c.key")
        with mock.patch.object(graph, "_client_assertion", return_value="jwt"), \
             mock.patch.object(graph, "_post_token", return_value="tok") as post:
            graph.get_token(cfg)
        self.assertIn("client_assertion", post.call_args[0][1])


class GraphGetAllTest(unittest.TestCase):
    """Paging must be followed, otherwise large tenants report too few objects."""

    def _responses(self, pages):
        for page in pages:
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.read.return_value = json.dumps(page).encode()
            yield response

    def test_follows_next_link_until_exhausted(self):
        pages = [{"value": [1, 2], "@odata.nextLink": "https://graph/next"},
                 {"value": [3]}]
        with mock.patch.object(graph.json, "load",
                               side_effect=pages), \
             mock.patch.object(graph.urllib.request, "urlopen",
                               side_effect=list(self._responses(pages))):
            items = graph.graph_get_all("tok", "/applications")
        self.assertEqual(items, [1, 2, 3])

    def test_single_page_makes_one_request(self):
        page = {"value": [1]}
        with mock.patch.object(graph.json, "load", side_effect=[page]), \
             mock.patch.object(graph.urllib.request, "urlopen",
                               side_effect=list(self._responses([page]))) as opened:
            self.assertEqual(graph.graph_get_all("tok", "/applications"), [1])
        self.assertEqual(opened.call_count, 1)


class CollectCredentialsTest(unittest.TestCase):
    def test_flattens_secrets_and_certificates(self):
        objects = [graph_object("App", secrets=[10, 20], certs=[30])]
        with mock.patch.object(graph, "graph_get_all", return_value=objects):
            creds = graph.collect_credentials("tok", include_sp=False)
        self.assertEqual(len(creds), 3)
        self.assertEqual(sorted(c.cred_type for c in creds), ["cert", "secret", "secret"])

    def test_object_identity_is_carried_through(self):
        # Without the object id, aggregation cannot tell two same-named apps apart.
        objects = [graph_object("App", object_id="obj-1", app_id="app-1", secrets=[10])]
        with mock.patch.object(graph, "graph_get_all", return_value=objects):
            cred = graph.collect_credentials("tok", include_sp=False)[0]
        self.assertEqual((cred.object_id, cred.app_id, cred.object_type),
                         ("obj-1", "app-1", "application"))

    def test_service_principals_are_queried_only_when_requested(self):
        with mock.patch.object(graph, "graph_get_all", return_value=[]) as get:
            graph.collect_credentials("tok", include_sp=False)
            self.assertEqual(get.call_count, 1)
            get.reset_mock()
            graph.collect_credentials("tok", include_sp=True)
            self.assertEqual(get.call_count, 2)

    def test_credentials_without_an_end_date_are_skipped(self):
        obj = graph_object("App", secrets=[10])
        obj["passwordCredentials"].append({"displayName": "kaputt", "keyId": "x"})
        with mock.patch.object(graph, "graph_get_all", return_value=[obj]):
            self.assertEqual(len(graph.collect_credentials("tok", False)), 1)

    def test_object_without_a_display_name_falls_back_to_the_app_id(self):
        obj = graph_object("App", app_id="app-1", secrets=[10])
        del obj["displayName"]
        with mock.patch.object(graph, "graph_get_all", return_value=[obj]):
            self.assertEqual(graph.collect_credentials("tok", False)[0].app_name, "app-1")


class CredentialTest(unittest.TestCase):
    def test_days_left_counts_down(self):
        self.assertEqual(make_credential(days=10).days_left, 10)

    def test_days_left_is_negative_once_expired(self):
        self.assertLess(make_credential(days=-3).days_left, 0)


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

class BuildChannelsTest(unittest.TestCase):
    def test_rolled_credential_hides_the_old_one_on_the_same_object(self):
        # A fresh secret makes the old one irrelevant, that is the intended merge.
        channels = graph.build_channels(
            [make_credential(days=300), make_credential(days=5)], make_config())
        self.assertEqual(len(channels), 1)
        self.assertEqual(channels[0]["days"], 300)
        self.assertEqual(channels[0]["count"], 2)

    def test_two_registrations_sharing_a_name_stay_separate(self):
        # Regression: grouping by display name hid an expiring credential behind
        # a healthy one belonging to a completely different registration.
        channels = graph.build_channels([
            make_credential(app_name="Doppel", app_id="app-a", object_id="obj-1", days=300),
            make_credential(app_name="Doppel", app_id="app-b", object_id="obj-2", days=5),
        ], make_config())
        self.assertEqual(len(channels), 2)
        self.assertEqual(min(c["days"] for c in channels), 5)

    def test_application_and_service_principal_stay_separate(self):
        # Both carry the same appId and display name, only the object type differs.
        channels = graph.build_channels([
            make_credential(app_name="Beide", object_id="obj-1",
                            object_type="application", days=300),
            make_credential(app_name="Beide", object_id="obj-2",
                            object_type="servicePrincipal", days=9),
        ], make_config())
        self.assertEqual(len(channels), 2)
        self.assertEqual(min(c["days"] for c in channels), 9)

    def test_secrets_and_certificates_are_separate_channels(self):
        channels = graph.build_channels(
            [make_credential(cred_type="secret"), make_credential(cred_type="cert")],
            make_config())
        self.assertEqual(len(channels), 2)

    def test_expired_credentials_are_hidden_unless_requested(self):
        creds = [make_credential(days=-5)]
        self.assertEqual(graph.build_channels(creds, make_config()), [])
        self.assertEqual(len(graph.build_channels(creds, make_config(show_expired=True))), 1)

    def test_filter_keeps_only_matching_names(self):
        creds = [make_credential(app_name="Alpha", object_id="1"),
                 make_credential(app_name="Beta", object_id="2")]
        channels = graph.build_channels(creds, make_config(app_filter="alph"))
        self.assertEqual([c["app"] for c in channels], ["Alpha"])

    def test_exclude_drops_matching_names_and_wins_over_filter(self):
        creds = [make_credential(app_name="Alpha", object_id="1"),
                 make_credential(app_name="Alpha Backup", object_id="2")]
        channels = graph.build_channels(
            creds, make_config(app_filter="alpha", app_exclude="backup"))
        self.assertEqual([c["app"] for c in channels], ["Alpha"])

    def test_exclude_accepts_a_comma_separated_list(self):
        creds = [make_credential(app_name=n, object_id=n) for n in ("A", "B", "C")]
        channels = graph.build_channels(creds, make_config(app_exclude="a, b"))
        self.assertEqual([c["app"] for c in channels], ["C"])

    def test_channels_are_sorted_by_urgency(self):
        creds = [make_credential(app_name="spaet", object_id="1", days=300),
                 make_credential(app_name="bald", object_id="2", days=5)]
        self.assertEqual([c["app"] for c in graph.build_channels(creds, make_config())],
                         ["bald", "spaet"])


class ChannelNamingTest(unittest.TestCase):
    """PRTG matches values to channels by name, duplicates break a sensor."""

    def test_unique_names_get_no_suffix(self):
        channels = graph.build_channels([make_credential(app_name="Solo")], make_config())
        self.assertEqual(channels[0]["name"], "Solo (Secret)")

    def test_object_type_separates_application_from_service_principal(self):
        channels = graph.build_channels([
            make_credential(app_name="Beide", object_id="1", object_type="application"),
            make_credential(app_name="Beide", object_id="2", object_type="servicePrincipal"),
        ], make_config())
        self.assertEqual({c["name"] for c in channels},
                         {"Beide (Secret) [App]", "Beide (Secret) [SP]"})

    def test_app_id_separates_two_registrations_of_the_same_type(self):
        channels = graph.build_channels([
            make_credential(app_name="Doppel", app_id="aaaa1111", object_id="1"),
            make_credential(app_name="Doppel", app_id="bbbb2222", object_id="2"),
        ], make_config())
        # The object type would not tell them apart, so it must not be appended.
        for channel in channels:
            self.assertNotIn("[App]", channel["name"])
        self.assertEqual(len({c["name"] for c in channels}), 2)

    def test_names_stay_unique_even_without_usable_identifiers(self):
        channels = graph.build_channels([
            make_credential(app_name="Leer", app_id="", object_id="1"),
            make_credential(app_name="Leer", app_id="", object_id="2"),
        ], make_config())
        self.assertEqual(len({c["name"] for c in channels}), len(channels))

    def test_certificates_are_labelled_in_german(self):
        channels = graph.build_channels(
            [make_credential(app_name="Solo", cred_type="cert")], make_config())
        self.assertEqual(channels[0]["name"], "Solo (Zertifikat)")


class SharedNamesTest(unittest.TestCase):
    def test_returns_only_the_colliding_groups(self):
        channels = [{"name": "a"}, {"name": "a"}, {"name": "b"}]
        groups = graph._shared_names(channels)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]), 2)

    def test_returns_nothing_when_all_names_are_unique(self):
        self.assertEqual(graph._shared_names([{"name": "a"}, {"name": "b"}]), [])


class SummarizeTest(unittest.TestCase):
    def test_counts_critical_and_expired_separately(self):
        channels = [{"days": -1}, {"days": 5}, {"days": 300}]
        summary = graph.summarize(channels, make_config(warn_days=30))
        self.assertEqual(summary, {"minimum": -1, "critical": 1, "expired": 1, "total": 3})

    def test_expired_does_not_count_as_critical(self):
        summary = graph.summarize([{"days": -10}], make_config(warn_days=30))
        self.assertEqual((summary["critical"], summary["expired"]), (0, 1))

    def test_empty_input_reports_a_harmless_minimum(self):
        # 9999 keeps an empty tenant from turning the sensor red.
        self.assertEqual(graph.summarize([], make_config())["minimum"], 9999)


class BuildResultTest(unittest.TestCase):
    def test_carries_tenant_metadata_and_channels(self):
        result = graph.build_result([make_credential()], make_config(display_name="Contoso"))
        self.assertEqual(result["tenant"], "demo")
        self.assertEqual(result["display_name"], "Contoso")
        self.assertEqual(result["summary"]["total"], 1)
        self.assertIn("checked", result)

    def test_scan_tenant_combines_fetching_and_building(self):
        with mock.patch.object(graph, "fetch_credentials", return_value=[make_credential()]):
            self.assertEqual(graph.scan_tenant(make_config())["summary"]["total"], 1)

    def test_fetch_credentials_passes_the_service_principal_flag(self):
        with mock.patch.object(graph, "get_token", return_value="tok"), \
             mock.patch.object(graph, "collect_credentials", return_value=[]) as collect:
            graph.fetch_credentials(make_config(include_sp=True))
        self.assertEqual(collect.call_args[0], ("tok", True))


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------

class RenderPrtgTest(unittest.TestCase):
    def _xml(self, creds, **cfg_kwargs):
        cfg = make_config(**cfg_kwargs)
        return graph.render_prtg(graph.build_result(creds, cfg), cfg)

    def test_contains_the_three_summary_channels_plus_one_per_app(self):
        xml = self._xml([make_credential(app_name="A", object_id="1"),
                         make_credential(app_name="B", object_id="2")])
        self.assertEqual(xml.count("<result>"), graph.SUMMARY_CHANNELS + 2)

    def test_never_exceeds_the_prtg_channel_limit(self):
        creds = [make_credential(app_name="App%03d" % i, object_id=str(i), days=i + 10)
                 for i in range(80)]
        for requested in (45, 48, 100, -5):
            xml = self._xml(creds, max_channels=requested)
            self.assertLessEqual(xml.count("<result>"), graph.PRTG_CHANNEL_LIMIT,
                                 "max_channels=%s" % requested)

    def test_is_well_formed_xml(self):
        from xml.etree import ElementTree
        ElementTree.fromstring(self._xml([make_credential()]))

    def test_thresholds_are_rendered_as_limits(self):
        self.assertIn("<limitmode>1</limitmode>", self._xml([make_credential()]))


class RenderPrtgErrorTest(unittest.TestCase):
    def test_marks_the_sensor_as_failed(self):
        xml = graph.render_prtg_error("kaputt")
        self.assertIn("<error>1</error>", xml)
        self.assertIn("kaputt", xml)

    def test_is_well_formed_and_truncates_long_messages(self):
        from xml.etree import ElementTree
        root = ElementTree.fromstring(graph.render_prtg_error("x" * 5000))
        self.assertLessEqual(len(root.findtext("text")), 2000)


class RenderTextTest(unittest.TestCase):
    def test_lists_every_channel_with_a_summary_line(self):
        cfg = make_config()
        result = graph.build_result([make_credential(app_name="Alpha")], cfg)
        text = graph.render_text(result, cfg)
        self.assertIn("Alpha", text)
        self.assertIn("1 Eintraege", text)

    def test_marks_urgent_entries(self):
        cfg = make_config(warn_days=30, error_days=14)
        result = graph.build_result([make_credential(app_name="Bald", days=3)], cfg)
        self.assertIn("!!", graph.render_text(result, cfg))


class PushToPrtgTest(unittest.TestCase):
    def test_posts_the_xml_as_form_content(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        with mock.patch.object(graph.urllib.request, "urlopen",
                               return_value=response) as opened:
            graph.push_to_prtg("https://prtg.example/push", "<prtg/>")
        request = opened.call_args[0][0]
        self.assertIn(b"content=", request.data)
        self.assertEqual(request.headers["Content-type"],
                         "application/x-www-form-urlencoded")


if __name__ == "__main__":
    unittest.main()
