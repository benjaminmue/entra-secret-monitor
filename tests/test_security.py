"""
Security tests: injection into every output format, authentication, hardening.

The HTTP cases run against a real server on a loopback port, because response
headers and the reflection behaviour of an error page cannot be observed by
calling the render functions alone.
"""
import unittest
from unittest import mock
from xml.etree import ElementTree

import graph
import server

from .support import LiveServer, make_config, make_credential

XSS = "<script>alert(1)</script>"
XML_BREAKER = "]]></text><injected>x</injected><text>"


# --------------------------------------------------------------------------
# Injection into the rendered output
# --------------------------------------------------------------------------

class HtmlEscapingTest(unittest.TestCase):
    """Every value that reaches HTML comes from Graph or the URL, never trusted."""

    def test_application_name_from_graph_is_escaped(self):
        cfg = make_config()
        result = graph.build_result([make_credential(app_name=XSS)], cfg)
        html_out = server.render_tenant_block(result, "")
        self.assertNotIn("<script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)

    def test_credential_name_from_graph_is_escaped(self):
        cfg = make_config()
        result = graph.build_result([make_credential(display_name=XSS)], cfg)
        self.assertNotIn("<script>", server.render_tenant_block(result, ""))

    def test_tenant_display_name_is_escaped(self):
        cfg = make_config(display_name=XSS)
        result = graph.build_result([make_credential()], cfg)
        self.assertNotIn("<script>", server.render_tenant_block(result, ""))

    def test_error_text_is_escaped(self):
        result = graph.build_result([], make_config())
        result["error"] = XSS
        self.assertNotIn("<script>", server.render_tenant_block(result, ""))

    def test_config_error_on_the_page_is_escaped(self):
        self.assertNotIn("<script>", server.render_page([], "", "host", XSS))

    def test_host_header_is_escaped_into_the_hint(self):
        # The Host header is attacker controlled and ends up in the example URL.
        self.assertNotIn("<script>", server.render_page([], "", XSS))

    def test_badge_label_is_escaped(self):
        self.assertNotIn("<script>", server.badge(-1, 30, 14))


class XmlEscapingTest(unittest.TestCase):
    """Broken PRTG XML costs the sensor entirely, so escaping must hold."""

    def test_application_name_cannot_break_out_of_a_channel(self):
        cfg = make_config()
        result = graph.build_result([make_credential(app_name=XML_BREAKER)], cfg)
        xml = graph.render_prtg(result, cfg)
        root = ElementTree.fromstring(xml)          # raises if malformed
        self.assertIsNone(root.find(".//injected"))

    def test_error_message_cannot_inject_elements(self):
        root = ElementTree.fromstring(graph.render_prtg_error(XML_BREAKER))
        self.assertIsNone(root.find(".//injected"))
        self.assertEqual(root.findtext("error"), "1")

    def test_control_characters_do_not_produce_malformed_xml(self):
        cfg = make_config()
        result = graph.build_result([make_credential(app_name='a"b\'c&d<e>f')], cfg)
        ElementTree.fromstring(graph.render_prtg(result, cfg))


class LogRedactionTest(unittest.TestCase):
    """Container logs are often shipped somewhere central."""

    def test_token_in_the_query_string_is_redacted(self):
        line = '127.0.0.1 "GET /?token=GEHEIM HTTP/1.1" 200 -'
        self.assertEqual(server._TOKEN_IN_QUERY.sub(r"\1<redacted>", line),
                         '127.0.0.1 "GET /?token=<redacted> HTTP/1.1" 200 -')

    def test_token_as_a_later_parameter_is_redacted(self):
        line = "GET /prtg?tenant=demo&token=GEHEIM HTTP/1.1"
        redacted = server._TOKEN_IN_QUERY.sub(r"\1<redacted>", line)
        self.assertNotIn("GEHEIM", redacted)
        self.assertIn("tenant=demo", redacted)

    def test_redaction_is_case_insensitive(self):
        self.assertNotIn("GEHEIM", server._TOKEN_IN_QUERY.sub(
            r"\1<redacted>", "GET /?TOKEN=GEHEIM HTTP/1.1"))

    def test_other_parameters_survive_untouched(self):
        line = "GET /?filter=abc&warn=30 HTTP/1.1"
        self.assertEqual(server._TOKEN_IN_QUERY.sub(r"\1<redacted>", line), line)


# --------------------------------------------------------------------------
# Live server: authentication and hardening
# --------------------------------------------------------------------------

class LiveServerTest(unittest.TestCase):
    """Boots the real handler, so headers and status codes are observed."""

    TOKEN = "GEHEIM-TOKEN-12345"

    @classmethod
    def setUpClass(cls):
        cls.server = LiveServer(
            tenants={"demo": make_config()}, token=cls.TOKEN,
            result=lambda cfg: graph.build_result(
                [make_credential(app_name="Alpha")], cfg)).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def get(self, path, headers=None):
        """Delegate to the shared server helper."""
        return self.server.get(path, headers)

    # -- authentication ----------------------------------------------------

    def test_request_without_a_token_is_rejected(self):
        self.assertEqual(self.get("/")[0], 401)

    def test_wrong_token_is_rejected(self):
        self.assertEqual(self.get("/?token=falsch")[0], 401)

    def test_correct_token_in_the_query_is_accepted(self):
        self.assertEqual(self.get("/?token=" + self.TOKEN)[0], 200)

    def test_correct_token_as_a_bearer_header_is_accepted(self):
        status, _, _ = self.get("/", {"Authorization": "Bearer " + self.TOKEN})
        self.assertEqual(status, 200)

    def test_bearer_prefix_is_matched_case_insensitively(self):
        status, _, _ = self.get("/", {"Authorization": "bearer " + self.TOKEN})
        self.assertEqual(status, 200)

    def test_non_ascii_token_is_rejected_without_crashing(self):
        # compare_digest raises TypeError on non-ASCII strings; an unauthenticated
        # request must never be able to kill the handler.
        self.assertEqual(self.get("/?token=%C3%A4")[0], 401)

    def test_health_endpoint_stays_reachable_without_a_token(self):
        self.assertEqual(self.get("/healthz")[0], 200)

    def test_token_is_not_echoed_back_into_the_page(self):
        _, _, body = self.get("/healthz")
        self.assertNotIn(self.TOKEN, body)

    # -- hardening ---------------------------------------------------------

    def test_security_headers_are_present(self):
        _, headers, _ = self.get("/?token=" + self.TOKEN)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertIn("default-src 'none'", headers.get("Content-Security-Policy", ""))

    def test_content_security_policy_forbids_scripts(self):
        # The GUI ships no JavaScript, so a reflection cannot be executed even
        # if escaping were ever missed somewhere.
        _, headers, _ = self.get("/?token=" + self.TOKEN)
        policy = headers.get("Content-Security-Policy", "")
        self.assertNotIn("script-src", policy)
        self.assertIn("default-src 'none'", policy)

    def test_error_responses_carry_the_headers_too(self):
        _, headers, _ = self.get("/")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_responses_are_not_cached(self):
        _, headers, _ = self.get("/?token=" + self.TOKEN)
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    # -- reflection --------------------------------------------------------

    def test_unknown_tenant_is_reflected_only_as_plain_text_with_nosniff(self):
        status, headers, body = self.get(
            "/?tenant=%3Cscript%3Ealert(1)%3C/script%3E&token=" + self.TOKEN)
        self.assertEqual(status, 404)
        self.assertTrue(headers["Content-Type"].startswith("text/plain"))
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_unknown_tenant_on_the_prtg_route_yields_escaped_xml(self):
        _, _, body = self.get(
            "/prtg?tenant=%3Cscript%3Ealert(1)%3C/script%3E&token=" + self.TOKEN)
        self.assertNotIn("<script>", body)
        ElementTree.fromstring(body)

    def test_bad_parameter_is_reported_without_reflecting_markup(self):
        _, _, body = self.get("/prtg?tenant=demo&warn=%3Cscript%3E&token=" + self.TOKEN)
        self.assertNotIn("<script>", body)


if __name__ == "__main__":
    unittest.main()
