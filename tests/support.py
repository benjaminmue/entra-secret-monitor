"""Shared builders and markers, so no test has to spell out full objects."""
import unittest
from datetime import datetime, timedelta, timezone

import graph

try:
    import flask  # noqa: F401
    import pyotp  # noqa: F401
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

    PORTAL_DEPS_AVAILABLE = True
except ImportError:                  # Die Extras des Portals sind optional,
    PORTAL_DEPS_AVAILABLE = False    # der Dienst in app/ bleibt reine stdlib.

# Marker fuer alles, was Flask, argon2, pyotp oder cryptography braucht.
needs_portal = unittest.skipUnless(
    PORTAL_DEPS_AVAILABLE,
    "Portal-Abhaengigkeiten fehlen, siehe requirements-portal.txt")

VALID_TENANT = "00000000-0000-0000-0000-000000000001"
VALID_CLIENT = "00000000-0000-0000-0000-000000000002"


def make_config(**overrides):
    """A TenantConfig that passes validation, with fields overridable per test."""
    fields = dict(key="demo", tenant_id=VALID_TENANT, client_id=VALID_CLIENT,
                  client_secret="secret")
    fields.update(overrides)
    return graph.TenantConfig(**fields)


def make_credential(app_name="App", days=100, **overrides):
    """
    A Credential expiring in `days` days.

    days_left truncates towards zero, so a credential built for exactly n days
    reports n - 1. Tests that assert on days_left add a margin of a few hours.
    """
    fields = dict(app_name=app_name, app_id="app-id", object_id="object-id",
                  object_type="application", cred_type="secret",
                  display_name="credential", key_id="key-id",
                  end_date=datetime.now(timezone.utc) + timedelta(days=days, hours=1))
    fields.update(overrides)
    return graph.Credential(**fields)


def graph_object(name="App", object_id="object-id", app_id="app-id",
                 secrets=(), certs=()):
    """One Graph application/servicePrincipal payload as collect_credentials sees it."""
    def entries(values):
        return [{"displayName": "cred-%d" % i,
                 "keyId": "key-%d" % i,
                 "endDateTime": (datetime.now(timezone.utc)
                                 + timedelta(days=d, hours=1)).isoformat()}
                for i, d in enumerate(values)]

    return {"id": object_id, "appId": app_id, "displayName": name,
            "passwordCredentials": entries(secrets), "keyCredentials": entries(certs)}


class LiveServer:
    """
    A real HTTP server on a loopback port, for tests that need the handler.

    Response headers, status codes and the reflection behaviour of the error
    pages cannot be observed by calling the render functions, so several test
    classes need this. It lives here so they do not each grow their own copy.
    """

    def __init__(self, tenants=None, token="", result=None):
        self.tenants = tenants
        self.token = token
        self.result = result
        self._patches = []
        self.httpd = None
        self.thread = None

    def start(self):
        """Patch the module globals, then serve in a background thread."""
        import threading
        from http.server import ThreadingHTTPServer
        from unittest import mock

        import server

        self._patches = [
            mock.patch.object(server, "API_TOKEN", self.token),
            # Ohne das schreibt jede Testanfrage eine Zugriffszeile in die Ausgabe.
            mock.patch.object(server.Handler, "log_message", lambda *a, **k: None),
        ]
        if self.tenants is not None:
            self._patches.append(mock.patch.object(
                server.Handler, "_tenants", lambda handler: self.tenants))
        if self.result is not None:
            self._patches.append(mock.patch.object(
                server, "get_result_safe", lambda cfg, force=False: self.result(cfg)))
            self._patches.append(mock.patch.object(
                server, "get_result", lambda cfg, force=False: self.result(cfg)))
        for patch in self._patches:
            patch.start()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        """Shut the server down and undo every patch."""
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
        for patch in self._patches:
            patch.stop()

    def get(self, path, headers=None):
        """Return (status, headers, body) without raising on a 4xx or 5xx."""
        import urllib.error
        import urllib.request

        request = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                         headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, dict(response.headers), response.read().decode()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, dict(exc.headers), exc.read().decode()


def make_certificate(days=365, key=None):
    """
    Build a throwaway self signed certificate and its private key, both PEM.

    Generated rather than checked in, so nothing that looks like a credential
    ever sits in the repository and the validity dates stay relative to today.
    Pass `key` to sign with a different key than the one returned, which is how
    a mismatched pair is produced.
    """
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "entra-monitor-test")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(subject)
                   .issuer_name(subject)
                   .public_key((key or private_key).public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1))
                   .not_valid_after(now + timedelta(days=days))
                   .sign(private_key, hashes.SHA256()))

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()).decode()
    return cert_pem, key_pem
