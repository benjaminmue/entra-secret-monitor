"""Shared builders for the tests, so no test has to spell out full objects."""
from datetime import datetime, timedelta, timezone

import graph

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
