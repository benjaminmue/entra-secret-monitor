#!/usr/bin/env python3
"""
openapi.py

Maschinenlesbare Beschreibung der REST-Schnittstelle.

Erzeugt statt abgelegt: eine JSON-Datei neben dem Code waere eine zweite
Quelle, die beim naechsten neuen Feld stillschweigend veraltet. Die Pfadliste
stammt aus demselben Verzeichnis, das die Einstellungsseite anzeigt, die
Schemas stehen hier.
"""

from portal.models import API_SCOPE_WRITE

# Ein Kunde, wie ihn die Schnittstelle herausgibt. Ohne Client Secret und ohne
# privaten Schluessel, das ist die Zusage der Schnittstelle und steht deshalb
# auch so im Schema.
CUSTOMER_SCHEMA = {
    "type": "object",
    "properties": {
        "key": {"type": "string", "example": "musterag"},
        "display_name": {"type": "string", "example": "Muster AG"},
        "tenant_id": {"type": "string", "format": "uuid"},
        "client_id": {"type": "string", "format": "uuid"},
        "auth_type": {"type": "string", "enum": ["secret", "certificate"]},
        "has_credential": {"type": "boolean",
                           "description": "Ob ein Secret oder ein Schlüsselpaar "
                                          "hinterlegt ist. Der Wert selbst wird nie "
                                          "herausgegeben."},
        "certificate": {
            "type": "object", "nullable": True,
            "properties": {"thumbprint": {"type": "string", "nullable": True},
                           "not_after": {"type": "string", "format": "date-time",
                                         "nullable": True}},
        },
        "is_active": {"type": "boolean"},
        "thresholds": {
            "type": "object",
            "properties": {"warn_days": {"type": "integer"},
                           "error_days": {"type": "integer"}},
        },
        "scan": {
            "type": "object",
            "properties": {
                "last_check_at": {"type": "string", "format": "date-time", "nullable": True},
                "status": {"type": "string", "enum": ["pending", "ok", "error"]},
                "error": {"type": "string", "nullable": True},
                "slot_minute": {"type": "integer",
                                "description": "Minute nach Mitternacht, zu der der "
                                               "tägliche Lauf startet."},
            },
        },
        "summary": {
            "type": "object",
            "properties": {
                "min_days": {"type": "integer", "nullable": True,
                             "description": "Kürzeste Restlaufzeit in Tagen."},
                "count_total": {"type": "integer"},
                "count_critical": {"type": "integer"},
                "count_expired": {"type": "integer"},
            },
        },
        "urls": {"$ref": "#/components/schemas/SensorUrls"},
        "credentials": {"type": "array",
                        "items": {"$ref": "#/components/schemas/Credential"}},
    },
}

# Bewusst ohne Ampelfarbe: die Schwellen des Kunden stehen im Feld thresholds,
# und days_left daneben. Eine hier gerechnete Farbe waere eine zweite Wahrheit,
# die von der des Sensors abweichen kann.
CREDENTIAL_SCHEMA = {
    "type": "object",
    "properties": {
        "app_name": {"type": "string"},
        "app_id": {"type": "string", "format": "uuid"},
        "object_type": {"type": "string", "enum": ["application", "serviceprincipal"]},
        "type": {"type": "string", "enum": ["secret", "cert"]},
        "credential_name": {"type": "string",
                            "description": "Name des Secrets oder Zertifikats im Tenant."},
        "key_id": {"type": "string", "format": "uuid"},
        "end_date": {"type": "string", "format": "date-time"},
        "days_left": {"type": "integer",
                      "description": "Ganze Tage bis zum Ablauf, negativ wenn abgelaufen."},
        "sibling_count": {"type": "integer",
                          "description": "Wie viele Zugangsdaten dieselbe Anwendung hat."},
    },
}

# Die URLs tragen das Sensor-Token. Wer sie kennt, liest die Kanäle dieses
# Kunden ohne API-Schlüssel, und der Widerruf eines Schlüssels nimmt das nicht
# zurück. Das steht so im Dokument, damit ein Integrator es nicht erst merkt,
# wenn die URL in einem Ticket steht.
SENSOR_URLS_SCHEMA = {
    "type": "object",
    "description": "Sensor-URLs des Kunden. Sie enthalten das Sensor-Token und "
                   "gelten, bis es über POST /customers/{key}/token gewechselt wird.",
    "properties": {
        "prtg_xml": {"type": "string", "format": "uri",
                     "description": "URL für einen HTTP Data Advanced Sensor."},
        "json": {"type": "string", "format": "uri"},
        "hinweis": {"type": "string"},
    },
}

CUSTOMER_INPUT_SCHEMA = {
    "type": "object",
    "required": ["key", "display_name", "tenant_id", "client_id"],
    "properties": {
        "key": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{1,47}$",
                "description": "Kurzname, Teil der Sensor-URL, später nicht mehr änderbar."},
        "display_name": {"type": "string", "maxLength": 128},
        "tenant_id": {"type": "string", "format": "uuid"},
        "client_id": {"type": "string", "format": "uuid"},
        "auth_type": {"type": "string", "enum": ["secret", "certificate"],
                      "default": "secret"},
        "client_secret": {"type": "string",
                          "description": "Pflicht bei auth_type 'secret'. Wird "
                                         "verschlüsselt abgelegt und nie zurückgegeben."},
        "cert_pem": {"type": "string", "description": "Pflicht bei auth_type 'certificate'."},
        "key_pem": {"type": "string", "description": "Pflicht bei auth_type 'certificate'."},
        "warn_days": {"type": "integer", "minimum": 1, "maximum": 3650},
        "error_days": {"type": "integer", "minimum": 1, "maximum": 3650,
                       "description": "Muss kleiner oder gleich warn_days sein."},
        "max_channels": {"type": "integer", "minimum": 1, "maximum": 200, "default": 45},
        "include_sp": {"type": "boolean", "default": False},
        "show_expired": {"type": "boolean", "default": False},
        "app_filter": {"type": "string"},
        "app_exclude": {"type": "string"},
        "notes": {"type": "string"},
        "is_active": {"type": "boolean", "default": True},
    },
}

ERROR_SCHEMA = {
    "type": "object",
    "properties": {
        "error": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "example": "validation_failed"},
                "message": {"type": "string"},
                "fields": {"type": "object", "additionalProperties": {"type": "string"},
                           "description": "Nur bei validation_failed: Feld auf Grund."},
            },
        },
    },
}

# Antworten, die an mehreren Endpunkten gleich aussehen. Einmal beschrieben und
# referenziert, sonst steht derselbe Block acht Mal im Dokument.
FEHLERANTWORTEN = {
    "401": {"$ref": "#/components/responses/Unauthorized"},
    "403": {"$ref": "#/components/responses/Forbidden"},
    "404": {"$ref": "#/components/responses/NotFound"},
    "429": {"$ref": "#/components/responses/RateLimited"},
}

SCHLUESSEL_PARAMETER = {
    "name": "key", "in": "path", "required": True,
    "schema": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{1,47}$"},
    "description": "Kurzname des Kunden.",
}


def _json(schema_ref):
    """Shorthand for one application/json body of the given schema."""
    return {"content": {"application/json": {"schema": schema_ref}}}


def _antwort(beschreibung, schema_ref=None):
    """One response entry, with or without a body."""
    eintrag = {"description": beschreibung}
    if schema_ref is not None:
        eintrag.update(_json(schema_ref))
    return eintrag


def _operation(endpunkt, extras):
    """
    Build one operation object from a directory entry plus its specifics.

    Zweck, Methode und Bereich stammen aus dem Verzeichnis, damit ein neuer
    Endpunkt nicht an zwei Stellen gepflegt werden muss. Alles Weitere, also
    Parameter und Antworten, kommt aus der Tabelle unten.
    """
    operation = {
        "summary": endpunkt["zweck"],
        "operationId": extras["id"],
        "tags": [extras.get("tag", "Kunden")],
        "responses": dict(FEHLERANTWORTEN, **extras["antworten"]),
    }
    if "<key>" in endpunkt["pfad"]:
        operation["parameters"] = [SCHLUESSEL_PARAMETER]
    if "koerper" in extras:
        operation["requestBody"] = dict(required=True, **_json(extras["koerper"]))
    if endpunkt["bereich"] == API_SCOPE_WRITE:
        operation["description"] = "Benötigt einen Schlüssel mit Bereich 'write'."
    return operation


# Was das Verzeichnis nicht hergibt: Kennung, Anfragekoerper und Antworten je
# Endpunkt. Der Schluessel ist "METHODE PFAD", genau wie im Verzeichnis.
BESONDERHEITEN = {
    "GET /api/v1/": {
        "id": "getIndex", "tag": "Allgemein",
        "antworten": {"200": _antwort("Version und Endpunktverzeichnis")},
    },
    "GET /api/v1/openapi.json": {
        "id": "getOpenApi", "tag": "Allgemein",
        "antworten": {"200": _antwort("Dieses Dokument")},
    },
    "GET /api/v1/customers": {
        "id": "listCustomers",
        "antworten": {"200": _antwort("Alle Kunden", {
            "type": "object",
            "properties": {"count": {"type": "integer"},
                           "customers": {"type": "array",
                                         "items": {"$ref": "#/components/schemas/Customer"}}},
        })},
    },
    "POST /api/v1/customers": {
        "id": "createCustomer",
        "koerper": {"$ref": "#/components/schemas/CustomerInput"},
        "antworten": {
            "201": _antwort("Kunde angelegt", {"$ref": "#/components/schemas/Customer"}),
            "409": _antwort("Der Kurzname ist bereits vergeben",
                            {"$ref": "#/components/schemas/Error"}),
            "422": {"$ref": "#/components/responses/ValidationFailed"},
        },
    },
    "GET /api/v1/customers/<key>": {
        "id": "getCustomer",
        "antworten": {"200": _antwort("Ein Kunde samt Zugangsdaten",
                                      {"$ref": "#/components/schemas/Customer"})},
    },
    "PATCH /api/v1/customers/<key>": {
        "id": "updateCustomer",
        "koerper": {"$ref": "#/components/schemas/CustomerInput"},
        "antworten": {
            "200": _antwort("Geänderter Kunde", {"$ref": "#/components/schemas/Customer"}),
            "422": {"$ref": "#/components/responses/ValidationFailed"},
        },
    },
    "DELETE /api/v1/customers/<key>": {
        "id": "deleteCustomer",
        "antworten": {"204": {"description": "Gelöscht"}},
    },
    "POST /api/v1/customers/<key>/check": {
        "id": "checkCustomer",
        "antworten": {
            "200": _antwort("Ergebnis des Laufs", {
                "type": "object",
                "properties": {"status": {"type": "string", "enum": ["ok", "error"]},
                               "error": {"type": "string", "nullable": True},
                               "customer": {"$ref": "#/components/schemas/Customer"}},
            }),
            "409": _antwort("Ein anderer Lauf blockiert länger als erlaubt",
                            {"$ref": "#/components/schemas/Error"}),
        },
    },
    "GET /api/v1/customers/<key>/credentials": {
        "id": "listCredentials", "tag": "Zugangsdaten",
        "antworten": {"200": _antwort("Zugangsdaten des Kunden", {
            "type": "object",
            "properties": {"customer": {"type": "string"},
                           "count": {"type": "integer"},
                           "last_check_at": {"type": "string", "format": "date-time",
                                             "nullable": True},
                           "credentials": {"type": "array",
                                           "items": {"$ref": "#/components/schemas/Credential"}}},
        })},
    },
    "GET /api/v1/customers/<key>/urls": {
        "id": "getSensorUrls", "tag": "Sensoren",
        "antworten": {"200": _antwort("Sensor-URLs",
                                      {"$ref": "#/components/schemas/SensorUrls"})},
    },
    "POST /api/v1/customers/<key>/token": {
        "id": "rotateToken", "tag": "Sensoren",
        "antworten": {"200": _antwort("Neue Sensor-URLs",
                                      {"$ref": "#/components/schemas/SensorUrls"})},
    },
}


def build(base_url, instance_name, endpunkte):
    """
    Render the OpenAPI document of this instance.

    base_url landet als Server im Dokument, damit ein erzeugter Client ohne
    Nacharbeit gegen genau diese Instanz laeuft.
    """
    pfade = {}
    for endpunkt in endpunkte:
        extras = BESONDERHEITEN.get("%s %s" % (endpunkt["methode"], endpunkt["pfad"]))
        if extras is None:                      # Neuer Endpunkt ohne Eintrag: Test faengt das
            continue
        pfad = endpunkt["pfad"].replace("<key>", "{key}")
        pfade.setdefault(pfad, {})[endpunkt["methode"].lower()] = _operation(endpunkt, extras)

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "%s API" % instance_name,
            "version": "1.0",
            "description": "Steuerung des Portals aus einem übergeordneten System. "
                           "Zugangsdaten der Kunden nimmt die Schnittstelle entgegen, "
                           "gibt sie aber nie heraus.",
        },
        "servers": [{"url": base_url}],
        "security": [{"bearerAuth": []}],
        "paths": pfade,
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer",
                               "description": "Im Portal unter Einstellungen, API "
                                              "ausgestellter Schlüssel."},
            },
            "schemas": {
                "Customer": CUSTOMER_SCHEMA,
                "CustomerInput": CUSTOMER_INPUT_SCHEMA,
                "Credential": CREDENTIAL_SCHEMA,
                "SensorUrls": SENSOR_URLS_SCHEMA,
                "Error": ERROR_SCHEMA,
            },
            "responses": {
                "Unauthorized": _antwort("Kein oder unbekannter Schlüssel",
                                         {"$ref": "#/components/schemas/Error"}),
                "Forbidden": _antwort("Der Schlüssel darf nur lesen",
                                      {"$ref": "#/components/schemas/Error"}),
                "NotFound": _antwort("Kein Kunde mit diesem Kurznamen",
                                     {"$ref": "#/components/schemas/Error"}),
                "ValidationFailed": _antwort("Eingaben unvollständig oder unzulässig",
                                             {"$ref": "#/components/schemas/Error"}),
                "RateLimited": dict(
                    _antwort("Zu viele Anfragen. Der Kopf Retry-After nennt die "
                             "Wartezeit in Sekunden.",
                             {"$ref": "#/components/schemas/Error"}),
                    headers={"Retry-After": {
                        "description": "Sekunden bis zum nächsten erlaubten Aufruf.",
                        "schema": {"type": "integer"}}}),
            },
        },
    }
