# Funktionsinventar

**Generiert, nicht von Hand gepflegt.** Neu erzeugen mit `python3 tools/inventory.py`.
Der Test `tests/test_inventory.py` schlägt fehl, sobald diese Datei vom Code abweicht.

Zweck ist, doppelte Arbeit sichtbar zu machen, bevor daraus zwei auseinanderlaufende
Implementierungen derselben Sache werden.

| Kennzahl | Wert |
|---|---|
| Module | 3 |
| Funktionen | 49 |
| Ohne Docstring | 0 |
| Namensdubletten | 0 |
| Strukturdubletten | 0 |

## Befunde

Keine. Jede Funktion existiert genau einmal, und kein Rumpf gleicht einem anderen.

## Bewusste Doppelungen

Geprüft und so gewollt. Wer hier etwas ergänzt, dokumentiert eine Entscheidung,
nicht eine Ausnahme vom Aufräumen.

### Gleicher Name

| Name | Begründung |
|---|---|
| `apply_overrides` | Zwei Quellen mit unterschiedlicher Form: die Kommandozeile liest einen argparse-Namespace, der Server eine Query-Parameter-Abbildung. Beide kopieren über dataclasses.replace, die Feldlisten sind aber verschieden. |
| `config` | Flask-Hilfsfunktion je Blueprint, nur ein Zugriff auf app.config. |
| `create` | Je Blueprint ein Anlegen-Endpunkt für einen anderen Datentyp. |
| `decorator` | Innere Funktion des jeweiligen Dekorator-Bauplans. |
| `delete` | Je Blueprint ein Löschen-Endpunkt für einen anderen Datentyp. |
| `edit` | Je Blueprint ein Bearbeiten-Endpunkt für einen anderen Datentyp. |
| `index` | Je Blueprint eine Übersichtsseite, gleiche Rolle, anderer Inhalt. |
| `main` | Jeder Einstiegspunkt hat sein eigenes main, das ist Konvention. |
| `verify_totp` | security.verify_totp prüft einen Code, auth.verify_totp ist die Seite dazu. Der View-Name bestimmt die URL über url_for, Umbenennen ändert also die Route. |
| `wrapper` | Innere Funktion des jeweiligen Dekorator-Bauplans. |

### Gleicher Aufbau

| Fundorte | Begründung |
|---|---|
| `portal/factory.py:_forbidden`, `portal/factory.py:_not_found` | Zwei Fehlerseiten mit demselben Aufbau und verschiedenem Statuscode. Zusammenlegen würde eine Fallunterscheidung einführen, wo heute zwei gerade Handler stehen. |
| `portal/models.py:object_label`, `portal/models.py:type_label` | Zwei Anzeigenamen auf verschiedenen Feldern desselben Modells. |
| `portal/security.py:decrypt_totp_secret`, `portal/security.py:encrypt_totp_secret` | Gegenstücke. Gleiche Form ist hier die Absicht, nicht die Kopie. |
| `portal/views/auth.py:_clear_pending`, `portal/views/auth.py:_clear_reenrollment` | Beide räumen zwei Session-Schlüssel weg, die Namen tragen aber die Bedeutung: halbfertiger Login gegen Fenster zur Neuregistrierung. Ein generisches _clear(*keys) wäre kürzer und schlechter zu lesen. |

## Alle Funktionen

### `app/cli.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 23 | `parse_args(argv=None)` | Wert | Define and parse the command line arguments. |
| 56 | `apply_overrides(cfg, args)` | Wert | Let command line arguments win over the configured tenant defaults. |
| 77 | `select_tenant(tenants, wanted)` | Wert | Pick the requested tenant, or the only one when none was requested. |
| 90 | `main(argv=None)` | Wert | Entry point: scan one tenant and emit the requested output format. |

### `app/graph.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 73 | `__post_init__(self)` | kein Rückgabewert | Fill in the display name and validate the credential configuration. |
| 86 | `_as_bool(value, default=False)` | Wert | Interpret common truthy strings from environment variables. |
| 93 | `_as_int(value, default)` | Wert | Parse an integer from an environment variable, falling back on default. |
| 101 | `_clamp_channels(value)` | Wert | Keep max_channels inside the range PRTG can actually render. |
| 125 | `_env_prefix(key)` | Wert | Turn a tenant key into its environment variable prefix. |
| 131 | `tenant_from_env(key, env=None)` | Wert | Build a TenantConfig from prefixed environment variables. |
| 136 | `get(name, fallback='')` | Wert | Read a prefixed variable, falling back to the unprefixed one. |
| 159 | `tenant_from_dict(key, data)` | Wert | Build a TenantConfig from one entry of tenants.json. |
| 180 | `load_tenants(env=None, config_path=None)` | Wert | Assemble all configured tenants. |
| 213 | `_post_token(tenant_id, data)` | Wert | POST to the tenant token endpoint and return the access token. |
| 232 | `_client_assertion(cfg)` | Wert | Build a signed JWT client assertion from the configured certificate. |
| 248 | `segment(obj)` | Wert | Base64url encode one JWT segment without padding. |
| 268 | `get_token(cfg)` | Wert | Acquire an app-only Graph token, certificate first, secret as fallback. |
| 304 | `days_left(self)` | Wert | Whole days until expiry; negative when already expired. |
| 309 | `graph_get_all(token, path)` | Wert | Follow @odata.nextLink and return all items of a Graph collection. |
| 331 | `parse_date(value)` | Wert | Parse a Graph ISO 8601 timestamp into a timezone aware datetime. |
| 341 | `collect_credentials(token, include_sp)` | Wert | Fetch app registrations (and optionally SPs) and flatten their credentials. |
| 374 | `build_channels(creds, cfg)` | Wert | Group credentials per app and type and keep the longest remaining runtime. |
| 429 | `_assign_channel_names(channels)` | kein Rückgabewert | Give every channel a unique display name, in place. |
| 458 | `_shared_names(channels)` | Wert | Return the groups of channels that currently share a name. |
| 466 | `summarize(channels, cfg)` | Wert | Compute the three headline numbers used by PRTG and the web GUI. |
| 476 | `fetch_credentials(cfg)` | Wert | Authenticate and return the raw credential list for one tenant. |
| 487 | `build_result(creds, cfg)` | Wert | Turn raw credentials into the result structure used by every renderer. |
| 501 | `scan_tenant(cfg)` | Wert | Run a full scan for one tenant and return channels plus summary. |
| 516 | `xml_text(value)` | Wert | Escape a value for XML and drop characters XML cannot represent. |
| 523 | `render_prtg(result, cfg, extra_channels=None)` | Wert | Render PRTG XML: three summary channels plus one channel per app. |
| 539 | `channel(name, value, unit, limits=None)` | kein Rückgabewert | Append one <result> block, optionally with static limits. |
| 581 | `render_prtg_error(message)` | Wert | Render a PRTG error response so the sensor turns red instead of staying silent. |
| 587 | `render_text(result, cfg)` | Wert | Render a readable table for manual runs on the shell. |
| 606 | `push_to_prtg(url, xml)` | kein Rückgabewert | Send the XML to a PRTG HTTP Push Data Advanced sensor. |

### `app/server.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 69 | `get_credentials(cfg, force=False)` | Wert | Return the raw credential list for one tenant, cached within the TTL. |
| 88 | `get_result(cfg, force=False)` | Wert | Return a rendered scan result for one tenant. |
| 93 | `apply_overrides(cfg, params)` | Wert | Copy the tenant config with per-request overrides from the query string. |
| 125 | `get_result_safe(cfg, force=False)` | Wert | Like get_result but turns exceptions into an error result instead of raising. |
| 214 | `badge(days, cfg_warn, cfg_error)` | Wert | Return the HTML badge for one remaining runtime value. |
| 226 | `render_tenant_block(result, token_qs)` | Wert | Render one tenant card including summary numbers and the credential table. |
| 280 | `render_setup_block()` | Wert | Render the card shown while no tenant is configured. |
| 324 | `render_page(results, token_qs, host, config_error=None)` | Wert | Render the complete overview page for all tenants. |
| 352 | `log_message(self, fmt, *args)` | kein Rückgabewert | Log one line per request, with any API token in the URL redacted. |
| 357 | `_authorized(self, params)` | Wert | Check the optional API token from query string or Bearer header. |
| 368 | `_send(self, code, body, content_type)` | kein Rückgabewert | Write one complete response. |
| 380 | `_tenants(self)` | Wert | Load the tenant configuration, raising GraphError on problems. |
| 384 | `do_GET(self)` | kein Rückgabewert | Route the request to the matching endpoint. |
| 465 | `push_loop()` | kein Rückgabewert | Periodically push PRTG XML for every tenant that has a push URL configured. |
| 483 | `main()` | kein Rückgabewert | Start the background push thread and serve HTTP until terminated. |
