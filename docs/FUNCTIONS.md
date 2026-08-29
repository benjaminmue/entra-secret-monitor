# Funktionsinventar

**Generiert, nicht von Hand gepflegt.** Neu erzeugen mit `python3 tools/inventory.py`.
Der Test `tests/test_inventory.py` schlägt fehl, sobald diese Datei vom Code abweicht.

Zweck ist, doppelte Arbeit sichtbar zu machen, bevor daraus zwei auseinanderlaufende
Implementierungen derselben Sache werden.

| Kennzahl | Wert |
|---|---|
| Module | 21 |
| Funktionen | 182 |
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
| 86 | `as_bool(value, default=False)` | Wert | Interpret common truthy strings from environment variables. |
| 98 | `as_int(value, default)` | Wert | Parse an integer from an environment variable, falling back on default. |
| 106 | `_clamp_channels(value)` | Wert | Keep max_channels inside the range PRTG can actually render. |
| 130 | `_env_prefix(key)` | Wert | Turn a tenant key into its environment variable prefix. |
| 136 | `tenant_from_env(key, env=None)` | Wert | Build a TenantConfig from prefixed environment variables. |
| 141 | `get(name, fallback='')` | Wert | Read a prefixed variable, falling back to the unprefixed one. |
| 164 | `tenant_from_dict(key, data)` | Wert | Build a TenantConfig from one entry of tenants.json. |
| 185 | `load_tenants(env=None, config_path=None)` | Wert | Assemble all configured tenants. |
| 218 | `_post_token(tenant_id, data)` | Wert | POST to the tenant token endpoint and return the access token. |
| 237 | `_client_assertion(cfg)` | Wert | Build a signed JWT client assertion from the configured certificate. |
| 253 | `segment(obj)` | Wert | Base64url encode one JWT segment without padding. |
| 273 | `get_token(cfg)` | Wert | Acquire an app-only Graph token, certificate first, secret as fallback. |
| 309 | `days_left(self)` | Wert | Whole days until expiry; negative when already expired. |
| 314 | `graph_get_all(token, path)` | Wert | Follow @odata.nextLink and return all items of a Graph collection. |
| 336 | `parse_date(value)` | Wert | Parse a Graph ISO 8601 timestamp into a timezone aware datetime. |
| 346 | `collect_credentials(token, include_sp)` | Wert | Fetch app registrations (and optionally SPs) and flatten their credentials. |
| 379 | `build_channels(creds, cfg)` | Wert | Group credentials per app and type and keep the longest remaining runtime. |
| 434 | `_assign_channel_names(channels)` | kein Rückgabewert | Give every channel a unique display name, in place. |
| 463 | `_shared_names(channels)` | Wert | Return the groups of channels that currently share a name. |
| 471 | `summarize(channels, cfg)` | Wert | Compute the three headline numbers used by PRTG and the web GUI. |
| 481 | `fetch_credentials(cfg)` | Wert | Authenticate and return the raw credential list for one tenant. |
| 492 | `build_result(creds, cfg)` | Wert | Turn raw credentials into the result structure used by every renderer. |
| 506 | `scan_tenant(cfg)` | Wert | Run a full scan for one tenant and return channels plus summary. |
| 521 | `xml_text(value)` | Wert | Escape a value for XML and drop characters XML cannot represent. |
| 528 | `render_prtg(result, cfg, extra_channels=None)` | Wert | Render PRTG XML: three summary channels plus one channel per app. |
| 544 | `channel(name, value, unit, limits=None)` | kein Rückgabewert | Append one <result> block, optionally with static limits. |
| 586 | `render_prtg_error(message)` | Wert | Render a PRTG error response so the sensor turns red instead of staying silent. |
| 592 | `render_text(result, cfg)` | Wert | Render a readable table for manual runs on the shell. |
| 611 | `push_to_prtg(url, xml)` | kein Rückgabewert | Send the XML to a PRTG HTTP Push Data Advanced sensor. |

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

### `portal/audit.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 17 | `client_ip(trust_proxy=False)` | Wert | Return the caller address, honouring X-Forwarded-For only when trusted. |
| 28 | `log(session, action, actor='system', target='', detail='', success=True, trust_proxy=False, commit=True)` | kein Rückgabewert | Write one audit row; never raises so logging cannot break a request. |

### `portal/config.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 71 | `_read_encryption_key(raw)` | Wert | Decode and validate the base64 master key used for credential encryption. |
| 82 | `load_config(env=None)` | Wert | Build the PortalConfig from the environment. |

### `portal/crypto.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 24 | `aad_for(kind, identity, column)` | Wert | Build the associated data for one stored value. |
| 40 | `generate_master_key()` | Wert | Return a fresh base64 encoded 32 byte master key for PORTAL_ENCRYPTION_KEY. |
| 45 | `encrypt(plaintext, key, aad=DOMAIN)` | Wert | Encrypt a string and return 'v1:<nonce>:<ciphertext>' in base64url. |
| 61 | `_b64decode(value)` | Wert | Decode base64url without padding. |
| 66 | `decrypt(stored, key, aad=DOMAIN)` | Wert | Reverse encrypt(); raises CryptoError on a wrong key or tampered value. |
| 86 | `mask(value, keep=4)` | Wert | Return a display safe fingerprint of a secret, never the secret itself. |

### `portal/db.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 31 | `_sqlite_pragmas(dbapi_connection, _record)` | kein Rückgabewert | Enable write ahead logging and foreign keys on every SQLite connection. |
| 40 | `init_engine(database_url)` | Wert | Create the engine and bind the session factory, idempotent per process. |
| 59 | `create_all()` | kein Rückgabewert | Create missing tables. The schema is additive, no migrations needed yet. |
| 64 | `remove_session(_exception=None)` | kein Rückgabewert | Drop the request bound session, registered as Flask teardown handler. |
| 70 | `session_scope()` | Generator | Provide a transactional session for background work outside a request. |

### `portal/factory.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 32 | `create_app(config=None)` | Wert | Build and return the configured Flask application. |
| 71 | `_load_user(user_id)` | Wert | Resolve the session user id to a User row, ignoring disabled accounts. |
| 80 | `_register_blueprints(app)` | kein Rückgabewert | Attach every route group and exempt the PRTG endpoint from CSRF. |
| 93 | `_register_hooks(app, cfg)` | Wert | Register teardown, security headers, template globals and error pages. |
| 98 | `_harden_session()` | kein Rückgabewert | Keep the session short lived and expose the config to the request. |
| 105 | `_security_headers(response)` | Wert | Send the headers a browser needs to protect the portal. |
| 121 | `_template_globals()` | Wert | Values every template needs without passing them through each view. |
| 131 | `_forbidden(_error)` | Wert | Render the styled error page instead of the Flask default. |
| 137 | `_not_found(_error)` | Wert | Render the styled error page instead of the Flask default. |
| 143 | `_server_error(error)` | Wert | Log the exception and show a neutral page without a stack trace. |
| 150 | `_ensure_schema_row()` | kein Rückgabewert | Write the schema marker on a fresh database. |
| 158 | `_bootstrap_admin(cfg)` | kein Rückgabewert | Create the first administrator from the environment when no user exists. |

### `portal/forms.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 33 | `pre_validate(self, form)` | kein Rückgabewert | Reject anything that is not a GUID before the form is used. |
| 122 | `validate(self, extra_validators=None)` | Wert | Enforce that the chosen authentication method is actually filled in. |

### `portal/models.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 43 | `utcnow()` | Wert | Timezone aware current time, used as default for every timestamp. |
| 48 | `new_token(length=32)` | Wert | Return a URL safe random token, used for the PRTG endpoints. |
| 85 | `totp_ready(self)` | Wert | True when the account finished TOTP enrollment. |
| 90 | `role_label(self)` | Wert | German label of the role for display. |
| 94 | `has_role(self, *roles)` | Wert | True when the account holds one of the given roles. |
| 99 | `is_authenticated(self)` | Wert | Flask-Login interface; a loaded user always counts as authenticated. |
| 104 | `is_anonymous(self)` | Wert | Flask-Login interface. |
| 108 | `get_id(self)` | Wert | Flask-Login interface; the session stores the primary key. |
| 184 | `slot_label(self)` | Wert | Assigned scan time of day as HH:MM in UTC. |
| 189 | `auth_label(self)` | Wert | German label of the configured authentication method. |
| 250 | `type_label(self)` | Wert | German label of the credential type. |
| 255 | `object_label(self)` | Wert | German label of the owning directory object. |

### `portal/scanner.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 35 | `customer_to_config(customer, encryption_key)` | Wert | Build the graph.TenantConfig for one customer, decrypting its credential. |
| 74 | `inspect_certificate(cert_pem, key_pem)` | Wert | Validate an uploaded key pair and return (thumbprint, not_after). |
| 96 | `run_check(session, customer, encryption_key, trigger=TRIGGER_SCHEDULE, actor='system', history_runs=30)` | Wert | Execute one scan for a customer and persist the outcome. |
| 166 | `_trim_history(session, customer_id, keep)` | kein Rückgabewert | Delete check runs beyond the configured history depth. |
| 175 | `result_from_db(session, customer, max_channels=None)` | Wert | Rebuild the renderer result structure from the stored snapshot. |
| 221 | `data_age_hours(customer)` | Wert | Whole hours since the last successful scan, -1 when never scanned. |
| 231 | `filter_result(result, app='', name_filter='', exclude='', cred_type='', warn_days=None, error_days=None, max_channels=None)` | Wert | Narrow a stored result down to a subset of its channels. |

### `portal/scheduler.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 33 | `assign_slot(session)` | Wert | Return the scan minute for a new customer: the middle of the largest gap. |
| 50 | `redistribute_slots(session)` | Wert | Spread all customers evenly over the day, ordered by key for stability. |
| 63 | `is_due(customer, now=None)` | Wert | True when the customer's slot has passed today and today's run is missing. |
| 86 | `force_check(customer_id, encryption_key, actor, history_runs=30, wait_seconds=120)` | Wert | Run one scan immediately, used by the force check button and on onboarding. |
| 109 | `_run_due(encryption_key, gap_seconds, history_runs, stop_event)` | kein Rückgabewert | Work through every due customer, one at a time, pausing in between. |
| 138 | `_loop(config, stop_event)` | kein Rückgabewert | Scheduler thread body: tick, run what is due, sleep again. |
| 149 | `start(config)` | Wert | Start the background scheduler once per process. |
| 164 | `stop()` | kein Rückgabewert | Signal the scheduler thread to end, used by tests and clean shutdowns. |
| 171 | `status()` | Wert | Return a small dict describing the scheduler for the GUI footer. |

### `portal/security.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 44 | `normalize(value)` | Wert | Normalise unicode so visually identical inputs compare equal. |
| 49 | `check_password_policy(password, min_length=12, username='', display_name='')` | Wert | Validate a password and return the list of violations, empty when fine. |
| 89 | `assert_password_policy(password, min_length=12, username='', display_name='')` | kein Rückgabewert | Raise PolicyError with a readable message when the password is too weak. |
| 96 | `hash_password(password)` | Wert | Return the Argon2id hash of a password. |
| 101 | `verify_password(stored_hash, password)` | Wert | Constant time password check; False on any mismatch or broken hash. |
| 115 | `dummy_verify(password)` | Wert | Burn the same time a real password check costs, for a missing account. |
| 129 | `needs_rehash(stored_hash)` | Wert | True when the hash was produced with weaker parameters than the current ones. |
| 137 | `suggest_password(length=20)` | Wert | Generate a policy compliant password for handing out a new account. |
| 150 | `new_totp_secret()` | Wert | Return a fresh base32 TOTP secret. |
| 155 | `totp_uri(secret, username, issuer)` | Wert | Build the otpauth:// URI an authenticator app scans. |
| 160 | `verify_totp(secret, code, last_counter=0)` | Wert | Validate a six digit code with one step of clock tolerance. |
| 181 | `new_recovery_codes(count=8)` | Wert | Generate readable single use recovery codes. |
| 191 | `hash_recovery_code(code)` | Wert | Hash a recovery code with the same Argon2 parameters as a password. |
| 196 | `verify_recovery_code(stored_hash, code)` | Wert | Check one recovery code against its stored hash. |
| 204 | `encrypt_totp_secret(secret, key, username)` | Wert | Encrypt the TOTP secret, bound to the account it belongs to. |
| 209 | `decrypt_totp_secret(stored, key, username)` | Wert | Decrypt the stored TOTP secret of one account. |

### `portal/serve.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 18 | `main()` | Wert | Start the portal and serve until terminated. |

### `portal/views/auth.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 47 | `_aware(value)` | Wert | Return a timezone aware copy of a datetime read from SQLite. |
| 54 | `_locked(user)` | Wert | True while the account is inside its lockout window. |
| 60 | `_register_failure(user, cfg, reason)` | kein Rückgabewert | Count a failed attempt and lock the account once the limit is reached. |
| 83 | `login()` | Wert | First factor: username and password. |
| 132 | `_pending_user()` | Wert | Return the user waiting for the second factor, or None when expired. |
| 157 | `_clear_pending()` | kein Rückgabewert | Drop the half finished login from the session. |
| 163 | `_complete_login(user, cfg)` | kein Rückgabewert | Sign the user in and reset the counters, without deciding where to go. |
| 175 | `_finish_login(user, cfg)` | Wert | Sign the user in and redirect to wherever the account has to go next. |
| 185 | `verify_totp()` | Wert | Second factor: the six digit code or one recovery code. |
| 224 | `_consume_recovery_code(user, code)` | Wert | Mark a matching unused recovery code as used and report success. |
| 251 | `_claim_totp_counter(user, counter)` | Wert | Store the accepted TOTP counter, but only if it really moved forward. |
| 267 | `_allow_reenrollment(user)` | kein Rückgabewert | Open the short window in which an existing authenticator may be replaced. |
| 273 | `_reenrollment_allowed(user)` | Wert | True while a step-up confirmation for this account is still valid. |
| 284 | `_clear_reenrollment()` | kein Rückgabewert | Close the re-enrollment window. |
| 290 | `_qr_svg(uri)` | Wert | Render the otpauth URI as an inline SVG, so no image endpoint is needed. |
| 299 | `setup_totp()` | Wert | Enrollment of the authenticator app. |
| 330 | `enrollment_page(status=200)` | Wert | Render the enrollment page with a QR code for the current secret. |
| 372 | `reenroll_totp()` | Wert | Step-up before an existing authenticator may be replaced. |
| 418 | `recovery_codes()` | Wert | Show how many recovery codes are left. |
| 433 | `change_password()` | Wert | Change the password of the signed in account. |
| 464 | `_policy_text(cfg)` | Wert | Return the password rules as a list for display next to the form. |
| 478 | `logout()` | Wert | End the session. |
| 489 | `_enforce_password_change()` | Wert | Keep an account with a temporary password inside the password page. |

### `portal/views/customers.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 30 | `_apply_credentials(form, customer, cfg, is_new)` | kein Rückgabewert | Store the credential that matches the chosen authentication method. |
| 69 | `_apply_settings(form, customer)` | kein Rückgabewert | Copy every non credential field from the form onto the customer. |
| 88 | `create()` | Wert | Onboard a new customer tenant and verify the connection right away. |
| 129 | `edit(customer_id)` | Wert | Change the settings or the credential of an existing customer. |
| 160 | `detail(customer_id)` | Wert | Show the stored credential state of one customer plus its run history. |
| 179 | `force(customer_id)` | Wert | Force check: fetch the current state now instead of waiting for the slot. |
| 209 | `rotate_token(customer_id)` | Wert | Issue a new PRTG token, invalidating the old sensor URL. |
| 226 | `delete(customer_id)` | Wert | Remove a customer with its history; only administrators may do this. |
| 244 | `redistribute()` | Wert | Spread every customer evenly over the day again. |

### `portal/views/dashboard.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 22 | `customer_rows()` | Wert | Return all customers with the derived values the overview shows. |
| 36 | `customer_state(customer, stale_hours=None)` | Wert | Classify a customer into ok, warn, error or unknown. |
| 67 | `index()` | Wert | Render the customer overview. |

### `portal/views/docs.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 35 | `base_url()` | Wert | Return the externally reachable base URL of this instance. |
| 43 | `index()` | Wert | Render the onboarding guide. |

### `portal/views/helpers.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 18 | `config()` | Wert | Return the PortalConfig of the running application. |
| 23 | `get_or_404(model, primary_key)` | Wert | Load one record by primary key or abort with 404. |
| 36 | `require_role(*roles)` | Wert | Decorator that rejects a signed in user without one of the given roles. |
| 38 | `decorator(view)` | Wert | Wrap one view function. |
| 41 | `wrapper(*args, **kwargs)` | Wert | Check the role before delegating to the view. |
| 52 | `require_write(view)` | Wert | Shortcut for the two roles that may change data. |
| 57 | `form_errors(form)` | kein Rückgabewert | Flash every validation error of a form in a readable form. |

### `portal/views/prtg.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 28 | `_customer_by_token(token)` | Wert | Resolve a PRTG token to an active customer, or None. |
| 38 | `_age_channel(customer, cfg)` | Wert | Build the data age channel. |
| 50 | `_int_param(name)` | Wert | Read an optional positive integer from the query string. |
| 64 | `_scoped_result(customer)` | Wert | Build the result for this request, honouring the optional scope parameters. |
| 86 | `prtg_xml(token)` | Wert | Serve PRTG XML for one customer from the stored snapshot. |
| 111 | `prtg_json(token)` | Wert | Serve the same data as JSON, for anything that is not PRTG. |
| 123 | `healthz()` | Wert | Liveness probe; never requires a token and never touches the database. |

### `portal/views/users.py`

| Zeile | Funktion | Rückgabe | Beschreibung |
|---|---|---|---|
| 27 | `_last_admin(user)` | Wert | True when removing or demoting this account would leave no administrator. |
| 36 | `_one_time_password_page(user, password, headline)` | Wert | Render a one time password exactly once, with caching switched off. |
| 54 | `index()` | Wert | List all portal accounts. |
| 63 | `create()` | Wert | Create an account and hand out its one time password. |
| 104 | `edit(user_id)` | Wert | Change role, contact data or the active state of an account. |
| 140 | `reset_password(user_id)` | Wert | Issue a new one time password for an account. |
| 161 | `reset_totp(user_id)` | Wert | Clear the second factor so the account enrols a new authenticator. |
| 182 | `delete(user_id)` | Wert | Delete an account, except the last administrator and oneself. |
