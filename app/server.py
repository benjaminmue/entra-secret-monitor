#!/usr/bin/env python3
"""
server.py

HTTP service of the Entra ID credential expiry monitor.

Serves the same data in three shapes:
  GET /                       web GUI, all configured tenants
  GET /prtg?tenant=<key>      PRTG XML for an HTTP Data Advanced sensor
                              optional: &filter= &exclude= &warn= &error=
                              &show_expired= &max_channels=
  GET /json[?tenant=<key>]    raw JSON
  GET /refresh?tenant=<key>   drop the cache entry and reload
  GET /healthz                liveness probe, never requires a token

Environment:
  LISTEN_ADDR   default 0.0.0.0
  LISTEN_PORT   default 8099
  API_TOKEN     when set, every endpoint except /healthz requires
                ?token=<value> or an Authorization: Bearer header
  CACHE_TTL     seconds a scan result is reused, default 1800
  PUSH_INTERVAL seconds between background pushes, 0 disables, default 0
"""

import html
import json
import os
import re
import threading
import time
import urllib.parse
from dataclasses import replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from secrets import compare_digest

import graph

LISTEN_ADDR = os.environ.get("LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8099"))
API_TOKEN = os.environ.get("API_TOKEN", "")

# Die GUI kommt ohne eigenes JavaScript aus, deshalb darf die Richtlinie Skripte
# ganz verbieten. Das entschaerft jede Reflexion, die trotz Escaping durchkaeme.
# nosniff haelt Browser davon ab, eine text/plain-Antwort als HTML zu deuten,
# no-referrer haelt einen Token in der URL aus dem Referer fremder Seiten.
SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy",
     "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"),
)

# Ein Token im Query-String darf nicht im Log landen, Container-Logs werden
# haeufig zentral eingesammelt.
_TOKEN_IN_QUERY = re.compile(r"([?&]token=)[^&\s]*", re.IGNORECASE)
CACHE_TTL = int(os.environ.get("CACHE_TTL", "1800"))
PUSH_INTERVAL = int(os.environ.get("PUSH_INTERVAL", "0"))

_cache = {}
_cache_lock = threading.Lock()


# --------------------------------------------------------------------------
# Scanning with cache
# --------------------------------------------------------------------------

def get_credentials(cfg, force=False):
    """
    Return the raw credential list for one tenant, cached within the TTL.

    Only the Graph round trip is cached. Filters and thresholds are applied
    afterwards, so several sensors can hit the same tenant with different
    query parameters without triggering extra requests.
    """
    now = time.time()
    with _cache_lock:
        entry = _cache.get(cfg.key)
        if entry and not force and now - entry[0] < CACHE_TTL:
            return entry[1]
    creds = graph.fetch_credentials(cfg)
    with _cache_lock:
        _cache[cfg.key] = (now, creds)
    return creds


def get_result(cfg, force=False):
    """Return a rendered scan result for one tenant."""
    return graph.build_result(get_credentials(cfg, force), cfg)


def apply_overrides(cfg, params):
    """
    Copy the tenant config with per-request overrides from the query string.

    Lets one tenant feed several PRTG sensors, for example one sensor per
    application with its own thresholds. include_sp is deliberately not
    overridable because it would change what the shared cache holds.
    """
    changes = {}
    if "filter" in params:
        changes["app_filter"] = params["filter"][0]
    if "exclude" in params:
        changes["app_exclude"] = params["exclude"][0]
    if "show_expired" in params:
        changes["show_expired"] = params["show_expired"][0].lower() in ("1", "true", "yes")
    for name, field in (("warn", "warn_days"), ("error", "error_days"),
                        ("max_channels", "max_channels")):
        if name in params:
            try:
                value = int(params[name][0])
            except ValueError:
                raise ValueError("Parameter '%s' ist keine Zahl: %s" % (name, params[name][0]))
            # Anders als in der Konfiguration wird hier abgewiesen statt geklemmt:
            # ein Request-Override ist eine bewusste Eingabe, die Rueckmeldung
            # verdient statt still korrigiert zu werden.
            if field == "max_channels" and not 1 <= value <= graph.MAX_APP_CHANNELS:
                raise ValueError("Parameter 'max_channels' muss zwischen 1 und %d liegen: %d"
                                 % (graph.MAX_APP_CHANNELS, value))
            changes[field] = value
    return replace(cfg, **changes) if changes else cfg


def get_result_safe(cfg, force=False):
    """Like get_result but turns exceptions into an error result instead of raising."""
    try:
        return get_result(cfg, force)
    except Exception as exc:                              # noqa: BLE001
        return {
            "tenant": cfg.key,
            "display_name": cfg.display_name,
            "warn_days": cfg.warn_days,
            "error_days": cfg.error_days,
            "checked": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "error": "%s: %s" % (type(exc).__name__, exc),
            "summary": {"minimum": 0, "critical": 0, "expired": 0, "total": 0},
            "channels": [],
        }


# --------------------------------------------------------------------------
# Web GUI
# --------------------------------------------------------------------------

PAGE_CSS = """
:root {
  --bg: #f5f6f8; --card: #ffffff; --fg: #16181d; --muted: #5c6470;
  --line: #dfe3e8; --ok: #1f8a4c; --warn: #b26a00; --err: #c02626;
  --ok-bg: #e6f4ec; --warn-bg: #fdf1de; --err-bg: #fbe9e9; --accent: #17497a;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --card: #1c1f25; --fg: #e8eaee; --muted: #9aa3af;
    --line: #2c313a; --ok: #56d38a; --warn: #e0a838; --err: #ff7a7a;
    --ok-bg: #16301f; --warn-bg: #33280f; --err-bg: #3a1c1c; --accent: #7fb3e8;
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; background: var(--bg); color: var(--fg);
  font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
h1 { font-size: 20px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 0; }
a { color: var(--accent); }
.sub { color: var(--muted); font-size: 12px; margin-bottom: 20px; }
.tenant { background: var(--card); border: 1px solid var(--line); border-radius: 8px;
  padding: 16px 18px; margin-bottom: 20px; }
.head { display: flex; flex-wrap: wrap; gap: 12px; align-items: baseline;
  justify-content: space-between; margin-bottom: 14px; }
.links a { margin-left: 12px; font-size: 12px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
.card { flex: 1 1 150px; border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; }
.card .n { font-size: 22px; font-weight: 600; }
.card .l { font-size: 11px; color: var(--muted); text-transform: uppercase;
  letter-spacing: .04em; }
.wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; min-width: 620px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line);
  white-space: nowrap; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
td.app { white-space: normal; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 10px;
  font-weight: 600; font-size: 12px; }
.b-ok { background: var(--ok-bg); color: var(--ok); }
.b-warn { background: var(--warn-bg); color: var(--warn); }
.b-err { background: var(--err-bg); color: var(--err); }
.err-box { background: var(--err-bg); color: var(--err); border-radius: 6px;
  padding: 10px 12px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.empty { color: var(--muted); font-style: italic; }
.setup p { margin: 0 0 10px; }
.setup pre { background: var(--bg); border: 1px solid var(--line); border-radius: 6px;
  padding: 10px 12px; margin: 0 0 14px; overflow-x: auto;
  font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
footer { color: var(--muted); font-size: 12px; margin-top: 24px; }
"""

PAGE_TEMPLATE = """<!doctype html>
<html lang="de"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="900">
<title>Entra ID Secret Monitor</title>
<style>__CSS__</style>
</head><body>
<h1>Entra ID Secret Monitor</h1>
<div class="sub">Restlaufzeit von Client Secrets und Zertifikaten &middot; Stand __NOW__
 &middot; Cache __TTL__ s</div>
__BODY__
<footer>PRTG-Sensor: HTTP Data Advanced auf <code>__PRTG_HINT__</code></footer>
</body></html>
"""


def badge(days, cfg_warn, cfg_error):
    """Return the HTML badge for one remaining runtime value."""
    if days < cfg_error:
        cls = "b-err"
    elif days < cfg_warn:
        cls = "b-warn"
    else:
        cls = "b-ok"
    label = "%d Tage" % days if days >= 0 else "abgelaufen (%d)" % days
    return '<span class="badge %s">%s</span>' % (cls, html.escape(label))


def render_tenant_block(result, token_qs):
    """Render one tenant card including summary numbers and the credential table."""
    esc = html.escape
    warn, err = result["warn_days"], result["error_days"]
    summary = result["summary"]
    key = esc(result["tenant"])

    parts = ['<div class="tenant">', '<div class="head">',
             "<h2>%s</h2>" % esc(result["display_name"]),
             '<div class="links">'
             '<a href="/prtg?tenant=%s%s">PRTG-XML</a>'
             '<a href="/json?tenant=%s%s">JSON</a>'
             '<a href="/refresh?tenant=%s%s">Neu laden</a></div>'
             % (key, token_qs, key, token_qs, key, token_qs),
             "</div>"]

    if result.get("error"):
        parts.append('<div class="err-box">%s</div></div>' % esc(result["error"]))
        return "".join(parts)

    cards = [("Minimale Restlaufzeit", "%d Tage" % summary["minimum"]),
             ("Kritisch", str(summary["critical"])),
             ("Abgelaufen", str(summary["expired"])),
             ("Ueberwacht", str(summary["total"]))]
    parts.append('<div class="cards">')
    for label, value in cards:
        parts.append('<div class="card"><div class="n">%s</div>'
                     '<div class="l">%s</div></div>' % (esc(value), esc(label)))
    parts.append("</div>")

    if not result["channels"]:
        parts.append('<p class="empty">Keine Credentials gefunden.</p></div>')
        return "".join(parts)

    parts.append('<div class="wrap"><table><thead><tr>'
                 "<th>Restlaufzeit</th><th>Ablauf</th><th>Typ</th>"
                 "<th>Anwendung</th><th>Credential</th><th>Objekt</th>"
                 "</tr></thead><tbody>")
    for entry in result["channels"]:
        type_label = "Secret" if entry["type"] == "secret" else "Zertifikat"
        obj_label = "App-Registrierung" if entry["object_type"] == "application" \
            else "Enterprise App"
        parts.append("<tr><td>%s</td><td>%s</td><td>%s</td>"
                     '<td class="app">%s</td><td>%s</td><td>%s</td></tr>'
                     % (badge(entry["days"], warn, err), esc(entry["expires"]),
                        esc(type_label), esc(entry["app"]), esc(entry["cred_name"]),
                        esc(obj_label)))
    parts.append("</tbody></table></div>")
    parts.append('<div class="sub" style="margin:10px 0 0">Zuletzt geprueft: %s</div>'
                 % esc(result["checked"]))
    parts.append("</div>")
    return "".join(parts)


def render_setup_block():
    """
    Render the card shown while no tenant is configured.

    The service is usable before any tenant exists, so a fresh install can be
    opened in the browser and states what to configure next instead of failing
    with a bare error page.
    """
    path = html.escape(os.environ.get("TENANTS_FILE", "/config/tenants.json"))
    env_example = html.escape(
        "TENANTS=contoso\n"
        "CONTOSO_DISPLAY_NAME=Contoso AG\n"
        "CONTOSO_TENANT_ID=<Verzeichnis-ID>\n"
        "CONTOSO_CLIENT_ID=<Anwendungs-ID>\n"
        "CONTOSO_CERT_PATH=/config/contoso.crt\n"
        "CONTOSO_KEY_PATH=/config/contoso.key")
    json_example = html.escape(
        '{\n'
        '  "contoso": {\n'
        '    "display_name": "Contoso AG",\n'
        '    "tenant_id": "<Verzeichnis-ID>",\n'
        '    "client_id": "<Anwendungs-ID>",\n'
        '    "cert_path": "/config/contoso.crt",\n'
        '    "key_path": "/config/contoso.key"\n'
        '  }\n'
        '}')
    return (
        '<div class="tenant setup">'
        '<div class="head"><h2>Kein Tenant eingerichtet</h2></div>'
        "<p>Der Dienst laeuft, es ist aber noch keine Anwendung hinterlegt. "
        "Sobald ein Tenant konfiguriert ist, stehen hier die Restlaufzeiten. "
        "Zwei Wege, wobei die Datei gewinnt wenn beide gesetzt sind:</p>"
        "<p><strong>1. Umgebungsvariablen</strong>, danach den Dienst neu starten:</p>"
        "<pre>%s</pre>"
        "<p><strong>2. Datei <code>%s</code></strong>, wird bei jedem Aufruf neu gelesen, "
        'ein <a href="/">Neuladen der Seite</a> genuegt:</p>'
        "<pre>%s</pre>"
        "<p>Die App-Registrierung braucht ausschliesslich die Anwendungsberechtigung "
        "<code>Application.Read.All</code> mit Admin-Consent. Ein Zertifikat ist einem "
        "Client Secret vorzuziehen, weil Entra Secrets bei 24 Monaten kappt. Anlegen "
        "laesst sich beides mit <code>scripts/New-MonitorAppRegistration.ps1</code>.</p>"
        "</div>" % (env_example, path, json_example))


def render_page(results, token_qs, host, config_error=None):
    """Render the complete overview page for all tenants."""
    if config_error:
        body = ('<div class="tenant"><div class="head"><h2>Konfigurationsfehler</h2></div>'
                '<div class="err-box">%s</div></div>' % html.escape(config_error))
    elif not results:
        body = render_setup_block()
    else:
        body = "".join(render_tenant_block(r, token_qs) for r in results)
    hint = "http://%s/prtg?tenant=&lt;key&gt;%s" % (html.escape(host), token_qs)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (PAGE_TEMPLATE
            .replace("__CSS__", PAGE_CSS)
            .replace("__BODY__", body)
            .replace("__NOW__", now)
            .replace("__TTL__", str(CACHE_TTL))
            .replace("__PRTG_HINT__", hint))


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    """Serves the GUI, the PRTG XML and the JSON representation."""

    server_version = "EntraSecretMonitor/1.0"

    def log_message(self, fmt, *args):
        """Log one line per request, with any API token in the URL redacted."""
        line = "%s %s" % (self.address_string(), fmt % args)
        print(_TOKEN_IN_QUERY.sub(r"\1<redacted>", line), flush=True)

    def _authorized(self, params):
        """Check the optional API token from query string or Bearer header."""
        if not API_TOKEN:
            return True
        header = self.headers.get("Authorization", "").strip()
        bearer = header[7:].strip() if header[:7].lower() == "bearer " else ""
        supplied = params.get("token", [""])[0] or bearer
        # Als Bytes vergleichen: compare_digest lehnt Zeichen ausserhalb ASCII ab
        # und wuerfe sonst bei jedem Umlaut im Token einen TypeError im Handler.
        return compare_digest(supplied.encode("utf-8"), API_TOKEN.encode("utf-8"))

    def _send(self, code, body, content_type):
        """Write one complete response."""
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _tenants(self):
        """Load the tenant configuration, raising GraphError on problems."""
        return graph.load_tenants()

    def do_GET(self):                                     # noqa: N802
        """Route the request to the matching endpoint."""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        route = parsed.path.rstrip("/") or "/"

        if route == "/healthz":
            self._send(200, "ok", "text/plain")
            return

        if not self._authorized(params):
            if route == "/prtg":
                self._send(200, graph.render_prtg_error("Ungueltiger oder fehlender Token"),
                           "text/xml")
            else:
                self._send(401, "401 Unauthorized", "text/plain")
            return

        token_qs = "&token=" + urllib.parse.quote(API_TOKEN) if API_TOKEN else ""
        wanted = params.get("tenant", [""])[0]
        force = route == "/refresh"

        try:
            tenants = self._tenants()
        except Exception as exc:                          # noqa: BLE001
            if route in ("/", "/refresh"):
                # The GUI stays reachable without a working configuration: an
                # empty setup shows what to do next, a broken one shows why.
                host = self.headers.get("Host", "%s:%d" % (LISTEN_ADDR, LISTEN_PORT))
                config_error = None if isinstance(exc, graph.NoTenantsConfigured) \
                    else "%s: %s" % (type(exc).__name__, exc)
                self._send(200, render_page([], token_qs, host, config_error), "text/html")
            elif route == "/prtg":
                self._send(200, graph.render_prtg_error(str(exc)), "text/xml")
            else:
                self._send(500, "Konfigurationsfehler: %s" % exc, "text/plain")
            return

        if wanted and wanted not in tenants:
            message = "Tenant '%s' nicht konfiguriert" % wanted
            if route == "/prtg":
                self._send(200, graph.render_prtg_error(message), "text/xml")
            else:
                self._send(404, message, "text/plain")
            return

        selected = [tenants[wanted]] if wanted else list(tenants.values())

        if route == "/prtg":
            if len(selected) > 1:
                self._send(200, graph.render_prtg_error(
                    "Bitte ?tenant= angeben (%s)" % ", ".join(sorted(tenants))), "text/xml")
                return
            try:
                cfg = apply_overrides(selected[0], params)
                result = get_result(cfg)
                self._send(200, graph.render_prtg(result, cfg), "text/xml")
            except Exception as exc:                      # noqa: BLE001
                self._send(200, graph.render_prtg_error(
                    "%s: %s" % (type(exc).__name__, exc)), "text/xml")
            return

        if route == "/json":
            results = [get_result_safe(apply_overrides(cfg, params), force) for cfg in selected]
            body = results[0] if len(results) == 1 and wanted else results
            self._send(200, json.dumps(body, indent=2, ensure_ascii=False), "application/json")
            return

        if route in ("/", "/refresh"):
            results = [get_result_safe(cfg, force) for cfg in selected]
            host = self.headers.get("Host", "%s:%d" % (LISTEN_ADDR, LISTEN_PORT))
            self._send(200, render_page(results, token_qs, host), "text/html")
            return

        self._send(404, "404 Not Found", "text/plain")


# --------------------------------------------------------------------------
# Background push
# --------------------------------------------------------------------------

def push_loop():
    """Periodically push PRTG XML for every tenant that has a push URL configured."""
    while True:
        try:
            for cfg in graph.load_tenants().values():
                if not cfg.push_url:
                    continue
                try:
                    result = get_result(cfg, force=True)
                    graph.push_to_prtg(cfg.push_url, graph.render_prtg(result, cfg))
                    print("push ok: %s" % cfg.key, flush=True)
                except Exception as exc:                  # noqa: BLE001
                    print("push fehlgeschlagen %s: %s" % (cfg.key, exc), flush=True)
        except Exception as exc:                          # noqa: BLE001
            print("push loop: %s" % exc, flush=True)
        time.sleep(PUSH_INTERVAL)


def main():
    """Start the background push thread and serve HTTP until terminated."""
    try:
        tenants = graph.load_tenants()
        print("Tenants: %s" % ", ".join(sorted(tenants)), flush=True)
    except Exception as exc:                              # noqa: BLE001
        print("WARNUNG: %s" % exc, flush=True)

    if PUSH_INTERVAL > 0:
        threading.Thread(target=push_loop, daemon=True).start()
        print("Push-Loop aktiv, Intervall %d s" % PUSH_INTERVAL, flush=True)

    server = ThreadingHTTPServer((LISTEN_ADDR, LISTEN_PORT), Handler)
    print("Listening on %s:%d%s" % (LISTEN_ADDR, LISTEN_PORT,
                                    " (Token aktiv)" if API_TOKEN else ""), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
