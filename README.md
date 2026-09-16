# Entra ID Secret Monitor

Monitors the remaining runtime of **client secrets and certificates of Entra ID
app registrations** and exposes it as **PRTG XML**, **JSON** and a small **web GUI**.

Runs as a single container on any Linux host. No Windows server, no Azure
Automation, no PowerShell. Multi-tenant: one container covers all your customers.

```
docker compose up -d
```

| Endpoint | Purpose |
|---|---|
| `http://host:8099/` | web GUI, all tenants at a glance |
| `http://host:8099/prtg?tenant=<key>` | PRTG XML for an *HTTP Data Advanced* sensor |
| `http://host:8099/json[?tenant=<key>]` | raw JSON for anything else |
| `http://host:8099/refresh?tenant=<key>` | drop the cache and rescan |
| `http://host:8099/healthz` | liveness probe, never needs a token |

## Three flavours

**Classic service** (`app/`, `Dockerfile`) is what the rest of this README
describes: stateless, configured through environment variables, no dependencies
beyond `cryptography`. Right for a handful of tenants and a host you own.

**Portal** (`portal/`, `Dockerfile.portal`) adds what a managed service provider
needs for dozens of customers: SQLite persistence, accounts with mandatory TOTP and
roles, customer onboarding through the browser, encrypted credential storage, one
scan per customer per day spread over 24 hours, a force check button, and a per
customer PRTG token that serves the stored snapshot without ever calling Graph.

```
cp .env.portal.example .env.portal   # fill in the two keys
docker compose -f docker-compose.portal.yml up -d
```

Documentation: [docs/PORTAL.md](docs/PORTAL.md) (German). Both share the Graph logic
in `app/graph.py` and can run side by side.

**PRTG sensor** (`prtg/Get-EntraSecretExpiry.ps1`) is the third option and needs no
host at all: one Windows PowerShell script on the PRTG instance itself, one sensor
per tenant, no modules. It only needs outbound 443 to Microsoft, so a customer
without a probe server is covered like every other one. Same channels, same limits,
same XML as the container, so a sensor can move from one to the other and keeps its
history. Documentation: [docs/PRTG-SENSOR.md](docs/PRTG-SENSOR.md) (German).

## Step by step

Three walkthroughs with screenshots, in German, on the project page:

| Guide | Covers |
|---|---|
| [Kunde einrichten](https://entra-monitor.bebamu.ch/anleitung-kunde.html) | App registration by script, then the customer in the portal |
| [PRTG-Sensor](https://entra-monitor.bebamu.ch/anleitung-prtg.html) | Registration, certificate into the store, device and sensor |
| [API, erste Schritte](https://entra-monitor.bebamu.ch/anleitung-api.html) | Issue a key, create customers, read expiry, fetch XML, handle errors |

Their screenshots are generated, not taken: `tools/demo_pages.py` builds a throwaway
instance with invented customers and renders every documented page and API response,
so the examples cannot drift away from the code.

## Why

Microsoft gives you a recommendation panel in the portal and a weekly digest mail
to Security Administrators. That is not monitoring. When a secret expires, an
integration dies silently at 03:00 on a Sunday.

Existing open source projects either send notifications
([kekzl/entra-id-secrets-notification](https://github.com/kekzl/entra-id-secrets-notification))
or expose Prometheus metrics
([dodevops/azure-app-exporter](https://github.com/mkoertgen/azure-app-exporter)).
PRTG speaks neither, and PRTG is what a lot of managed service providers actually run.
This project outputs PRTG XML natively, and JSON for everyone else.

## How it works

The service acquires an app-only token via client credentials and reads

```
GET /applications?$select=id,appId,displayName,passwordCredentials,keyCredentials
GET /servicePrincipals?...        (optional, for enterprise apps and SAML certificates)
```

Credentials are grouped **per Graph object and credential type**, and the group
reports the **longest** remaining runtime. That is deliberate: once a new secret
has been rolled, the old one is irrelevant and must not raise an alarm. Fully
expired leftovers are hidden unless `show_expired` is set.

Grouping keys on the object id rather than the display name, because two
registrations can share a name, and an application and its service principal
always do. Keyed on the name, one healthy credential would hide an expiring one
belonging to a different object entirely. Where names then collide, the channel
gets the smallest suffix that separates the group: `[App]` or `[SP]`, otherwise
the appId, and the object id as a last resort. A name that does not collide is
left alone, so existing sensors keep their history.

Results are cached (`CACHE_TTL`, default 30 minutes), so a five minute PRTG
interval does not hammer Graph.

## Entra ID setup

1. **App registration**, single tenant, no redirect URI. One per monitored tenant.
2. **API permissions** -> Microsoft Graph -> *Application permission*
   `Application.Read.All`, then grant admin consent. Nothing else, no
   `Directory.Read.All`.
3. **Authentication**: a client secret is the default here, for operational
   reasons: it works in every tenant and on every host, with no certificate
   store and no private key to place anywhere. That is a convenience argument,
   not a security one. A certificate is the stronger credential, since a secret
   is a bearer value while a certificate proves possession of a key that never
   leaves the host, and Microsoft's own guidance prefers it. Use a certificate
   when the tenant restricts client secrets through an app management policy,
   when 24 months is too short for how you operate, or when the stronger
   credential is worth the extra handling.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 1095 \
  -keyout config/contoso.key -out config/contoso.crt \
  -subj "/CN=entra-secret-monitor"
```

For a secret, take the value under *Certificates & secrets -> Client secrets*.
The block above is only needed for the certificate route; upload `contoso.crt`
under *Certificates & secrets -> Certificates*.

The monitoring app registration shows up in its own report, so its own expiry is
reported too. That holds while a single credential is attached: several
credentials of the same application and type collapse into one channel carrying
the longest remaining runtime, so during an overlapping rotation the fresh one
hides the one about to expire.

## Creating the app registration

`scripts/New-MonitorAppRegistration.ps1` does the whole setup in one call:
it creates a dedicated app registration, grants and consents to
`Application.Read.All`, attaches a credential and prints the environment block.

```powershell
./scripts/New-MonitorAppRegistration.ps1 `
  -TenantId 00000000-1111-2222-3333-444444444444 `
  -TenantKey contoso
```

Without further switches this creates a client secret valid for 24 months.

Requires the `Microsoft.Graph.Applications` module and an account allowed to
create app registrations and grant admin consent. Add `-UseDeviceCode` when no
browser is available.

For a certificate instead, add `-CreateCertificate` (with `-CertificateYears` to
change the three year default) or `-CertificatePath` to upload an existing one.
The private key is then written next to the certificate, never sent to Entra,
and both files belong in the `config` directory of the monitoring host.
Certificate lifetime is not capped by Entra, unlike the 24 months a client
secret gets, so a longer lifetime mainly extends the window in which a leaked
key stays usable.

## Configuration

Everything is environment variables, so one container serves many tenants:

```env
TENANTS=contoso,fabrikam

CONTOSO_DISPLAY_NAME=Contoso AG
CONTOSO_TENANT_ID=...
CONTOSO_CLIENT_ID=...
CONTOSO_CERT_PATH=/config/contoso.crt
CONTOSO_KEY_PATH=/config/contoso.key
CONTOSO_WARN_DAYS=30
CONTOSO_ERROR_DAYS=14

FABRIKAM_TENANT_ID=...
FABRIKAM_CLIENT_ID=...
FABRIKAM_CLIENT_SECRET=...
```

Alternatively mount a `tenants.json` (see `config/tenants.example.json`) and point
`TENANTS_FILE` at it. Both sources can be combined; the file wins.

| Per-tenant key | Default | Meaning |
|---|---|---|
| `TENANT_ID`, `CLIENT_ID` | - | required |
| `CLIENT_SECRET` *or* `CERT_PATH` + `KEY_PATH` | - | one of both required |
| `DISPLAY_NAME` | tenant key | label in the GUI |
| `WARN_DAYS` / `ERROR_DAYS` | 30 / 14 | thresholds in days |
| `INCLUDE_SP` | false | include service principals / enterprise apps |
| `APP_FILTER` | empty | only apps whose display name contains this text |
| `APP_EXCLUDE` | empty | comma separated list of display name fragments to drop; wins over `APP_FILTER` |
| `SHOW_EXPIRED` | false | also report already expired credentials |
| `MAX_CHANNELS` | 45 | PRTG allows 50 channels per sensor |
| `PUSH_URL` | empty | PRTG HTTP Push Data Advanced sensor URL |

| Service key | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` / `LISTEN_PORT` | `0.0.0.0` / `8099` | bind address |
| `API_TOKEN` | empty | when set, all endpoints except `/healthz` require `?token=` or a Bearer header |
| `CACHE_TTL` | `1800` | seconds a scan result is reused |
| `PUSH_INTERVAL` | `0` | seconds between background pushes, `0` disables |

## PRTG integration

**Pull (recommended)** - sensor type **HTTP Data Advanced**:

- URL: `http://<docker-host>:8099/prtg?tenant=contoso&token=<API_TOKEN>`
- Scanning interval: 6 hours (uncheck "inherit")

The first run creates the channels including their limits. PRTG only takes limits
from the XML when a channel appears for the first time; later changes have to be
made on the channel itself.

Channels:

| Channel | Meaning | Limits |
|---|---|---|
| Minimale Restlaufzeit | smallest remaining runtime in the tenant | warning < `WARN_DAYS`, error < `ERROR_DAYS` |
| Kritisch unter Warngrenze | number of apps below the warning threshold | warning > 0 |
| Abgelaufen | number of expired credentials | error > 0 |
| `<app> (Secret)` / `<app> (Zertifikat)` | remaining runtime per app | warning / error as above |

### One sensor per application

`/prtg` accepts per-request overrides, so one tenant can feed several sensors
without a second configuration entry:

| Parameter | Effect |
|---|---|
| `filter=` | only apps whose display name contains this text |
| `exclude=` | comma separated fragments to drop |
| `warn=` / `error=` | thresholds in days for this sensor |
| `show_expired=true` | include already expired credentials |
| `max_channels=` | channel cap for this sensor |

```
# everything except the self-renewing Connect certificate, 30/14 days
/prtg?tenant=contoso&exclude=ConnectSyncProvisioning

# the Connect certificate on its own, 10/5 days, so a stalled sync still shows
/prtg?tenant=contoso&filter=ConnectSyncProvisioning&warn=10&error=5

# one application, one sensor
/prtg?tenant=contoso&filter=KeyCloak
```

Only the Graph round trip is cached, filtering happens per request, so extra
sensors cost no extra Graph calls. `include_sp` is not overridable for that
reason: it would change what the shared cache holds.

**Push** - sensor type **HTTP Push Data Advanced**: set `PUSH_URL` per tenant and
`PUSH_INTERVAL=21600`. Use this when PRTG cannot reach the container.

**SSH** - if you would rather not run a service at all, `bare-metal/` contains an
installer and a wrapper for the **SSH Script Advanced** sensor. It uses the same
code without the HTTP layer.

Errors never fail silently: the `/prtg` endpoint answers with
`<error>1</error>` and the actual Graph message, so the sensor turns red and shows
the cause (a missing admin consent surfaces as `Graph HTTP 403 ...`).

## Command line

The container image doubles as a CLI:

```bash
docker compose run --rm entra-secret-monitor /app/cli.py --tenant contoso --format text
```

```
Restlaufzeit     Ablauf       Typ      App / Credential
----------------------------------------------------------------------------
        19 d !  2026-09-09   cert     Backup SAML / saml-signing
       399 d    2027-09-24   secret   Reporting API / rotated-2026
----------------------------------------------------------------------------
2 entries, 0 expired, 1 below 30 days
```

`--format prtg|json|text`, `--warn`, `--error`, `--filter`, `--exclude`, `--include-sp`,
`--show-expired`, `--max-channels`, `--push`, `--list-tenants`.

## REST API

The portal exposes `/api/v1` so an upstream system, for example a service provider's
own customer portal, can drive it: create a customer with tenant id, client id and
secret, trigger a scan, read the remaining lifetimes, hand out the sensor URLs. Keys are
issued under **Einstellungen, API** in two scopes, `read` and `write`, and authenticate
through `Authorization: Bearer esm_...`.

Credentials go in and never come back out. A response tells whether a credential is
stored and, for a certificate, its thumbprint and expiry, never the secret itself.

Every customer also carries a `state` and a list of `problems`: a machine readable
code, a sentence saying what is wrong, and the next step where there is one. Seven
Entra error codes are translated, so `AADSTS7000215` arrives as "the stored client
secret is wrong or has since been renewed" rather than as a code to look up.
`GET /api/v1/problems` returns only the customers that need attention, worst first.

The machine readable description lives at `/api/v1/openapi.json`. Full documentation in
[docs/PORTAL.md](docs/PORTAL.md#rest-schnittstelle).

## Security

- Only `Application.Read.All` is required, which reads metadata. Secret **values**
  are never returned by Graph and never leave the tenant.
- The container runs as UID 10001, read only, `no-new-privileges`.
- Mount `./config` read only. Keep private keys at mode 0640.
- Set `API_TOKEN` whenever the port is reachable beyond a management VLAN, and put
  a reverse proxy with TLS in front of it if it leaves the host. The token is
  accepted as `?token=` for PRTG, which cannot send headers, or as
  `Authorization: Bearer <token>` where the client can. It is redacted from the
  access log either way.
- Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options:
  DENY`, `Referrer-Policy: no-referrer` and a content security policy of
  `default-src 'none'`. The GUI ships no JavaScript, so scripts are forbidden
  outright rather than allow-listed.

## Security gate

Before anything reaches `main`, [docs/SECURITY-GATE.md](docs/SECURITY-GATE.md)
is worked through. Everything that can be automated runs in
`.github/workflows/security.yml`: both test runs, gitleaks over the tree and the
history, `pip-audit`, builds of both images with a non-root check and Trivy. The rest,
route sweeps against every role and the adversarial pass, is a manual step the
document describes.

## Tests

The suite is standard library only, no dependencies and no network:

```bash
python3 -m unittest discover -s tests -t .
```

It covers configuration parsing, Graph paging and aggregation, both renderers,
the request path, and a security group asserting HTML and XML escaping, token
handling and the response headers against a live server on a loopback port.

Install `requirements-portal.txt` as well and the portal suite runs too: login with
its second factor, credential encryption, the customer lifecycle and the REST API
including scope separation, input validation and the promise that no stored
credential leaves the building. With the extras present the run must report zero
skipped tests, otherwise the portal half silently did not run.

## Function inventory

`docs/FUNCTIONS.md` lists every function with its signature, what it returns and
the first line of its docstring. It is generated, never edited:

```bash
python3 tools/inventory.py           # regenerate
python3 tools/inventory.py --check   # exit 1 if stale or newly duplicated
```

The generator also reports duplicated work, which is the actual point: the same
function name defined in more than one module, and two bodies that share their
shape once identifiers are stripped, so renamed copy-paste still shows up. A
deliberate repeat goes into `ALLOWED_NAME_DUPLICATES` or
`ALLOWED_STRUCTURE_DUPLICATES` with a reason, and `tests/test_inventory.py`
fails on anything else, so the document cannot rot and a new duplicate cannot
land quietly.

It detects copies, not reinvention: a second implementation written from scratch
with a different shape will not be caught.

## Known limitations

- GUI labels and PRTG channel names are German. Renaming them later renames the
  PRTG channels too, which loses their history, so it is not a cosmetic change.
  See `STRINGS` candidates in `app/graph.py` and `app/server.py` if you fork.
- Entra Connect rolls its own `ConnectSyncProvisioning_*` certificate every few
  months. It dips below a 30 day warning threshold on every cycle and recovers on
  its own. Either exclude it with `APP_EXCLUDE=ConnectSyncProvisioning` or give it
  its own sensor with a lower threshold, so a genuinely stalled Connect server is
  still caught.
- PRTG caps sensors at 50 channels. Large tenants need `APP_FILTER`,
  `MAX_CHANNELS`, or one sensor per app group.
- Certificate authentication requires the `cryptography` package
  (`pip install -r requirements-monitor.txt`). Client secret authentication is
  pure standard library.

## License

MIT
