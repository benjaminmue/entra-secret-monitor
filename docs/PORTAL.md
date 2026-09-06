# Entra Credential Portal (v2)

Mehrmandantenfähiges Webportal für die Überwachung ablaufender Client Secrets und
Zertifikate in Entra-ID-App-Registrierungen. Ausgelegt auf rund 50 Kundentenants,
lesend, mit Anmeldung samt zweitem Faktor, Datenbank und einem Zeitplan, der die
Graph-Abfragen über den Tag verteilt.

Der klassische Dienst aus `app/` bleibt unverändert erhalten. Beide teilen sich die
Graph-Logik in `app/graph.py`, laufen aber als getrennte Images.

| | klassischer Dienst | Portal |
|---|---|---|
| Konfiguration | Umgebungsvariablen je Tenant | Datenbank, Pflege über die Oberfläche |
| Anmeldung | optionaler API-Token | Konto, Passwort, TOTP, Rollen |
| Graph-Abfrage | bei jedem Sensorabruf, Cache 30 Minuten | einmal täglich je Kunde, Sensor liest die Datenbank |
| Zugangsdaten | Dateien und Variablen auf dem Host | AES-256-GCM verschlüsselt in der Datenbank |
| Image | `Dockerfile` | `Dockerfile.portal` |

## Betrieb

```bash
cp .env.portal.example .env.portal
python3 -c "import secrets,base64;print(secrets.token_urlsafe(64));print(base64.b64encode(secrets.token_bytes(32)).decode())"
# erste Zeile nach PORTAL_SECRET_KEY, zweite nach PORTAL_ENCRYPTION_KEY
# PORTAL_BOOTSTRAP_PASSWORD setzen
docker compose -f docker-compose.portal.yml up -d
```

Nach dem ersten Start meldet man sich mit dem Bootstrap-Konto an. Das Portal erzwingt
in dieser Reihenfolge: Einrichtung der Authenticator-App, Anzeige der Recovery-Codes,
Wechsel des Passworts. Erst danach ist die Oberfläche erreichbar.

Anschliessend `PORTAL_BOOTSTRAP_PASSWORD` aus der Umgebungsdatei entfernen. Die
Variable wirkt ohnehin nur, solange die Benutzertabelle leer ist.

### Zwei Schlüssel, die nicht verloren gehen dürfen

`PORTAL_ENCRYPTION_KEY` entschlüsselt die Kundenzugangsdaten und die TOTP-Geheimnisse.
Geht er verloren, sind alle hinterlegten Secrets und privaten Schlüssel unbrauchbar und
müssen bei jedem Kunden neu erzeugt werden. `PORTAL_SECRET_KEY` signiert die
Sitzungscookies, ein Wechsel meldet lediglich alle Benutzer ab.

Beide gehören zusammen mit der Datei `/data/portal.db` ins Backup. Ein Backup der
Datenbank allein nützt ohne den Schlüssel nichts.

## Rollen

| Rolle | Darf |
|---|---|
| Leser | alles sehen, nichts ändern |
| Operator | Kunden anlegen und bearbeiten, Prüfungen auslösen, PRTG-Token erneuern |
| Administrator | zusätzlich Konten verwalten, Kunden löschen, Slots neu verteilen |

Das letzte aktive Administratorkonto lässt sich weder löschen noch herabstufen.

## Kunden anlegen

Voraussetzung ist eine App-Registrierung im Kundentenant mit der
Anwendungsberechtigung `Application.Read.All` und erteilter Administratorzustimmung.
Die vollständige Anleitung steht im Portal selbst unter *Anleitung*, inklusive der
generierten Sensor-URLs dieser Instanz.

Beim Anlegen führt das Portal sofort eine Prüfung aus. Eine falsche Tenant-ID, eine
fehlende Zustimmung oder ein nicht zum privaten Schlüssel passendes Zertifikat fällt
damit im Onboarding auf und nicht erst am nächsten Morgen.

Zertifikat und Schlüssel werden als PEM eingefügt. Der private Schlüssel wird sofort
verschlüsselt abgelegt und danach nie wieder angezeigt. Beim Bearbeiten bleiben leere
Credential-Felder ohne Wirkung, so lassen sich Schwellwerte ändern, ohne das Secret
erneut in die Hand zu nehmen.

## Zeitplan

Jeder Kunde besitzt eine feste Minute im Tag (`slot_minute`, UTC). Ein neuer Kunde
landet automatisch in der Mitte der grössten freien Lücke, bestehende Kunden behalten
ihre Zeit. Bei 50 Kunden liegen die Läufe damit rund 29 Minuten auseinander.

Der Scheduler läuft im Portalprozess, wacht standardmässig jede Minute auf und
arbeitet die fälligen Kunden nacheinander ab, mit `PORTAL_GAP_SECONDS` Pause
dazwischen. Eine prozessweite Sperre stellt sicher, dass nie zwei Abfragen
gleichzeitig laufen, auch nicht zwischen Zeitplan und Schaltfläche *Jetzt prüfen*.

Fälligkeit heisst: die eigene Minute ist heute vorbei und der letzte Lauf liegt davor.
Daraus folgt zweierlei. Ein Container, der über den Slot hinweg gestanden hat, holt
den Lauf beim Start genau einmal nach. Und eine manuelle Prüfung nach dem Slot ersetzt
den Tageslauf, kostet also keine zusätzliche Graph-Anfrage.

*Slots neu verteilen* setzt alle Kunden auf gleichmässige Abstände. Das ist nach
grösseren Bereinigungen sinnvoll, verschiebt aber die Uhrzeit jedes Sensors.

## PRTG

Sensortyp **HTTP Data Advanced**, Intervall sechs Stunden:

```
https://<portal>/prtg/<token>
```

Der Token gehört zu genau einem Kunden, steht im Pfad statt in der Abfragezeichenfolge
und lässt sich in der Kundenansicht erneuern, ohne ein Konto anzufassen. Der Abruf
liest ausschliesslich die Datenbank. 50 Sensoren erzeugen damit keine einzige Anfrage
an Microsoft.

Kanäle:

| Kanal | Bedeutung | Grenzwerte |
|---|---|---|
| Datenalter | Stunden seit dem letzten erfolgreichen Lauf | Warnung ab `PORTAL_STALE_HOURS`, Fehler ab dem Doppelten |
| Minimale Restlaufzeit | kleinste Restlaufzeit über alle Credentials | Warn- und Fehlergrenze des Kunden |
| Kritisch unter Warngrenze | Anzahl betroffener Anwendungen | Warnung ab 1 |
| Abgelaufen | Anzahl abgelaufener Credentials | Fehler ab 1 |
| je Anwendung | Restlaufzeit dieser Anwendung | Warn- und Fehlergrenze des Kunden |

Der Kanal *Datenalter* ist der Grund, weshalb ein stehengebliebener Scheduler auffällt.
Ohne ihn würde der Sensor mit eingefrorenen, aber grünen Werten weiterlaufen.

PRTG ordnet Kanäle über den Namen zu und übernimmt Grenzwerte nur beim ersten
Auftreten eines Kanals. Spätere Änderungen an Warn- oder Fehlergrenze müssen im Sensor
nachgezogen werden.

Fehlerfälle liefern bewusst HTTP 200 mit `<error>1</error>`, damit der Sensor rot wird
statt in einen Verbindungsfehler zu laufen.

### Sensor für eine einzelne Anwendung

Ein Token bedient beliebig viele Sensoren. Gefiltert wird der gespeicherte Stand, ein
zusätzlicher Sensor kostet also keine weitere Graph-Anfrage. In der Kundenansicht führt
neben jedem Credential ein Link direkt auf die passende URL.

| Parameter | Wirkung |
|---|---|
| `app` | genau diese Anwendung, exakter Name |
| `filter` | nur Anwendungen, deren Name den Wert enthält |
| `exclude` | kommagetrennte Ausschlüsse, gewinnt über `filter` |
| `type` | `secret` oder `cert` |
| `warn`, `error` | eigene Schwellen in Tagen |
| `max_channels` | Kanäle begrenzen |

Der Anwendungsfall dahinter ist Entra Connect. Das Zertifikat
`ConnectSyncProvisioning_*` erneuert sich alle sechs Monate selbst und fällt dabei
zyklisch unter jede 30-Tage-Schwelle. Zwei Sensoren lösen das:

```
# Tenant ohne das selbst rotierende Zertifikat, Schwellen des Kunden
https://<portal>/prtg/<token>?exclude=ConnectSyncProvisioning

# nur dieses Zertifikat, 10/5, damit ein stehender Connect-Server auffällt
https://<portal>/prtg/<token>?filter=ConnectSyncProvisioning&warn=10&error=5
```

Minimale Restlaufzeit, Kritisch und Abgelaufen werden über den gefilterten Umfang neu
berechnet. Ein Sensor beschreibt damit immer nur seinen eigenen Ausschnitt und nicht
mehr den ganzen Tenant.

Dieselben Daten als JSON: `https://<portal>/json/<token>`, dieselben Parameter.

## REST-Schnittstelle

Für die Ansteuerung aus einem übergeordneten System, etwa einem Cloudportal, liegt unter
`/api/v1` eine REST-Schnittstelle. Sie kann alles, was die Oberfläche kann: Kunden
anlegen und ändern, Prüfungen auslösen, Restlaufzeiten und Sensor-URLs abfragen.

Verwaltet wird sie unter **Einstellungen, API**. Die Seite listet die Endpunkte, stellt
Schlüssel aus und verlinkt die maschinenlesbare Beschreibung.

### Schlüssel

Ein Schlüssel hat die Form `esm_<präfix>_<geheimnis>` und wird genau einmal angezeigt.
Gespeichert wird nur ein Argon2-Hash; der Präfix dient dem Nachschlagen und berechtigt
allein zu nichts. Zwei Bereiche stehen zur Wahl:

| Bereich | Darf |
|---|---|
| `read` | Kunden, Zugangsdaten, Sensor-URLs und das OpenAPI-Dokument lesen |
| `write` | zusätzlich anlegen, ändern, löschen, Prüfungen auslösen, Token wechseln |

Nur Administratoren stellen Schlüssel aus. Ein schreibender Schlüssel wiegt so schwer wie
ein Bedienerkonto, nur ohne zweiten Faktor. Widerrufen wirkt sofort und lässt die Zeile
für das Protokoll stehen; jede Nutzung schreibt `last_used_at` fort, ein abgelehnter
Versuch landet im Audit-Log.

Mitgeschickt wird der Schlüssel im Kopf:

```
Authorization: Bearer esm_xxxxxxxx_...
```

### Endpunkte

| Methode | Pfad | Bereich | Zweck |
|---|---|---|---|
| GET | `/api/v1/` | read | Version und Endpunktverzeichnis |
| GET | `/api/v1/openapi.json` | read | Maschinenlesbare Beschreibung |
| GET | `/api/v1/customers` | read | Alle Kunden mit Zusammenfassung und Befunden |
| GET | `/api/v1/problems` | read | Nur die Kunden, bei denen etwas nicht stimmt |
| POST | `/api/v1/customers` | write | Kunde anlegen |
| GET | `/api/v1/customers/<key>` | read | Ein Kunde samt Laufzeiten |
| PATCH | `/api/v1/customers/<key>` | write | Ändern, weggelassene Felder bleiben stehen |
| DELETE | `/api/v1/customers/<key>` | write | Kunde mit Verlauf entfernen |
| POST | `/api/v1/customers/<key>/check` | write | Prüfung sofort auslösen |
| GET | `/api/v1/customers/<key>/credentials` | read | Zugangsdaten, kürzeste Laufzeit zuerst |
| GET | `/api/v1/customers/<key>/urls` | read | Sensor-URLs |
| POST | `/api/v1/customers/<key>/token` | write | Neues Sensor-Token |

Kunde anlegen:

```bash
curl -X POST https://<portal>/api/v1/customers \
  -H "Authorization: Bearer esm_xxxxxxxx_..." \
  -H "Content-Type: application/json" \
  -d '{
        "key": "musterag",
        "display_name": "Muster AG",
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "client_id": "11111111-1111-1111-1111-111111111111",
        "auth_type": "secret",
        "client_secret": "..."
      }'
```

Die Antwort enthält den angelegten Kunden samt Sensor-URLs. Der Kunde bekommt sofort
einen Platz im Tagesplan; eine erste Prüfung löst `POST /customers/musterag/check` aus,
die Antwort trägt das Ergebnis.

Statt eines Secrets nimmt `auth_type: "certificate"` ein Paar aus `cert_pem` und
`key_pem` entgegen. Der private Schlüssel muss unverschlüsselt sein.

### Befunde statt Rohtext

Ein anbindendes System will nicht wissen, dass Microsoft `AADSTS7000215` gesagt hat, sondern
was zu tun ist. Jeder Kunde trägt deshalb zwei zusätzliche Felder.

`state` ist der Gesamtzustand, dieselbe Bewertung wie in der Oberfläche: `ok`, `warn`, `error`,
`stale`, `unknown` oder `inactive`. Wichtig daran ist die Veraltungsregel: alte Zahlen schlagen
eine grüne Restlaufzeit, denn eine Prüfung von vor vier Tagen sagt nichts über heute. Wer das
selbst nachbaut, übersieht genau diesen Fall.

`problems` ist eine Liste von Befunden, schwerster zuerst, und leer, wenn nichts anliegt. Jeder
Befund hat einen Code für die Maschine, einen Satz für den Menschen und, wo es einen gibt, den
nächsten Schritt:

```json
{
  "code": "scan_failed",
  "severity": "error",
  "message": "Das hinterlegte Client Secret ist falsch oder wurde inzwischen erneuert.",
  "action": "Im Kundentenant ein neues Secret erzeugen und hier hinterlegen.",
  "entra_code": "AADSTS7000215",
  "detail": "GraphError: Token-Endpoint HTTP 401: ..."
}
```

Der Rohtext bleibt in `detail`, weil er bei einer Rückfrage an Microsoft gebraucht wird. Er ist
nur nicht mehr das Einzige, was herauskommt.

| Code | Bedeutet |
|---|---|
| `scan_failed` | Die letzte Prüfung schlug fehl. Sieben Entra-Kennungen sind übersetzt, dazu Netzwerk-, Berechtigungs- und Drosselungsfehler |
| `credential_expired` | Zugangsdaten des Kunden sind bereits abgelaufen |
| `credential_critical` | unter der Fehlergrenze dieses Kunden |
| `credential_warning` | unter der Warngrenze dieses Kunden |
| `data_stale` | Die Zahlen sind älter als `PORTAL_STALE_HOURS` |
| `never_checked` | Noch kein erfolgreicher Lauf |
| `no_credential` | Kein Secret und kein Zertifikat hinterlegt, es kann nicht geprüft werden |
| `own_certificate_expired` / `_expiring` | Das Zertifikat, mit dem sich das Portal anmeldet, läuft ab. Der Kunde wird dabei nicht rot, seine eigenen Zugangsdaten sind ja in Ordnung, aber die Überwachung endet |
| `inactive` | Überwachung abgeschaltet. Dann steht dieser Befund allein, alte Zahlen wären bedeutungslos |

### Nur die Auffälligen holen

`GET /api/v1/problems` liefert ausschliesslich die Kunden mit mindestens einem Befund, sortiert
nach Dringlichkeit. Der erste Eintrag ist der, den jemand zuerst ansehen sollte.

```bash
curl -H "Authorization: Bearer esm_..." https://<portal>/api/v1/problems?severity=error
```

`?severity=` grenzt auf `error`, `warn` oder `info` ein. `count` sagt, wie viele Kunden einen
Befund haben, `checked_customers` wie viele es insgesamt gibt.

### Zugangsdaten: entgegennehmen, nie herausgeben

Client Secrets und private Schlüssel gehen hinein und kommen nicht wieder heraus. Keine
Antwort trägt sie, auch nicht die Detailansicht eines Kunden. Zurück kommt nur
`has_credential`, und bei einem Zertifikat dessen Fingerabdruck und Ablaufdatum. Der
Test `test_the_stored_secret_is_encrypted_and_never_returned` prüft das an der Datenbank
und an jeder Antwort, die einen Kunden ausgibt.

Anders liegt der Fall bei den **Sensor-URLs**: sie enthalten das PRTG-Token, weil genau
das ihr Zweck ist. Wer eine solche URL hat, liest die Kanäle dieses Kunden auch ohne
API-Schlüssel, und der Widerruf eines API-Schlüssels nimmt das nicht zurück. Wurde eine
URL weitergegeben, ist `POST /customers/<key>/token` der Weg: das alte Token verfällt,
im PRTG muss die URL des Sensors nachgezogen werden.

### Fehler

Jede Antwort ist JSON, auch im Fehlerfall, mit maschinenlesbarem Code und einem Satz für
den Menschen davor:

```json
{"error": {"code": "validation_failed", "message": "Eingaben unvollständig.",
           "fields": {"error_days": "Muss kleiner oder gleich warn_days sein, hier 14 gegen 1"}}}
```

| Code | Status | Bedeutung |
|---|---|---|
| `unauthenticated` | 401 | Kein Schlüssel im Kopf |
| `invalid_key` | 401 | Unbekannt oder widerrufen |
| `read_only` | 403 | Schreibversuch mit lesendem Schlüssel |
| `not_found` | 404 | Kein Kunde mit diesem Kurznamen |
| `duplicate` | 409 | Kurzname bereits vergeben |
| `busy` | 409 | Ein anderer Scan blockiert länger als erlaubt |
| `rate_limited` | 429 | Zu viele Anfragen, `Retry-After` nennt die Wartezeit |
| `validation_failed` | 422 | `fields` nennt Feld und Grund |
| `invalid_credential` | 422 | Zertifikat und Schlüssel passen nicht zusammen |

Eingaben werden vor der Verarbeitung auf Typ und Wertebereich geprüft, und zwar für
Anlage und Änderung nach denselben Regeln. Eine Zahl in einem Textfeld, ein `"false"` in
einem Wahrheitsfeld oder ein Wechsel der Anmeldeart ohne passendes Material sind
Feldfehler, keine Serverfehler.

## Sicherheit

**SQL-Injection.** Jeder Datenbankzugriff läuft über SQLAlchemy mit gebundenen
Parametern, es gibt keine Stelle mit zusammengesetztem SQL. Zusätzlich validiert jedes
Formularfeld gegen ein Muster, bevor der Wert überhaupt in die Datenschicht gelangt:
Tenant- und Client-ID müssen GUIDs sein, der Kundenschlüssel besteht aus
Kleinbuchstaben, Ziffern und Bindestrich, Benutzernamen aus Buchstaben, Ziffern, Punkt,
Bindestrich und Unterstrich. Der Test `test_02_sql_injection_in_login_is_harmless`
schiesst eine klassische Nutzlast gegen die Anmeldung, `test_08_invalid_guid_is_refused`
gegen das Kundenformular.

**Passwörter.** Argon2id, Vorgabe 12 Zeichen aufwärts mit Gross- und Kleinbuchstaben,
Ziffer und Sonderzeichen. Zusätzlich abgelehnt werden Passwörter, die den
Benutzernamen enthalten, auf einem leicht erratbaren Wortstamm aufbauen oder ein
Zeichen mehr als dreimal hintereinander wiederholen. Neue Konten erhalten ein
generiertes Einmalpasswort, das genau einmal angezeigt wird.

**Drosselung.** Vier Grenzen, weil vier verschiedene Dinge schiefgehen können.
Das Raten des Geheimnisses zu einem bekannten Schlüssel zählt **je Präfix**,
voreingestellt zehn pro Minute: das ist der Pfad, auf dem ein Argon2-Vergleich
anfällt. Das Durchprobieren wechselnder Präfixe zählt je Adresse,
voreingestellt sechzig pro Minute; jeder einzelne Versuch kostet dort nur eine
indizierte Abfrage, die Menge ist trotzdem Last.

Beide zählen ausschliesslich Fehlversuche und geben ihren Eintrag zurück,
sobald die Authentifizierung gelingt. **Ein gültiger Schlüssel wird also nie
durch fremde Fehlversuche gesperrt**. Nach der Adresse zu zählen hatte genau
diesen Fehler: hinter einem Reverse Proxy teilen sich alle Aufrufer eine
Adresse. Anfragen zählen
je Schlüssel, voreingestellt 120 pro Minute. Und `POST /customers/<key>/check`
zählt je Kunde, voreingestellt zwölf pro Stunde, weil dahinter eine echte
Abfrage im Tenant des Kunden steht. Eine 429-Antwort trägt `Retry-After`.
Dieselbe Grenze je Kunde gilt für den Prüfknopf der Oberfläche: ein Knopf
lässt sich so oft drücken wie ein Endpunkt aufrufen.

Einstellbar über `PORTAL_API_KEY_ATTEMPTS_PER_MINUTE`,
`PORTAL_API_ANON_ATTEMPTS_PER_MINUTE`, `PORTAL_API_RATE_PER_MINUTE` und
`PORTAL_API_CHECK_PER_HOUR`. Ein Wert unter 1 wird beim Start abgelehnt. Der Zähler liegt
im Prozessspeicher, siehe Grenzen.

**API-Schlüssel.** Argon2id wie bei Passwörtern, nachgeschlagen über den Präfix und
verglichen über den Hash. Der Bereich `read` kann nichts verändern, jeder Schreibversuch
mit einem lesenden Schlüssel endet in 403 und im Audit-Log. Die Schnittstelle ist von der
CSRF-Prüfung ausgenommen, weil sie kein Sitzungscookie akzeptiert: die Berechtigung steckt
im mitgeschickten Kopf, nicht im Browserzustand, und damit greift kein Angriff über eine
fremde Seite.

**Zweiter Faktor.** TOTP ist Pflicht, nicht optional. Ein Konto ohne eingerichtete
Authenticator-App kommt über die Einrichtungsseite nicht hinaus. Der Zähler des zuletzt
akzeptierten Codes wird per konditionalem UPDATE fortgeschrieben, derselbe Code lässt
sich weder nacheinander noch parallel zweimal verwenden. Acht Recovery-Codes werden
gehasht abgelegt, ebenfalls mit konditionalem UPDATE eingelöst. Das TOTP-Geheimnis liegt
verschlüsselt in der Datenbank, ein gestohlener Datenbankauszug gibt den zweiten Faktor
also nicht mit heraus.

Eine bereits bestätigte Authenticator-App lässt sich nur auf drei Wegen ersetzen: über
die Step-up-Bestätigung unter *2FA* in der Kopfzeile, die aktuelles Passwort und einen
aktuell gültigen Code verlangt, nach einer Anmeldung mit Recovery-Code, oder durch einen
Administrator über *Benutzer, 2FA*. Die Einrichtungsseite selbst weist jeden anderen
Aufruf ab. Ohne diese Sperre reicht das blosse Passwort: den Code-Dialog überspringen,
die Einrichtungsseite direkt aufrufen, eigenen Authenticator hinterlegen, angemeldet
sein. Genau dieser Weg war in der ersten Fassung offen und wird von
`test_04b_setup_page_cannot_replace_a_confirmed_authenticator` abgesichert.

Recovery-Codes und generierte Einmalpasswörter werden ausschliesslich in der Antwort
angezeigt, die sie erzeugt hat. Sie laufen nie über die Flask-Session, denn die ist
signiert, aber nicht verschlüsselt: ein Wert darin steht im Klartext im Browser-Cookie.

**Anmeldeversuche.** Nach `PORTAL_LOGIN_MAX_ATTEMPTS` Fehlversuchen sperrt das Konto
für `PORTAL_LOCKOUT_MINUTES`. Die Sperre greift auf beiden Stufen, auch beim Raten von
TOTP-Codes. Der Zähler wird mit einem einzelnen UPDATE erhöht, nicht über die ORM-Session
gelesen und zurückgeschrieben, sonst überholen sich parallele Versuche. Ein unbekannter
Benutzername durchläuft trotzdem eine Hashberechnung, damit die Antwortzeit nicht verrät,
ob das Konto existiert. Ein Recovery-Code wird nur dann gegen Argon2 geprüft, wenn die
Eingabe dem Format `XXXX-XXXX-XXXX` entspricht: sonst würde jeder falsche Sechsstellige
bis zu acht Argon2-Läufe auslösen und die Worker blockieren.

**Sitzungen.** Cookie mit HttpOnly, SameSite=Lax und Secure, feste Lebensdauer,
`session_protection = strong`. Die Sitzung wird zwischen erstem und zweitem Faktor
geleert, der Anmeldezustand entsteht erst nach dem TOTP-Schritt.

**Formulare.** CSRF-Token auf jedem POST, auch auf Schaltflächen wie *Jetzt prüfen*
oder *Löschen*. Ausgenommen sind allein die beiden Maschinenendpunkte unter `/prtg`
und `/json`, die über ihren Token authentisieren.

**Kopfzeilen.** Content-Security-Policy ohne `unsafe-inline` und ohne externe Quellen,
dazu `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy` und HSTS.
Kein Skript, kein Stylesheet und keine Schriftart kommt von aussen.

**Verschlüsselung.** AES-256-GCM mit einem Nonce pro Wert. Die zugehörigen Daten (AAD)
binden jeden Ciphertext an Tabelle, Datensatz und Spalte. Wer Schreibzugriff auf die
Datenbank hat, kann einen verschlüsselten Wert deshalb nicht zwischen zwei Kunden oder
zwischen zwei Spalten umhängen, die Authentisierung schlägt fehl.

**Protokoll.** Jede Änderung und jede Anmeldeentscheidung landet in `audit_events` mit
Zeitpunkt, Konto, Adresse und Ergebnis. Lesezugriffe werden bewusst nicht protokolliert.

**PRTG-Token.** Nur Rollen mit Schreibrecht sehen Token und Sensor-URLs. Ein Leserkonto
könnte den Token sonst mitnehmen und nach seiner Deaktivierung weiter abrufen, denn der
Token hängt an keinem Konto.

## Tests

```bash
python -m pip install -r requirements-portal.txt
PYTHONPATH=. python -m unittest discover -s tests -v
```

420 Tests, keiner spricht mit Microsoft. Abgedeckt sind Passwortregeln, Verschlüsselung,
TOTP-Wiedereinspielung, der zweistufige Anmeldeablauf, die Sperre auf der TOTP-Stufe, die
Unmöglichkeit, eine bestätigte Authenticator-App über die Einrichtungsseite zu ersetzen,
CSRF, der Kundenlebenszyklus samt PRTG-Ausgabe und Filterparametern, die Slotverteilung,
die Einmal-pro-Tag-Regel, die Rollentrennung, die REST-Schnittstelle samt Bereichstrennung,
Eingabeprüfung und der Zusage, dass kein Zugangsdatum herauskommt, sowie die Drosselung
samt der Zusicherung, dass ein gültiger Schlüssel nie durch fremde Fehlversuche gesperrt
wird.

Mit installierten Extras muss die Zahl übersprungener Tests **null** sein. Der
`needs_portal`-Marker überspringt sonst alles, was Flask, pyotp oder cryptography braucht,
und ein halber Lauf meldet `OK (skipped=226)` statt eines Fehlers. Die CI prüft das.

## Grenzen

- Ein Prozess, ein Scheduler. Zwei Instanzen auf derselben Datenbank würden Kunden
  doppelt prüfen. Aus demselben Grund liegt der Drosselungszähler im
  Prozessspeicher: er überlebt keinen Neustart und zählt nicht über Instanzen. Für Hochverfügbarkeit müsste die Fälligkeitsprüfung eine Sperre in
  der Datenbank setzen.
- SQLite genügt für 50 Kunden bequem. Der `PORTAL_DATABASE_URL` nimmt aber auch
  PostgreSQL, dann zusätzlich `psycopg` installieren.
- Kein Mailversand. Alarmierung ist Aufgabe von PRTG, das Portal ist die Datenquelle.
- Zeiten im Zeitplan sind UTC, auch in der Anzeige. Das vermeidet den Sonderfall der
  doppelten Stunde bei der Zeitumstellung.
- Kein Rotationsverfahren für `PORTAL_ENCRYPTION_KEY`. Der Präfix `v1` im gespeicherten
  Wert ist dafür vorgesehen, ein Umschlüsseln mit alt entschlüsseln und neu verschlüsseln
  ist aber nicht gebaut. Bei Verdacht auf Kompromittierung des Schlüssels müssen die
  Zugangsdaten aller Kunden neu hinterlegt werden.
- `PORTAL_BASE_URL` sollte gesetzt sein. Ohne die Variable stammen die angezeigten
  Sensor-URLs aus dem Host-Header des Aufrufers, ein manipulierter Header erzeugt dann
  eine URL samt Kundentoken auf fremdem Host. Das Portal warnt beim Start darauf hin.
