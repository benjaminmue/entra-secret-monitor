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

20 Tests, keiner spricht mit Microsoft. Abgedeckt sind Passwortregeln, Verschlüsselung,
TOTP-Wiedereinspielung, der zweistufige Anmeldeablauf, die Sperre auf der TOTP-Stufe, die
Unmöglichkeit, eine bestätigte Authenticator-App über die Einrichtungsseite zu ersetzen,
CSRF, der Kundenlebenszyklus samt PRTG-Ausgabe und Filterparametern, die Slotverteilung,
die Einmal-pro-Tag-Regel und die Rollentrennung.

## Grenzen

- Ein Prozess, ein Scheduler. Zwei Instanzen auf derselben Datenbank würden Kunden
  doppelt prüfen. Für Hochverfügbarkeit müsste die Fälligkeitsprüfung eine Sperre in
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
