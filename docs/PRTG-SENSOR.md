# PRTG Custom Sensor

`prtg/Get-EntraSecretExpiry.ps1` macht dasselbe wie der Container, aber direkt in
PRTG: ein Sensor pro Kundentenant, keine zusätzliche Infrastruktur, kein Portal,
kein Docker-Host. Windows PowerShell 5.1, keine Module.

## Betriebsmodell

Das Skript liegt auf der **PRTG-Instanz im eigenen Rechenzentrum**, nicht auf einer
Probe beim Kunden. Es wird einmal installiert und bedient danach alle Tenants.

Das geht, weil der Sensor kein Kundennetz braucht. Entra ID und Microsoft Graph sind
öffentliche Endpunkte, der Sensor spricht ausschliesslich:

| Ziel | Port | Zweck |
|---|---|---|
| `login.microsoftonline.com` | TCP 443 | Token (client credentials) |
| `graph.microsoft.com` | TCP 443 | App Registrations lesen |

Kein Domain Controller, kein Site-to-Site-Tunnel, kein Agent beim Kunden. Ein Kunde
ohne eigenen Server für eine Remote Probe wird genauso überwacht wie einer mit, das
Gerät hängt in beiden Fällen an der lokalen Probe der Instanz.

Steht die Instanz hinter einem Proxy, kommt `-Proxy http://proxy:8080` dazu.

Wer den Sensor trotzdem auf einer Remote Probe betreiben will, kann das: Installation
und Parameter sind identisch, das Skript muss dann nur dort liegen und die Probe
braucht den Weg ins Internet.

## Zugangsdaten: Credentials for Script Sensors

Die Sektion *Credentials for Microsoft 365* im Gerät ist den eingebauten
M365-Sensoren vorbehalten, für Custom Sensoren gibt es darauf keinen Platzhalter
(offener Feature Request bei Paessler).

Direkt darunter steht aber **Credentials for Script Sensors**, und genau dafür ist
sie da. Fünf freie Platzhalter mit Beschreibung und Wert, vererbbar von Probe und
Gruppe, die Werte zeigt PRTG weder in den Einstellungen noch im Sensorlog.

| Platzhalter | Beschreibung | Wert |
|---|---|---|
| Placeholder 1 | Entra Tenant ID | Directory (tenant) ID |
| Placeholder 2 | Entra Client ID | Application (client) ID |
| Placeholder 3 | Entra Client Secret | Client Secret |

Im Sensor referenziert als `%scriptplaceholder1` bis `%scriptplaceholder3` im Feld
*Parameters*.

**Nur als Parameter, nicht über die Umgebung.** Auf PRTG 26.3 nachgemessen: die
Sensoroption *Set placeholders as environment values* liefert
`prtg_windowsdomain`, `prtg_windowsuser`, `prtg_windowspassword`,
`prtg_linuxuser`, `prtg_linuxpassword`, `prtg_snmpcommunity`, `prtg_host`,
`prtg_device`, `prtg_deviceid`, `prtg_groupid`, `prtg_probe`, `prtg_probeid`,
`prtg_sensorid`, `prtg_name`, `prtg_primarychannel`, `prtg_url`, `prtg_version`.
Ein `prtg_scriptplaceholder*` ist nicht dabei. Prüfen lässt sich das jederzeit mit
`-ShowEnvironmentNames`.

Damit steht das Client Secret in der Kommandozeile des Sensorprozesses, die jeder
lokale Prozess mitlesen kann. Auf der PRTG-Instanz sind das Administratoren, in den
meisten Umgebungen also vertretbar. Wer es sauberer will, hat zwei Wege:

**Zertifikat.** In den Parametern steht nur der Fingerabdruck, der ist kein
Geheimnis, der private Schlüssel liegt im Zertifikatsspeicher der Instanz. Zusätzlich
läuft ein Client Secret nach spätestens 24 Monaten ab und nimmt die Überwachung mit
sich, ein Zertifikat nicht.

**Credentials for Windows des Geräts.** Domain, User und Passwort tragen Tenant ID,
Client ID und Client Secret. Diese drei kommen mit der Umgebungsoption tatsächlich in
den Prozess, das Secret bleibt also aus der Kommandozeile. Preis dafür: semantischer
Missbrauch der Felder, und das Gerät darf keine echten Windows-Sensoren tragen. Der
Sensor liest sie, wenn weder Parameter noch Script-Platzhalter etwas liefern.

Eine Regel unabhängig von der Variante: Platzhalternamen gehören nie in eine Ausgabe
des Skripts. PRTG löst Platzhalter auch in der Sensormeldung auf und würde den Wert
damit anzeigen. Der Sensor hält sich daran, seine Fehlertexte enthalten keine
Platzhalternamen.

## Voraussetzungen im Tenant

App Registration mit **genau einer** Application Permission auf Microsoft Graph:
`Application.Read.All`, mit Admin Consent. Graph gibt Secret-Werte nie heraus, die
Berechtigung liest ausschliesslich Metadaten.

`scripts/New-MonitorAppRegistration.ps1` legt die Registrierung inklusive Consent
und Zertifikat in einem Durchgang an.

## Installation auf der Instanz

1. Skript ablegen unter
   `C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\Get-EntraSecretExpiry.ps1`
2. Datei entsperren, falls sie über einen Browser kam:
   `Unblock-File .\Get-EntraSecretExpiry.ps1`
3. Execution Policy setzen. Der Probe-Dienst ist auch auf dem Core Server ein
   32-Bit-Prozess und startet die 32-Bit-PowerShell, deren Policy ist von der
   64-Bit-Policy unabhängig und auf Windows-Clients standardmässig `Restricted`:

```powershell
# als Administrator in C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
Set-ExecutionPolicy -Scope LocalMachine RemoteSigned
```

   Fehlt dieser Schritt, schreibt PowerShell einen Klartextfehler nach stdout und der
   Sensor meldet **PE233** plus **PE231**, nicht etwa ein fehlendes Skript. Prüfen:

```powershell
& "$env:WINDIR\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -Command "Get-ExecutionPolicy -Scope LocalMachine"
```

4. Bei Zertifikatsanmeldung: PFX pro Kunde nach `LocalMachine\My` importieren und dem
   Dienstkonto von PRTG Leserecht auf den privaten Schlüssel geben (certlm.msc,
   Rechtsklick auf das Zertifikat, Alle Aufgaben, Private Schlüssel verwalten).

Die Zertifikate aller Kunden liegen damit an einem Ort. Wer darauf Zugriff hat, kann
die Metadaten aller Tenants lesen, mehr nicht: `Application.Read.All` ist read-only
und gibt keine Secret-Werte heraus.

## Sensor anlegen

Ein Gerät pro Kundentenant an der lokalen Probe. Als Host des Geräts eignet sich
`graph.microsoft.com`; das Gerät bekommt keinen Ping-Sensor und keine Auto-Discovery.
In den Geräteeinstellungen die *Credentials for Script Sensors* füllen.

Der Sensor heisst nicht wie das Skript. Im Dialog *Add Sensor* nach
**EXE/Script Advanced** suchen (Filter *Monitor What?* auf *Custom Sensors*), im
zweiten Schritt erscheint das Skript in der Auswahlliste *EXE/Script*. Taucht es
dort nicht auf, liegt es nicht im EXEXML-Ordner der Maschine, auf der die Probe
dieses Geräts läuft, oder der Probe-Dienst muss einmal neu gestartet werden.

| Einstellung | Wert |
|---|---|
| Sensor Name | `Entra Secret Expiry`, nicht der Vorgabename |
| EXE/Script | `Get-EntraSecretExpiry.ps1` |
| Parameters | siehe unten |
| Environment | `Default`, ausser bei Variante C |
| Security Context | Use security context of probe service |
| Mutex Name | `entra-secret-monitor`, damit die Tenants nacheinander laufen |
| Timeout | 120 Sekunden |
| Result Handling | Store result in case of error |
| Primary Channel | `Minimale Restlaufzeit` |
| Scanning Interval | Vererbung aus, 6 Stunden. Die Vorgabe von 60 Sekunden sind 1440 Graph-Abfragen pro Tag und Tenant für eine Zahl, die sich einmal täglich um eins ändert |

Der Mutex ist auf der zentralen Instanz relevant: alle Kundensensoren laufen auf
derselben Probe und starten im selben Intervall sonst gleichzeitig.

### Variante A, Script-Platzhalter als Parameter (Standard)

```
-TenantId "%scriptplaceholder1" -ClientId "%scriptplaceholder2" -ClientSecret "%scriptplaceholder3"
```

Environment bleibt auf `Default`. PRTG setzt die Werte vor dem Start ein.

### Variante B, Zertifikat statt Secret (sicherste Variante)

```
-TenantId "%scriptplaceholder1" -ClientId "%scriptplaceholder2" -CertificateThumbprint "A1B2C3..."
```

Kein Geheimnis in der Kommandozeile, kein Ablauf nach 24 Monaten. Der private
Schlüssel liegt im Store der Instanz und verlässt ihn nie. Platzhalter 3 bleibt leer.

### Variante C, Secret über die Windows-Credentials

```
-WarnDays 30 -ErrorDays 14
```

Environment auf **Set placeholders as environment values**, im Gerät unter
*Credentials for Windows* Domain, User und Passwort mit Tenant, Client und Secret
füllen. Damit bleibt das Secret aus der Kommandozeile, ohne dass ein Zertifikat
verwaltet werden muss. Das Gerät darf dann keine echten Windows-Sensoren tragen.

### Variante D, alles als Parameter

```
-TenantId "322fec94-..." -ClientId "9c1b..." -ClientSecret "abc~..." -WarnDays 45
```

Nur für einen schnellen Test. Das Secret steht danach im Klartext in der
Sensorkonfiguration und in der Kommandozeile des Prozesses.

## Parameter

Fallback-Reihenfolge für die drei Zugangsdaten: Parameter, dann
`prtg_scriptplaceholder1` bis `3` (heute leer, siehe oben), dann
`prtg_windowsdomain` / `prtg_windowsuser` / `prtg_windowspassword`.

| Parameter | Vorgabe | Wirkung |
|---|---|---|
| `-TenantId` | Windows-Domain | Tenant ID oder verifizierte Domain |
| `-ClientId` | Windows-User | Application ID der Monitoring-App |
| `-ClientSecret` | Windows-Passwort | Client Secret |
| `-CertificateThumbprint` | leer | Zertifikat aus `LocalMachine\My` oder `CurrentUser\My`, schlägt das Secret |
| `-WarnDays` | 30 | Kanal wird gelb unter dieser Restlaufzeit |
| `-ErrorDays` | 14 | Kanal wird rot unter dieser Restlaufzeit |
| `-IncludeServicePrincipals` | aus | auch Enterprise Applications und SAML-Zertifikate |
| `-ShowExpired` | aus | bereits abgelaufene Credentials als Kanal behalten |
| `-Filter` | leer | nur Apps, deren Name diesen Text enthält |
| `-Exclude` | leer | Komma-Liste, schlägt `-Filter` |
| `-MaxChannels` | 40 | App-Kanäle, hart begrenzt auf 47 |
| `-Proxy` | leer | z.B. `http://proxy:8080`, mit Default-Credentials |
| `-TimeoutSec` | 60 | pro HTTP-Aufruf |
| `-ShowEnvironmentNames` | aus | Diagnose: meldet die Namen der `prtg_*` Variablen, nie deren Werte |

`-ShowEnvironmentNames` beantwortet die Frage, ob die Umgebungsoption greift und wie
die Platzhalter auf dieser PRTG-Version heissen. Einmal setzen, Sensormeldung lesen,
Schalter wieder entfernen.

## Kanäle

Drei feste Kanäle plus einer pro App und Credential-Typ. Namen, Einheiten und
Grenzwerte sind identisch mit der XML-Ausgabe des Containers, ein bestehender
Sensor kann also von der einen auf die andere Quelle wechseln und behält seine
Historie.

| Kanal | Einheit | Grenzwerte |
|---|---|---|
| Minimale Restlaufzeit | Tage | gelb unter `WarnDays`, rot unter `ErrorDays` |
| Kritisch unter Warngrenze | Anzahl | gelb ab 1 |
| Abgelaufen | Anzahl | rot ab 1 |
| `<App> (Secret)` bzw. `<App> (Zertifikat)` | Tage | gelb unter `WarnDays`, rot unter `ErrorDays` |

Mehrere Credentials derselben App und desselben Typs werden zu einem Kanal
zusammengefasst, gezählt wird die längste Restlaufzeit. Ein frisch gerolltes
Secret macht das alte irrelevant, und genau das beschreibt das Risiko der App.

PRTG erlaubt 50 Kanäle pro Sensor. Bei mehr Apps schneidet der Sensor ab und
schreibt die Zahl der ausgelassenen Einträge in die Sensormeldung. Gegenmittel:
`-Filter` oder `-Exclude`, oder mehrere Sensoren auf demselben Gerät.

## Fehlerbilder

Der Sensor gibt Fehler als `<error>1</error>` mit Klartext zurück, der Exit Code
bleibt 0. Die Meldung enthält den AADSTS-Code von Entra, damit steht die Ursache
direkt im Sensor.

| Meldung | Ursache |
|---|---|
| `AADSTS90002 Tenant not found` | Tenant ID falsch |
| `AADSTS700016 Application not found` | Client ID falsch oder App im falschen Tenant |
| `AADSTS7000215 Invalid client secret` | Secret falsch oder abgelaufen |
| `AADSTS700027 client assertion` | Zertifikat nicht in der App Registration hinterlegt |
| `HTTP 403 auf /applications` | `Application.Read.All` fehlt oder kein Admin Consent |
| `Zertifikat ... nicht gefunden` | falscher Store oder PRTG-Dienstkonto hat kein Leserecht auf den privaten Schlüssel |
| `HTTP 0 auf .../token` | ausgehend 443 zu `login.microsoftonline.com` fehlt oder Proxy nicht gesetzt |
| `Keine Tenant ID` / `Keine Client ID` | Platzhalter leer oder Umgebungsoption nicht aktiv, mit `-ShowEnvironmentNames` prüfen |
| `PE233` und `PE231` in PRTG | Execution Policy der 32-Bit-PowerShell fehlt. PowerShell schreibt Text statt XML, PRTG kann weder XML noch JSON parsen |
| Skript fehlt in der Auswahlliste | falsche Probe-Maschine oder Probe-Dienst noch nicht neu gestartet |

Zum Nachsehen der Rohausgabe im Sensor unter *Result Handling* die Option
*Store result* setzen, die Datei landet in
`C:\ProgramData\Paessler\PRTG Network Monitor\Logs\sensors`.

## Manueller Testlauf

```powershell
cd 'C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML'
.\Get-EntraSecretExpiry.ps1 -TenantId <tenant> -ClientId <client> -CertificateThumbprint <thumb>
```

Die Ausgabe ist das XML, das PRTG erhält.
