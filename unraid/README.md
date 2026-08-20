# Unraid

## Vorlage installieren

1. `entra-secret-monitor.xml` nach `/boot/config/plugins/dockerMan/templates-user/`
   kopieren (per SMB auf die Freigabe `flash`, Ordner
   `config/plugins/dockerMan/templates-user/`).
2. Unraid-Weboberflaeche, Reiter **Docker**, **Add Container**, oben unter
   *Template* den Eintrag `entra-secret-monitor` waehlen.

## Zugangsdaten NICHT in die Variablenfelder

Unraid schreibt alle Variablen der Docker-Vorlage im Klartext nach
`/boot/config/plugins/dockerMan/templates-user/my-entra-secret-monitor.xml`.
Diese Datei liegt auf dem Flash-Stick und ist Teil des Flash-Backups.
`Mask="true"` verdeckt nur die Anzeige im Browser, nicht die Datei.

Die Vorlage laedt darum die Zugangsdaten ueber `--env-file` aus dem
appdata-Ordner. Vor dem ersten Start anlegen:

```bash
mkdir -p /mnt/user/appdata/entra-secret-monitor
cat > /mnt/user/appdata/entra-secret-monitor/monitor.env <<'EOF'
TENANTS=contoso

CONTOSO_DISPLAY_NAME=Contoso AG
CONTOSO_TENANT_ID=00000000-0000-0000-0000-000000000000
CONTOSO_CLIENT_ID=00000000-0000-0000-0000-000000000000
CONTOSO_CLIENT_SECRET=...
CONTOSO_WARN_DAYS=30
CONTOSO_ERROR_DAYS=14

API_TOKEN=ein-langes-zufaelliges-token
EOF
chmod 644 /mnt/user/appdata/entra-secret-monitor/monitor.env
```

Ohne diese Datei startet der Container nicht, weil `--env-file` auf eine
fehlende Datei mit einem Fehler abbricht.

## Zertifikat statt Client Secret

Zertifikatsdateien in denselben Ordner legen und in `monitor.env` referenzieren:

```env
CONTOSO_CERT_PATH=/config/contoso.crt
CONTOSO_KEY_PATH=/config/contoso.key
```

Der Container laeuft als **UID 10001**. Die Dateien in appdata gehoeren
ueblicherweise `nobody:users` (99:100), deshalb muss der private Schluessel
fuer andere lesbar sein:

```bash
chmod 644 /mnt/user/appdata/entra-secret-monitor/contoso.key
```

Das ist der Preis des unprivilegierten Containers. Wer das nicht will,
nimmt auf Unraid ein Client Secret und laesst die Zertifikatsvariante dem
Server, auf dem die Datei mit 0640 und eigener Gruppe liegen kann.

## Grundsaetzliche Ueberlegung vor dem Einsatz

Der Container braucht ein Credential mit Leserechten auf den ueberwachten
Tenant. Ob so ein Credential auf privater Hardware liegen darf, ist keine
technische, sondern eine organisatorische Frage. Fuer Kundentenants gehoert
die Instanz auf einen betrieblichen Host. Auf einem privaten Unraid ist der
sinnvolle Einsatz der eigene Tenant oder eine Testumgebung.

## Update

Unraid zeigt Updates an, sobald ein neues `:latest` in der GHCR vorliegt.
Alternativ im Container-Kontextmenue **Force Update**.

## Fehlersuche

| Symptom | Ursache |
|---|---|
| Container startet nicht, Log erwaehnt `--env-file` | `monitor.env` fehlt oder ist nicht lesbar |
| GUI zeigt rote Box `Graph HTTP 403` | Admin-Consent fuer `Application.Read.All` fehlt |
| GUI zeigt `Permission denied` beim Zertifikat | Datei fuer UID 10001 nicht lesbar, `chmod 644` |
| `/prtg` antwortet `Ungueltiger oder fehlender Token` | `API_TOKEN` gesetzt, aber im PRTG-Sensor nicht angehaengt |
| Keine Tenants im Log | `TENANTS` nicht gesetzt oder Praefixe passen nicht zu den Keys |
