# Sicherheitsgate

Vor jedem Push auf `main`, jeder Veröffentlichung und jedem Rollout wird diese
Liste durchgegangen. Jeder Punkt bekommt PASS, FAIL, BLOCKED oder N/A mit einem
Beleg. PASS setzt eine Prüfung oder einen Test voraus, nicht eine Annahme;
ungeprüft heisst BLOCKED, nicht PASS. N/A braucht eine Begründung aus der
Architektur dieses Projekts, nicht den blossen Satz "trifft nicht zu".

Solange ein zutreffender Punkt FAIL oder BLOCKED ist, wird nicht gemerged,
veröffentlicht oder ausgerollt.

## Was die CI übernimmt

`.github/workflows/security.yml` fährt bei jedem Push und Pull Request und
zusätzlich montags:

| Job | Deckt ab |
|---|---|
| `tests` | die Testsuite zweimal, ohne und mit den Extras, mit der Bedingung null übersprungener Tests |
| `secrets` | gitleaks über Arbeitsbaum und History, plus zwei deterministische Prüfungen auf eingecheckte `.env`- und Schlüsseldateien |
| `dependencies` | `pip-audit --strict` gegen `requirements-portal.txt` und `requirements-monitor.txt` |
| `image` | Portal- und Monitor-Abbild bauen, Nachweis dass keines als root startet, Trivy auf HIGH und CRITICAL für beide |

Die Testsuite selbst trägt die inhaltlichen Zusicherungen: Bereichstrennung der
API-Schlüssel, Eingabeprüfung, dass kein Zugangsdatum in einer Antwort landet,
Drosselung, CSRF, Rollentrennung, Trennung von `app/` und `portal/`.

## Was von Hand nachgezogen wird

Diese Punkte brauchen Urteil und stehen deshalb nicht in der CI. Der Ablauf ist
jedes Mal derselbe, die Skripte dazu liegen nicht im Repo, weil sie gegen eine
Wegwerfdatenbank fahren und mit dem Stand des Codes wandern.

### Routen gegen anonym und gegen jede Rolle

Nicht aus Dekoratoren ablesen, sondern fahren: ein Dekorator auf der falschen
Zeile sieht im Quelltext richtig aus. Jede Route aus `app.url_map` wird gegen
jede Rolle gefahren, und zwar gegen eine Erwartung je Route, Methode und Rolle.
Ein pauschales "muss abweisen" trifft es nicht, weil `viewer` lesen und
`operator` schreiben darf.

Anonym: alles ausser den bewusst öffentlichen Routen muss 302, 401 oder 403
liefern.

| Route | Warum öffentlich |
|---|---|
| `/login`, `/login/2fa`, `/login/2fa/setup`, `/logout` | Anmeldung selbst |
| `/healthz` | Probe des Containers |
| `/prtg/<token>`, `/json/<token>` | Sensor, die Berechtigung steckt im Token |
| `/api/v1/openapi.json` | prüft selbst auf Schlüssel oder Sitzung |
| `/static/<datei>` | CSS |

Angemeldet, je Rolle. Erwartet wird 403 auf allem, was die Rolle nicht darf,
und ein Erfolg auf allem, was sie darf:

| Rolle | Darf lesen | Darf schreiben | Muss 403 bekommen auf |
|---|---|---|---|
| `viewer` | Übersicht, Kundendetail, Anleitung | nichts | `/kunden/neu`, `/kunden/slots`, alles unter `/kunden/<id>/`, `/benutzer/*`, `/einstellungen/api/*` |
| `operator` | dasselbe | Kunden anlegen, ändern, löschen, prüfen, Token wechseln | `/benutzer/*`, `/einstellungen/api/*` |
| `admin` | alles | alles | nichts |

Die Erlaubnisseite ist genauso wichtig wie die Verbotsseite: eine Rolle, die
plötzlich nichts mehr darf, fällt sonst erst im Betrieb auf.

### Angriffstests

Zerstörungsfrei und nur lokal. Nie gegen eine produktive Instanz und nie gegen
einen Kundentenant.

- Sensor-Token um ein Zeichen verändern: muss Fehler-XML liefern, keine Daten
- Zwei Kunden mit je einer nur bei ihnen vorhandenen Anwendung anlegen, dann
  jedes Token gegen den fremden Namen prüfen, auch über `?filter=` und `?app=`
- Massenzuweisung: `PATCH` mit `id`, `prtg_token`, `client_secret_enc`,
  `count_total`, `created_at`. Kein Feld darf ankommen
- Kopfvarianten: Grossschreibung, zwei Schlüssel, angehängtes Leerzeichen,
  angehängtes Nullbyte
- `X-Original-URL` und `X-Rewrite-URL` dürfen das Routing nicht ändern
- Lesender Schlüssel gegen jeden schreibenden Endpunkt: 403
- Konto versucht die eigene Rolle anzuheben: 403
- Injektionsnutzlasten (SQL, Skript, Template, Traversal, XML-verbotene Zeichen,
  5000 Zeichen) in jedes Freitextfeld. Kein 5xx, keine unmaskierte Spiegelung
  in XML oder HTML, Tabellenstand von `users` und `api_keys` unverändert

### Was das Berechtigungsmodell nicht kennt

Das Portal ist ein Betreiberwerkzeug, kein Mehrbenutzerprodukt. Es gibt keinen
Datenbesitz je Konto: jedes angemeldete Konto sieht jeden Kunden, die Rolle
entscheidet nur über Schreiben. Ein IDOR-Test auf Kundendatensätze zwischen
zwei Konten prüft deshalb nichts, was es gibt.

Die Trennung, die es tatsächlich gibt, liegt woanders und wird oben geprüft:
ein Sensor-Token gilt für genau einen Kunden. Wer die Instanz gegen mehrere
Parteien öffnen will, braucht vorher ein Besitzmodell; bis dahin ist der
API-Schlüssel bewusst ein Schlüssel zur Instanz, nicht zu einem Kunden.

## Grenzen, die bekannt sind

- **gitleaks erkennt Entra Client Secrets nur über eine eigene Regel.** Die
  mitgelieferten Regeln lassen einen Wert der Form `Rt8Q~aBcDeF...` durch,
  nachgemessen. `.gitleaks.toml` trägt deshalb `entra-client-secret`. Ein
  Mustererkenner bleibt ein Netz mit Löchern; die deterministischen Prüfungen
  auf eingecheckte `.env`- und Schlüsseldateien sind die Absicherung dagegen.
- **Die Drosselung liegt im Prozessspeicher.** Sie überlebt keinen Neustart und
  zählt nicht über mehrere Instanzen. Das passt, solange das Portal ein Prozess
  ist, so wie es in `PORTAL.md` unter Grenzen steht. Wer es hinter einen
  Lastverteiler stellt, braucht einen gemeinsamen Zähler.
- **Der Adresszähler ist nur so gut wie die Adresse.** Hinter einem Reverse
  Proxy sehen alle Aufrufer gleich aus, solange `PORTAL_TRUST_PROXY` nicht
  gesetzt ist; ist es gesetzt, wird dem ersten Eintrag in `X-Forwarded-For`
  geglaubt, und der lässt sich fälschen, wenn der Proxy ihn nicht überschreibt.
  Deshalb hängt an diesem Zähler nur der billige Pfad: er bremst das
  Durchprobieren wechselnder Präfixe. Das Raten eines Geheimnisses zu einem
  bekannten Schlüssel zählt je Präfix, und da spielt die Adresse keine Rolle.
  Wer den Proxy einrichtet, muss `X-Forwarded-For` dort setzen und nicht
  durchreichen.
- **Ein gültiger Schlüssel wird nie durch Fehlversuche gesperrt.** Die Zähler
  werden erst nach der Prüfung angefasst und sehen deshalb nur Fehlversuche.
  Zwei Fassungen davor waren schwächer und die Zusicherung hier war falsch:
  die erste zählte je Adresse, also sperrten fremde Fehlversuche hinter einem
  Reverse Proxy jeden mit; die zweite zählte je Präfix, prüfte aber **vor** der
  Authentifizierung, also sperrte das Raten am eigenen Schlüssel dessen Inhaber
  aus. Beides fiel erst in einer Gegenprüfung auf. Ein Test hält den heutigen
  Stand fest.
- **Sensor-URLs enthalten das Token.** Wer eine URL hat, liest die Kanäle dieses
  Kunden ohne API-Schlüssel, und der Widerruf eines Schlüssels nimmt das nicht
  zurück. Gegenmittel ist `POST /api/v1/customers/<key>/token`.
- **Die Datenbankdatei ist 0644.** Innerhalb des Containers gibt es keinen
  anderen Benutzer, das Abbild läuft ohne Fähigkeiten und schreibgeschützt; auf
  dem Host liegt das Volume unter einem Pfad, den nur root liest. Ein Lesen der
  Datei allein gibt keine Zugangsdaten her, weil der Schlüssel in der Umgebung
  steht und nicht in der Datenbank, aber die PRTG-Token stehen im Klartext.

## Eine unabhängige Prüfung vor dem Merge

Zusätzlich zur Liste oben geht jede Änderung an Code durch ein Review eines
zweiten Modells, **bevor** der Pull Request gemergt wird, nicht danach.

Der Grund steht in der Historie dieses Projekts. Ein Review nach dem Merge fand
in einem Fall eine Eingabeprüfung, die einen Kunden anlegte, den die eigene
Schnittstelle danach nicht mehr adressieren konnte, und in einem zweiten einen
Formulardefault, der bei einer Absendung ohne das Feld ein hinterlegtes
Zertifikat samt privatem Schlüssel löschte. Beides stand zwischenzeitlich auf
`main`. Die Testsuite war in beiden Fällen grün, weil sie prüft, was jemand zu
prüfen gedacht hat.

Was das Review bekommt: den Diff, den Zweck der Änderung und die Stellen, an
denen ein Fehler teuer wäre. Was es zurückgeben muss: Befunde mit Datei und
Zeile, oder ausdrücklich nichts. Ein Befund wird nachgestellt, bevor er
behoben wird, und ein Befund, der sich nicht nachstellen lässt, wird nicht
behoben, sondern verworfen.

## Wie eine Änderung auf main kommt

`main` ist seit dem 06.09.2026 durch ein Ruleset geschützt. Ein direkter Push
wird vom Server abgewiesen:

```
- Changes must be made through a pull request.
- 4 of 4 required status checks are expected.
```

Der Weg ist deshalb immer derselbe:

```bash
git switch -c thema
git push -u origin thema
gh pr create --fill
gh pr merge --auto --squash --delete-branch
```

`--auto` statt einer Warteschleife auf `gh pr checks`: der Merge passiert von
selbst, sobald die vier Checks grün sind. Eine Schleife über `gh pr checks`
hängt, sobald ein Job übersprungen wird.

Erforderlich sind `Testsuite`, `Geheimnisse`, `Abhaengigkeiten` und `Abbild`,
dazu keine Genehmigung. Bei einem einzigen Betreuer wäre eine
Genehmigungspflicht eine Selbstblockade, denn den eigenen Pull Request kann
niemand freigeben; die Bedingung entsteht über die Checks, nicht über ein
Review. Force-Push und Löschen von `main` sind gesperrt.

**Niemand hat einen Bypass, auch der Betreuer nicht.** Eine Ausnahme für sich
selbst macht das Gate zur Dekoration.

**Wenn ein Pull Request hängen bleibt**, weil ein Check gar nicht erst startet
(Tippfehler im Workflow, umbenannter Job, Störung bei GitHub), steht er auf
*Expected, waiting for status* und lässt sich nicht mergen. Ausweg: das Ruleset
kurz stilllegen, den Fix einbringen, wieder scharf schalten.

```bash
gh api --method PUT repos/benjaminmue/entra-secret-monitor/rulesets/22382604 \
  -f enforcement=disabled
# Fix einbringen, dann
gh api --method PUT repos/benjaminmue/entra-secret-monitor/rulesets/22382604 \
  -f enforcement=active
```

**Namen der Checks müssen genau stimmen.** Im Ruleset stehen die kurzen Namen,
weil `security.yml` bei einem Pull Request direkt läuft. Aus dem
Veröffentlichungslauf heraus heissen dieselben Jobs `gate / Testsuite` und so
weiter; wer einen Job umbenennt, muss das Ruleset mitziehen, sonst wartet jeder
künftige Pull Request auf einen Check, den es nicht mehr gibt.

## Ein Durchlauf ist an einen Stand gebunden

Das Ergebnis gilt für einen Commit, nicht für einen Zeitraum. Ändert sich nach
dem Durchlauf noch etwas, werden die betroffenen Punkte erneut gefahren. Ein
bestandenes Gate ist zudem keine Freigabe: es sagt, dass nichts Bekanntes
entgegensteht, nicht dass veröffentlicht werden soll.
