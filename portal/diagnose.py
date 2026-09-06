#!/usr/bin/env python3
"""
diagnose.py

Aus dem gespeicherten Zustand eines Kunden lesbare Befunde machen.

Die Schnittstelle gab bisher nur den Rohtext von Microsoft heraus, also etwa
"GraphError: Token-Endpoint HTTP 401: ... AADSTS7000215 ...". Ein anbindendes
System kann damit nichts anfangen, und ein Techniker muss den Code
nachschlagen. Hier entsteht daraus ein Befund mit drei Teilen: ein
maschinenlesbarer Code, ein Satz fuer den Menschen und, wo es einen gibt, der
naechste Schritt.

Bewusst ein eigenes Modul und nicht in views/api.py: die Oberflaeche zeigt
dieselben Befunde, und zwei Auslegungen desselben Zustands waeren genau die
Sorte Abweichung, die niemandem auffaellt.
"""

import re
from datetime import timezone

from portal.scanner import data_age_hours

# Fehlerkennungen von Entra ID, nach denen im Rohtext gesucht wird. Microsoft
# haengt sie an jede Ablehnung des Token-Endpunkts an, und sie sind stabiler
# als der begleitende englische Satz.
# Fehlerkennungen von Entra ID, nach denen im Rohtext gesucht wird. Microsoft
# haengt sie an jede Ablehnung des Token-Endpunkts an, und sie sind stabiler
# als der begleitende englische Satz.
#
# Die Texte nennen die haeufigste Ursache und lassen offen, was die Kennung
# nicht hergibt. Ein zu enger Rat schickt jemanden in die falsche Richtung,
# und das kostet mehr als gar kein Rat. Geprueft gegen die Fehlerreferenz von
# Microsoft, siehe docs/PORTAL.md.
AADSTS = {
    "AADSTS7000215": (
        "Das hinterlegte Client Secret wird abgelehnt.",
        "Zuerst den hinterlegten Wert mit dem im Tenant vergleichen. Stimmt er "
        "nicht mehr überein, ein neues Secret erzeugen und hier eintragen."),
    "AADSTS7000222": (
        "Das hinterlegte Client Secret ist abgelaufen.",
        "Im Kundentenant ein neues Secret erzeugen und hier hinterlegen."),
    "AADSTS700016": (
        "Die App-Registrierung ist in diesem Tenant nicht auffindbar.",
        "Client-ID und Tenant-ID prüfen. Möglich ist auch, dass die "
        "Zustimmung des Administrators nie erteilt oder wieder entzogen wurde."),
    "AADSTS700027": (
        "Die Signatur der Anmeldung wurde abgelehnt.",
        "Meist passt das hinterlegte Zertifikat nicht mehr zu dem in der "
        "App-Registrierung. Beide vergleichen, bevor eines ersetzt wird."),
    "AADSTS90002": (
        "Der Tenant ist unbekannt.",
        "Tenant-ID prüfen."),
    "AADSTS500011": (
        "Der Dienstprinzipal der angeforderten Ressource fehlt in diesem Tenant.",
        "Entweder wurde die Zustimmung nie erteilt, oder die Anfrage geht an "
        "den falschen Tenant. Tenant-ID prüfen."),
    "AADSTS650057": (
        "Die App-Registrierung darf diese Ressource nicht anfordern.",
        "Berechtigung Application.Read.All als Anwendungsberechtigung setzen "
        "und Administratorzustimmung erteilen."),
}

AADSTS_MUSTER = re.compile(r"AADSTS(\d+)")

# Fehler, die nicht am Token-Endpunkt entstehen, sondern beim Abruf selbst.
GRAPH_MUSTER = [
    (re.compile(r"Graph HTTP 403"),
     "Microsoft Graph hat den Abruf abgelehnt.",
     "Meist fehlt Application.Read.All als Anwendungsberechtigung samt "
     "Administratorzustimmung. Es gibt weitere Gründe für eine Ablehnung, "
     "deshalb den Meldungstext im Feld detail mitlesen."),
    (re.compile(r"Graph HTTP 429"),
     "Microsoft hat die Abfrage wegen zu vieler Anfragen gedrosselt.",
     "Der nächste Tageslauf versucht es erneut. Bei wiederholtem Auftreten die "
     "Anzahl manueller Prüfungen senken."),
    (re.compile(r"Graph HTTP 5\d\d"),
     "Microsoft Graph hat mit einem Serverfehler geantwortet.",
     "Vorübergehend, der nächste Tageslauf versucht es erneut."),
    (re.compile(r"(Graph|Token-Endpoint) nicht erreichbar"),
     "Microsoft war vom Portal aus nicht erreichbar.",
     "Ausgehend 443 zu login.microsoftonline.com und graph.microsoft.com prüfen."),
    (re.compile(r"CryptoError|InvalidTag"),
     "Die gespeicherten Zugangsdaten lassen sich nicht entschlüsseln.",
     "Das passiert, wenn PORTAL_ENCRYPTION_KEY gewechselt wurde. Zugangsdaten "
     "des Kunden neu hinterlegen."),
    (re.compile(r"TENANT_ID oder CLIENT_ID fehlt"),
     "Tenant-ID oder Client-ID fehlt.",
     "Angaben des Kunden vervollständigen."),
    (re.compile(r"weder CLIENT_SECRET noch"),
     "Es ist kein Zugangsdatum hinterlegt.",
     "Client Secret oder Zertifikatspaar hinterlegen."),
]


def _als_utc(wert):
    """
    Treat a stored datetime as UTC when it comes back without a zone.

    SQLite kennt keine Zeitzone. Ein Wert, den die Sitzung noch im Speicher
    haelt, traegt seine Zone, derselbe Wert nach einem Neuladen nicht. Wer nur
    den einen Fall testet, sieht den anderen nie.
    """
    return wert if wert.tzinfo else wert.replace(tzinfo=timezone.utc)


def _befund(code, schwere, meldung, massnahme=None, **felder):
    """One finding: machine readable code, a sentence, optionally what to do."""
    eintrag = {"code": code, "severity": schwere, "message": meldung}
    if massnahme:
        eintrag["action"] = massnahme
    eintrag.update(felder)
    return eintrag


def erklaere_lauffehler(rohtext):
    """
    Turn the stored error text into a readable finding.

    Der Rohtext bleibt erhalten, weil er beim Nachfragen bei Microsoft
    gebraucht wird. Er ist nur nicht mehr das Einzige, was herauskommt.
    """
    if not rohtext:
        return None
    # Exakt suchen, nicht als Teilstring: "AADSTS70002150" enthaelt
    # "AADSTS7000215" und bekaeme sonst dessen Erklaerung.
    for treffer in AADSTS_MUSTER.findall(rohtext):
        eintrag = AADSTS.get("AADSTS" + treffer)
        if eintrag:
            meldung, massnahme = eintrag
            return _befund("scan_failed", "error", meldung, massnahme,
                           entra_code="AADSTS" + treffer, detail=rohtext[:500])
    for muster, meldung, massnahme in GRAPH_MUSTER:
        if muster.search(rohtext):
            return _befund("scan_failed", "error", meldung, massnahme,
                           detail=rohtext[:500])
    return _befund("scan_failed", "error",
                   "Die letzte Prüfung ist fehlgeschlagen.",
                   "Der Meldungstext steht im Feld detail.", detail=rohtext[:500])


def _liste(credentials):
    """Readable names of the affected credentials, sorted and without repeats."""
    return sorted({"%s (%s)" % (c.app_name, c.cred_name or c.cred_type)
                   for c in credentials})


def _satz(namen, einzahl, mehrzahl):
    """
    Build the sentence in the right number.

    "1 Zugangsdaten" waere falsch, und "Zugangsdatum" allein sagt nicht,
    welches. Bei einem einzelnen Eintrag steht deshalb der Name im Satz, bei
    mehreren die Anzahl mit der Aufzaehlung dahinter.
    """
    if len(namen) == 1:
        return einzahl % namen[0]
    return mehrzahl % (len(namen), ", ".join(namen))


def _ablaufende(credentials, kunde):
    """Findings about the credentials this customer has in its tenant."""
    befunde_liste = []
    abgelaufen = [c for c in credentials if c.days_left is not None and c.days_left < 0]
    kritisch = [c for c in credentials
                if c.days_left is not None and 0 <= c.days_left < kunde.error_days]
    warnend = [c for c in credentials
               if c.days_left is not None and kunde.error_days <= c.days_left < kunde.warn_days]

    if abgelaufen:
        namen = _liste(abgelaufen)
        befunde_liste.append(_befund(
            "credential_expired", "error",
            _satz(namen,
                  "%s ist bereits abgelaufen.",
                  "%d Zugangsdaten sind bereits abgelaufen: %s."),
            "Im Kundentenant prüfen, ob das Zugangsdatum noch benutzt wird, und "
            "es gegebenenfalls ersetzen. Ob etwas ausgefallen ist, lässt sich "
            "von hier aus nicht sagen: die Anwendung kann bereits ein zweites, "
            "gültiges Zugangsdatum verwenden.",
            count=len(abgelaufen), applications=namen))
    if kritisch:
        namen = _liste(kritisch)
        befunde_liste.append(_befund(
            "credential_critical", "error",
            _satz(namen,
                  "%s läuft in weniger als " + str(kunde.error_days) + " Tagen ab.",
                  "%d Zugangsdaten laufen in weniger als " + str(kunde.error_days)
                  + " Tagen ab: %s."),
            "Erneuerung einplanen.",
            count=len(kritisch), applications=namen,
            min_days_left=min(c.days_left for c in kritisch)))
    if warnend:
        namen = _liste(warnend)
        befunde_liste.append(_befund(
            "credential_warning", "warn",
            _satz(namen,
                  "%s läuft in weniger als " + str(kunde.warn_days) + " Tagen ab.",
                  "%d Zugangsdaten laufen in weniger als " + str(kunde.warn_days)
                  + " Tagen ab: %s."),
            None,
            count=len(warnend), applications=namen,
            min_days_left=min(c.days_left for c in warnend)))
    return befunde_liste


def befunde(kunde, credentials, stale_hours):
    """
    Every finding for one customer, most severe first.

    credentials sind die gespeicherten Zugangsdaten des Kunden. Sie werden
    uebergeben statt hier geladen, damit der Aufrufer sie einmal holt und
    nicht je Kunde eine weitere Abfrage entsteht.
    """
    gefunden = []

    if not kunde.is_active:
        gefunden.append(_befund(
            "inactive", "info",
            "Die Überwachung ist für diesen Kunden abgeschaltet.",
            "Kunde aktivieren, wenn wieder geprüft werden soll."))
        return gefunden

    if not (kunde.client_secret_enc or kunde.key_pem_enc):
        gefunden.append(_befund(
            "no_credential", "error",
            "Für diesen Kunden ist kein Zugangsdatum hinterlegt, es kann nicht "
            "geprüft werden.",
            "Client Secret oder Zertifikatspaar hinterlegen."))

    if kunde.last_check_at is None or kunde.last_status == "pending":
        gefunden.append(_befund(
            "never_checked", "warn",
            "Dieser Kunde wurde noch nie erfolgreich geprüft.",
            "Eine Prüfung auslösen oder den nächsten Tageslauf abwarten."))
    else:
        if kunde.last_status == "error":
            fehler = erklaere_lauffehler(kunde.last_error)
            if fehler:
                gefunden.append(fehler)
        alter = data_age_hours(kunde)
        if alter >= 0 and alter > stale_hours:
            gefunden.append(_befund(
                "data_stale", "error",
                "Die Zahlen stammen von einer Prüfung vor %d Stunden und sind "
                "damit älter als die zulässigen %d." % (int(alter), stale_hours),
                "Läuft der Scheduler? Ohne frische Prüfung sagen die Zahlen "
                "nichts über heute aus.",
                age_hours=int(alter)))

    gefunden.extend(_ablaufende(credentials, kunde))

    # Das Zertifikat, mit dem sich das Portal selbst anmeldet. Laeuft es ab,
    # hoert die Ueberwachung auf, ohne dass ein einzelner Kunde rot wird.
    if kunde.cert_not_after is not None:
        from portal.models import utcnow
        # SQLite gibt Datumswerte ohne Zeitzone zurueck, sobald das Objekt
        # frisch geladen wird. Ohne diese Zeile stuerzt jede Kundenliste ab,
        # bei der ein Kunde ein Zertifikat hinterlegt hat.
        rest = (_als_utc(kunde.cert_not_after) - utcnow()).days
        if rest < 0:
            gefunden.append(_befund(
                "own_certificate_expired", "error",
                "Das Zertifikat, mit dem sich das Portal bei diesem Kunden "
                "anmeldet, ist seit %d Tagen abgelaufen." % abs(rest),
                "Neues Zertifikat erzeugen, im Tenant hinterlegen und hier "
                "ersetzen.", days_left=rest))
        elif rest < kunde.warn_days:
            gefunden.append(_befund(
                "own_certificate_expiring", "warn",
                "Das Zertifikat, mit dem sich das Portal bei diesem Kunden "
                "anmeldet, läuft in %d Tagen ab." % rest,
                "Erneuerung einplanen, sonst endet die Überwachung dieses "
                "Kunden.", days_left=rest))

    reihenfolge = {"error": 0, "warn": 1, "info": 2}
    return sorted(gefunden, key=lambda b: reihenfolge.get(b["severity"], 3))
