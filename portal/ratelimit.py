#!/usr/bin/env python3
"""
ratelimit.py

Drosselung im Prozessspeicher, gleitendes Fenster.

Bewusst ohne Redis und ohne Datenbanktabelle. Das Portal ist ein Prozess mit
einem Scheduler, das steht so in den Grenzen von docs/PORTAL.md; ein zweiter
Prozess auf derselben Datenbank wuerde ohnehin Kunden doppelt pruefen. Damit
ist der Zaehler genau so weit verteilt wie der Rest des Zustands.

Zwei Dinge, die diese Umsetzung nicht kann: sie ueberlebt keinen Neustart, und
sie zaehlt nicht ueber mehrere Instanzen. Beides ist hier vertretbar, weil die
Drosselung das Durchprobieren verlangsamt und nicht die einzige Verteidigung
ist: ein Schluessel traegt 256 Bit Entropie.

Zur Speicherbegrenzung: ein Eimer, dessen Fenster noch laeuft, wird niemals
geraeumt. Sonst waere die Grenze selbst der Hebel, sie aufzuheben, indem man
die Tabelle mit erfundenen Kennungen flutet. Ist die Tabelle voll und nichts
abgelaufen, wird eine *neue* Kennung abgewiesen statt eine bestehende Sperre
vergessen.
"""

import threading
import time
from collections import deque

_EIMER = {}
_SPERRE = threading.Lock()

# Deckel gegen unbegrenztes Wachstum. Gross genug fuer jeden echten Betrieb:
# 50 Kunden, eine Handvoll Schluessel und die Adressen, die tatsaechlich
# anfragen, liegen zusammen weit darunter.
MAX_EIMER = 16384


class Grenze:
    """
    One named limit: at most `anzahl` events per `fenster` seconds.

    Als Objekt statt als Zahlenpaar, damit die Aufrufstelle liest wie das, was
    sie durchsetzt. Der Name trennt zugleich die Namensraeume: eine Kennung
    unter "check" und dieselbe unter "apikey" sind verschiedene Eimer.
    """

    def __init__(self, name, anzahl, fenster):
        if anzahl < 1:
            raise ValueError("Grenze '%s': anzahl muss mindestens 1 sein, ist %r"
                             % (name, anzahl))
        if fenster < 1:
            raise ValueError("Grenze '%s': fenster muss mindestens 1 Sekunde sein, "
                             "ist %r" % (name, fenster))
        self.name = name
        self.anzahl = anzahl
        self.fenster = fenster

    def __repr__(self):
        return "Grenze(%s, %d/%ds)" % (self.name, self.anzahl, self.fenster)


def _jetzt():
    """Monotone Zeit, damit ein Sprung der Systemuhr die Grenze nicht aufhebt."""
    return time.monotonic()


def pruefe(grenze, kennung):
    """
    Register one event and report whether it stays inside the limit.

    Gibt (erlaubt, wartezeit) zurueck. wartezeit sind die Sekunden bis zum
    naechsten freien Platz und wandern in den Kopf Retry-After. Ein einziger
    Aufruf unter einer Sperre, damit Nachsehen und Zaehlen nicht auseinander
    fallen koennen: zwei getrennte Schritte liessen nebenlaeufige Aufrufer
    gemeinsam durch die Vorpruefung.
    """
    schluessel = "%s|%s" % (grenze.name, kennung)
    jetzt = _jetzt()
    with _SPERRE:
        eimer = _EIMER.get(schluessel)
        if eimer is None:
            if len(_EIMER) >= MAX_EIMER and not _raeume_auf(jetzt):
                # Voll und nichts abgelaufen. Lieber die neue Kennung abweisen
                # als eine laufende Sperre vergessen.
                return False, 1
            eimer = _EIMER[schluessel] = deque()
        while eimer and jetzt - eimer[0] >= grenze.fenster:
            eimer.popleft()
        if len(eimer) >= grenze.anzahl:
            # Aufrunden, aber nie unter eine Sekunde: eine 0 im Retry-After
            # laedt zum sofortigen Wiederholen ein.
            return False, max(1, int(grenze.fenster - (jetzt - eimer[0])) + 1)
        eimer.append(jetzt)
        return True, 0


def _raeume_auf(jetzt, aelter_als=3600):
    """
    Drop buckets whose last event is long past. Caller holds the lock.

    Gibt zurueck, ob Platz entstanden ist. Entfernt werden ausschliesslich
    Eimer ohne Eintraege und solche, deren letzter Eintrag laenger zurueckliegt
    als das laengste hier verwendete Fenster. Eine laufende Sperre bleibt
    stehen, auch wenn die Tabelle dadurch voll bleibt.
    """
    vorher = len(_EIMER)
    for schluessel in [s for s, e in _EIMER.items()
                       if not e or jetzt - e[-1] > aelter_als]:
        del _EIMER[schluessel]
    return len(_EIMER) < vorher


def gib_frei(grenze, kennung):
    """
    Take back the most recent event under this key.

    Fuer den Fall, dass erst gezaehlt und dann festgestellt wird, dass der
    Versuch keiner war: die Schluesselpruefung zaehlt jeden Aufruf, bevor sie
    weiss, ob er stimmt, damit Nachsehen und Zaehlen atomar bleiben. Stimmt
    der Schluessel, wird der Eintrag hier zurueckgenommen.
    """
    schluessel = "%s|%s" % (grenze.name, kennung)
    with _SPERRE:
        eimer = _EIMER.get(schluessel)
        if eimer:
            eimer.pop()
            if not eimer:
                del _EIMER[schluessel]


def belegung():
    """How many buckets are currently held. Für Diagnose und Tests."""
    with _SPERRE:
        return len(_EIMER)


def zuruecksetzen():
    """Alles vergessen. Nur für Tests."""
    with _SPERRE:
        _EIMER.clear()
