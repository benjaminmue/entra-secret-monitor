#!/usr/bin/env python3
"""
terminal_shot.py

Baut aus einer Textdatei eine HTML-Seite, die wie ein Windows-Terminal
aussieht, damit Konsolenausgaben der Dokumentation als Bild vorliegen.

Warum nachgebaut und nicht abfotografiert: die Ausgaben zeigen Tenant-IDs,
Fingerabdruecke und Pfade eines echten Mandanten. Ein nachgebautes Terminal
zeigt genau das, was die Anleitung erklaert, mit erfundenen Werten und in
jedem Durchlauf identisch.

Eingabeformat, ein Zeilenpraefix bestimmt die Farbe:

    $ <text>    Eingabeaufforderung mit Befehl
    # <text>    Kommentar, gedaempft
    c <text>    Cyan, die Abschnittsueberschriften des Skripts
    g <text>    Gruen, Erfolg
    y <text>    Gelb, Warnung
    r <text>    Rot, Fehler
    <text>      normale Ausgabe

Aufruf:

    python3 tools/terminal_shot.py eingabe.txt ausgabe.html "Fenstertitel"
"""

import html
import pathlib
import sys

FARBEN = {
    "$": ("#d7d7d7", "prompt"),
    "#": ("#6f7f8f", "kommentar"),
    "c": ("#3ec9d6", "cyan"),
    "g": ("#3ecf6b", "gruen"),
    "y": ("#e8b339", "gelb"),
    "r": ("#f05c4a", "rot"),
}

VORLAGE = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>%(titel)s</title>
<style>
  body { margin: 0; padding: 24px; background: #f4f6f8; }
  .fenster {
    max-width: 1000px; margin: 0 auto; border-radius: 8px; overflow: hidden;
    box-shadow: 0 12px 32px rgba(15, 58, 111, .18); background: #0c0c0c;
  }
  .leiste {
    display: flex; align-items: center; gap: 8px; padding: 8px 12px;
    background: #2b2b2b; color: #cfcfcf;
    font: 12px/1 "Segoe UI", system-ui, sans-serif;
  }
  .leiste .punkt { width: 11px; height: 11px; border-radius: 50%%; }
  .leiste .rot { background: #ff5f57; }
  .leiste .gelb { background: #febc2e; }
  .leiste .gruen { background: #28c840; }
  .leiste .titel { margin-left: 6px; }
  pre {
    margin: 0; padding: 18px 20px; color: #d7d7d7; white-space: pre-wrap;
    font: 13px/1.55 "Cascadia Mono", Consolas, "Courier New", monospace;
  }
  .prompt { color: #d7d7d7; }
  .prompt .pfad { color: #3ec9d6; }
  .prompt .zeichen { color: #3ecf6b; }
  .kommentar { color: #6f7f8f; }
  .cyan { color: #3ec9d6; }
  .gruen { color: #3ecf6b; }
  .gelb { color: #e8b339; }
  .rot { color: #f05c4a; }
</style>
</head>
<body>
<div class="fenster">
  <div class="leiste">
    <span class="punkt rot"></span><span class="punkt gelb"></span><span class="punkt gruen"></span>
    <span class="titel">%(titel)s</span>
  </div>
  <pre>%(inhalt)s</pre>
</div>
</body>
</html>
"""


def zeile_zu_html(zeile):
    """Turn one prefixed source line into a span of the matching colour."""
    if not zeile.strip():
        return ""
    marke = zeile[0]
    # Nur das eine trennende Leerzeichen faellt weg. Wuerde hier lstrip stehen,
    # verloere jede farbige Zeile ihre Einrueckung und die Ausgabe saehe anders
    # aus als die des Skripts.
    rest = zeile[2:] if zeile[1:2] == " " else zeile[1:]
    if marke == "$":
        return ('<span class="prompt"><span class="pfad">PS C:\\&gt;</span> %s</span>'
                % html.escape(rest))
    if marke in FARBEN:
        _, klasse = FARBEN[marke]
        return '<span class="%s">%s</span>' % (klasse, html.escape(rest))
    return html.escape(zeile)


def main():
    """Render the input file into a terminal looking HTML page."""
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    quelle = pathlib.Path(sys.argv[1])
    ziel = pathlib.Path(sys.argv[2])
    titel = sys.argv[3] if len(sys.argv) > 3 else "Windows PowerShell"

    zeilen = quelle.read_text(encoding="utf-8").splitlines()
    inhalt = "\n".join(zeile_zu_html(z) for z in zeilen)
    ziel.write_text(VORLAGE % {"titel": html.escape(titel), "inhalt": inhalt},
                    encoding="utf-8")
    print("%s geschrieben (%d Zeilen)" % (ziel, len(zeilen)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
