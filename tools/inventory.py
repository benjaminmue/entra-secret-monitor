#!/usr/bin/env python3
"""
inventory.py

Generate the function inventory and report duplicate work.

The inventory is generated rather than written, because a hand maintained list
is stale one commit later and then does harm: it is believed. Everything here
comes from the AST, so the document can only be wrong if the code changed and
nobody regenerated it, which the accompanying test refuses to allow.

Two kinds of duplication are reported:

  name      the same function name defined in more than one module, which is
            how one implementation quietly grows a second, diverging twin
  structure two bodies with the same shape after identifiers are stripped,
            which catches copy-paste that renamed its variables

Usage:
    python3 tools/inventory.py            write docs/FUNCTIONS.md
    python3 tools/inventory.py --check    exit 1 if stale or newly duplicated
"""

import argparse
import ast
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs" / "FUNCTIONS.md"
SOURCE_DIRS = ("app", "portal")

# Rümpfe unterhalb dieser Grösse sind zwangsläufig ähnlich, etwa ein einzelnes
# return. Sie als Fund zu melden erzeugt nur Rauschen.
MIN_BODY_NODES = 12

# Bewusste Doppelungen, jeweils mit Grund. Wer hier etwas einträgt, sagt damit:
# geprüft, gewollt, kein Handlungsbedarf.
ALLOWED_NAME_DUPLICATES = {
    "main": "Jeder Einstiegspunkt hat sein eigenes main, das ist Konvention.",
    "apply_overrides": (
        "Zwei Quellen mit unterschiedlicher Form: die Kommandozeile liest einen "
        "argparse-Namespace, der Server eine Query-Parameter-Abbildung. Beide "
        "kopieren über dataclasses.replace, die Feldlisten sind aber verschieden."),
    "config": "Flask-Hilfsfunktion je Blueprint, nur ein Zugriff auf app.config.",
    "index": "Je Blueprint eine Übersichtsseite, gleiche Rolle, anderer Inhalt.",
    "create": "Je Blueprint ein Anlegen-Endpunkt für einen anderen Datentyp.",
    "edit": "Je Blueprint ein Bearbeiten-Endpunkt für einen anderen Datentyp.",
    "delete": "Je Blueprint ein Löschen-Endpunkt für einen anderen Datentyp.",
    "decorator": "Innere Funktion des jeweiligen Dekorator-Bauplans.",
    "wrapper": "Innere Funktion des jeweiligen Dekorator-Bauplans.",
    "verify_totp": (
        "security.verify_totp prüft einen Code, auth.verify_totp ist die Seite "
        "dazu. Der View-Name bestimmt die URL über url_for, Umbenennen ändert "
        "also die Route."),
}

# Geprüfte Strukturgleichheiten. Schlüssel ist die sortierte Liste der Fundorte,
# damit ein Eintrag nur genau dieses Paar entschuldigt und nicht pauschal wirkt.
ALLOWED_STRUCTURE_DUPLICATES = {
    ("portal/factory.py:_forbidden", "portal/factory.py:_not_found"):
        "Zwei Fehlerseiten mit demselben Aufbau und verschiedenem Statuscode. "
        "Zusammenlegen würde eine Fallunterscheidung einführen, wo heute zwei "
        "gerade Handler stehen.",
    ("portal/models.py:object_label", "portal/models.py:type_label"):
        "Zwei Anzeigenamen auf verschiedenen Feldern desselben Modells.",
    ("portal/security.py:decrypt_totp_secret", "portal/security.py:encrypt_totp_secret"):
        "Gegenstücke. Gleiche Form ist hier die Absicht, nicht die Kopie.",
    ("portal/views/auth.py:_clear_pending", "portal/views/auth.py:_clear_reenrollment"):
        "Beide räumen zwei Session-Schlüssel weg, die Namen tragen aber die "
        "Bedeutung: halbfertiger Login gegen Fenster zur Neuregistrierung. Ein "
        "generisches _clear(*keys) wäre kürzer und schlechter zu lesen.",
}


def iter_source_files():
    """Yield every Python file of the project, sorted, tests excluded."""
    for folder in SOURCE_DIRS:
        base = ROOT / folder
        if base.is_dir():
            yield from sorted(base.rglob("*.py"))


def signature_of(node):
    """Render a function signature the way it is written in the source."""
    args = node.args
    parts = []
    positional = args.posonlyargs + args.args
    defaults = list(args.defaults)
    padding = [None] * (len(positional) - len(defaults))
    for argument, default in zip(positional, padding + defaults):
        text = argument.arg
        if default is not None:
            text += "=" + ast.unparse(default)
        parts.append(text)
    if args.vararg:
        parts.append("*" + args.vararg.arg)
    for argument, default in zip(args.kwonlyargs, args.kw_defaults):
        text = argument.arg
        if default is not None:
            text += "=" + ast.unparse(default)
        parts.append(text)
    if args.kwarg:
        parts.append("**" + args.kwarg.arg)
    return "%s(%s)" % (node.name, ", ".join(parts))


def returns_of(node):
    """
    Describe what the function hands back.

    Prefers an annotation; otherwise reports whether any return carries a value,
    which is what tells a caller apart from a side effect only helper.
    """
    if node.returns is not None:
        return ast.unparse(node.returns)
    has_value = any(isinstance(child, ast.Return) and child.value is not None
                    for child in ast.walk(node))
    if any(isinstance(child, (ast.Yield, ast.YieldFrom)) for child in ast.walk(node)):
        return "Generator"
    return "Wert" if has_value else "kein Rückgabewert"


def summary_of(node):
    """First sentence of the docstring, or a marker when there is none."""
    doc = ast.get_docstring(node)
    if not doc:
        return "_ohne Docstring_"
    first = doc.strip().split("\n")[0].strip()
    return first or "_ohne Docstring_"


def structure_hash(node):
    """
    Hash the shape of a body with all identifiers and constants removed.

    Two functions that differ only in their names then hash the same, which is
    what makes renamed copy-paste visible.
    """
    shape = []
    for child in ast.walk(node):
        if isinstance(child, ast.FunctionDef) and child is not node:
            continue
        shape.append(type(child).__name__)
    return hashlib.sha256("|".join(shape).encode()).hexdigest()[:16], len(shape)


def collect():
    """Return one record per function found in the project."""
    functions = []
    for path in iter_source_files():
        relative = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            digest, size = structure_hash(node)
            functions.append({
                "module": relative,
                "name": node.name,
                "line": node.lineno,
                "signature": signature_of(node),
                "returns": returns_of(node),
                "summary": summary_of(node),
                "hash": digest,
                "size": size,
            })
    return functions


def duplicate_names(functions):
    """Names defined in more than one module, minus the accepted ones."""
    seen = {}
    for entry in functions:
        seen.setdefault(entry["name"], []).append(entry)
    findings = []
    for name, entries in sorted(seen.items()):
        modules = {e["module"] for e in entries}
        if len(modules) > 1 and name not in ALLOWED_NAME_DUPLICATES:
            findings.append((name, sorted(entries, key=lambda e: e["module"])))
    return findings


def duplicate_structures(functions):
    """Bodies of a meaningful size that share their shape."""
    seen = {}
    for entry in functions:
        if entry["size"] >= MIN_BODY_NODES:
            seen.setdefault(entry["hash"], []).append(entry)
    findings = []
    for entries in seen.values():
        if len(entries) <= 1:
            continue
        group = sorted(entries, key=lambda e: (e["module"], e["line"]))
        key = tuple(sorted("%s:%s" % (e["module"], e["name"]) for e in group))
        if key not in ALLOWED_STRUCTURE_DUPLICATES:
            findings.append(group)
    return sorted(findings, key=lambda group: group[0]["module"])


def render(functions):
    """Build the Markdown document."""
    names = duplicate_names(functions)
    structures = duplicate_structures(functions)
    modules = {}
    for entry in functions:
        modules.setdefault(entry["module"], []).append(entry)

    lines = [
        "# Funktionsinventar",
        "",
        "**Generiert, nicht von Hand gepflegt.** Neu erzeugen mit "
        "`python3 tools/inventory.py`.",
        "Der Test `tests/test_inventory.py` schlägt fehl, sobald diese Datei vom "
        "Code abweicht.",
        "",
        "Zweck ist, doppelte Arbeit sichtbar zu machen, bevor daraus zwei "
        "auseinanderlaufende",
        "Implementierungen derselben Sache werden.",
        "",
        "| Kennzahl | Wert |",
        "|---|---|",
        "| Module | %d |" % len(modules),
        "| Funktionen | %d |" % len(functions),
        "| Ohne Docstring | %d |" % sum(1 for e in functions
                                        if e["summary"] == "_ohne Docstring_"),
        "| Namensdubletten | %d |" % len(names),
        "| Strukturdubletten | %d |" % len(structures),
        "",
        "## Befunde",
        "",
    ]

    if not names and not structures:
        lines += ["Keine. Jede Funktion existiert genau einmal, und kein Rumpf "
                  "gleicht einem anderen.", ""]
    if names:
        lines += ["### Gleicher Name in mehreren Modulen", "",
                  "Entweder zusammenlegen, oder unterscheidbar benennen, oder mit "
                  "Begründung in", "`ALLOWED_NAME_DUPLICATES` eintragen.", ""]
        for name, entries in names:
            lines.append("- **`%s`**" % name)
            for entry in entries:
                lines.append("  - `%s:%d` - %s" % (entry["module"], entry["line"],
                                                   entry["summary"]))
        lines.append("")
    if structures:
        lines += ["### Gleicher Aufbau", "",
                  "Die Rümpfe haben dieselbe Form, nachdem Namen entfernt wurden. "
                  "Das ist der übliche", "Abdruck von Copy-Paste.", ""]
        for group in structures:
            lines.append("- " + ", ".join("`%s:%d` (`%s`)" % (e["module"], e["line"],
                                                              e["name"])
                                          for e in group))
        lines.append("")

    lines += ["## Bewusste Doppelungen", "",
              "Geprüft und so gewollt. Wer hier etwas ergänzt, dokumentiert eine "
              "Entscheidung,", "nicht eine Ausnahme vom Aufräumen.", "",
              "### Gleicher Name", "",
              "| Name | Begründung |", "|---|---|"]
    for name, reason in sorted(ALLOWED_NAME_DUPLICATES.items()):
        lines.append("| `%s` | %s |" % (name, reason))
    lines += ["", "### Gleicher Aufbau", "", "| Fundorte | Begründung |", "|---|---|"]
    for places, reason in sorted(ALLOWED_STRUCTURE_DUPLICATES.items()):
        lines.append("| %s | %s |" % (", ".join("`%s`" % p for p in places), reason))
    lines += ["", "## Alle Funktionen", ""]

    for module in sorted(modules):
        lines += ["### `%s`" % module, "",
                  "| Zeile | Funktion | Rückgabe | Beschreibung |", "|---|---|---|---|"]
        for entry in sorted(modules[module], key=lambda e: e["line"]):
            lines.append("| %d | `%s` | %s | %s |" % (
                entry["line"], entry["signature"], entry["returns"],
                entry["summary"].replace("|", "\\|")))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main(argv=None):
    """Write the inventory, or verify it is current and free of new duplicates."""
    parser = argparse.ArgumentParser(description="Funktionsinventar erzeugen oder prüfen")
    parser.add_argument("--check", action="store_true",
                        help="nichts schreiben, nur melden ob veraltet oder dupliziert")
    args = parser.parse_args(argv)

    functions = collect()
    document = render(functions)
    names = duplicate_names(functions)
    structures = duplicate_structures(functions)

    if not args.check:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(document, encoding="utf-8")
        print("%s geschrieben: %d Funktionen in %d Modulen"
              % (OUTPUT.relative_to(ROOT), len(functions),
                 len({e["module"] for e in functions})))

    problems = []
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
        if current != document:
            problems.append("docs/FUNCTIONS.md ist veraltet, "
                            "'python3 tools/inventory.py' ausführen")
    for name, entries in names:
        problems.append("Name '%s' in mehreren Modulen: %s"
                        % (name, ", ".join(e["module"] for e in entries)))
    for group in structures:
        problems.append("Gleicher Aufbau: %s"
                        % ", ".join("%s:%d %s" % (e["module"], e["line"], e["name"])
                                    for e in group))

    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
