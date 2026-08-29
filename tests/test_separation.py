"""
Tests that keep the two flavours apart now that one branch holds both.

app/ is the classic service and must stay importable with nothing but the
standard library, because that is its entire selling point: a container with no
dependency tree to patch. portal/ builds on top of it and may use Flask and the
rest.

This used to be guaranteed by keeping the flavours on separate branches, which
guaranteed something else too: fixes stopped travelling. A grouping bug lived on
in the portal for weeks after it was fixed for the service, and an XML hardening
lived the other way round. The separation belongs in the directory layout and in
these assertions, not in branches.
"""
import ast
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Alles, was der klassische Dienst importieren darf: Standardbibliothek und
# seine eigenen Module. cryptography ist der eine Sonderfall, siehe unten.
STDLIB = set(sys.stdlib_module_names)
OWN_MODULES = {"graph", "server", "cli", "healthcheck"}
# Nur fuer die Zertifikatsanmeldung, im Dockerfile eigens installiert und im
# Code hinter einem lokalen Import, damit der Secret-Pfad ohne sie laeuft.
OPTIONAL = {"cryptography"}


def imported_roots(path):
    """Yield the top level module name of every import in one file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0]


class ClassicServiceTest(unittest.TestCase):
    def test_app_imports_only_the_standard_library(self):
        offenders = []
        for path in sorted((ROOT / "app").rglob("*.py")):
            for name in imported_roots(path):
                if name not in STDLIB | OWN_MODULES | OPTIONAL:
                    offenders.append("%s: %s" % (path.relative_to(ROOT), name))
        self.assertEqual([], offenders,
                         "app/ muss ohne Zusatzpakete lauffaehig bleiben")

    def test_app_never_imports_the_portal(self):
        # The dependency runs one way only: the portal builds on the service.
        for path in sorted((ROOT / "app").rglob("*.py")):
            self.assertNotIn("portal", set(imported_roots(path)),
                             "%s importiert das Portal" % path.relative_to(ROOT))

    def test_the_service_runs_without_the_portal_dependencies(self):
        """
        Import the service modules in a fresh interpreter, proving they stand alone.

        healthcheck.py is left out on purpose: it is a probe script, not a
        module, and importing it fires an HTTP request and exits. Its imports
        are still checked above, which reads the source rather than running it.
        """
        code = ("import sys; sys.path.insert(0, %r);"
                "import graph, server, cli; print('ok')" % str(ROOT / "app"))
        result = subprocess.run([sys.executable, "-c", code],
                                capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("ok", result.stdout)


class ImageContentTest(unittest.TestCase):
    """The Dockerfiles are what actually keeps the shipped images apart."""

    def test_the_service_image_does_not_copy_the_portal(self):
        lines = (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
        copies = [line for line in lines if line.startswith("COPY")]
        self.assertTrue(copies, "Dockerfile kopiert nichts")
        for line in copies:
            self.assertNotIn("portal", line,
                             "das schlanke Image zieht Portal-Dateien mit")

    def test_the_portal_image_copies_both_parts(self):
        content = (ROOT / "Dockerfile.portal").read_text(encoding="utf-8")
        self.assertIn("COPY app/", content, "dem Portal fehlt der Graph-Code")
        self.assertIn("COPY portal/", content)

    def test_only_the_portal_image_installs_the_extras(self):
        service = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn("requirements-portal.txt", service,
                         "das schlanke Image installiert Portal-Abhaengigkeiten")


if __name__ == "__main__":
    unittest.main()
