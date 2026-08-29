"""
Tests for tools/inventory.py, the gate against duplicated work.

Two things must hold. The generated document has to match the code, otherwise it
becomes the kind of stale reference that is worse than none because it is
believed. And a newly introduced duplicate has to make this suite red, not
merely appear in a report nobody reads.
"""
import ast
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import inventory  # noqa: E402


def _function(source):
    """Parse a single function definition into a record like collect() builds."""
    node = ast.parse(source).body[0]
    digest, size = inventory.structure_hash(node)
    return {"module": "x.py", "name": node.name, "line": 1,
            "signature": inventory.signature_of(node),
            "returns": inventory.returns_of(node),
            "summary": inventory.summary_of(node),
            "hash": digest, "size": size}


class GateTest(unittest.TestCase):
    def test_the_repository_is_free_of_unreviewed_duplicates(self):
        """
        The actual gate.

        A failure here means either the inventory needs regenerating with
        `python3 tools/inventory.py`, or a duplicate appeared that has to be
        merged away or entered in the allowlist with a reason.
        """
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "inventory.py"), "--check"],
            capture_output=True, text=True, cwd=str(ROOT), check=False)
        self.assertEqual(0, result.returncode, result.stderr or result.stdout)

    def test_the_document_exists(self):
        self.assertTrue((ROOT / "docs" / "FUNCTIONS.md").is_file(),
                        "docs/FUNCTIONS.md fehlt, 'python3 tools/inventory.py' ausführen")


class DetectionTest(unittest.TestCase):
    """The gate is only worth having if it actually catches things."""

    def test_a_name_in_two_modules_is_reported(self):
        functions = [_function("def helper():\n    return 1"),
                     dict(_function("def helper():\n    return 2"), module="y.py")]
        self.assertEqual(["helper"], [name for name, _ in
                                      inventory.duplicate_names(functions)])

    def test_a_name_twice_in_one_module_is_not_a_finding(self):
        # Overloads and nested definitions live in one file legitimately.
        functions = [_function("def helper():\n    return 1"),
                     _function("def helper():\n    return 2")]
        self.assertEqual([], inventory.duplicate_names(functions))

    def test_an_allowlisted_name_is_not_reported(self):
        functions = [_function("def main():\n    return 1"),
                     dict(_function("def main():\n    return 2"), module="y.py")]
        self.assertEqual([], inventory.duplicate_names(functions))

    def test_copy_paste_with_renamed_variables_is_reported(self):
        # The whole point: identical shape, nothing but the names changed.
        first = """
def load_customer(session, key):
    record = session.get(key)
    if record is None:
        raise LookupError(key)
    if not record.active:
        raise LookupError(key)
    return record.value
"""
        second = """
def fetch_user(store, identifier):
    entry = store.get(identifier)
    if entry is None:
        raise LookupError(identifier)
    if not entry.enabled:
        raise LookupError(identifier)
    return entry.data
"""
        functions = [_function(first), dict(_function(second), module="y.py")]
        groups = inventory.duplicate_structures(functions)
        self.assertEqual(1, len(groups))
        self.assertEqual({"load_customer", "fetch_user"},
                         {entry["name"] for entry in groups[0]})

    def test_genuinely_different_bodies_are_not_reported(self):
        first = """
def total(rows):
    result = 0
    for row in rows:
        result += row.value
    return result
"""
        second = """
def label(value):
    if value < 0:
        return "negativ"
    if value == 0:
        return "null"
    return "positiv"
"""
        functions = [_function(first), dict(_function(second), module="y.py")]
        self.assertEqual([], inventory.duplicate_structures(functions))

    def test_tiny_bodies_are_ignored(self):
        # Every one-line getter looks like every other; reporting them is noise.
        functions = [_function("def a():\n    return 1"),
                     dict(_function("def b():\n    return 2"), module="y.py")]
        self.assertEqual([], inventory.duplicate_structures(functions))


class RenderingTest(unittest.TestCase):
    def test_signatures_keep_defaults_and_star_args(self):
        record = _function("def f(a, b=2, *rest, c, d=4, **kw):\n    return a")
        self.assertEqual("f(a, b=2, *rest, c, d=4, **kw)", record["signature"])

    def test_a_function_without_a_return_value_is_marked_as_such(self):
        self.assertEqual("kein Rückgabewert",
                         _function("def f(x):\n    print(x)")["returns"])

    def test_a_generator_is_recognised(self):
        self.assertEqual("Generator", _function("def f():\n    yield 1")["returns"])

    def test_an_annotation_wins_over_the_guess(self):
        self.assertEqual("str", _function("def f() -> str:\n    return 'x'")["returns"])

    def test_a_missing_docstring_is_visible(self):
        self.assertEqual("_ohne Docstring_", _function("def f():\n    return 1")["summary"])

    def test_the_document_lists_every_function_found(self):
        functions = inventory.collect()
        document = inventory.render(functions)
        self.assertIn("| Funktionen | %d |" % len(functions), document)
        for entry in functions[:20]:
            self.assertIn(entry["name"], document)


if __name__ == "__main__":
    unittest.main()
