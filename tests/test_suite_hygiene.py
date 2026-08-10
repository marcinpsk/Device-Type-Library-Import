"""Structural checks on the test suite itself."""

import ast
import pathlib

_TESTS_DIR = pathlib.Path(__file__).resolve().parent


def _orphaned_docstrings(tree):
    """Yield (function, lineno) for every bare string statement that is not a docstring."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for statement in node.body[1:]:
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                if isinstance(statement.value.value, str):
                    yield node.name, statement.lineno


def test_no_test_function_contains_an_orphaned_docstring():
    """A dropped ``def`` header silently merges two tests into one.

    The second test's docstring is left as a bare string statement, so the body keeps
    running as the tail of the first test: unnamed, unreported, and skipped entirely
    once an earlier assertion fails. Ruff has no rule for this; B018 exempts strings.
    """
    offenders = []
    for path in sorted(_TESTS_DIR.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name, lineno in _orphaned_docstrings(tree):
            offenders.append(f"{path.relative_to(_TESTS_DIR)}:{lineno} in {name}")

    assert not offenders, "Bare string statement inside a test function, likely a lost `def` header:\n" + "\n".join(
        offenders
    )
