"""Structural checks on the test suite itself."""

import ast
import pathlib
import tomllib

_TESTS_DIR = pathlib.Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent

# pytest's own default when python_files is not configured.
_DEFAULT_PYTHON_FILES = ["test_*.py", "*_test.py"]


def _discover(root, patterns, pruned):
    """Return files under *root* matching *patterns*, minus anything inside *pruned*."""
    found = {path for pattern in patterns for path in root.rglob(pattern)}
    return sorted(p for p in found if not any(p.is_relative_to(d) for d in pruned))


def _collected_test_files():
    """Return the test files pytest collects, following python_files and norecursedirs."""
    config = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    options = config["tool"]["pytest"]["ini_options"]
    patterns = options.get("python_files", _DEFAULT_PYTHON_FILES)
    if isinstance(patterns, str):
        patterns = patterns.split()
    # norecursedirs entries are read as paths; pytest also accepts globs, which this ignores.
    pruned = [(_ROOT / entry).resolve() for entry in options.get("norecursedirs", [])]
    return _discover(_TESTS_DIR, patterns, pruned)


def _orphaned_docstrings(tree):
    """Yield (function, lineno) for every bare string statement that is not a docstring."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for statement in node.body[1:]:
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                if isinstance(statement.value.value, str):
                    yield node.name, statement.lineno


def test_the_scan_follows_pytest_discovery(tmp_path):
    """Scanning a different set than pytest runs makes the guard below miss files, or invent them."""
    (tmp_path / "test_first.py").touch()
    (tmp_path / "second_test.py").touch()
    (tmp_path / "helpers.py").touch()
    (tmp_path / "skipped").mkdir()
    (tmp_path / "skipped" / "test_third.py").touch()

    found = _discover(tmp_path, _DEFAULT_PYTHON_FILES, [tmp_path / "skipped"])

    assert [p.name for p in found] == ["second_test.py", "test_first.py"]


def test_no_test_function_contains_an_orphaned_docstring():
    """A dropped ``def`` header silently merges two tests into one.

    The second test's docstring is left as a bare string statement, so the body keeps
    running as the tail of the first test: unnamed, unreported, and skipped entirely
    once an earlier assertion fails. Ruff has no rule for this; B018 exempts strings.
    """
    offenders = []
    for path in _collected_test_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name, lineno in _orphaned_docstrings(tree):
            offenders.append(f"{path.relative_to(_TESTS_DIR)}:{lineno} in {name}")

    assert not offenders, "Bare string statement inside a test function, likely a lost `def` header:\n" + "\n".join(
        offenders
    )
