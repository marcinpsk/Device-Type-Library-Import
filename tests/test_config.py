"""Tests for configuration resolution."""

import os
import pathlib
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_ENTRY = _ROOT / "nb-dt-import.py"


def _run_cli(*argv, **env_overrides):
    """Run the real CLI in a fresh process and return the completed process."""
    env = {**os.environ, **env_overrides}
    return subprocess.run(
        [sys.executable, str(_ENTRY), *argv],
        capture_output=True,
        text=True,
        env=env,
        cwd=_ROOT,
        timeout=60,
    )


class TestConfigurationIsNotReadAtImport:
    """Reading the environment at import time makes unrelated values fatal too early."""

    def test_help_survives_an_invalid_value_it_never_reads(self):
        """--help asks the parser a question, so no environment value should be able to answer it."""
        result = _run_cli("--help", GRAPHQL_PAGE_SIZE="abc")

        assert result.returncode == 0, result.stderr
        assert "usage: nb-dt-import.py" in result.stdout

    @pytest.mark.parametrize("variable", ["GRAPHQL_PAGE_SIZE", "PRELOAD_THREADS"])
    def test_an_invalid_value_is_reported_without_a_traceback(self, variable):
        """The value is a user mistake, so it deserves a message rather than a stack trace."""
        result = _run_cli(**{variable: "abc"})

        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "Traceback" not in combined, combined
        assert variable in combined


class TestOptionalVariablesUseTheirDefault:
    """README marks REPO_URL optional with a default, so demanding it contradicts the default."""

    def test_an_absent_repo_url_does_not_stop_the_run(self):
        """--export-diff returns before any clone, so this reaches the check without network use."""
        result = _run_cli("--export-diff", REPO_URL="")

        assert 'Environment variable "REPO_URL" is not set' not in result.stdout + result.stderr
