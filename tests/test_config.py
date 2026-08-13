"""Tests for configuration resolution."""

import os
import pathlib
import subprocess
import sys

import pytest

from core.config import EnvironmentVariableError, resolve_run_config

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_ENTRY = _ROOT / "nb-dt-import.py"


def _resolve(**env):
    """Resolve a config from an explicit environment, so the ambient one cannot change the answer."""
    return resolve_run_config(argv=[], env={"NETBOX_URL": "http://netbox.local", "NETBOX_TOKEN": "token", **env})


def _run_cli(*argv, **env_overrides):
    """Run the real CLI in a fresh process and return the completed process."""
    env = {
        **os.environ,
        "NETBOX_URL": "http://netbox.invalid",
        "NETBOX_TOKEN": "token",
        **env_overrides,
    }
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
    def test_an_invalid_value_is_reported_without_a_traceback(self, variable, monkeypatch):
        """The value is a user mistake, so it deserves a message rather than a stack trace."""
        # Empty inherited values prevent load_dotenv from hiding a missing helper default.
        monkeypatch.setenv("NETBOX_URL", "")
        monkeypatch.setenv("NETBOX_TOKEN", "")
        result = _run_cli(**{variable: "abc"})

        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "Traceback" not in combined, combined
        assert variable in combined


@pytest.mark.parametrize("value", ["true", "TRUE", " True ", "1", "yes", "YES"])
def test_ignore_ssl_errors_accepts_common_true_values(value):
    """Boolean environment values are trimmed and parsed without case sensitivity."""
    assert _resolve(IGNORE_SSL_ERRORS=value).ignore_ssl_errors is True


@pytest.mark.parametrize("value", ["false", "FALSE", " False ", "0", "no", "NO"])
def test_ignore_ssl_errors_accepts_common_false_values(value):
    """Common false values preserve the secure default."""
    assert _resolve(IGNORE_SSL_ERRORS=value).ignore_ssl_errors is False


class TestOptionalVariablesUseTheirDefault:
    """README marks REPO_URL optional with a default, so demanding it contradicts the default."""

    def test_an_absent_repo_url_does_not_stop_the_run(self, monkeypatch):
        """An invalid numeric value stops this after resolution but before any network request."""
        monkeypatch.setenv("NETBOX_URL", "")
        monkeypatch.setenv("NETBOX_TOKEN", "")
        result = _run_cli("--export-diff", REPO_URL="", GRAPHQL_PAGE_SIZE="invalid")

        assert 'Environment variable "REPO_URL" is not set' not in result.stdout + result.stderr
        assert 'Environment variable "NETBOX_URL" is not set' not in result.stdout + result.stderr


class TestRequiredVariables:
    """Required environment values fail with a typed configuration error."""

    def test_one_missing_variable_uses_the_catalogue_error(self):
        with pytest.raises(EnvironmentVariableError, match='Environment variable "NETBOX_TOKEN" is not set.'):
            resolve_run_config(argv=[], env={"NETBOX_URL": "http://netbox.local"})

    def test_all_missing_variables_use_one_typed_error(self):
        with pytest.raises(EnvironmentVariableError) as exc_info:
            resolve_run_config(argv=[], env={})

        assert str(exc_info.value) == (
            'Environment variable "NETBOX_URL" is not set.\n'
            'Environment variable "NETBOX_TOKEN" is not set.\n\n'
            "Required: NETBOX_URL, NETBOX_TOKEN"
        )


class TestRepoPathHasOneResolution:
    """Whoever re-derives this path by hand gets a different one, and reads a directory with no schema."""

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_an_unusable_repo_path_falls_back_to_the_default(self, value):
        """A blank value is what an .env line with nothing after the '=' produces."""
        config = _resolve() if value is None else _resolve(REPO_PATH=value)

        assert config.repo_path == str(_ROOT / "repo")

    def test_an_explicit_repo_path_is_taken_as_given(self, tmp_path):
        config = _resolve(REPO_PATH=str(tmp_path))

        assert config.repo_path == str(tmp_path)
