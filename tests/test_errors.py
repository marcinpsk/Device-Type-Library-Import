"""Tests for the fatal error catalogue."""

import pytest

from core.config import EnvironmentVariableError
from core.errors import UnknownError
from core.netbox_api import SSLVerificationError
from core.repo import (
    GitBranchNotFoundError,
    GitCommandError,
    GitInvalidRepositoryError,
    InvalidGitURLError,
    InvalidRepoPathError,
)


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (
            EnvironmentVariableError("NETBOX_URL"),
            'Environment variable "NETBOX_URL" is not set.\n\nRequired: NETBOX_URL, NETBOX_TOKEN',
        ),
        (
            SSLVerificationError(False),
            "SSL verification failed. IGNORE_SSL_ERRORS is False. "
            "Set IGNORE_SSL_ERRORS to True if you want to ignore this error. EXITING.",
        ),
        (GitCommandError("my-repo"), 'Git error for repo "my-repo".'),
        (GitInvalidRepositoryError("my-repo"), 'The repo "my-repo" is not a valid git repo.'),
        (
            GitBranchNotFoundError("release"),
            'Branch "release" was not found in the remote repository. Check your REPO_BRANCH setting.',
        ),
        (
            InvalidGitURLError("ftp://invalid.example/repo.git"),
            "Invalid Git URL: ftp://invalid.example/repo.git. URL must use HTTPS, SSH, or file protocol.",
        ),
        (InvalidRepoPathError("bad-path"), 'Invalid repository path "bad-path".'),
        (UnknownError("something bad"), 'An unknown error occurred: "something bad"'),
    ],
)
def test_fatal_error_messages_match_the_old_catalogue(error, message):
    assert str(error) == message


def test_fatal_error_formats_the_originating_exception_traceback():
    try:
        raise RuntimeError("network failed")
    except RuntimeError as cause:
        error = UnknownError("Git Repository Error", cause=cause)

    assert str(error) == 'An unknown error occurred: "Git Repository Error"'
    assert "Traceback (most recent call last)" in error.formatted_traceback
    assert "RuntimeError: network failed" in error.formatted_traceback


def test_validation_reason_is_part_of_the_user_facing_message():
    error = InvalidRepoPathError("bad-path", "The path is a file.")

    assert str(error) == 'Invalid repository path "bad-path". The path is a file.'
