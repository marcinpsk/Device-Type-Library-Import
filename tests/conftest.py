import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Ensure the project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture(autouse=True)
def mock_env_vars():
    """Set mandatory environment variables to prevent settings.py from exiting."""
    with patch.dict(
        os.environ,
        {
            "REPO_URL": "https://example.com/repo.git",
            "NETBOX_URL": "http://netbox.local",
            "NETBOX_TOKEN": "dummy_token",
            "IGNORE_SSL_ERRORS": "True",
        },
    ):
        yield


@pytest.fixture(autouse=True)
def mock_git_repo():
    """Mock git.Repo to prevent actual git operations during settings import."""
    with patch("repo.Repo") as mock_repo:
        # Mock the remote origin logic
        mock_remote = MagicMock()
        mock_remote.url = "https://example.com/repo.git"
        mock_repo.return_value.remotes.origin = mock_remote
        mock_repo.clone_from.return_value.remotes.origin = mock_remote
        yield mock_repo


@pytest.fixture
def mock_pynetbox():
    """Mock pynetbox to prevent API calls."""
    with patch("netbox_api.pynetbox") as mock_nb:
        yield mock_nb
