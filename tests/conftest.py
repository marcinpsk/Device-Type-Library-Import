import os
import pytest
from unittest.mock import MagicMock, patch


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
            "GRAPHQL_PAGE_SIZE": "5000",
            "PRELOAD_THREADS": "8",
        },
    ):
        yield


@pytest.fixture(autouse=True)
def mock_git_repo():
    """Mock git.Repo to prevent actual git operations during settings import."""
    with patch("core.repo.Repo") as mock_repo:
        mock_remote = MagicMock()
        mock_remote.url = "https://example.com/repo.git"
        mock_repo.return_value.remotes.origin = mock_remote
        mock_repo.clone_from.return_value.remotes.origin = mock_remote
        yield mock_repo


@pytest.fixture
def mock_pynetbox():
    """Mock pynetbox to prevent API calls."""
    with patch("core.netbox_api.pynetbox") as mock_nb:
        yield mock_nb


@pytest.fixture(autouse=True)
def mock_graphql_requests():
    """Mock the HTTP session used by NetBoxGraphQLClient to prevent real calls.

    Patches ``requests.Session`` in ``core.graphql_client`` so any client created
    during a test uses a mock session.  Returns empty lists for all GraphQL
    list queries by default.
    """
    with patch("core.graphql_client.requests.Session") as MockSession:
        mock_session = MockSession.return_value
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status = MagicMock()
        response.json.return_value = {
            "data": {
                "manufacturer_list": [],
                "device_type_list": [],
                "module_type_list": [],
                "image_attachment_list": [],
            }
        }
        mock_session.post.return_value = response
        yield mock_session.post


@pytest.fixture
def mock_post(mock_graphql_requests):
    """Alias for mock_graphql_requests — the mock session.post callable."""
    return mock_graphql_requests


@pytest.fixture
def graphql_client():
    """Provide a NetBoxGraphQLClient instance backed by the mock session."""
    from core.graphql_client import NetBoxGraphQLClient

    return NetBoxGraphQLClient("http://netbox.local", "dummy_token")
