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
            "GRAPHQL_PAGE_SIZE": "5000",
            "PRELOAD_THREADS": "8",
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


@pytest.fixture(autouse=True)
def mock_graphql_requests():
    """Mock the HTTP session used by NetBoxGraphQLClient to prevent real calls.

    Patches ``requests.Session`` in ``graphql_client`` so any client created
    during a test uses a mock session.  Returns empty lists for all GraphQL
    list queries by default.  Tests that need specific data can override via
    ``mock_graphql_requests.side_effect`` or ``.return_value``.
    """
    with patch("graphql_client.requests.Session") as MockSession:
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
    """Alias for mock_graphql_requests — the mock session.post callable.

    Allows test_graphql_client.py methods to accept ``mock_post`` as a fixture
    parameter with the same interface as the old ``@patch`` decorator provided.
    """
    return mock_graphql_requests


@pytest.fixture
def graphql_client():
    """Provide a NetBoxGraphQLClient instance for tests that need one.

    Relies on the ``mock_graphql_requests`` fixture (autouse=True) which patches
    ``graphql_client.requests.Session`` so that no real HTTP calls are made.
    Tests using this fixture can override mock_graphql_requests.side_effect or
    mock_graphql_requests.return_value to supply custom GraphQL responses.
    """
    from graphql_client import NetBoxGraphQLClient

    return NetBoxGraphQLClient("http://netbox.local", "dummy_token")
