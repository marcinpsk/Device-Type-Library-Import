import os
import sys
import pytest
from unittest.mock import MagicMock, patch

# Ensure the project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def paginate_dispatch(data_dict):
    """Return a ``requests.post`` side-effect that simulates a single-page result.

    Returns *data_dict* when the request uses ``offset=0`` (first page) and empty
    lists for every subsequent page, so tests that contain non-empty data don't loop
    forever under ``query_all``'s empty-page termination logic.

    Usage::

        mock_post.side_effect = paginate_dispatch({"manufacturer_list": [{...}]})
    """

    def handler(url, json=None, **kwargs):
        r = MagicMock()
        r.status_code = 200
        r.raise_for_status = MagicMock()
        offset = (((json or {}).get("variables") or {}).get("pagination") or {}).get("offset", 0)
        if offset == 0:
            r.json.return_value = {"data": data_dict}
        else:
            r.json.return_value = {"data": {k: [] for k in data_dict}}
        return r

    return handler


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


@pytest.fixture(autouse=True)
def mock_graphql_requests():
    """Mock requests.post in graphql_client to prevent actual HTTP calls.

    Returns empty lists for all GraphQL list queries by default.
    Tests that need specific data can override via mock_graphql_requests.
    """
    with patch("graphql_client.requests.post") as mock_post:
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
        mock_post.return_value = response
        yield mock_post


@pytest.fixture
def graphql_client():
    """Provide a NetBoxGraphQLClient instance for tests that need one."""
    from graphql_client import NetBoxGraphQLClient

    return NetBoxGraphQLClient("http://netbox.local", "dummy_token")
