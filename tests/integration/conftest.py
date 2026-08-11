"""Conftest for integration tests.

All tests in this package require a live NetBox instance reachable at
``NETBOX_URL`` with a valid ``NETBOX_TOKEN``.  Normal ``pytest`` runs skip this
package automatically via ``norecursedirs`` in pyproject.toml; the CI workflow
invokes it explicitly with ``pytest tests/integration/ -m integration``.

When ``NETBOX_URL`` or ``NETBOX_TOKEN`` are absent every test in the package is
marked as skipped during collection, so the suite shows "s" markers instead of
errors.

Note: the env check reads ``os.environ``, so this module loads any local ``.env``
first.  Nothing else does it during collection: the CLI loads it inside
``core.config.resolve_run_config()``, which pytest never calls.  A developer with a
configured ``.env`` therefore runs these tests with the shell vars unset; the skip
path fires only in a clean checkout (e.g. CI before its real ``NETBOX_*`` vars are
exported).
"""

import os

import pytest
from dotenv import load_dotenv

# At import, so the values are in os.environ before pytest_collection_modifyitems reads them.
load_dotenv()


def pytest_collection_modifyitems(items):
    """Attach ``integration`` mark to every test in this package; skip all if env is missing."""
    url = os.environ.get("NETBOX_URL", "").strip()
    token = os.environ.get("NETBOX_TOKEN", "").strip()
    missing_env = not url or not token
    skip_marker = pytest.mark.skip(
        reason=(
            "Integration tests require NETBOX_URL and NETBOX_TOKEN environment variables. "
            "Run: export NETBOX_URL=http://localhost:8000 NETBOX_TOKEN=<token>"
        )
    )
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
            if missing_env:
                item.add_marker(skip_marker)
