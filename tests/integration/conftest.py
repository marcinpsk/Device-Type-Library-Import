"""Conftest for integration tests.

All tests in this package require a live NetBox instance reachable at
``NETBOX_URL`` with a valid ``NETBOX_TOKEN``.  Normal ``pytest`` runs skip this
package automatically via ``norecursedirs`` in pyproject.toml; the CI workflow
invokes it explicitly with ``pytest tests/integration/ -m integration``.

When ``NETBOX_URL`` or ``NETBOX_TOKEN`` are absent every test in the package is
marked as skipped during collection, so the suite shows "s" markers instead of
errors.
"""

import os

import pytest


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
