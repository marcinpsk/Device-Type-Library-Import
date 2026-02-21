#!/usr/bin/env python3
"""
Integration test for the NetBox device-type importer.

Runs the importer against a live NetBox instance using the test fixtures in
tests/fixtures/ and validates the results.  Designed to run in CI (weekly)
against the latest NetBox main branch to catch API schema changes early.

Test scenarios
--------------
1. First import  – all test device/module types created successfully
2. Front port linkage (regression: NetBox 4.5 M2M rear_ports) – every front
   port template has a non-empty rear_ports list with correct rear_port_position
3. Idempotency – second run reports 0 new and 0 modified device/module types

Usage::

    export NETBOX_URL=http://localhost:8000
    export NETBOX_TOKEN=<token>
    export REPO_URL=file:///tmp/test-fixtures   # local git repo with fixtures
    export REPO_BRANCH=main
    uv run python tests/integration/test_import.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).resolve().parents[2]
NETBOX_URL = os.environ["NETBOX_URL"].rstrip("/")
NETBOX_TOKEN = os.environ["NETBOX_TOKEN"]
IGNORE_SSL = os.environ.get("IGNORE_SSL_ERRORS", "False").lower() == "true"

session = requests.Session()
session.headers["Authorization"] = f"Token {NETBOX_TOKEN}"
session.verify = not IGNORE_SSL

EXPECTED_DEVICE_TYPES = [
    ("testvendor-patch-panel-4", "Test Patch Panel 4-Port"),
    ("testvendor-server-1u", "Test Server 1U"),
]
EXPECTED_MODULE_TYPES = [
    "Test Fiber Cassette 4-Port",
]

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def fail(msg: str) -> None:
    print(f"\nFAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def run_importer(*extra_args: str) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["uv", "run", str(REPO_ROOT / "nb-dt-import.py"), *extra_args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={**os.environ},
    )
    sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result


def get_json(path: str, **params) -> dict:
    r = session.get(f"{NETBOX_URL}/api{path}", params=params)
    r.raise_for_status()
    return r.json()


# ──────────────────────────────────────────────────────────────────────────────
# Test scenarios
# ──────────────────────────────────────────────────────────────────────────────


def test_first_import() -> None:
    print("\n=== Scenario 1: First import ===")
    result = run_importer()
    if result.returncode != 0:
        fail(f"Importer exited with code {result.returncode}")

    # Manufacturer
    mfrs = get_json("/dcim/manufacturers/", slug="testvendor")
    if mfrs["count"] == 0:
        fail("Manufacturer 'TestVendor' was not created")
    ok("Manufacturer TestVendor created")

    # Device types
    for slug, model in EXPECTED_DEVICE_TYPES:
        results = get_json("/dcim/device-types/", slug=slug)
        if results["count"] == 0:
            fail(f"Device type '{model}' (slug={slug}) not found")
    ok(f"{len(EXPECTED_DEVICE_TYPES)} device types created")

    # Module types
    for model in EXPECTED_MODULE_TYPES:
        results = get_json("/dcim/module-types/", manufacturer__slug="testvendor")
        models = {mt["model"] for mt in results["results"]}
        if model not in models:
            fail(f"Module type '{model}' not found")
    ok(f"{len(EXPECTED_MODULE_TYPES)} module types created")


def test_front_port_linkage() -> None:
    print("\n=== Scenario 2: Front port linkage (M2M rear_ports regression) ===")

    # --- device-type front ports ---
    dt = get_json("/dcim/device-types/", slug="testvendor-patch-panel-4")["results"][0]
    fps = get_json("/dcim/front-port-templates/", device_type_id=dt["id"])["results"]

    if not fps:
        fail("No front port templates found for Test Patch Panel 4-Port")

    broken = [fp for fp in fps if not fp.get("rear_ports")]
    if broken:
        fail(
            f"{len(broken)}/{len(fps)} device-type front port(s) have empty rear_ports: {[fp['name'] for fp in broken]}"
        )

    for fp in fps:
        mapping = fp["rear_ports"][0]
        if mapping.get("rear_port_position") is None:
            fail(f"Front port '{fp['name']}' mapping has no rear_port_position")
    ok(f"{len(fps)} device-type front ports correctly linked with rear_port mappings")

    # --- module-type front ports ---
    mt_results = get_json("/dcim/module-types/", manufacturer__slug="testvendor")["results"]
    mt_ids = [mt["id"] for mt in mt_results]
    if mt_ids:
        mt_fps: list[dict] = []
        for mt_id in mt_ids:
            mt_fps.extend(get_json("/dcim/front-port-templates/", module_type_id=mt_id)["results"])

        broken_mt = [fp for fp in mt_fps if not fp.get("rear_ports")]
        if broken_mt:
            fail(f"{len(broken_mt)}/{len(mt_fps)} module-type front port(s) have empty rear_ports")
        if mt_fps:
            ok(f"{len(mt_fps)} module-type front ports correctly linked")


def test_component_counts() -> None:
    print("\n=== Scenario 2b: Component counts ===")

    # Patch panel: 4 front ports + 4 rear ports
    dt = get_json("/dcim/device-types/", slug="testvendor-patch-panel-4")["results"][0]
    fp_count = get_json("/dcim/front-port-templates/", device_type_id=dt["id"])["count"]
    rp_count = get_json("/dcim/rear-port-templates/", device_type_id=dt["id"])["count"]
    if fp_count != 4:
        fail(f"Patch panel: expected 4 front ports, got {fp_count}")
    if rp_count != 4:
        fail(f"Patch panel: expected 4 rear ports, got {rp_count}")
    ok("Patch panel: 4 front ports + 4 rear ports")

    # Server: 2 interfaces + 1 power port
    srv = get_json("/dcim/device-types/", slug="testvendor-server-1u")["results"][0]
    iface_count = get_json("/dcim/interface-templates/", device_type_id=srv["id"])["count"]
    pp_count = get_json("/dcim/power-port-templates/", device_type_id=srv["id"])["count"]
    if iface_count != 2:
        fail(f"Server: expected 2 interfaces, got {iface_count}")
    if pp_count != 1:
        fail(f"Server: expected 1 power port, got {pp_count}")
    ok("Server: 2 interfaces + 1 power port")


def test_idempotency() -> None:
    print("\n=== Scenario 3: Idempotency (second run) ===")
    result = run_importer()
    if result.returncode != 0:
        fail(f"Importer (2nd run) exited with code {result.returncode}")

    out = result.stdout

    if "New device types: 0" not in out:
        fail("Second run reported new device types (expected 0)")
    if "Modified device types: 0" not in out:
        fail("Second run reported modified device types (expected 0)")
    ok("0 new device types, 0 modified device types")

    if "New module types:" in out:
        if "New module types:       0" not in out:
            fail("Second run reported new module types (expected 0)")
        if "Modified module types:  0" not in out:
            fail("Second run reported modified module types (expected 0)")
        ok("0 new module types, 0 modified module types")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────


def main() -> None:
    print(f"NetBox URL : {NETBOX_URL}")
    print(f"Repo root  : {REPO_ROOT}")

    test_first_import()
    test_front_port_linkage()
    test_component_counts()
    test_idempotency()

    print("\n=== All integration tests passed ✓ ===\n")


if __name__ == "__main__":
    main()
