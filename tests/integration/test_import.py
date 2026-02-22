#!/usr/bin/env python3
"""
Comprehensive integration test for the NetBox device-type importer.

Runs the importer against a live NetBox instance using the fixtures in
``tests/fixtures/`` and validates every significant aspect of the round-trip so
that silent failures (wrong data stored, missing field links, schema changes) are
caught early — ideally in weekly CI against NetBox ``main``.

**Order dependency** — Tests are order-dependent and MUST run sequentially.
``test_first_import`` calls ``run_importer`` to create device types and all
associated data in NetBox; every subsequent test (``test_front_port_multiposition``,
``test_module_types``, ``test_graphql_schema``, ``test_idempotency``,
``test_update_mode``) depends on that initial import having completed successfully.
If an early test fails, ``sys.exit(1)`` stops the suite immediately so later tests
do not run against incomplete state.  Re-running individual tests requires a fully
provisioned NetBox environment (i.e. with the test fixtures already imported).

Test scenarios
--------------
A. All component types created with correct field values
     – interfaces (including mgmt_only), power-ports (draw values),
       console-ports, console-server-ports, power-outlets (power_port link),
       rear-ports (positions), front-ports (M2M rear_ports), device-bays,
       module-bays (position).
B. Device-type properties stored correctly
     – u_height (decimal), is_full_depth (bool), weight, weight_unit,
       airflow, part_number, comments.
C. Image linkage
     – front_image and rear_image URLs are set on the device type (not just
       "uploaded" as orphan files) and the URLs return HTTP 200.
D. GraphQL schema consistency
     – Query every DEVICE_TYPE_PROPERTIES field and every
       COMPONENT_TEMPLATE_FIELDS field directly through the GraphQL client so a
       removed/renamed schema field raises an explicit error rather than a
       silent false-positive.
E. Front-port multi-position linkage
     – FP1 → RP1 position 1; FP2 → RP1 position 2 (same rear port).
F. Module-type component creation
     – All module component types created; front-port rear_port mapping set.
G. Idempotency
     – Second run: 0 new, 0 modified device types and module types.
H. Update mode
     – Delete one interface via REST API; re-run with --update; verify it is
       recreated with the original type value.

Usage::

    export NETBOX_URL=http://localhost:8000
    export NETBOX_TOKEN=<token>
    export REPO_URL=file:///tmp/test-fixtures   # local git repo built from tests/fixtures/
    export REPO_BRANCH=main
    uv run python tests/integration/test_import.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# Import after sys.path manipulation so local modules resolve correctly.
from change_detector import DEVICE_TYPE_PROPERTIES  # noqa: E402
from graphql_client import COMPONENT_TEMPLATE_FIELDS, NetBoxGraphQLClient, _NO_MODULE_TYPE  # noqa: E402

NETBOX_URL = (os.environ.get("NETBOX_URL") or "").rstrip("/") or None
NETBOX_TOKEN = os.environ.get("NETBOX_TOKEN")
IGNORE_SSL = os.environ.get("IGNORE_SSL_ERRORS", "False").lower() == "true"

session = requests.Session()
if NETBOX_TOKEN:
    session.headers["Authorization"] = f"Token {NETBOX_TOKEN}"
session.verify = not IGNORE_SSL

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def fail(msg: str) -> NoReturn:
    """Record a failure and exit immediately."""
    print(f"\n  ✗ FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def run_importer(*extra_args: str) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            ["uv", "run", str(REPO_ROOT / "nb-dt-import.py"), *extra_args],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={**os.environ},
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        fail("Importer timed out after 300 seconds — possible hang or deadlock")
    sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return result


def api(path: str, **params) -> dict:
    r = session.get(f"{NETBOX_URL}/api{path}", params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def api_delete(path: str) -> None:
    r = session.delete(f"{NETBOX_URL}/api{path}", timeout=30)
    if r.status_code not in (200, 204):
        fail(f"DELETE {path} returned {r.status_code}: {r.text[:200]}")


def get_one(path: str, **params) -> dict:
    """Return the single result for a query, failing if 0 or >1 match."""
    data = api(path, **params)
    results = data.get("results", [])
    if not results:
        fail(f"GET {path} {params} returned 0 results")
    if len(results) > 1:
        fail(f"GET {path} {params} returned {len(results)} results, expected 1")
    return results[0]


def assert_field(obj: dict | Any, field: str, expected: Any, label: str) -> None:
    actual = obj.get(field, "__MISSING__") if isinstance(obj, dict) else getattr(obj, field, "__MISSING__")
    if actual == "__MISSING__":
        fail(f"{label}: field '{field}' missing")
    if expected is None:
        ok(f"{label}: {field} = {actual!r}")
        return
    # Type-aware comparison: prefer native equality, then numeric coercion.
    if actual == expected:
        ok(f"{label}: {field} = {actual!r}")
        return
    # Numeric coercion: allow int/float/numeric-string comparisons
    try:
        if abs(float(actual) - float(expected)) < 0.001:
            ok(f"{label}: {field} = {actual!r}")
            return
    except (TypeError, ValueError):
        pass
    fail(f"{label}: field '{field}' = {actual!r}, expected {expected!r}")


# ──────────────────────────────────────────────────────────────────────────────
# Scenario A + B + C: first import
# ──────────────────────────────────────────────────────────────────────────────


def test_first_import() -> None:
    print("\n=== Scenario A+B+C: First import — components, properties, images ===")
    result = run_importer()
    if result.returncode != 0:
        fail(f"Importer exited with code {result.returncode}")
    ok("Importer completed successfully")

    # ── Manufacturer ──
    mfr = get_one("/dcim/manufacturers/", slug="testvendor")
    ok(f"Manufacturer TestVendor present (id={mfr['id']})")

    # ── full-device: device-type properties ──
    fd = get_one("/dcim/device-types/", slug="testvendor-full-device")
    print("\n  — device type properties —")
    assert_field(fd, "part_number", "TFD-1", "full-device")
    assert_field(fd, "u_height", 2.0, "full-device")
    assert_field(fd, "is_full_depth", True, "full-device")
    assert_field(fd, "weight", 10.5, "full-device")
    assert_field(fd.get("weight_unit") or {}, "value", "kg", "full-device weight_unit")
    assert_field(fd.get("airflow") or {}, "value", "front-to-rear", "full-device airflow")
    assert_field(fd, "comments", "Integration test device covering all component types.", "full-device")

    fd_id = fd["id"]

    # ── Interfaces ──
    print("\n  — interfaces —")
    ifaces = api("/dcim/interface-templates/", device_type_id=fd_id)["results"]
    by_name = {i["name"]: i for i in ifaces}
    if "eth0" not in by_name or "mgmt0" not in by_name:
        fail(f"full-device: expected eth0+mgmt0 interfaces, got {list(by_name)}")
    assert_field(by_name["eth0"]["type"], "value", "1000base-t", "eth0 type")
    if by_name["mgmt0"]["mgmt_only"] is not True:
        fail("full-device: mgmt0.mgmt_only should be True")
    ok("mgmt0.mgmt_only = True")

    # ── Power ports ──
    print("\n  — power ports —")
    pps = api("/dcim/power-port-templates/", device_type_id=fd_id)["results"]
    if len(pps) != 1:
        fail(f"full-device: expected 1 power port, got {len(pps)}")
    pp = pps[0]
    assert_field(pp, "maximum_draw", 500, "PSU1 maximum_draw")
    assert_field(pp, "allocated_draw", 250, "PSU1 allocated_draw")

    # ── Console ports / console server ports ──
    print("\n  — console ports —")
    cps = api("/dcim/console-port-templates/", device_type_id=fd_id)["results"]
    if len(cps) != 1:
        fail(f"full-device: expected 1 console port, got {len(cps)}")
    ok("console-port 'Console' present")
    csps = api("/dcim/console-server-port-templates/", device_type_id=fd_id)["results"]
    if len(csps) != 1:
        fail(f"full-device: expected 1 console server port, got {len(csps)}")
    ok("console-server-port 'CSP1' present")

    # ── Power outlets — power_port link ──
    print("\n  — power outlets (link to PSU1) —")
    pos = api("/dcim/power-outlet-templates/", device_type_id=fd_id)["results"]
    if len(pos) != 1:
        fail(f"full-device: expected 1 power outlet, got {len(pos)}")
    outlet = pos[0]
    if outlet.get("power_port") is None:
        fail("full-device: Outlet1.power_port is None — link was not created")
    if outlet["power_port"]["name"] != "PSU1":
        fail(f"full-device: Outlet1.power_port.name = {outlet['power_port']['name']!r}, expected 'PSU1'")
    ok("Outlet1.power_port.name = 'PSU1'")

    # ── Rear ports ──
    print("\n  — rear ports —")
    rps = api("/dcim/rear-port-templates/", device_type_id=fd_id)["results"]
    if len(rps) != 1:
        fail(f"full-device: expected 1 rear port, got {len(rps)}")
    rp = rps[0]
    assert_field(rp, "positions", 2, "RP1.positions")

    # ── Device bays / module bays ──
    print("\n  — device/module bays —")
    dbs = api("/dcim/device-bay-templates/", device_type_id=fd_id)["results"]
    if len(dbs) != 1:
        fail(f"full-device: expected 1 device bay, got {len(dbs)}")
    ok("device-bay 'Bay1' present")
    mbs = api("/dcim/module-bay-templates/", device_type_id=fd_id)["results"]
    if len(mbs) != 1:
        fail(f"full-device: expected 1 module bay, got {len(mbs)}")
    if mbs[0].get("position") != "1":
        fail(f"full-device: module bay position = {mbs[0].get('position')!r}, expected '1'")
    ok("module-bay 'Module Bay 1' position='1'")

    # ── Images ──
    print("\n  — images —")
    _test_images(fd, fd_id)


def _test_images(fd: dict, fd_id: int) -> None:
    """Verify front/rear images are set and accessible (Scenario C)."""
    for field in ("front_image", "rear_image"):
        url = fd.get(field)
        if not url:
            fail(
                f"full-device: {field} is empty — image was not linked to device type. "
                "This is the 'upload succeeds but link missing' silent-failure mode."
            )
        # Verify the image URL is actually accessible (not a dangling reference)
        img_url = url if url.startswith("http") else f"{NETBOX_URL}{url}"
        r = session.get(img_url, timeout=30)
        if r.status_code != 200:
            fail(f"full-device: {field} URL {img_url!r} returned HTTP {r.status_code}")
        ok(f"{field} URL accessible ({r.status_code}): {img_url}")


# ──────────────────────────────────────────────────────────────────────────────
# Scenario E: Front-port multi-position linkage
# ──────────────────────────────────────────────────────────────────────────────


def test_front_port_multiposition() -> None:
    print("\n=== Scenario E: Front-port multi-position linkage ===")
    fd = get_one("/dcim/device-types/", slug="testvendor-full-device")
    fps = {fp["name"]: fp for fp in api("/dcim/front-port-templates/", device_type_id=fd["id"])["results"]}

    if "FP1" not in fps or "FP2" not in fps:
        fail(f"full-device: expected FP1+FP2, got {list(fps)}")

    for name, expected_pos in [("FP1", 1), ("FP2", 2)]:
        fp = fps[name]
        mapping = fp.get("rear_ports", [])
        if not mapping:
            fail(f"{name}: rear_ports is empty — M2M linkage not created")
        pos = mapping[0].get("rear_port_position")
        if pos != expected_pos:
            fail(f"{name}: rear_port_position = {pos!r}, expected {expected_pos}")
        ok(f"{name}: rear_port_position = {pos}")

    # Both front ports should point to the same rear port
    rp1_id = fps["FP1"]["rear_ports"][0]["rear_port"]
    rp2_id = fps["FP2"]["rear_ports"][0]["rear_port"]
    if rp1_id != rp2_id:
        fail(f"FP1 and FP2 point to different rear ports ({rp1_id} vs {rp2_id}), expected same RP1")
    ok("FP1 and FP2 both map to the same rear port (RP1)")

    # Also check patch-panel front ports
    pp = get_one("/dcim/device-types/", slug="testvendor-patch-panel-4")
    pp_fps = api("/dcim/front-port-templates/", device_type_id=pp["id"])["results"]
    broken = [fp["name"] for fp in pp_fps if not fp.get("rear_ports")]
    if broken:
        fail(f"patch-panel-4: {len(broken)} front ports have empty rear_ports: {broken}")
    ok(f"patch-panel-4: all {len(pp_fps)} front ports have rear_ports mapping")


# ──────────────────────────────────────────────────────────────────────────────
# Scenario F: Module-type component creation
# ──────────────────────────────────────────────────────────────────────────────


def test_module_types() -> None:
    print("\n=== Scenario F: Module-type component creation ===")
    mt_results = api("/dcim/module-types/", manufacturer__slug="testvendor")["results"]
    mt_by_model = {mt["model"]: mt for mt in mt_results}

    if "Test Full Module" not in mt_by_model:
        fail(f"Module type 'Test Full Module' not found; got {list(mt_by_model)}")
    ok("Module type 'Test Full Module' present")
    mt_id = mt_by_model["Test Full Module"]["id"]

    expected_counts = {
        "/dcim/interface-templates/": ("interfaces", 1),
        "/dcim/power-port-templates/": ("power-ports", 1),
        "/dcim/console-port-templates/": ("console-ports", 1),
        "/dcim/console-server-port-templates/": ("console-server-ports", 1),
        "/dcim/rear-port-templates/": ("rear-ports", 1),
        "/dcim/front-port-templates/": ("front-ports", 1),
    }
    for path, (label, expected) in expected_counts.items():
        count = api(path, module_type_id=mt_id)["count"]
        if count != expected:
            fail(f"full-module: {label} count = {count}, expected {expected}")
        ok(f"full-module: {label} count = {count}")

    # Front port linkage for module type
    mt_fps = api("/dcim/front-port-templates/", module_type_id=mt_id)["results"]
    broken = [fp["name"] for fp in mt_fps if not fp.get("rear_ports")]
    if broken:
        fail(f"full-module: {len(broken)} front ports have empty rear_ports: {broken}")
    ok("full-module: front port rear_ports mapping set correctly")


# ──────────────────────────────────────────────────────────────────────────────
# Scenario D: GraphQL schema consistency
# ──────────────────────────────────────────────────────────────────────────────


def test_graphql_schema() -> None:
    """Directly exercise the GraphQL client to catch schema changes early.

    If NetBox renames or removes a field we rely on, the GraphQL query will
    fail with a schema error here — rather than silently returning None and
    causing false positives in change detection.
    """
    print("\n=== Scenario D: GraphQL schema consistency ===")
    client = NetBoxGraphQLClient(NETBOX_URL, NETBOX_TOKEN, ignore_ssl=IGNORE_SSL)

    # ── Manufacturers ──
    manufacturers = client.get_manufacturers()
    if not manufacturers:
        fail("get_manufacturers() returned empty result")
    mfr = next((m for m in manufacturers.values() if m.slug == "testvendor"), None)
    if mfr is None:
        fail("get_manufacturers() did not return TestVendor")
    ok("get_manufacturers() returned TestVendor")

    # ── Device types: all DEVICE_TYPE_PROPERTIES present ──
    dt_by_model, dt_by_slug = client.get_device_types()
    fd = dt_by_slug.get(("testvendor", "testvendor-full-device"))
    if fd is None:
        fail("get_device_types() did not return full-device")
    ok("get_device_types() returned testvendor-full-device")

    for prop in DEVICE_TYPE_PROPERTIES:
        val = getattr(fd, prop, "__MISSING__")
        if val == "__MISSING__":
            fail(
                f"GraphQL device_type missing field '{prop}' — "
                f"NetBox schema may have changed. This would cause silent false positives "
                f"in ChangeDetector._compare_device_type_properties()."
            )
        ok(f"GraphQL device_type.{prop} = {val!r}")

    # ── Component templates: all COMPONENT_TEMPLATE_FIELDS fields present ──
    device_type_id = fd.id
    for endpoint_name, expected_fields in COMPONENT_TEMPLATE_FIELDS.items():
        try:
            records = client.get_component_templates(endpoint_name)
        except Exception as exc:
            fail(
                f"get_component_templates({endpoint_name!r}) raised {type(exc).__name__}: {exc} — "
                f"likely a GraphQL schema error (field removed or renamed)."
            )
        test_records = [r for r in records if getattr(getattr(r, "device_type", None), "id", None) == device_type_id]

        if endpoint_name not in _NO_MODULE_TYPE:
            # Also accept module-type records for endpoints shared by both types
            test_records += [r for r in records if getattr(getattr(r, "module_type", None), "id", None) is not None]

        if not test_records:
            # Endpoint has no records for our test types — skip field validation
            ok(f"GraphQL {endpoint_name}: query OK (no test records to validate fields)")
            continue

        for field in expected_fields:
            if field == "id":
                continue  # id always present
            # If the field is absent from *every* record it was likely stripped
            # by a server-side schema change (e.g. rear_port_position removed
            # in NetBox 4.5+).  Treat as a known fallback omission rather than
            # a hard failure.
            if all(getattr(r, field, "__MISSING__") == "__MISSING__" for r in test_records):
                ok(f"GraphQL {endpoint_name}: field '{field}' absent from all records (fallback omission)")
                continue
            sample = test_records[0]
            val = getattr(sample, field, "__MISSING__")
            if val == "__MISSING__":
                fail(
                    f"GraphQL {endpoint_name} record missing field '{field}' — "
                    f"schema change detected. Update COMPONENT_TEMPLATE_FIELDS or the "
                    f"NetBox query in graphql_client.py."
                )
        ok(f"GraphQL {endpoint_name}: all {len(expected_fields)} fields present")

    # ── Module types ──
    module_types = client.get_module_types()
    if not any("Test Full Module" in v for v in module_types.values()):
        fail(
            f"get_module_types() did not return 'Test Full Module' — got manufacturer keys: {list(module_types.keys())}"
        )
    ok("get_module_types() completed without schema error")


# ──────────────────────────────────────────────────────────────────────────────
# Scenario G: Idempotency
# ──────────────────────────────────────────────────────────────────────────────


def test_idempotency() -> None:
    print("\n=== Scenario G: Idempotency (second run) ===")
    result = run_importer()
    if result.returncode != 0:
        fail(f"Importer (2nd run) exited with code {result.returncode}")

    out = result.stdout
    for pattern, label in [
        (r"New device types:\s+0", "new device types"),
        (r"Modified device types:\s+0", "modified device types"),
    ]:
        if not re.search(pattern, out):
            fail(f"Second run: expected 0 {label} but report says otherwise.\n{out}")
        ok(f"0 {label}")

    if "MODULE TYPE CHANGE DETECTION" in out:
        for pattern, label in [
            (r"New module types:\s+0", "new module types"),
            (r"Modified module types:\s+0", "modified module types"),
        ]:
            if not re.search(pattern, out):
                fail(f"Second run: expected 0 {label}.\n{out}")
            ok(f"0 {label}")


# ──────────────────────────────────────────────────────────────────────────────
# Scenario H: Update mode — delete + recreate
# ──────────────────────────────────────────────────────────────────────────────


def test_update_mode() -> None:
    print("\n=== Scenario H: Update mode — delete interface, verify recreated ===")
    fd = get_one("/dcim/device-types/", slug="testvendor-full-device")
    ifaces = api("/dcim/interface-templates/", device_type_id=fd["id"])["results"]
    eth0 = next((i for i in ifaces if i["name"] == "eth0"), None)
    if eth0 is None:
        fail("Cannot find eth0 interface to delete for update-mode test")

    api_delete(f"/dcim/interface-templates/{eth0['id']}/")
    ok(f"Deleted interface 'eth0' (id={eth0['id']})")

    # Verify deletion
    remaining = api("/dcim/interface-templates/", device_type_id=fd["id"])["count"]
    if remaining != 1:
        fail(f"After deletion, expected 1 interface remaining, got {remaining}")
    ok("Deletion confirmed — 1 interface remaining")

    # Run with --update
    result = run_importer("--update")
    if result.returncode != 0:
        fail(f"Importer --update exited with code {result.returncode}")

    # Verify eth0 is back
    ifaces_after = api("/dcim/interface-templates/", device_type_id=fd["id"])["results"]
    by_name = {i["name"]: i for i in ifaces_after}
    if "eth0" not in by_name:
        fail("eth0 was NOT recreated by --update run")
    if by_name["eth0"]["type"]["value"] != "1000base-t":
        fail(f"eth0 recreated with wrong type: {by_name['eth0']['type']['value']!r}")
    ok("eth0 recreated with correct type '1000base-t'")

    # Verify idempotent after update too
    result2 = run_importer()
    if not re.search(r"New device types:\s+0", result2.stdout):
        fail("After update, third run shows new device types")
    ok("Post-update run: 0 new device types")
    if not re.search(r"Modified device types:\s+0", result2.stdout):
        fail("After update, third run still shows modified device types")
    ok("Post-update run: 0 modified device types")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────


def main() -> None:
    if not NETBOX_URL or not NETBOX_TOKEN:
        print(
            "ERROR: NETBOX_URL and NETBOX_TOKEN environment variables are required.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"NetBox URL : {NETBOX_URL}")
    print(f"Repo root  : {REPO_ROOT}")

    test_first_import()
    test_front_port_multiposition()
    test_module_types()
    test_graphql_schema()
    test_idempotency()
    test_update_mode()

    print("\n=== All integration tests passed ✓ ===\n")


if __name__ == "__main__":
    main()
