#!/usr/bin/env python3
"""
Repair broken FrontPortTemplate records on NetBox >= 4.5.

NetBox 4.5 replaced the old FrontPortTemplate.rear_port FK + rear_port_position int
with a ManyToMany PortMapping through-table (issue #20564).  Records created by the
importer BEFORE this fix have rear_ports=[] and must be deleted so the importer can
recreate them with the correct rear_port mapping.

Usage:
    uv run repair_front_ports.py           # dry-run: report only
    uv run repair_front_ports.py --fix     # delete broken records
"""

import argparse
import re
import sys

import requests
import urllib3
from dotenv import load_dotenv
import os

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _version_tuple(version_str: str) -> tuple[int, int]:
    parts = [int(re.sub(r"\D.*", "", x) or "0") for x in version_str.split(".")]
    return tuple((parts + [0, 0])[:2])


def paginate(session: requests.Session, url: str, params: dict | None = None):
    """Yield all items from a paginated NetBox REST endpoint."""
    params = dict(params or {})
    params.setdefault("limit", 1000)
    params["offset"] = 0
    while True:
        resp = session.get(url, params=params)
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        if not results:
            break
        yield from results
        params["offset"] += len(results)
        if params["offset"] >= data["count"]:
            break


def delete_ids(session: requests.Session, base_url: str, ids: list[int], label: str):
    """Delete records by ID using the bulk-delete endpoint (list of objects)."""
    if not ids:
        return
    # NetBox bulk delete: DELETE /api/dcim/front-port-templates/ with body [{"id": x}, ...]
    payload = [{"id": i} for i in ids]
    resp = session.delete(f"{base_url}/api/dcim/front-port-templates/", json=payload)
    if resp.status_code == 204:
        print(f"  Deleted {len(ids)} {label} front port templates.")
    else:
        print(f"  ERROR deleting {label} records: {resp.status_code} {resp.text[:200]}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fix", action="store_true", help="Actually delete broken records (default: dry-run)")
    args = parser.parse_args()

    netbox_url = os.environ.get("NETBOX_URL", "").rstrip("/")
    token = os.environ.get("NETBOX_TOKEN", "")
    if not netbox_url or not token:
        print("ERROR: NETBOX_URL and NETBOX_TOKEN must be set (check .env)")
        sys.exit(1)
    ignore_ssl = os.environ.get("IGNORE_SSL_ERRORS", "False").lower() == "true"

    session = requests.Session()
    session.headers.update({"Authorization": f"Token {token}", "Content-Type": "application/json"})
    session.verify = not ignore_ssl

    # Detect NetBox version via status endpoint
    status_resp = session.get(f"{netbox_url}/api/status/")
    status_resp.raise_for_status()
    nb_version = status_resp.json().get("netbox-version", "")
    version = _version_tuple(nb_version)
    print(f"NetBox version: {nb_version} → parsed {version}")

    if version < (4, 5):
        print("This NetBox version uses the old rear_port FK model; no repair needed.")
        sys.exit(0)

    # Collect broken front port templates
    print("\nScanning front_port_templates…")
    dt_broken: list[int] = []
    mt_broken: list[int] = []

    for fp in paginate(session, f"{netbox_url}/api/dcim/front-port-templates/"):
        if fp.get("rear_ports"):
            continue  # already linked — not broken
        if fp.get("device_type"):
            dt_broken.append(fp["id"])
        elif fp.get("module_type"):
            mt_broken.append(fp["id"])

    total = len(dt_broken) + len(mt_broken)
    print(f"  Broken device-type front port templates : {len(dt_broken)}")
    print(f"  Broken module-type front port templates : {len(mt_broken)}")
    print(f"  Total to {'delete' if args.fix else 'fix (dry-run)'}: {total}")

    if total == 0:
        print("\nNothing to do.")
        return

    if not args.fix:
        print(
            "\nDry-run complete.  Run with --fix to delete the broken records so the\n"
            "importer can recreate them with correct rear_port mappings on next run."
        )
        return

    print(f"\nDeleting {total} broken front port templates…")
    # NetBox bulk-delete has no hard limit documented but keep batches sane
    BATCH = 500

    for i in range(0, len(dt_broken), BATCH):
        delete_ids(session, netbox_url, dt_broken[i : i + BATCH], "device-type")

    for i in range(0, len(mt_broken), BATCH):
        delete_ids(session, netbox_url, mt_broken[i : i + BATCH], "module-type")

    print("\nDone.  Run the importer to recreate front port templates with correct rear_port mappings.")


if __name__ == "__main__":
    main()
