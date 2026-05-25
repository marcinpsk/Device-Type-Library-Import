"""Manifest helpers for the --export-diff feature.

The manifest (`.export-manifest.json`) lives in the export directory and
records the NetBox ``last_updated`` timestamp for each exported type so that
repeat runs can skip re-exporting unchanged types.
"""

import json
import os
from pathlib import Path

_EMPTY = {"device-types": {}, "module-types": {}, "rack-types": {}}


def load_manifest(path: Path) -> dict:
    """Load manifest from *path*.  Returns an empty manifest on any error."""
    try:
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            return {k: {} for k in _EMPTY}
        # Ensure each expected section exists and is a dict.
        return {k: (loaded[k] if isinstance(loaded.get(k), dict) else {}) for k in _EMPTY}
    except (OSError, json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return {k: {} for k in _EMPTY}


def save_manifest(path: Path, data: dict) -> None:
    """Atomically write *data* to *path* (write-then-rename)."""
    path = Path(path)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def is_entry_fresh(manifest: dict, kind: str, key: str, last_updated: str) -> bool:
    """Return True if the manifest entry for *key* matches *last_updated*."""
    section = manifest.get(kind)
    if not isinstance(section, dict):
        return False
    entry = section.get(key)
    if not isinstance(entry, dict):
        return False
    return entry.get("last_updated") == last_updated


def update_entry(manifest: dict, kind: str, key: str, last_updated: str) -> None:
    """Write (or overwrite) the manifest entry for *key*."""
    section = manifest.get(kind)
    if not isinstance(section, dict):
        manifest[kind] = {}
    manifest[kind][key] = {"last_updated": last_updated}
