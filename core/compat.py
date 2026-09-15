"""NetBox version-compatibility helpers.

Centralises the version line each feature sits behind so that every caller uses the
same logic and drift is impossible.
"""

from __future__ import annotations

import re

# Selecting or sending the relation below this release fails the whole query.
MODULE_BAY_TYPE_MINIMUM_VERSION = (4, 7)


def parse_netbox_version(version) -> tuple[int, int]:
    """Return ``(major, minor)`` from a NetBox version string.

    Padded to two parts so a single-component string cannot raise, and tolerant of the
    suffixes NetBox ships ("4.7.0-beta2").
    """
    raw = [int(re.sub(r"\D.*", "", part.strip()) or "0") for part in str(version).split(".")]
    return tuple(([*raw, 0, 0])[:2])  # type: ignore[return-value]


def supports_module_bay_types(version) -> bool:
    """Return True when this NetBox release exposes the module bay type relation."""
    return parse_netbox_version(version) >= MODULE_BAY_TYPE_MINIMUM_VERSION
