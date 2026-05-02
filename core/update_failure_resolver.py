"""Classify NetBox PATCH/POST failures and (when safe) propose remediation.

This module exists to translate raw ``pynetbox.RequestError`` exceptions —
which carry NetBox's business-logic constraint messages as JSON strings — into
structured outcomes the caller can act on:

* identify well-known constraints (e.g. ``subdevice_role`` parent→child blocked
  by existing device-bay templates);
* inspect NetBox to determine whether the affected type is *in use* by live
  devices (in which case automated remediation is unsafe);
* return an ordered sequence of remediation steps the caller may execute when
  the operator has explicitly opted in via ``--force-resolve-conflicts``.

The classifier is intentionally narrow: only constraints we can recognize with
high confidence are mapped to actionable resolutions.  Everything else is
returned as :data:`FailureKind.UNHANDLED` so the caller falls back to plain
error logging.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, List, Optional

from core.compat import device_type_filter_kwargs


class FailureKind(str, Enum):
    """High-level classification of a NetBox update failure."""

    UNHANDLED = "unhandled"
    SUBDEVICE_ROLE_FLIP = "subdevice_role_flip"
    MANUAL_REQUIRED = "manual_required"


@dataclass
class FailureResolution:
    """Structured outcome of classifying a NetBox update failure.

    Attributes:
        kind: Which constraint we recognised, or :data:`FailureKind.UNHANDLED`.
        description: Human-readable summary safe to log to the operator.
        blocking_objects: Names/labels of NetBox objects that are blocking the
            update (e.g. device-bay template names).  May be empty.
        dependent_devices_count: Number of live ``Device`` records that
            reference this device-type / module-type.  ``None`` when not
            queried; ``0`` confirmed safe; ``> 0`` means automated remediation
            is forbidden regardless of the ``--force-resolve-conflicts`` flag.
        dependent_devices_sample: Up to 5 device names referencing this type,
            for inclusion in the operator-facing log.
        remediation_steps: Ordered list of zero-arg callables that perform the
            remediation.  Only executed when the operator has opted in AND
            ``dependent_devices_count == 0``.
        hint: Operator-facing one-line hint advising how to proceed (e.g.
            "re-run with --force-resolve-conflicts").
    """

    kind: FailureKind
    description: str = ""
    blocking_objects: List[str] = field(default_factory=list)
    dependent_devices_count: Optional[int] = None
    dependent_devices_sample: List[str] = field(default_factory=list)
    remediation_steps: List[Callable[[], None]] = field(default_factory=list)
    hint: str = ""

    @property
    def is_actionable(self) -> bool:
        """True when remediation steps exist and no live devices block them."""
        return (
            self.kind not in (FailureKind.UNHANDLED, FailureKind.MANUAL_REQUIRED)
            and bool(self.remediation_steps)
            and (self.dependent_devices_count == 0)
        )


_SUBDEVICE_ROLE_MARKERS = (
    "device bay templates",
    "declassifying it as a parent device",
)


def _extract_error_payload(error: Any) -> Any:
    """Best-effort decode of ``pynetbox.RequestError.error`` into a dict/str.

    pynetbox surfaces the body either pre-parsed (dict) or as a JSON string;
    occasionally as a raw bytes payload.  Normalise to a dict when possible,
    otherwise return the original object.
    """
    if isinstance(error, dict):
        return error
    if isinstance(error, (bytes, bytearray)):
        try:
            error = error.decode("utf-8", errors="replace")
        except Exception:
            return error
    if isinstance(error, str):
        try:
            return json.loads(error)
        except (ValueError, TypeError):
            return error
    return error


def _matches_subdevice_role_constraint(payload: Any) -> bool:
    """Return True if *payload* describes the parent→child device-bay block."""
    if isinstance(payload, dict):
        msgs = payload.get("subdevice_role")
        if not msgs:
            return False
        if isinstance(msgs, str):
            text = msgs
        else:
            try:
                text = " ".join(str(m) for m in msgs)
            except TypeError:
                text = str(msgs)
        return all(marker in text for marker in _SUBDEVICE_ROLE_MARKERS)
    if isinstance(payload, str):
        return all(marker in payload for marker in _SUBDEVICE_ROLE_MARKERS)
    return False


def _count_dependent_devices(netbox: Any, device_type_id: int, *, new_filters: bool = False) -> tuple[int, List[str]]:
    """Query NetBox for devices using *device_type_id*.

    Returns ``(count, sample_names)`` where ``sample_names`` is up to 5 names
    for inclusion in operator-facing logs.  Defensive: any pynetbox/network
    failure is reported as an UNKNOWN large count (``-1``) so the caller treats
    the type as unsafe to auto-resolve.

    Args:
        netbox: pynetbox API client.
        device_type_id: ID of the device type to query.
        new_filters: When True, use ``device_type_id`` filter name (NetBox ≥ 4.1);
            otherwise use the legacy ``devicetype_id`` name.
    """
    filter_kwargs = device_type_filter_kwargs(device_type_id, new_filters=new_filters)
    try:
        devices = list(netbox.dcim.devices.filter(**filter_kwargs, limit=5))
    except Exception:
        return -1, []
    sample = [getattr(d, "name", None) or str(getattr(d, "id", "?")) for d in devices[:5]]
    if len(devices) < 5:
        return len(devices), sample
    # We capped at limit=5; query the real total separately.
    try:
        total = netbox.dcim.devices.count(**filter_kwargs)
    except Exception:
        total = len(devices)
    return total, sample


def _list_device_bay_templates(netbox: Any, device_type_id: int, *, new_filters: bool = False) -> Optional[List[Any]]:
    """Return all ``DeviceBayTemplate`` records attached to *device_type_id*.

    Returns ``None`` when the NetBox query itself fails (network error, 5xx, etc.)
    so the caller can distinguish "no templates" from "lookup failed".

    Args:
        netbox: pynetbox API client.
        device_type_id: ID of the device type to query.
        new_filters: When True, use ``device_type_id`` filter name (NetBox ≥ 4.1);
            otherwise use the legacy ``devicetype_id`` name.
    """
    try:
        return list(
            netbox.dcim.device_bay_templates.filter(
                **device_type_filter_kwargs(device_type_id, new_filters=new_filters)
            )
        )
    except Exception:
        return None


def classify_device_type_update_failure(
    error: Any,
    *,
    netbox: Any,
    device_type_id: int,
    device_type_yaml: dict,
    new_filters: bool = False,
) -> FailureResolution:
    """Classify a ``pynetbox.RequestError`` raised while updating a device type.

    Args:
        error: ``RequestError.error`` payload (dict or JSON string).
        netbox: pynetbox API client used to query for dependent devices and
            blocking templates.
        device_type_id: ID of the device-type being updated.
        device_type_yaml: Parsed YAML dict for this device-type (used to detect
            whether the YAML *also* lists device bays — in which case we cannot
            blindly delete them).
        new_filters: When True, use updated filter parameter names (NetBox ≥ 4.1).

    Returns:
        A :class:`FailureResolution` describing the constraint and (when safe)
        the steps required to clear it.
    """
    payload = _extract_error_payload(error)

    if not _matches_subdevice_role_constraint(payload):
        return FailureResolution(
            kind=FailureKind.UNHANDLED,
            description=str(payload),
        )

    # SUBDEVICE_ROLE_FLIP path -------------------------------------------------
    blocking_templates = _list_device_bay_templates(netbox, device_type_id, new_filters=new_filters)
    if blocking_templates is None:
        return FailureResolution(
            kind=FailureKind.MANUAL_REQUIRED,
            description="Cannot inspect blocking device-bay templates: the NetBox lookup failed.",
            hint="Retry after restoring NetBox connectivity, then re-run the update.",
        )
    blocking_names = [getattr(t, "name", str(getattr(t, "id", "?"))) for t in blocking_templates]

    dep_count, dep_sample = _count_dependent_devices(netbox, device_type_id, new_filters=new_filters)

    # YAML must NOT redefine device-bays — otherwise deleting them would just
    # cause our own component-creation step to fail or thrash.  This catches
    # the edge case where the user intends a parent->child flip but their YAML
    # still declares device-bays.
    yaml_has_device_bays = bool(device_type_yaml.get("device-bays"))

    if dep_count != 0:
        # Live devices reference this type — auto-resolve forbidden.
        sample = ", ".join(dep_sample) if dep_sample else "(unknown)"
        if dep_count < 0:
            count_text = "unknown number of"
        elif dep_count > len(dep_sample):
            count_text = f"{dep_count} (showing first {len(dep_sample)})"
        else:
            count_text = str(dep_count)
        return FailureResolution(
            kind=FailureKind.MANUAL_REQUIRED,
            description=(
                "Cannot change subdevice_role: device bay templates exist AND "
                f"{count_text} device(s) currently use this type."
            ),
            blocking_objects=blocking_names,
            dependent_devices_count=dep_count,
            dependent_devices_sample=dep_sample,
            hint=(
                f"Live devices use this type ({sample}). Resolve manually in NetBox "
                "(remove devices or convert them) before re-running."
            ),
        )

    if yaml_has_device_bays:
        return FailureResolution(
            kind=FailureKind.MANUAL_REQUIRED,
            description=(
                "Cannot auto-resolve subdevice_role flip while YAML still declares "
                "device-bays — removing them would create a churn loop."
            ),
            blocking_objects=blocking_names,
            dependent_devices_count=0,
            hint="Remove the 'device-bays' section from the YAML or revert the subdevice_role change.",
        )

    # Safe path: build remediation steps (delete each blocking template).
    if not blocking_templates:
        # The PATCH failed with the subdevice_role constraint but there are no
        # blocking templates (race condition, prior run cleaned them, or the
        # filter returned nothing).  Advertising --force-resolve-conflicts would
        # be a no-op, so give a manual-inspection hint instead.
        return FailureResolution(
            kind=FailureKind.SUBDEVICE_ROLE_FLIP,
            description=(
                "subdevice_role parent→child blocked but no device-bay templates found "
                "(may be a transient state or templates were already removed)."
            ),
            blocking_objects=[],
            dependent_devices_count=0,
            hint=(
                "Inspect the NetBox database for residual device-bay templates "
                "and remove them manually if present, then re-run."
            ),
        )

    def _make_deleter(template):
        def _delete():
            template.delete()

        return _delete

    steps = [_make_deleter(t) for t in blocking_templates]

    return FailureResolution(
        kind=FailureKind.SUBDEVICE_ROLE_FLIP,
        description=(
            f"subdevice_role parent→child blocked by {len(blocking_templates)} "
            "device-bay template(s); no live devices use this type."
        ),
        blocking_objects=blocking_names,
        dependent_devices_count=0,
        remediation_steps=steps,
        hint=(
            "Re-run with --force-resolve-conflicts to delete the blocking device-bay templates and retry the update."
        ),
    )
