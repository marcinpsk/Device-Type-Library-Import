"""Tests for ``core.update_failure_resolver``."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.update_failure_resolver import (
    FailureKind,
    _extract_error_payload,
    classify_device_type_update_failure,
)


SUBDEVICE_ROLE_ERROR_DICT = {
    "subdevice_role": [
        "Must delete all device bay templates associated with this device before declassifying it as a parent device."
    ]
}
SUBDEVICE_ROLE_ERROR_JSON = (
    '{"subdevice_role": ["Must delete all device bay templates associated '
    'with this device before declassifying it as a parent device."]}'
)


def _make_netbox(*, devices=None, device_count=None, templates=None):
    """Build a minimal mock pynetbox client with .dcim.devices and .device_bay_templates."""
    nb = MagicMock()
    devices = devices or []
    nb.dcim.devices.filter.return_value = devices
    nb.dcim.devices.count.return_value = device_count if device_count is not None else len(devices)
    nb.dcim.device_bay_templates.filter.return_value = templates or []
    return nb


def test_classifier_unhandled_for_unrelated_error():
    nb = _make_netbox()
    res = classify_device_type_update_failure(
        {"some_other_field": ["nope"]},
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.UNHANDLED


def test_classifier_unhandled_for_unparseable_payload():
    nb = _make_netbox()
    res = classify_device_type_update_failure(
        "totally not json",
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.UNHANDLED


def test_classifier_recognises_subdevice_role_error_dict_safe_path():
    """Dict payload + zero dependent devices + blocking templates -> SUBDEVICE_ROLE_FLIP, actionable."""
    t1 = MagicMock()
    t1.name = "bay-1"
    t2 = MagicMock()
    t2.name = "bay-2"
    nb = _make_netbox(templates=[t1, t2], devices=[], device_count=0)

    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=42,
        device_type_yaml={},
    )

    assert res.kind == FailureKind.SUBDEVICE_ROLE_FLIP
    assert res.dependent_devices_count == 0
    assert res.blocking_objects == ["bay-1", "bay-2"]
    assert len(res.remediation_steps) == 2
    assert res.is_actionable is True
    assert "--force-resolve-conflicts" in res.hint


def test_classifier_accepts_json_string_payload():
    """Pynetbox sometimes returns the body as a JSON string; classifier must handle it."""
    t = MagicMock()
    t.name = "t"
    nb = _make_netbox(templates=[t], devices=[], device_count=0)
    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_JSON,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.SUBDEVICE_ROLE_FLIP


def test_classifier_blocks_auto_resolve_when_dependent_devices_exist():
    """Live devices reference the type -> MANUAL_REQUIRED, no remediation."""
    d1 = MagicMock()
    d1.name = "router-1"
    d2 = MagicMock()
    d2.name = "router-2"
    nb = _make_netbox(devices=[d1, d2], device_count=2, templates=[MagicMock()])

    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )

    assert res.kind == FailureKind.MANUAL_REQUIRED
    assert res.dependent_devices_count == 2
    assert res.dependent_devices_sample == ["router-1", "router-2"]
    assert res.is_actionable is False
    assert res.remediation_steps == []
    assert "router-1" in res.hint


def test_classifier_returns_inspection_hint_when_no_blocking_templates():
    """If device-bay templates list is empty, the force-resolve hint must NOT be shown.

    The PATCH error fired but there are no templates to delete (race condition
    or prior run already cleaned them up).  Advertising --force-resolve-conflicts
    in that case would be a guaranteed no-op that confuses the operator.
    """
    nb = _make_netbox(templates=[], devices=[], device_count=0)
    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.SUBDEVICE_ROLE_FLIP
    assert res.is_actionable is False
    assert res.remediation_steps == []
    assert "--force-resolve-conflicts" not in res.hint


def test_classifier_blocks_auto_resolve_when_yaml_still_lists_device_bays():
    """YAML still declares device-bays -> auto-deleting them would loop; MANUAL_REQUIRED."""
    nb = _make_netbox(templates=[MagicMock()], devices=[], device_count=0)
    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={"device-bays": [{"name": "bay-1"}]},
    )
    assert res.kind == FailureKind.MANUAL_REQUIRED
    assert res.is_actionable is False


def test_classifier_dependent_count_unknown_blocks_resolve():
    """If the count query raises, classifier must treat the type as unsafe (MANUAL_REQUIRED)."""
    nb = MagicMock()
    nb.dcim.device_bay_templates.filter.return_value = [MagicMock()]
    nb.dcim.devices.filter.side_effect = RuntimeError("API down")

    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.MANUAL_REQUIRED
    assert res.dependent_devices_count == -1
    assert res.is_actionable is False


def test_classifier_remediation_step_calls_template_delete():
    """Each remediation_steps entry must, when invoked, delete the corresponding template."""
    t = MagicMock()
    t.name = "bay-1"
    nb = _make_netbox(templates=[t], devices=[], device_count=0)

    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert len(res.remediation_steps) == 1
    res.remediation_steps[0]()
    t.delete.assert_called_once()


def test_classifier_handles_bytes_payload():
    """RequestError content can be bytes; classifier must decode before parsing."""
    nb = _make_netbox(templates=[MagicMock()], devices=[], device_count=0)
    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_JSON.encode("utf-8"),
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.SUBDEVICE_ROLE_FLIP


class _BrokenBytes(bytes):
    def decode(self, *args, **kwargs):
        raise RuntimeError("decode failed")


def test_extract_error_payload_returns_original_bytes_on_decode_failure():
    payload = _BrokenBytes(b"bad")
    assert _extract_error_payload(payload) is payload


@pytest.mark.parametrize(
    ("payload", "expected_kind"),
    [
        (
            {"subdevice_role": "Must delete all device bay templates declassifying it as a parent device"},
            FailureKind.SUBDEVICE_ROLE_FLIP,
        ),
        (
            {"subdevice_role": ["completely unrelated message"]},
            FailureKind.UNHANDLED,
        ),
    ],
)
def test_classifier_marker_matching_is_strict(payload, expected_kind):
    """Classifier matches only when both required markers are present in the message."""
    nb = _make_netbox(templates=[MagicMock()], devices=[], device_count=0)
    res = classify_device_type_update_failure(
        payload,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == expected_kind


def test_classifier_recognises_subdevice_role_error_string_marker():
    """Plain-string payload containing both markers must classify as SUBDEVICE_ROLE_FLIP."""
    nb = _make_netbox(templates=[MagicMock()], devices=[], device_count=0)
    payload = (
        "Must delete all device bay templates associated with this device before declassifying it as a parent device."
    )
    res = classify_device_type_update_failure(
        payload,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.SUBDEVICE_ROLE_FLIP


def test_classifier_handles_non_string_msg_in_subdevice_role_list():
    """If subdevice_role list contains non-string objects, classifier degrades gracefully."""

    class _BadObj:
        def __iter__(self):
            raise TypeError("not iterable as expected")

    nb = _make_netbox(templates=[MagicMock()], devices=[], device_count=0)
    res = classify_device_type_update_failure(
        {"subdevice_role": _BadObj()},
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    # Should not raise; falls through to UNHANDLED because the markers won't match.
    assert res.kind == FailureKind.UNHANDLED


def test_classifier_handles_template_query_failure():
    """If listing device-bay templates raises, classifier returns MANUAL_REQUIRED.

    When the template-listing call fails, the result must distinguish
    "lookup failed" from "no templates" so the operator gets a connectivity
    hint rather than a misleading "inspect for residual templates" message.
    """
    nb = MagicMock()
    nb.dcim.device_bay_templates.filter.side_effect = RuntimeError("API down")
    nb.dcim.devices.filter.return_value = []
    nb.dcim.devices.count.return_value = 0
    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    # Lookup failure → MANUAL_REQUIRED with connectivity hint (not a race-condition message).
    assert res.kind == FailureKind.MANUAL_REQUIRED
    assert "lookup failed" in res.description
    assert res.is_actionable is False


def test_classifier_count_query_used_when_filter_returns_full_page():
    """When filter returns 5 records (page cap), classifier must call .count() for the real total."""
    devs = [MagicMock() for i in range(5)]
    for i, d in enumerate(devs):
        d.name = f"router-{i}"
    nb = _make_netbox(devices=devs, device_count=137, templates=[MagicMock()])
    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.MANUAL_REQUIRED
    assert res.dependent_devices_count == 137
    nb.dcim.devices.count.assert_called_once()


def test_classifier_count_fallback_when_count_query_fails():
    """If .count() raises, classifier falls back to len(filter_results)."""
    devs = [MagicMock() for _ in range(5)]
    for i, d in enumerate(devs):
        d.name = f"router-{i}"
    nb = MagicMock()
    nb.dcim.device_bay_templates.filter.return_value = [MagicMock()]
    nb.dcim.devices.filter.return_value = devs
    nb.dcim.devices.count.side_effect = RuntimeError("boom")
    res = classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=1,
        device_type_yaml={},
    )
    assert res.kind == FailureKind.MANUAL_REQUIRED
    assert res.dependent_devices_count == 5


def test_new_filters_uses_device_type_id_key():
    """new_filters=True must call filter(device_type_id=...) not devicetype_id=...

    This matters because NetBox >= 4.1 changed the query param name.
    Passing the wrong key causes pynetbox to silently return ALL templates.
    """
    nb = _make_netbox()
    classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=99,
        device_type_yaml={},
        new_filters=True,
    )
    nb.dcim.device_bay_templates.filter.assert_called_once_with(device_type_id=99)


def test_old_filters_uses_devicetype_id_key():
    """new_filters=False (default) must call filter(devicetype_id=...) for NetBox < 4.1."""
    nb = _make_netbox()
    classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=99,
        device_type_yaml={},
        new_filters=False,
    )
    nb.dcim.device_bay_templates.filter.assert_called_once_with(devicetype_id=99)


def test_count_dependent_devices_uses_new_filter_key():
    """When new_filters=True, dcim.devices must be queried with device_type_id= not devicetype_id=."""
    nb = _make_netbox(devices=[], device_count=0)
    classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=77,
        device_type_yaml={},
        new_filters=True,
    )
    nb.dcim.devices.filter.assert_called_once_with(device_type_id=77, limit=5)


def test_count_dependent_devices_uses_legacy_filter_key():
    """When new_filters=False (default), dcim.devices must be queried with devicetype_id=."""
    nb = _make_netbox(devices=[], device_count=0)
    classify_device_type_update_failure(
        SUBDEVICE_ROLE_ERROR_DICT,
        netbox=nb,
        device_type_id=77,
        device_type_yaml={},
        new_filters=False,
    )
    nb.dcim.devices.filter.assert_called_once_with(devicetype_id=77, limit=5)
