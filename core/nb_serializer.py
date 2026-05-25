"""Serialize NetBox API records to DTL-compatible YAML dicts (export-diff feature).

Direction: NetBox record → Python dict suitable for ``yaml.dump()`` and
comparison against existing repo YAML files.
"""

import warnings
from typing import Any

# Maps YAML component key → NetBox endpoint name.
# Order defines the output key order in the serialized YAML.
COMPONENT_ENDPOINTS = [
    ("interfaces", "interface_templates"),
    ("power-ports", "power_port_templates"),
    ("console-ports", "console_port_templates"),
    ("power-outlets", "power_outlet_templates"),
    ("console-server-ports", "console_server_port_templates"),
    ("rear-ports", "rear_port_templates"),
    ("front-ports", "front_port_templates"),
    ("device-bays", "device_bay_templates"),
    ("module-bays", "module_bay_templates"),
]

# The DTL endpoint names (for use with get_component_templates())
COMPONENT_ENDPOINT_NAMES = [ep_name for _, ep_name in COMPONENT_ENDPOINTS]

# Field lists per component type (same fields as graphql_client.COMPONENT_TEMPLATE_FIELDS,
# minus "id" and parent fields).
_IFACE_FIELDS = ["name", "type", "label", "description", "mgmt_only", "enabled", "poe_mode", "poe_type", "rf_role"]
_POWER_PORT_FIELDS = ["name", "type", "label", "description", "maximum_draw", "allocated_draw"]
_CONSOLE_FIELDS = ["name", "type", "label", "description"]
_POWER_OUTLET_FIELDS = ["name", "type", "label", "description", "feed_leg"]
_REAR_PORT_FIELDS = ["name", "type", "label", "description", "positions", "color"]
_FRONT_PORT_FIELDS = ["name", "type", "label", "description", "color"]  # rear_port handled separately
_DEVICE_BAY_FIELDS = ["name", "label", "description"]
_MODULE_BAY_FIELDS = ["name", "position", "label", "description"]

_COMPONENT_FIELDS = {
    "interface_templates": _IFACE_FIELDS,
    "power_port_templates": _POWER_PORT_FIELDS,
    "console_port_templates": _CONSOLE_FIELDS,
    "console_server_port_templates": _CONSOLE_FIELDS,
    "power_outlet_templates": _POWER_OUTLET_FIELDS,
    "rear_port_templates": _REAR_PORT_FIELDS,
    "front_port_templates": _FRONT_PORT_FIELDS,
    "device_bay_templates": _DEVICE_BAY_FIELDS,
    "module_bay_templates": _MODULE_BAY_FIELDS,
}

# Values that are defaults — omit from output to keep YAML clean.
_OMIT_IF_EQUAL = {
    "label": "",
    "description": "",
    "comments": "",
    "mgmt_only": False,
    "enabled": True,  # True is the interface default; include only when False
    "color": "",
    "poe_mode": None,
    "poe_type": None,
    "rf_role": None,
    "feed_leg": None,
    "maximum_draw": None,
    "allocated_draw": None,
    "positions": 1,  # rear port default; include only when > 1
}

# Device type scalar field order for output.
_DT_SCALAR_FIELDS = [
    "manufacturer",
    "model",
    "slug",
    "part_number",
    "u_height",
    "is_full_depth",
    "airflow",
    "weight",
    "weight_unit",
    "description",
    "comments",
]

# Module type scalar field order for output.
_MT_SCALAR_FIELDS = [
    "manufacturer",
    "model",
    "part_number",
    "airflow",
    "weight",
    "weight_unit",
    "description",
    "comments",
]

# Rack type scalar field order for output.
_RT_SCALAR_FIELDS = [
    "manufacturer",
    "model",
    "slug",
    "form_factor",
    "description",
    "width",
    "u_height",
    "starting_unit",
    "outer_width",
    "outer_height",
    "outer_depth",
    "outer_unit",
    "mounting_depth",
    "weight",
    "max_weight",
    "weight_unit",
    "desc_units",
    "comments",
]


def _coerce_numeric(val: Any) -> Any:
    """Coerce float-with-integer-value or numeric string to a Python numeric type.

    - ``1.0``     → ``1``    (float integer → int)
    - ``'12.0'``  → ``12``   (string integer → int)
    - ``'13.60'`` → ``13.6`` (string float → float, trailing zeros dropped)
    """
    if isinstance(val, float) and not isinstance(val, bool) and val.is_integer():
        return int(val)
    # Only coerce strings that look like decimals (contain '.') — NetBox
    # DecimalField values come back as e.g. '13.60' or '1.0'. Plain integer
    # strings like '1' are preserved (they may belong to CharField columns
    # such as ``position`` where DTL convention keeps them quoted).
    if isinstance(val, str) and "." in val:
        try:
            f = float(val)
            if f.is_integer():
                return int(f)
            return f
        except (ValueError, TypeError):
            pass
    return val


def _should_include(field: str, val: Any) -> bool:
    """Return True when *val* should be written to the YAML output."""
    if val is None:
        return False
    if isinstance(val, str) and val == "":
        return False
    if field in _OMIT_IF_EQUAL and val == _OMIT_IF_EQUAL[field]:
        return False
    return True


def _serialize_component(record: Any, fields: list) -> dict:
    """Serialize a single component template record to a YAML-ready dict."""
    result = {}
    for field in fields:
        val = getattr(record, field, None)
        val = _coerce_numeric(val)
        if _should_include(field, val):
            result[field] = val
    return result


def _serialize_front_port(record: Any) -> dict:
    """Serialize a front port template, including rear_port mapping."""
    result = _serialize_component(record, _FRONT_PORT_FIELDS)
    mappings = getattr(record, "mappings", None) or []
    if mappings:
        if len(mappings) > 1:
            port_name = getattr(record, "name", "<unknown>")
            warnings.warn(
                f"Front port '{port_name}' has {len(mappings)} mappings; "
                "only the first will be exported. "
                "Full multi-mapping support requires DTL schema update (see issue #78).",
                UserWarning,
                stacklevel=4,
            )
        m = mappings[0]
        rear_port = getattr(m, "rear_port", None)
        if rear_port:
            result["rear_port"] = rear_port.name
        rear_pos = getattr(m, "rear_port_position", None)
        rear_pos = _coerce_numeric(rear_pos)
        if rear_pos is not None and rear_pos > 1:
            result["rear_port_position"] = rear_pos
    else:
        # Legacy: pre-4.5 NetBox returns rear_port / rear_port_position as direct scalar fields
        legacy_rp = getattr(record, "rear_port", None)
        if legacy_rp:
            result["rear_port"] = legacy_rp.name
        legacy_pos = getattr(record, "rear_port_position", None)
        legacy_pos = _coerce_numeric(legacy_pos)
        if legacy_pos is not None and legacy_pos > 1:
            result["rear_port_position"] = legacy_pos
    return result


def _serialize_component_list(endpoint_name: str, records: list) -> list:
    """Serialize a list of component template records for a given endpoint."""
    out = []
    for record in sorted(records, key=lambda r: str(getattr(r, "name", "") or "")):
        if endpoint_name == "front_port_templates":
            out.append(_serialize_front_port(record))
        else:
            out.append(_serialize_component(record, _COMPONENT_FIELDS[endpoint_name]))
    return out


def _add_components(result: dict, type_id: int, components_by_id: dict) -> None:
    """Append serialized component lists to *result* for a given type id."""
    type_components = components_by_id.get(type_id, {})
    for yaml_key, endpoint_name in COMPONENT_ENDPOINTS:
        records = type_components.get(endpoint_name, [])
        if records:
            result[yaml_key] = _serialize_component_list(endpoint_name, records)


def serialize_device_type(nb_record: Any, components_by_dt_id: dict) -> dict:
    """Convert a NetBox device type record to a DTL-compatible YAML dict.

    Args:
        nb_record: DotDict returned by ``NetBoxGraphQLClient.get_device_types()``.
        components_by_dt_id: ``{device_type_id: {endpoint_name: [records]}}``.

    Returns:
        Ordered dict suitable for ``yaml.dump()``.
    """
    result = {}
    for field in _DT_SCALAR_FIELDS:
        if field == "manufacturer":
            mfr = getattr(nb_record, "manufacturer", None)
            if mfr is not None:
                result["manufacturer"] = mfr.name
            continue
        val = getattr(nb_record, field, None)
        val = _coerce_numeric(val)
        if field in ("u_height", "is_full_depth"):
            # Always include — commonly explicit in DTL files
            if val is not None:
                result[field] = val
        elif _should_include(field, val):
            result[field] = val

    if getattr(nb_record, "front_image", None):
        result["front_image"] = True
    if getattr(nb_record, "rear_image", None):
        result["rear_image"] = True

    _add_components(result, nb_record.id, components_by_dt_id)
    return result


def serialize_module_type(nb_record: Any, components_by_mt_id: dict) -> dict:
    """Convert a NetBox module type record to a DTL-compatible YAML dict.

    Args:
        nb_record: DotDict returned by ``NetBoxGraphQLClient.get_module_types()``.
        components_by_mt_id: ``{module_type_id: {endpoint_name: [records]}}``.

    Returns:
        Ordered dict suitable for ``yaml.dump()``.
    """
    result = {}
    for field in _MT_SCALAR_FIELDS:
        if field == "manufacturer":
            mfr = getattr(nb_record, "manufacturer", None)
            if mfr is not None:
                result["manufacturer"] = mfr.name
            continue
        val = getattr(nb_record, field, None)
        val = _coerce_numeric(val)
        if _should_include(field, val):
            result[field] = val

    _add_components(result, nb_record.id, components_by_mt_id)
    return result


def serialize_rack_type(nb_record: Any) -> dict:
    """Convert a NetBox rack type record to a DTL-compatible YAML dict.

    Rack types have no component templates.
    """
    result = {}
    for field in _RT_SCALAR_FIELDS:
        if field == "manufacturer":
            mfr = getattr(nb_record, "manufacturer", None)
            if mfr is not None:
                result["manufacturer"] = mfr.name
            continue
        val = getattr(nb_record, field, None)
        val = _coerce_numeric(val)
        # desc_units is bool — include regardless of value (explicit design choice)
        if field == "desc_units":
            if val is not None:
                result[field] = val
        elif _should_include(field, val):
            result[field] = val
    return result
