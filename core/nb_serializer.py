"""Serialize NetBox API records to DTL-compatible YAML dicts (export-diff feature).

Direction: NetBox record → Python dict suitable for ``yaml.dump()`` and
comparison against existing repo YAML files.
"""

from typing import Any, Sequence

from core.component_registry import BY_ENDPOINT, COMPONENT_TYPES, MODULE_TYPE_RELATIONS

# Row order sets the component key order of the serialized YAML.
COMPONENT_ENDPOINT_NAMES = [component.endpoint for component in COMPONENT_TYPES]

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


def _serialize_component(record: Any, fields: Sequence[str]) -> dict:
    """Serialize a single component template record to a YAML-ready dict."""
    result = {}
    for field in fields:
        val = getattr(record, field, None)
        val = _coerce_numeric(val)
        if _should_include(field, val):
            result[field] = val
    return result


def _serialize_relations(record: Any, relations: Sequence[str]) -> dict:
    """Return the catalog name of each related object, which is how YAML names them.

    The names come off the record the query returned, not from the import-side catalog:
    an export run resolves nothing, so it has no id-to-name mapping of its own.

    An empty relation writes no key.  Emitting an empty list instead would add the key to
    every bay in the library and make _repo_supersedes report every existing definition as
    differing, and it tells a fresh import nothing that omitting it does not.
    """
    result = {}
    for relation in relations:
        names = sorted(
            name for name in (getattr(item, "name", None) for item in getattr(record, relation, None) or []) if name
        )
        if names:
            result[relation] = names
    return result


def _serialize_front_port(record: Any) -> dict:
    """Serialize a front port template's own fields.

    The rear-port linkage is no longer written here: NetBox 4.5 moved it to a through
    table and the library schema follows, carrying it in a top-level ``port-mappings``
    stanza built by :func:`_port_mappings`.
    """
    result = _serialize_component(record, BY_ENDPOINT["front_port_templates"].fields)
    # positions is schema-required but arrived in 4.5, so a pre-4.5 record has none.
    result.setdefault("positions", 1)
    return result


def _port_mappings(records: list) -> list:
    """Return the ``port-mappings`` stanza for a type's front port templates.

    Every mapping is written, not just the first: one front port may occupy several
    positions across rear ports, which is what the through table exists to express.

    A server below 4.5 has no through table and answers with ``rear_port`` and
    ``rear_port_position`` scalars instead.  Those describe one mapping, so they are
    written as one entry rather than dropped.
    """
    stanza = []
    for record in sorted(records, key=lambda r: str(getattr(r, "name", "") or "")):
        name = getattr(record, "name", None)
        for mapping in getattr(record, "mappings", None) or []:
            rear_port = getattr(mapping, "rear_port", None)
            if not rear_port:
                continue
            stanza.append(
                {
                    "front_port": name,
                    "front_port_position": _coerce_numeric(getattr(mapping, "front_port_position", None)) or 1,
                    "rear_port": rear_port.name,
                    "rear_port_position": _coerce_numeric(getattr(mapping, "rear_port_position", None)) or 1,
                }
            )
        if getattr(record, "mappings", None):
            continue
        legacy = getattr(record, "rear_port", None)
        if legacy:
            stanza.append(
                {
                    "front_port": name,
                    "front_port_position": 1,
                    "rear_port": legacy.name,
                    "rear_port_position": _coerce_numeric(getattr(record, "rear_port_position", None)) or 1,
                }
            )
    return stanza


def module_bays_missing_position(serialized: dict) -> list:
    """Return the names of module bays the library schema would reject.

    NetBox leaves ``position`` blank on a bay that names no physical slot, and a blank
    string writes no key, but the schema requires one on every module bay.
    """
    return [bay.get("name", "?") for bay in serialized.get("module-bays", []) if "position" not in bay]


def _serialize_component_list(endpoint_name: str, records: list) -> list:
    """Serialize a list of component template records for a given endpoint."""
    component = BY_ENDPOINT[endpoint_name]
    out = []
    for record in sorted(records, key=lambda r: str(getattr(r, "name", "") or "")):
        if endpoint_name == "front_port_templates":
            serialized = _serialize_front_port(record)
        else:
            serialized = _serialize_component(record, component.fields)
        serialized.update(_serialize_relations(record, component.relations))
        out.append(serialized)
    return out


def _add_components(result: dict, type_id: int, components_by_id: dict) -> None:
    """Append serialized component lists to *result* for a given type id."""
    type_components = components_by_id.get(type_id, {})
    for component in COMPONENT_TYPES:
        records = type_components.get(component.endpoint, [])
        if records:
            result[component.yaml_key] = _serialize_component_list(component.endpoint, records)
    mappings = _port_mappings(type_components.get("front_port_templates", []))
    if mappings:
        result["port-mappings"] = mappings


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

    result.update(_serialize_relations(nb_record, MODULE_TYPE_RELATIONS))
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
