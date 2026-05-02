"""Utilities for loading comparable property names from devicetype-library JSON schemas.

Reads the JSON schemas bundled in the cloned devicetype-library repository and
extracts scalar (non-array, non-object) property names that can be used for
change detection comparison.
"""

import json
import os

# All JSON Schema primitive types that are safe to compare and PATCH as scalars.
_SCALAR_TYPES = frozenset({"string", "integer", "number", "boolean", "null"})


def load_scalar_properties(schema_path, exclude=None):
    """Read a JSON schema file and return names of comparable scalar properties.

    A property is considered *scalar* (and therefore comparable) when it is
    **explicitly** one of:

    * A ``$ref`` (references are assumed to resolve to a scalar choice/enum)
    * A plain scalar type: ``string``, ``integer``, ``number``, ``boolean``, or
      ``null``
    * A ``type`` union (list) whose every member is one of the scalar types above

    Everything else — arrays, objects, ``anyOf``/``oneOf``/``allOf``, or entries
    with no recognisable type — is excluded.  This explicit allowlist prevents
    bogus PATCH attempts for properties whose schema representation is more
    complex than a single scalar value.

    Args:
        schema_path (str): Absolute path to the JSON schema file.
        exclude (set | None): Property names to exclude from the result.

    Returns:
        list[str]: Property names in schema definition order.

    Raises:
        FileNotFoundError: If *schema_path* does not exist.
        ValueError: If the file is not valid JSON or lacks a ``properties`` key.
    """
    exclude = set(exclude or [])

    try:
        with open(schema_path) as f:
            schema = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {schema_path}: {exc}") from exc

    if not isinstance(schema, dict):
        raise ValueError(f"Schema {schema_path} root is not a JSON object")
    if "properties" not in schema:
        raise ValueError(f"Schema {schema_path} has no 'properties' key")
    if not isinstance(schema["properties"], dict):
        raise ValueError(f"Schema {schema_path} has non-object 'properties'")

    result = []
    for name, defn in schema["properties"].items():
        if name in exclude:
            continue
        if not isinstance(defn, dict):
            # Malformed property entry; skip silently rather than raising.
            continue
        # $ref entries (enum choices, foreign-key slugs, etc.) are scalar by
        # convention in the NetBox device-type library schemas.
        if "$ref" in defn:
            result.append(name)
            continue
        prop_type = defn.get("type")
        if isinstance(prop_type, list):
            # JSON Schema allows "type": ["string", "null"] union types.
            if set(prop_type) <= _SCALAR_TYPES:
                result.append(name)
        elif prop_type in _SCALAR_TYPES:
            result.append(name)
        # All other entries (anyOf, oneOf, allOf, missing type, object, array)
        # are intentionally excluded.

    return result


def load_properties_for_type(schema_dir, type_name, exclude=None):
    """Load scalar properties for a named schema type from the schema directory.

    Falls back to an empty list if the schema file is missing or unreadable,
    so callers can safely fall back to their own hardcoded lists.

    Args:
        schema_dir (str): Directory containing the schema JSON files (e.g.
            ``/path/to/repo/schema``).
        type_name (str): Schema file basename without extension, e.g.
            ``"moduletype"``, ``"devicetype"``, ``"racktype"``.
        exclude (set | None): Property names to exclude (forwarded to
            :func:`load_scalar_properties`).

    Returns:
        list[str]: Scalar property names, or ``[]`` if the schema is unavailable.
    """
    schema_path = os.path.join(schema_dir, f"{type_name}.json")
    try:
        return load_scalar_properties(schema_path, exclude=exclude)
    except (OSError, ValueError):
        return []
