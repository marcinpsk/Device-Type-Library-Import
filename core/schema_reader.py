"""Utilities for loading comparable property names from devicetype-library JSON schemas.

Reads the JSON schemas bundled in the cloned devicetype-library repository and
extracts scalar (non-array, non-object) property names that can be used for
change detection comparison.
"""

import json
import os


def load_scalar_properties(schema_path, exclude=None):
    """Read a JSON schema file and return names of comparable scalar properties.

    A property is considered *scalar* (and therefore comparable) when it is
    **not** one of:

    * An array (``"type": "array"``)
    * A nested object (``"type": "object"``)
    * Explicitly listed in *exclude*

    Properties with a ``$ref`` or a plain scalar type (``string``, ``integer``,
    ``number``, ``boolean``) are included.

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

    if "properties" not in schema:
        raise ValueError(f"Schema {schema_path} has no 'properties' key")
    if not isinstance(schema["properties"], dict):
        raise ValueError(f"Schema {schema_path} has non-object 'properties'")

    result = []
    for name, defn in schema["properties"].items():
        if name in exclude:
            continue
        prop_type = defn.get("type") if isinstance(defn, dict) else None
        if prop_type in ("array", "object"):
            continue
        result.append(name)

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
