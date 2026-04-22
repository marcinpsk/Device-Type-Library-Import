"""Shared value-normalization helpers for YAML-vs-NetBox comparisons."""


def normalize_values(yaml_val, nb_val):
    """Normalize a YAML/NetBox value pair for comparison.

    Handles the common type mismatches that arise between YAML-parsed values
    and values returned by pynetbox / GraphQL:

    - pynetbox choice fields: reads ``.value`` from Record objects
    - empty string normalised to None on both sides
    - trailing whitespace stripped from strings (YAML literal-block scalars
      append a trailing newline; some editors add trailing spaces)
    - numeric-string coercion in both directions; int preserved when the
      non-string side is int (avoids ``166 vs 166.0`` display noise)
    - bool guard: ``bool`` is a subclass of ``int`` but boolean fields
      (``is_full_depth``, ``mgmt_only``, …) must never be coerced to numeric

    Returns:
        Tuple ``(normalized_yaml, normalized_nb)``
    """
    # pynetbox choice objects (e.g. weight_unit, face) expose the raw value
    # via a .value attribute; unwrap so comparison works against YAML strings.
    if hasattr(nb_val, "value"):
        nb_val = nb_val.value

    # Strip trailing whitespace first (YAML literal blocks add \n; editors add spaces),
    # then normalize empty/whitespace-only strings to None.
    if isinstance(yaml_val, str):
        yaml_val = yaml_val.rstrip()
    if isinstance(nb_val, str):
        nb_val = nb_val.rstrip()
    if yaml_val == "":
        yaml_val = None
    if nb_val == "":
        nb_val = None

    # Coerce numeric strings.  GraphQL / pynetbox serialise some numeric fields
    # as strings (e.g. "166.00" for int 166, "26.10" for float 26.1).  We
    # coerce the string side to match the numeric side so the comparison is
    # type-safe.  The bool guard prevents True/False being treated as 1/0.
    if isinstance(yaml_val, (int, float)) and not isinstance(yaml_val, bool) and isinstance(nb_val, str):
        try:
            tmp = float(nb_val)
            # Preserve int when yaml is int (avoids 166 vs 166.0 noise)
            nb_val = int(tmp) if isinstance(yaml_val, int) and tmp.is_integer() else tmp
        except (ValueError, TypeError):
            pass
    elif isinstance(nb_val, (int, float)) and not isinstance(nb_val, bool) and isinstance(yaml_val, str):
        try:
            tmp = float(yaml_val)
            # Preserve int when nb is int
            yaml_val = int(tmp) if isinstance(nb_val, int) and tmp.is_integer() else tmp
        except (ValueError, TypeError):
            pass

    return yaml_val, nb_val


def values_equal(yaml_val, nb_val) -> bool:
    """Return True if *yaml_val* and *nb_val* are equal after normalization."""
    y, n = normalize_values(yaml_val, nb_val)
    return y == n
