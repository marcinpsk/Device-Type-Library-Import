"""Shared output-formatting helpers."""


def _display(val):
    """Normalise a value for diff display.

    Empty / whitespace-only strings are shown as ``None`` — the same
    canonical "not set" representation used by the comparison layer — so
    that a NetBox field returning ``""`` and one returning ``None`` look
    identical in the diff output.
    """
    if isinstance(val, str):
        val = val.rstrip() or None
    return str(val)


def log_property_diffs(triples, log_fn, indent="      "):
    """Emit diff-u style lines for a set of property changes.

    Args:
        triples: Iterable of ``(property_name, old_value, new_value)``.
        log_fn: Callable that accepts a single string; used to emit each line.
        indent (str): Prefix prepended to every emitted line (default: 6 spaces).
    """
    triples = list(triples)
    if not triples:
        return
    pad = min(max(len(name) for name, _, _ in triples), 30)
    for name, old_val, new_val in triples:
        padded = f"{name}:{'':{max(0, pad - len(name))}}"
        blank = " " * len(padded)
        for i, line in enumerate(_display(old_val).splitlines() or [""]):
            log_fn(f"{indent}- {padded if i == 0 else blank} {line}")
        for i, line in enumerate(_display(new_val).splitlines() or [""]):
            log_fn(f"{indent}+ {padded if i == 0 else blank} {line}")
