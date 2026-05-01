"""NetBox version-compatibility helpers.

Centralises filter parameter names that changed between NetBox releases so
that every caller uses the same logic and drift is impossible.

NetBox 4.1 renamed several filter keys on the DCIM endpoints:

    devicetype_id  →  device_type_id
    moduletype_id  →  module_type_id

Any code that constructs endpoint filter kwargs should call the helpers
here rather than inlining ``"device_type_id" if new_filters else "devicetype_id"``.
"""

from __future__ import annotations


def device_type_filter_key(new_filters: bool) -> str:
    """Return the correct filter parameter name for device-type component queries.

    Args:
        new_filters: ``True`` for NetBox ≥ 4.1 (returns ``"device_type_id"``);
            ``False`` for older releases (returns ``"devicetype_id"``).
    """
    return "device_type_id" if new_filters else "devicetype_id"


def module_type_filter_key(new_filters: bool) -> str:
    """Return the correct filter parameter name for module-type component queries.

    Args:
        new_filters: ``True`` for NetBox ≥ 4.1 (returns ``"module_type_id"``);
            ``False`` for older releases (returns ``"moduletype_id"``).
    """
    return "module_type_id" if new_filters else "moduletype_id"


def device_type_filter_kwargs(device_type_id: int, *, new_filters: bool) -> dict:
    """Return filter kwargs for querying components of a device type.

    Args:
        device_type_id: NetBox ID of the device type.
        new_filters: ``True`` for NetBox ≥ 4.1; ``False`` for older releases.

    Returns:
        A dict suitable for unpacking into ``endpoint.filter(**kwargs)``.
    """
    return {device_type_filter_key(new_filters): device_type_id}


def module_type_filter_kwargs(module_type_id: int, *, new_filters: bool) -> dict:
    """Return filter kwargs for querying components of a module type.

    Args:
        module_type_id: NetBox ID of the module type.
        new_filters: ``True`` for NetBox ≥ 4.1; ``False`` for older releases.

    Returns:
        A dict suitable for unpacking into ``endpoint.filter(**kwargs)``.
    """
    return {module_type_filter_key(new_filters): module_type_id}
