"""Change detection module for comparing YAML device types against NetBox data.

Provides functionality to detect differences between device type definitions
in the repository and existing data in NetBox, supporting the --update workflow.
"""

import os
from dataclasses import dataclass, field
from typing import Any, List, Optional
from enum import Enum

from core.normalization import normalize_values
from core.formatting import log_property_diffs
from core.schema_reader import load_properties_for_type


class ChangeType(Enum):
    """Types of changes that can be detected."""

    NEW = "new"
    PROPERTY_CHANGED = "property_changed"
    COMPONENT_ADDED = "component_added"
    COMPONENT_CHANGED = "component_changed"
    COMPONENT_REMOVED = "component_removed"


@dataclass
class PropertyChange:
    """Represents a single property change."""

    property_name: str
    old_value: Any
    new_value: Any


@dataclass
class ComponentChange:
    """Represents a component-level change."""

    component_type: str  # e.g., "interfaces", "power-ports"
    component_name: str
    change_type: ChangeType
    property_changes: List[PropertyChange] = field(default_factory=list)


@dataclass
class DeviceTypeChange:
    """Represents all changes for a single device type."""

    manufacturer_slug: str
    model: str
    slug: str
    is_new: bool = False
    property_changes: List[PropertyChange] = field(default_factory=list)
    component_changes: List[ComponentChange] = field(default_factory=list)
    netbox_id: Optional[int] = None

    @property
    def has_changes(self) -> bool:
        """Return True if this device type is new or has any property or component changes."""
        return self.is_new or bool(self.property_changes) or bool(self.component_changes)

    @property
    def has_updates(self) -> bool:
        """Returns True if there are property or component changes (not just new)."""
        return bool(self.property_changes) or bool(self.component_changes)


@dataclass
class ChangeReport:
    """Aggregated change report for all device types."""

    new_device_types: List[DeviceTypeChange] = field(default_factory=list)
    modified_device_types: List[DeviceTypeChange] = field(default_factory=list)
    unchanged_count: int = 0


# Device type properties that can be compared and updated.
# Loaded from the cloned devicetype-library schema at runtime; the list below
# serves as a fallback when the schema is not yet available.  Identity fields
# (manufacturer, model, slug) and image fields (front_image, rear_image) are
# excluded by the schema reader — images are handled separately via IMAGE_PROPERTIES.
_DEVICE_TYPE_PROPERTIES_FALLBACK = [
    "u_height",
    "part_number",
    "is_full_depth",
    "subdevice_role",
    "airflow",
    "weight",
    "weight_unit",
    "description",
    "comments",
]

_DEVICE_TYPE_SCHEMA_EXCLUDE = {"manufacturer", "model", "slug", "front_image", "rear_image"}


def _load_device_type_properties():
    """Load device type scalar properties from the schema, falling back to hardcoded list."""
    try:
        from core import settings as _settings

        props = load_properties_for_type(
            os.path.join(_settings.REPO_PATH, "schema"),
            "devicetype",
            exclude=_DEVICE_TYPE_SCHEMA_EXCLUDE,
        )
        return props if props else list(_DEVICE_TYPE_PROPERTIES_FALLBACK)
    except (ImportError, AttributeError):
        return list(_DEVICE_TYPE_PROPERTIES_FALLBACK)


_CACHED_DEVICE_TYPE_PROPERTIES = None


def get_device_type_properties():
    """Lazily resolve and cache the device-type schema properties.

    Resolved at first call rather than at import time so the schema lookup
    sees a populated repo even when ``change_detector`` is imported before
    the repo is cloned (e.g., test bootstrap, fresh CI environments).
    """
    global _CACHED_DEVICE_TYPE_PROPERTIES
    if _CACHED_DEVICE_TYPE_PROPERTIES is None:
        _CACHED_DEVICE_TYPE_PROPERTIES = _load_device_type_properties()
    return _CACHED_DEVICE_TYPE_PROPERTIES


# Backwards-compatible eager constant.  Prefer ``get_device_type_properties()``
# in code paths that may run before the repo schema is available.
DEVICE_TYPE_PROPERTIES = _load_device_type_properties()

# Sentinel used to distinguish "attribute missing from record" from a genuine
# None/null value returned by NetBox.  When a property is in the schema-derived
# comparison list but was not fetched by the GraphQL query, getattr returns this
# sentinel and the property is skipped to avoid false-positive change detection.
_MISSING = object()

# Image properties: YAML uses boolean flags, NetBox stores URL strings.
# Only existence is compared (YAML=true vs NetBox=empty).
IMAGE_PROPERTIES = ["front_image", "rear_image"]

# Component type mapping: YAML key -> (cache_key, comparable_properties)
COMPONENT_TYPES = {
    "interfaces": (
        "interface_templates",
        ["name", "type", "mgmt_only", "label", "enabled", "poe_mode", "poe_type", "description", "rf_role"],
    ),
    "power-ports": (
        "power_port_templates",
        ["name", "type", "maximum_draw", "allocated_draw", "label", "description"],
    ),
    "console-ports": ("console_port_templates", ["name", "type", "label", "description"]),
    "power-outlets": ("power_outlet_templates", ["name", "type", "feed_leg", "label", "description"]),
    "console-server-ports": (
        "console_server_port_templates",
        ["name", "type", "label", "description"],
    ),
    "rear-ports": ("rear_port_templates", ["name", "type", "positions", "label", "description", "color"]),
    "front-ports": ("front_port_templates", ["name", "type", "_mappings", "label", "description", "color"]),
    "device-bays": ("device_bay_templates", ["name", "label", "description"]),
    "module-bays": ("module_bay_templates", ["name", "position", "label", "description"]),
}


class ChangeDetector:
    """Detects changes between YAML device types and NetBox cached data."""

    def __init__(self, device_types_instance, handle):
        """Initialize the change detector.

        Args:
            device_types_instance: DeviceTypes instance with cached data
            handle: LogHandler for logging
        """
        self.device_types = device_types_instance
        self.handle = handle

    def detect_changes(self, device_types: List[dict], progress=None) -> ChangeReport:
        """Analyze all device types and generate a change report.

        Args:
            device_types: List of parsed YAML device type dictionaries
            progress: Optional iterable wrapper (e.g. rich.progress) for progress display

        Returns:
            ChangeReport with categorized changes
        """
        report = ChangeReport()
        iterable = progress if progress is not None else device_types
        existing_by_model = self.device_types.existing_device_types
        existing_by_slug = self.device_types.existing_device_types_by_slug

        for dt_data in iterable:
            manufacturer_slug = dt_data["manufacturer"]["slug"]
            model = dt_data["model"]
            slug = dt_data.get("slug", "")

            # Try to find existing device type
            existing_dt = existing_by_model.get((manufacturer_slug, model))

            # Fallback to slug lookup
            if existing_dt is None and slug:
                existing_dt = existing_by_slug.get((manufacturer_slug, slug))

            change = DeviceTypeChange(
                manufacturer_slug=manufacturer_slug,
                model=model,
                slug=slug,
            )

            if existing_dt is None:
                # New device type
                change.is_new = True
                report.new_device_types.append(change)
            else:
                # Existing - check for changes
                change.netbox_id = existing_dt.id
                change.property_changes = self._compare_device_type_properties(dt_data, existing_dt)
                change.property_changes.extend(self._compare_image_properties(dt_data, existing_dt))
                change.component_changes = self._compare_components(dt_data, existing_dt.id)

                if change.has_changes:
                    report.modified_device_types.append(change)
                else:
                    report.unchanged_count += 1

        return report

    def _compare_device_type_properties(self, yaml_data: dict, netbox_dt) -> List[PropertyChange]:
        """Compare YAML device type properties against NetBox device type.

        Args:
            yaml_data: Parsed YAML device type dictionary
            netbox_dt: pynetbox Record object for existing device type

        Returns:
            List of PropertyChange objects for any differences found
        """
        changes = []

        for prop in get_device_type_properties():
            # Only compare properties explicitly present in YAML;
            # an omitted property means the YAML doesn't manage it,
            # matching the component semantics (absent key != removal).
            if prop not in yaml_data:
                continue
            # Only compare properties that were actually fetched from NetBox.
            # If the GraphQL query doesn't include a field yet, skip it to
            # avoid false-positive change detections.
            netbox_value = getattr(netbox_dt, prop, _MISSING)
            if netbox_value is _MISSING:
                continue

            yaml_value = yaml_data.get(prop)

            yaml_value, netbox_value = normalize_values(yaml_value, netbox_value)

            if yaml_value != netbox_value:
                changes.append(
                    PropertyChange(
                        property_name=prop,
                        old_value=netbox_value,
                        new_value=yaml_value,
                    )
                )

        return changes

    @staticmethod
    def _compare_image_properties(yaml_data: dict, netbox_dt) -> List[PropertyChange]:
        """Compare image properties between YAML and NetBox device type.

        YAML uses boolean flags (front_image: true) meaning "an image should exist",
        while NetBox stores a URL string (or None). This only flags missing images
        (YAML=true, NetBox=empty). Omitted keys and false values are ignored.

        Note: this only detects images missing from NetBox; modifications to local
        files with the same name are not redetected because NetBox stores only the
        URL, not a content hash.

        Args:
            yaml_data: Parsed YAML device type dictionary
            netbox_dt: pynetbox Record object for existing device type

        Returns:
            List of PropertyChange objects for missing images
        """
        changes = []
        for prop in IMAGE_PROPERTIES:
            yaml_value = yaml_data.get(prop)
            if yaml_value is not True:
                continue
            netbox_value = getattr(netbox_dt, prop, None)
            if not netbox_value:
                changes.append(
                    PropertyChange(
                        property_name=prop,
                        old_value=None,
                        new_value=True,
                    )
                )
        return changes

    def _compare_components(
        self,
        yaml_data: dict,
        device_type_id: int,
        parent_type: str = "device",
    ) -> List[ComponentChange]:
        """Compare all components between YAML and cached NetBox data.

        Args:
            yaml_data: Parsed YAML device type dictionary
            device_type_id: ID of the device type in NetBox
            parent_type: "device" or "module"

        Returns:
            List of ComponentChange objects for all differences
        """
        changes = []
        cache_key = (parent_type, device_type_id)

        for yaml_key, (cache_name, properties) in COMPONENT_TYPES.items():
            yaml_components = list(yaml_data.get(yaml_key) or [])

            # Get cached components for this device type
            cached = self.device_types.cached_components.get(cache_name, {})
            existing_components = cached.get(cache_key, {})

            # Build set of YAML component names for this type
            yaml_component_names = {comp.get("name") for comp in yaml_components if comp.get("name")}

            # Check for removed components (exist in NetBox but not in YAML)
            # Only flag removals when the YAML explicitly defines this component type;
            # a missing key means the YAML doesn't manage this type at all.
            if yaml_key in yaml_data:
                for existing_name in existing_components.keys():
                    if existing_name not in yaml_component_names:
                        changes.append(
                            ComponentChange(
                                component_type=yaml_key,
                                component_name=existing_name,
                                change_type=ChangeType.COMPONENT_REMOVED,
                            )
                        )

            # Check each YAML component for additions or modifications
            for yaml_comp in yaml_components:
                comp_name = yaml_comp.get("name")
                if not comp_name:
                    continue

                if comp_name not in existing_components:
                    # Component doesn't exist in NetBox
                    changes.append(
                        ComponentChange(
                            component_type=yaml_key,
                            component_name=comp_name,
                            change_type=ChangeType.COMPONENT_ADDED,
                        )
                    )
                else:
                    # Check for property changes on existing component
                    existing = existing_components[comp_name]
                    prop_changes = self._compare_component_properties(
                        yaml_comp, existing, properties, comp_type=yaml_key
                    )
                    if prop_changes:
                        changes.append(
                            ComponentChange(
                                component_type=yaml_key,
                                component_name=comp_name,
                                change_type=ChangeType.COMPONENT_CHANGED,
                                property_changes=prop_changes,
                            )
                        )

        return changes

    def _compare_component_properties(
        self,
        yaml_comp: dict,
        netbox_comp,
        properties: List[str],
        comp_type: str = "",
    ) -> List[PropertyChange]:
        """Compare properties between YAML and NetBox component."""
        changes = []

        for prop in properties:
            if prop == "name":
                # Name is the key, skip comparison
                continue

            if prop == "_mappings" and comp_type == "front-ports":
                # Only compare when YAML explicitly declares _mappings (absent key = not managed).
                if "_mappings" not in yaml_comp:
                    continue
                # Full port-mapping comparison: compare sets of (rear_port, fp_pos, rp_pos)
                # so that any change to rear port name, front_port_position, or
                # rear_port_position is detected.
                yaml_mappings = yaml_comp.get("_mappings") or []
                yaml_set = frozenset(
                    (
                        m.get("rear_port", ""),
                        m.get("front_port_position", 1),
                        m.get("rear_port_position", 1),
                    )
                    for m in yaml_mappings
                )
                canonical = getattr(netbox_comp, "_mappings_canonical", None)
                if canonical is None:
                    # GraphQL response lacked both mappings and rear_port_position;
                    # treat as unmanaged to avoid a false COMPONENT_CHANGED.
                    continue
                has_names = any(m.get("rear_port_name") is not None for m in canonical)
                if has_names:
                    # NetBox >= 4.5: compare with rear port names
                    netbox_set = frozenset(
                        (
                            m.get("rear_port_name", ""),
                            m.get("front_port_position", 1),
                            m.get("rear_port_position", 1),
                        )
                        for m in canonical
                    )
                else:
                    # NetBox < 4.5: rear port names unavailable; compare positions only
                    yaml_set = frozenset(
                        (
                            m.get("front_port_position", 1),
                            m.get("rear_port_position", 1),
                        )
                        for m in yaml_mappings
                    )
                    netbox_set = frozenset(
                        (
                            m.get("front_port_position", 1),
                            m.get("rear_port_position", 1),
                        )
                        for m in canonical
                    )
                if yaml_set != netbox_set:
                    changes.append(
                        PropertyChange(
                            property_name="_mappings",
                            old_value=netbox_set,
                            new_value=yaml_set,
                        )
                    )
                continue

            # Only compare properties explicitly present in the YAML component;
            # an omitted property means the YAML doesn't manage it (absent key != removal).
            if prop not in yaml_comp:
                continue

            yaml_value = yaml_comp.get(prop)
            netbox_value = getattr(netbox_comp, prop, _MISSING)
            if netbox_value is _MISSING:
                # NetBox version / GraphQL selection didn't return this field;
                # treat it as unmanaged to avoid a false COMPONENT_CHANGED that
                # would PATCH an unsupported attribute.
                continue

            yaml_value, netbox_value = normalize_values(yaml_value, netbox_value)

            if yaml_value != netbox_value:
                changes.append(
                    PropertyChange(
                        property_name=prop,
                        old_value=netbox_value,
                        new_value=yaml_value,
                    )
                )

        return changes

    def _log_modified_summary(self, report: ChangeReport) -> None:
        """Compute category counts and log the summary section for modified device types.

        Args:
            report: The ChangeReport containing modified_device_types to summarise.
        """
        ct_props = 0
        ct_images = 0
        ct_added = 0
        ct_changed = 0
        ct_removed = 0
        for dt in report.modified_device_types:
            if any(pc.property_name not in IMAGE_PROPERTIES for pc in dt.property_changes):
                ct_props += 1
            if any(pc.property_name in IMAGE_PROPERTIES for pc in dt.property_changes):
                ct_images += 1
            if any(c.change_type == ChangeType.COMPONENT_ADDED for c in dt.component_changes):
                ct_added += 1
            if any(c.change_type == ChangeType.COMPONENT_CHANGED for c in dt.component_changes):
                ct_changed += 1
            if any(c.change_type == ChangeType.COMPONENT_REMOVED for c in dt.component_changes):
                ct_removed += 1

        self.handle.log(f"Modified device types: {len(report.modified_device_types)}")
        parts = []
        if ct_props:
            parts.append(f"{ct_props} property")
        if ct_images:
            parts.append(f"{ct_images} missing image")
        if ct_added:
            parts.append(f"{ct_added} new component")
        if ct_changed:
            parts.append(f"{ct_changed} changed component")
        if ct_removed:
            parts.append(f"{ct_removed} removed component")
        if parts:
            self.handle.log(f"  Breakdown: {', '.join(parts)}")

    def _log_property_diffs(self, prop_changes: List[PropertyChange], indent: str) -> None:
        """Emit diff-u style lines for *prop_changes* at the given *indent*."""
        log_property_diffs(
            [(pc.property_name, pc.old_value, pc.new_value) for pc in prop_changes],
            self.handle.verbose_log,
            indent,
        )

    def _log_modified_device_details(self, dt: DeviceTypeChange):
        """Log the per-device detail section for a single modified device type.

        Args:
            dt: The DeviceTypeChange whose changes should be logged.
        """
        added = [c for c in dt.component_changes if c.change_type == ChangeType.COMPONENT_ADDED]
        changed = [c for c in dt.component_changes if c.change_type == ChangeType.COMPONENT_CHANGED]
        removed = [c for c in dt.component_changes if c.change_type == ChangeType.COMPONENT_REMOVED]

        prop_changes = [pc for pc in dt.property_changes if pc.property_name not in IMAGE_PROPERTIES]
        image_changes = [pc for pc in dt.property_changes if pc.property_name in IMAGE_PROPERTIES]

        # Build a short inline summary so the name line is informative even without --verbose.
        parts = []
        if prop_changes:
            parts.append(f"{len(prop_changes)} prop")
        if image_changes:
            parts.append(f"{len(image_changes)} image")
        if added:
            parts.append(f"+{len(added)} component")
        if changed:
            parts.append(f"~{len(changed)} component")
        if removed:
            parts.append(f"-{len(removed)} component")
        suffix = f"  [{', '.join(parts)}]" if parts else ""
        self.handle.log(f"  ~ {dt.manufacturer_slug}/{dt.model}{suffix}")

        if prop_changes or image_changes:
            self.handle.verbose_log("    Properties:")
            self._log_property_diffs(prop_changes, "      ")
            for pc in image_changes:
                label = pc.property_name.replace("_", " ").title()
                self.handle.verbose_log(f"      ~ {label}: missing in NetBox (YAML defines image)")

        if added:
            for comp in added:
                self.handle.verbose_log(f"        + {comp.component_type}: {comp.component_name}")
        if changed:
            for comp in changed:
                self.handle.verbose_log(f"        ~ {comp.component_type}: {comp.component_name}")
                self._log_property_diffs(comp.property_changes, "            ")
        if removed:
            self.handle.log(f"      - {len(removed)} component(s) not in YAML (deleted with --remove-components)")
            for comp in removed:
                self.handle.verbose_log(f"        - {comp.component_type}: {comp.component_name}")

    def log_change_report(self, report: ChangeReport):
        """Log the change report in a clear, readable format."""
        self.handle.log("=" * 60)
        self.handle.log("CHANGE DETECTION REPORT")
        self.handle.log("=" * 60)

        self.handle.log(f"New device types: {len(report.new_device_types)}")
        self.handle.log(f"Unchanged device types: {report.unchanged_count}")

        if report.modified_device_types:
            self._log_modified_summary(report)

            self.handle.log("-" * 60)
            self.handle.log("MODIFIED DEVICE TYPES:")
            for dt in report.modified_device_types:
                self._log_modified_device_details(dt)
            if not self.handle.args.verbose:
                self.handle.log("  (use --verbose for property diffs and component names)")
        else:
            self.handle.log("Modified device types: 0")

        self.handle.log("=" * 60)
