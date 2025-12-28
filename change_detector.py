"""
Change detection module for comparing YAML device types against NetBox data.

Provides functionality to detect differences between device type definitions
in the repository and existing data in NetBox, supporting the --update workflow.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class ChangeType(Enum):
    """Types of changes that can be detected."""

    NEW = "new"
    PROPERTY_CHANGED = "property_changed"
    COMPONENT_ADDED = "component_added"
    COMPONENT_CHANGED = "component_changed"


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


# Device type properties that can be compared and updated
DEVICE_TYPE_PROPERTIES = [
    "u_height",
    "part_number",
    "is_full_depth",
    "subdevice_role",
    "airflow",
    "weight",
    "weight_unit",
    "comments",
]

# Component type mapping: YAML key -> (cache_key, comparable_properties)
COMPONENT_TYPES = {
    "interfaces": ("interface_templates", ["name", "type", "mgmt_only", "label", "enabled", "poe_mode", "poe_type"]),
    "power-ports": ("power_port_templates", ["name", "type", "maximum_draw", "allocated_draw", "label"]),
    "power-port": ("power_port_templates", ["name", "type", "maximum_draw", "allocated_draw", "label"]),
    "console-ports": ("console_port_templates", ["name", "type", "label"]),
    "power-outlets": ("power_outlet_templates", ["name", "type", "feed_leg", "label"]),
    "console-server-ports": ("console_server_port_templates", ["name", "type", "label"]),
    "rear-ports": ("rear_port_templates", ["name", "type", "positions", "label"]),
    "front-ports": ("front_port_templates", ["name", "type", "rear_port_position", "label"]),
    "device-bays": ("device_bay_templates", ["name", "label"]),
    "module-bays": ("module_bay_templates", ["name", "position", "label"]),
}


class ChangeDetector:
    """Detects changes between YAML device types and NetBox cached data."""

    def __init__(self, device_types_instance, handle):
        """
        Initialize the change detector.

        Args:
            device_types_instance: DeviceTypes instance with cached data
            handle: LogHandler for logging
        """
        self.device_types = device_types_instance
        self.handle = handle

    def detect_changes(self, device_types: List[dict]) -> ChangeReport:
        """
        Analyze all device types and generate a change report.

        Args:
            device_types: List of parsed YAML device type dictionaries

        Returns:
            ChangeReport with categorized changes
        """
        report = ChangeReport()

        for dt_data in device_types:
            manufacturer_slug = dt_data["manufacturer"]["slug"]
            model = dt_data["model"]
            slug = dt_data.get("slug", "")

            # Try to find existing device type
            existing_dt = self.device_types.existing_device_types.get((manufacturer_slug, model))

            # Fallback to slug lookup
            if existing_dt is None and slug:
                existing_dt = self.device_types.existing_device_types_by_slug.get((manufacturer_slug, slug))

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
                change.component_changes = self._compare_components(dt_data, existing_dt.id)

                if change.has_changes:
                    report.modified_device_types.append(change)
                else:
                    report.unchanged_count += 1

        return report

    def _compare_device_type_properties(self, yaml_data: dict, netbox_dt) -> List[PropertyChange]:
        """
        Compare YAML device type properties against NetBox device type.

        Args:
            yaml_data: Parsed YAML device type dictionary
            netbox_dt: pynetbox Record object for existing device type

        Returns:
            List of PropertyChange objects for any differences found
        """
        changes = []

        for prop in DEVICE_TYPE_PROPERTIES:
            yaml_value = yaml_data.get(prop)
            netbox_value = getattr(netbox_dt, prop, None)

            # Skip if both are None/missing
            if yaml_value is None and netbox_value is None:
                continue

            # Handle NetBox choice fields that return dicts with 'value' key
            if isinstance(netbox_value, dict) and "value" in netbox_value:
                netbox_value = netbox_value["value"]

            # Normalize empty string to None for comparison
            if yaml_value == "":
                yaml_value = None
            if netbox_value == "":
                netbox_value = None

            # Compare values - only flag if YAML has a value that differs
            if yaml_value is not None and yaml_value != netbox_value:
                changes.append(
                    PropertyChange(
                        property_name=prop,
                        old_value=netbox_value,
                        new_value=yaml_value,
                    )
                )

        return changes

    def _compare_components(
        self,
        yaml_data: dict,
        device_type_id: int,
        parent_type: str = "device",
    ) -> List[ComponentChange]:
        """
        Compare all components between YAML and cached NetBox data.

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
            yaml_components = yaml_data.get(yaml_key, [])
            if not yaml_components:
                continue

            # Get cached components for this device type
            cached = self.device_types.cached_components.get(cache_name, {})
            existing_components = cached.get(cache_key, {})

            # Check each YAML component
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
                    prop_changes = self._compare_component_properties(yaml_comp, existing, properties)
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
    ) -> List[PropertyChange]:
        """Compare properties between YAML and NetBox component."""
        changes = []

        for prop in properties:
            if prop == "name":
                # Name is the key, skip comparison
                continue

            yaml_value = yaml_comp.get(prop)
            netbox_value = getattr(netbox_comp, prop, None)

            # Handle NetBox choice fields
            if isinstance(netbox_value, dict) and "value" in netbox_value:
                netbox_value = netbox_value["value"]

            # Normalize empty/None
            if yaml_value == "":
                yaml_value = None
            if netbox_value == "":
                netbox_value = None

            # Only flag if YAML has a value that differs
            if yaml_value is not None and yaml_value != netbox_value:
                changes.append(
                    PropertyChange(
                        property_name=prop,
                        old_value=netbox_value,
                        new_value=yaml_value,
                    )
                )

        return changes

    def log_change_report(self, report: ChangeReport):
        """Log the change report in a clear, readable format."""
        self.handle.log("=" * 60)
        self.handle.log("CHANGE DETECTION REPORT")
        self.handle.log("=" * 60)

        # Summary
        self.handle.log(f"New device types: {len(report.new_device_types)}")
        self.handle.log(f"Modified device types: {len(report.modified_device_types)}")
        self.handle.log(f"Unchanged device types: {report.unchanged_count}")

        # Details for modified device types (verbose mode)
        if report.modified_device_types:
            self.handle.log("-" * 60)
            self.handle.log("MODIFIED DEVICE TYPES:")
            for dt in report.modified_device_types:
                self.handle.verbose_log(f"  ~ {dt.manufacturer_slug}/{dt.model}")

                # Property changes
                for pc in dt.property_changes:
                    self.handle.verbose_log(
                        f"      Property '{pc.property_name}': " f"'{pc.old_value}' -> '{pc.new_value}'"
                    )

                # Component changes
                added = [c for c in dt.component_changes if c.change_type == ChangeType.COMPONENT_ADDED]
                changed = [c for c in dt.component_changes if c.change_type == ChangeType.COMPONENT_CHANGED]

                if added:
                    self.handle.verbose_log(f"      + {len(added)} new component(s)")
                if changed:
                    self.handle.verbose_log(f"      ~ {len(changed)} changed component(s)")

        self.handle.log("=" * 60)

    def get_update_data(self, dt_change: DeviceTypeChange, yaml_data: dict) -> Dict[str, Any]:
        """
        Get the update payload for a device type based on detected changes.

        Args:
            dt_change: The DeviceTypeChange object with detected changes
            yaml_data: Original YAML data for the device type

        Returns:
            Dictionary with update data for device type properties
        """
        updates = {}
        for pc in dt_change.property_changes:
            updates[pc.property_name] = pc.new_value
        return updates
