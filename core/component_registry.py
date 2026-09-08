"""One row per component template type; every other table is derived from it.

NetBox device types and module types carry nine kinds of component template.  Each kind
used to be described in eleven places (YAML key, cache name, endpoint attribute, GraphQL
list key, GraphQL field list, comparable properties, serializer fields, display label,
module-type support, create method), so adding a field to one copy and not the others
changed nothing visible and broke the import quietly.

This module holds the row.  Consumers read it; they do not restate it.
"""

from dataclasses import dataclass, field
from typing import Optional

# What a create call must resolve from a name to a NetBox id before it can POST.
LINK_BRIDGE = "bridge"
LINK_POWER_PORT = "power_port"
LINK_REAR_PORTS = "rear_ports"

# Fields holding names that must become NetBox ids before a POST.
RELATION_MODULE_BAY_TYPES = "module_bay_types"

# Relation fields a module type carries itself, rather than through one of its components.
MODULE_TYPE_RELATIONS = (RELATION_MODULE_BAY_TYPES,)


@dataclass(frozen=True)
class ComponentType:
    """One kind of component template, described once."""

    yaml_key: str
    endpoint: str
    label: str
    fields: tuple[str, ...]
    module_types: bool = True
    relations: tuple[str, ...] = field(default_factory=tuple)
    graphql_extra: tuple[str, ...] = field(default_factory=tuple)
    compare_extra: tuple[str, ...] = field(default_factory=tuple)
    link: Optional[str] = None

    @property
    def graphql_fields(self):
        """Fields to select in a GraphQL query, including the id every consumer needs.

        A relation is a list of related objects, so it is selected by name rather than
        read as a scalar.
        """
        return ["id", *self.fields, *self.graphql_extra, *self.graphql_relation_fields]

    @property
    def graphql_relation_fields(self):
        """GraphQL selections for this row's relations, one nested block per relation."""
        # slug plus owning manufacturer is the identity; the name alone is ambiguous.
        return [f"{name} {{ id name slug manufacturer {{ slug }} }}" for name in self.relations]

    @property
    def compare_properties(self):
        """Properties change detection compares between YAML and NetBox."""
        return [*self.fields, *self.compare_extra, *self.relations]

    @property
    def list_key(self):
        """The GraphQL list field for this endpoint, e.g. ``interface_template_list``."""
        return f"{self.endpoint.removesuffix('s')}_list"

    @property
    def plural_label(self):
        """Label for a group of these components, as shown in the progress display."""
        return f"{self.label}s"

    def create_label(self, parent_type):
        """Label used in create and error messages, distinguishing module parents."""
        return self.label if parent_type == "device" else f"Module {self.label}"


# Order is canonical: it sets the YAML key order of an export, the progress-bar order,
# and the create order.  Rear ports precede front ports, and power ports precede power
# outlets, because the later type resolves names against the earlier one.
COMPONENT_TYPES = (
    ComponentType(
        yaml_key="interfaces",
        endpoint="interface_templates",
        label="Interface",
        fields=("name", "type", "label", "description", "mgmt_only", "enabled", "poe_mode", "poe_type", "rf_role"),
        link=LINK_BRIDGE,
    ),
    ComponentType(
        yaml_key="power-ports",
        endpoint="power_port_templates",
        label="Power Port",
        fields=("name", "type", "label", "description", "maximum_draw", "allocated_draw"),
    ),
    ComponentType(
        yaml_key="console-ports",
        endpoint="console_port_templates",
        label="Console Port",
        fields=("name", "type", "label", "description"),
    ),
    ComponentType(
        yaml_key="power-outlets",
        endpoint="power_outlet_templates",
        label="Power Outlet",
        fields=("name", "type", "label", "description", "feed_leg"),
        link=LINK_POWER_PORT,
    ),
    ComponentType(
        yaml_key="console-server-ports",
        endpoint="console_server_port_templates",
        label="Console Server Port",
        fields=("name", "type", "label", "description"),
    ),
    ComponentType(
        yaml_key="rear-ports",
        endpoint="rear_port_templates",
        label="Rear Port",
        fields=("name", "type", "label", "description", "positions", "color"),
    ),
    ComponentType(
        yaml_key="front-ports",
        endpoint="front_port_templates",
        label="Front Port",
        fields=("name", "type", "label", "description", "color"),
        graphql_extra=("mappings { id front_port_position rear_port_position rear_port { id name } }",),
        compare_extra=("_mappings",),
        link=LINK_REAR_PORTS,
    ),
    ComponentType(
        yaml_key="device-bays",
        endpoint="device_bay_templates",
        label="Device Bay",
        fields=("name", "label", "description"),
        # NetBox exposes no module_type on device_bay_templates, and a module type cannot
        # hold a device bay.
        module_types=False,
    ),
    ComponentType(
        yaml_key="module-bays",
        endpoint="module_bay_templates",
        label="Module Bay",
        fields=("name", "position", "label", "description"),
        relations=(RELATION_MODULE_BAY_TYPES,),
    ),
)

BY_YAML_KEY = {component.yaml_key: component for component in COMPONENT_TYPES}
BY_ENDPOINT = {component.endpoint: component for component in COMPONENT_TYPES}

MODULE_TYPE_COMPONENTS = tuple(component for component in COMPONENT_TYPES if component.module_types)
