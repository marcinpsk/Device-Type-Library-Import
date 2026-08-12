"""The registry is the single source for nine component types.

These tests pin every table the rest of the codebase derives from it.  A row edited
without the matching consumer change now fails here instead of silently dropping a
field from a query, a comparison or an export.
"""

import pytest

from core.component_registry import (
    BY_ENDPOINT,
    BY_YAML_KEY,
    COMPONENT_TYPES,
    LINK_BRIDGE,
    LINK_POWER_PORT,
    LINK_REAR_PORTS,
    MODULE_TYPE_COMPONENTS,
)

_FRONT_PORT_MAPPINGS = "mappings { id front_port_position rear_port_position rear_port { id name } }"


class TestTheTableItself:
    """The rows, their order, and the columns that only a few rows set."""

    def test_nine_component_types_in_a_fixed_order(self):
        assert [component.yaml_key for component in COMPONENT_TYPES] == [
            "interfaces",
            "power-ports",
            "console-ports",
            "power-outlets",
            "console-server-ports",
            "rear-ports",
            "front-ports",
            "device-bays",
            "module-bays",
        ]

    def test_every_yaml_key_maps_to_one_endpoint(self):
        assert {key: component.endpoint for key, component in BY_YAML_KEY.items()} == {
            "interfaces": "interface_templates",
            "power-ports": "power_port_templates",
            "console-ports": "console_port_templates",
            "power-outlets": "power_outlet_templates",
            "console-server-ports": "console_server_port_templates",
            "rear-ports": "rear_port_templates",
            "front-ports": "front_port_templates",
            "device-bays": "device_bay_templates",
            "module-bays": "module_bay_templates",
        }

    def test_the_endpoint_index_covers_the_same_rows(self):
        assert set(BY_ENDPOINT) == {component.endpoint for component in COMPONENT_TYPES}
        assert len(BY_ENDPOINT) == len(COMPONENT_TYPES)

    def test_only_device_bays_are_absent_from_module_types(self):
        assert [component.yaml_key for component in MODULE_TYPE_COMPONENTS] == [
            "interfaces",
            "power-ports",
            "console-ports",
            "power-outlets",
            "console-server-ports",
            "rear-ports",
            "front-ports",
            "module-bays",
        ]

    def test_only_three_types_resolve_a_name_to_an_id(self):
        assert {component.yaml_key: component.link for component in COMPONENT_TYPES if component.link} == {
            "interfaces": LINK_BRIDGE,
            "power-outlets": LINK_POWER_PORT,
            "front-ports": LINK_REAR_PORTS,
        }

    def test_a_type_that_resolves_rear_ports_precedes_none_of_them(self):
        order = [component.yaml_key for component in COMPONENT_TYPES]
        assert order.index("rear-ports") < order.index("front-ports")
        assert order.index("power-ports") < order.index("power-outlets")


class TestDerivedGraphQLTables:
    """What the GraphQL client used to hold as two hand-maintained dicts."""

    def test_the_list_key_is_the_endpoint_singularised(self):
        assert {component.endpoint: component.list_key for component in COMPONENT_TYPES} == {
            "interface_templates": "interface_template_list",
            "power_port_templates": "power_port_template_list",
            "console_port_templates": "console_port_template_list",
            "console_server_port_templates": "console_server_port_template_list",
            "power_outlet_templates": "power_outlet_template_list",
            "rear_port_templates": "rear_port_template_list",
            "front_port_templates": "front_port_template_list",
            "device_bay_templates": "device_bay_template_list",
            "module_bay_templates": "module_bay_template_list",
        }

    def test_the_query_selects_exactly_these_fields(self):
        assert {component.endpoint: component.graphql_fields for component in COMPONENT_TYPES} == {
            "interface_templates": [
                "id",
                "name",
                "type",
                "label",
                "description",
                "mgmt_only",
                "enabled",
                "poe_mode",
                "poe_type",
                "rf_role",
            ],
            "power_port_templates": [
                "id",
                "name",
                "type",
                "label",
                "description",
                "maximum_draw",
                "allocated_draw",
            ],
            "console_port_templates": ["id", "name", "type", "label", "description"],
            "console_server_port_templates": ["id", "name", "type", "label", "description"],
            "power_outlet_templates": ["id", "name", "type", "label", "description", "feed_leg"],
            "rear_port_templates": ["id", "name", "type", "label", "description", "positions", "color"],
            "front_port_templates": [
                "id",
                "name",
                "type",
                "label",
                "description",
                "color",
                _FRONT_PORT_MAPPINGS,
            ],
            "device_bay_templates": ["id", "name", "label", "description"],
            "module_bay_templates": ["id", "name", "position", "label", "description"],
        }

    def test_only_the_front_port_query_selects_a_nested_block(self):
        with_extra = {component.yaml_key: component.graphql_extra for component in COMPONENT_TYPES}
        assert with_extra["front-ports"] == (_FRONT_PORT_MAPPINGS,)
        assert all(extra == () for key, extra in with_extra.items() if key != "front-ports")


class TestDerivedComparisonAndExport:
    """The invariants that make a dropped field loud instead of silent."""

    @pytest.mark.parametrize("component", COMPONENT_TYPES, ids=lambda c: c.yaml_key)
    def test_every_compared_property_is_fetched(self, component):
        """A property compared but never queried reads as missing and is skipped in silence."""
        queried = set(component.graphql_fields) | {"_mappings"}
        assert set(component.compare_properties) <= queried

    @pytest.mark.parametrize("component", COMPONENT_TYPES, ids=lambda c: c.yaml_key)
    def test_the_export_writes_every_scalar_the_query_reads(self, component):
        """Export fields are the query's scalars: an unexported scalar drops out of a round trip."""
        scalars = [name for name in component.graphql_fields if name != "id" and name not in component.graphql_extra]
        assert list(component.fields) == scalars

    def test_front_ports_compare_the_mapping_the_query_selects(self):
        front_ports = BY_YAML_KEY["front-ports"]
        assert "_mappings" in front_ports.compare_properties
        assert "_mappings" not in front_ports.fields

    def test_name_leads_every_field_list(self):
        assert all(component.fields[0] == "name" for component in COMPONENT_TYPES)


class TestLabels:
    """One label per row, with the plural and the module prefix derived from it."""

    def test_the_singular_label_names_the_component(self):
        assert [component.label for component in COMPONENT_TYPES] == [
            "Interface",
            "Power Port",
            "Console Port",
            "Power Outlet",
            "Console Server Port",
            "Rear Port",
            "Front Port",
            "Device Bay",
            "Module Bay",
        ]

    def test_the_progress_display_uses_the_plural(self):
        assert [component.plural_label for component in COMPONENT_TYPES] == [
            "Interfaces",
            "Power Ports",
            "Console Ports",
            "Power Outlets",
            "Console Server Ports",
            "Rear Ports",
            "Front Ports",
            "Device Bays",
            "Module Bays",
        ]

    def test_a_module_parent_prefixes_the_label(self):
        interfaces = BY_YAML_KEY["interfaces"]
        assert interfaces.create_label("device") == "Interface"
        assert interfaces.create_label("module") == "Module Interface"
