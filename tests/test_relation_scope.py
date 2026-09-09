"""A relation assigned from the wrong manufacturer scope must be detected as a change.

The catalog resolves a reference name in the owning manufacturer's scope first and only
then in Generic.  If NetBox already holds the Generic object where the owner has one of
its own, comparing names alone reports equality and the wrong object survives.
"""

import pytest

from core.change_detector import ChangeDetector
from core.module_bay_types import ModuleBayTypeCatalog


class Handle:
    """Capture what the detector logs."""

    def __init__(self):
        """Start with no recorded lines."""
        self.lines = []

    def log(self, message):
        """Record one line."""
        self.lines.append(message)

    def verbose_log(self, message):
        """Record one verbose line."""
        self.lines.append(message)


class Related:
    """A module bay type as NetBox returns it inside a relation."""

    def __init__(self, name, slug, manufacturer_slug):
        """Store the identity fields the comparison needs."""
        self.name = name
        self.slug = slug
        self.manufacturer = type("M", (), {"slug": manufacturer_slug})()


class NetBoxBay:
    """A module bay template as the cache hands it to the detector."""

    def __init__(self, name, module_bay_types):
        """Store the bay name and its assigned classes."""
        self.name = name
        self.module_bay_types = module_bay_types


@pytest.fixture
def two_scope_catalog(tmp_path):
    """Build a catalog where the same class name exists under Acme and under Generic."""
    for manufacturer, slug in (("Acme", "acme-x"), ("Generic", "generic-x")):
        directory = tmp_path / "module-bay-types" / manufacturer
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{slug}.yaml").write_text(
            f"name: X\nslug: {slug}\nmanufacturer: {manufacturer}\n", encoding="utf-8"
        )
    return str(tmp_path)


def _detector(catalog, handle=None):
    """Build a detector whose device_types exposes the catalog, as the real one does."""
    device_types = type("DeviceTypes", (), {"module_bay_types": catalog, "module_bay_types_supported": True})()
    return ChangeDetector(device_types, handle or Handle())


def test_wrong_scope_assignment_is_detected(two_scope_catalog):
    """Acme owns X, but NetBox assigned Generic's X. The names match; the objects do not."""
    catalog = ModuleBayTypeCatalog(None, two_scope_catalog, Handle())
    detector = _detector(catalog)

    yaml_comp = {"name": "Slot 0", "module_bay_types": ["X"]}
    netbox_comp = NetBoxBay("Slot 0", [Related("X", "generic-x", "generic")])

    changes = detector._compare_component_properties(
        yaml_comp, netbox_comp, ["module_bay_types"], comp_type="module-bays", manufacturer="acme"
    )
    assert [c.property_name for c in changes] == ["module_bay_types"], (
        "a bay owned by Acme holding Generic's X must be corrected to Acme's X"
    )


def test_right_scope_assignment_is_left_alone(two_scope_catalog):
    """The same bay already holding Acme's X is correct and must not be rewritten."""
    catalog = ModuleBayTypeCatalog(None, two_scope_catalog, Handle())
    detector = _detector(catalog)

    yaml_comp = {"name": "Slot 0", "module_bay_types": ["X"]}
    netbox_comp = NetBoxBay("Slot 0", [Related("X", "acme-x", "acme")])

    changes = detector._compare_component_properties(
        yaml_comp, netbox_comp, ["module_bay_types"], comp_type="module-bays", manufacturer="acme"
    )
    assert changes == []


def test_generic_fallback_is_correct_when_the_owner_has_no_such_class(two_scope_catalog):
    """A Nokia bay resolves X to Generic's X, so holding Generic's X is right."""
    catalog = ModuleBayTypeCatalog(None, two_scope_catalog, Handle())
    detector = _detector(catalog)

    yaml_comp = {"name": "Slot 0", "module_bay_types": ["X"]}
    netbox_comp = NetBoxBay("Slot 0", [Related("X", "generic-x", "generic")])

    changes = detector._compare_component_properties(
        yaml_comp, netbox_comp, ["module_bay_types"], comp_type="module-bays", manufacturer="nokia"
    )
    assert changes == []


def _changes(detector, yaml_comp, netbox_comp, manufacturer="acme"):
    """Run the real property comparison for the relation and return what it found."""
    return detector._compare_component_properties(
        yaml_comp, netbox_comp, ["module_bay_types"], comp_type="module-bays", manufacturer=manufacturer
    )


class TestUnmanagedRelations:
    """A relation is only rewritten when both sides say something about it."""

    def test_an_omitted_key_leaves_the_relation_alone(self, two_scope_catalog):
        """A definition that never mentions the relation is not asking for it to be cleared."""
        detector = _detector(ModuleBayTypeCatalog(None, two_scope_catalog, Handle()))
        netbox_comp = NetBoxBay("Slot 0", [Related("X", "acme-x", "acme")])
        assert _changes(detector, {"name": "Slot 0"}, netbox_comp) == []

    def test_a_bare_key_leaves_the_relation_alone_but_says_so(self, two_scope_catalog):
        """Parses as None, so nothing is cleared; a typo must still not be invisible."""
        handle = Handle()
        detector = _detector(ModuleBayTypeCatalog(None, two_scope_catalog, Handle()), handle)
        netbox_comp = NetBoxBay("Slot 0", [Related("X", "acme-x", "acme")])

        assert _changes(detector, {"name": "Slot 0", "module_bay_types": None}, netbox_comp) == []
        assert any("module_bay_types" in line and "Slot 0" in line for line in handle.lines)

    def test_a_non_name_entry_leaves_the_relation_alone(self, two_scope_catalog):
        detector = _detector(ModuleBayTypeCatalog(None, two_scope_catalog, Handle()))
        netbox_comp = NetBoxBay("Slot 0", [Related("X", "acme-x", "acme")])
        assert _changes(detector, {"name": "Slot 0", "module_bay_types": [{"name": "X"}]}, netbox_comp) == []

    def test_a_field_the_query_did_not_return_is_skipped(self, two_scope_catalog):
        """Reading an absent field as empty would report a change on every run."""
        detector = _detector(ModuleBayTypeCatalog(None, two_scope_catalog, Handle()))
        netbox_comp = type("Bay", (), {"name": "Slot 0"})()
        assert _changes(detector, {"name": "Slot 0", "module_bay_types": ["X"]}, netbox_comp) == []

    def test_an_unresolvable_reference_reaches_the_write_path(self, two_scope_catalog):
        """Reporting "no change" leaves the bay unrestricted in silence.

        The write path is the only thing that logs and records an unresolvable name, and it
        only ever sees a component the detector reported as changed.
        """
        detector = _detector(ModuleBayTypeCatalog(None, two_scope_catalog, Handle()))
        netbox_comp = NetBoxBay("Slot 0", [Related("X", "acme-x", "acme")])

        changes = _changes(detector, {"name": "Slot 0", "module_bay_types": ["NO-SUCH-CLASS"]}, netbox_comp)

        assert [(c.property_name, c.new_value) for c in changes] == [("module_bay_types", ["NO-SUCH-CLASS"])]


class TestNameComparisonFallback:
    """Where an identity cannot be had, comparing names is still better than doing nothing."""

    def test_names_are_compared_when_netbox_returned_no_slug(self, two_scope_catalog):
        """A read path returning only id and name cannot answer the scope question."""
        detector = _detector(ModuleBayTypeCatalog(None, two_scope_catalog, Handle()))
        netbox_comp = NetBoxBay("Slot 0", [Related("Y", None, None)])
        changes = _changes(detector, {"name": "Slot 0", "module_bay_types": ["X"]}, netbox_comp)
        assert [(c.property_name, c.old_value, c.new_value) for c in changes] == [("module_bay_types", ["Y"], ["X"])]

    def test_matching_names_are_left_alone_when_netbox_returned_no_slug(self, two_scope_catalog):
        detector = _detector(ModuleBayTypeCatalog(None, two_scope_catalog, Handle()))
        netbox_comp = NetBoxBay("Slot 0", [Related("X", None, None)])
        assert _changes(detector, {"name": "Slot 0", "module_bay_types": ["X"]}, netbox_comp) == []

    def test_names_are_compared_without_a_catalog(self):
        """A caller that has not wired a catalog still gets the name comparison."""
        detector = _detector(None)
        netbox_comp = NetBoxBay("Slot 0", [Related("Y", "generic-y", "generic")])
        changes = _changes(detector, {"name": "Slot 0", "module_bay_types": ["X"]}, netbox_comp)
        assert [(c.old_value, c.new_value) for c in changes] == [(["Y"], ["X"])]

    def test_an_empty_list_clears_the_relation(self, two_scope_catalog):
        """`module_bay_types: []` is an explicit instruction to hold no classes."""
        detector = _detector(ModuleBayTypeCatalog(None, two_scope_catalog, Handle()))
        netbox_comp = NetBoxBay("Slot 0", [Related("X", "acme-x", "acme")])
        changes = _changes(detector, {"name": "Slot 0", "module_bay_types": []}, netbox_comp)
        assert [(c.old_value, c.new_value) for c in changes] == [(["X"], [])]
