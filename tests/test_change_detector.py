from types import SimpleNamespace
from unittest.mock import MagicMock

from core.change_detector import (
    ChangeDetector,
    ChangeReport,
    ChangeType,
    ComponentChange,
    DeviceTypeChange,
    PropertyChange,
)


class TestDeviceTypeChangeProperties:
    """Tests for TestDeviceTypeChangeProperties."""

    def test_has_changes_new(self):
        c = DeviceTypeChange(manufacturer_slug="cisco", model="X", slug="x", is_new=True)
        assert c.has_changes is True

    def test_has_changes_property(self):
        c = DeviceTypeChange(manufacturer_slug="cisco", model="X", slug="x")
        c.property_changes = [PropertyChange("u_height", 1, 2)]
        assert c.has_changes is True

    def test_has_changes_component(self):
        c = DeviceTypeChange(manufacturer_slug="cisco", model="X", slug="x")
        c.component_changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)]
        assert c.has_changes is True

    def test_has_changes_false(self):
        c = DeviceTypeChange(manufacturer_slug="cisco", model="X", slug="x")
        assert c.has_changes is False

    def test_has_updates_property(self):
        c = DeviceTypeChange(manufacturer_slug="cisco", model="X", slug="x")
        c.property_changes = [PropertyChange("u_height", 1, 2)]
        assert c.has_updates is True

    def test_has_updates_component(self):
        c = DeviceTypeChange(manufacturer_slug="cisco", model="X", slug="x")
        c.component_changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)]
        assert c.has_updates is True

    def test_has_updates_new_only(self):
        c = DeviceTypeChange(manufacturer_slug="cisco", model="X", slug="x", is_new=True)
        assert c.has_updates is False


class TestChangeDetectorInit:
    """Tests for TestChangeDetectorInit."""

    def test_init_stores_instance_and_handle(self):
        dt_instance = MagicMock()
        handle = MagicMock()
        detector = ChangeDetector(dt_instance, handle)
        assert detector.device_types is dt_instance
        assert detector.handle is handle


class TestNormalizeValues:
    """Tests for TestNormalizeValues."""

    def test_netbox_choice_object_reads_value(self):
        choice = MagicMock()
        choice.value = "1000base-t"
        y, n = ChangeDetector._normalize_values("1000base-t", choice)
        assert n == "1000base-t"

    def test_empty_string_normalized_to_none(self):
        y, n = ChangeDetector._normalize_values("", "")
        assert y is None
        assert n is None

    def test_trailing_whitespace_stripped(self):
        y, n = ChangeDetector._normalize_values("hello  ", "world\n")
        assert y == "hello"
        assert n == "world"

    def test_numeric_yaml_coerces_string_netbox(self):
        y, n = ChangeDetector._normalize_values(1.0, "1.0")
        assert n == 1.0

    def test_numeric_netbox_coerces_string_yaml(self):
        y, n = ChangeDetector._normalize_values("2.5", 2.5)
        assert y == 2.5

    def test_bool_not_coerced(self):
        y, n = ChangeDetector._normalize_values(True, "1")
        assert y is True
        assert n == "1"

    def test_non_numeric_string_netbox_stays_string(self):
        y, n = ChangeDetector._normalize_values(1.0, "notanumber")
        assert n == "notanumber"

    def test_non_numeric_string_yaml_stays_string(self):
        y, n = ChangeDetector._normalize_values("notanumber", 1.0)
        assert y == "notanumber"


class TestCompareDeviceTypeProperties:
    """Tests for TestCompareDeviceTypeProperties."""

    def _make_detector(self):
        dt_instance = MagicMock()
        handle = MagicMock()
        return ChangeDetector(dt_instance, handle)

    def test_no_changes_when_values_match(self):
        detector = self._make_detector()
        netbox_dt = MagicMock()
        netbox_dt.u_height = 2
        changes = detector._compare_device_type_properties({"u_height": 2}, netbox_dt)
        assert changes == []

    def test_change_detected(self):
        detector = self._make_detector()
        netbox_dt = MagicMock()
        netbox_dt.u_height = 1
        changes = detector._compare_device_type_properties({"u_height": 2}, netbox_dt)
        assert len(changes) == 1
        assert changes[0].property_name == "u_height"
        assert changes[0].old_value == 1
        assert changes[0].new_value == 2

    def test_omitted_property_not_compared(self):
        detector = self._make_detector()
        netbox_dt = MagicMock()
        netbox_dt.u_height = 99
        # u_height not in yaml_data → should not be compared
        changes = detector._compare_device_type_properties({"model": "X"}, netbox_dt)
        assert changes == []

    def test_multiple_changes(self):
        detector = self._make_detector()
        netbox_dt = MagicMock()
        netbox_dt.u_height = 1
        netbox_dt.is_full_depth = False
        changes = detector._compare_device_type_properties({"u_height": 2, "is_full_depth": True}, netbox_dt)
        assert len(changes) == 2


class TestCompareComponents:
    """Tests for TestCompareComponents."""

    def _make_detector(self, cached_components=None):
        dt_instance = MagicMock()
        dt_instance.cached_components = cached_components or {}
        handle = MagicMock()
        return ChangeDetector(dt_instance, handle)

    def test_component_added_when_missing_in_netbox(self):
        detector = self._make_detector()
        detector.device_types.cached_components = {"interface_templates": {("device", 1): {}}}
        yaml_data = {"interfaces": [{"name": "eth0", "type": "virtual"}]}
        changes = detector._compare_components(yaml_data, 1)
        assert any(c.component_name == "eth0" and c.change_type == ChangeType.COMPONENT_ADDED for c in changes)

    def test_component_removed_when_missing_in_yaml(self):
        existing_comp = MagicMock()
        existing_comp.name = "eth99"
        detector = self._make_detector()
        detector.device_types.cached_components = {"interface_templates": {("device", 1): {"eth99": existing_comp}}}
        yaml_data = {"interfaces": []}  # key present but empty → removal detected
        changes = detector._compare_components(yaml_data, 1)
        assert any(c.component_name == "eth99" and c.change_type == ChangeType.COMPONENT_REMOVED for c in changes)

    def test_no_removal_when_key_absent(self):
        existing_comp = MagicMock()
        detector = self._make_detector()
        detector.device_types.cached_components = {"interface_templates": {("device", 1): {"eth99": existing_comp}}}
        yaml_data = {}  # 'interfaces' key absent → YAML doesn't manage this type
        changes = detector._compare_components(yaml_data, 1)
        assert not any(c.component_name == "eth99" for c in changes)

    def test_component_changed_when_property_differs(self):
        existing_comp = MagicMock()
        existing_comp.type = "virtual"
        detector = self._make_detector()
        detector.device_types.cached_components = {"interface_templates": {("device", 1): {"eth0": existing_comp}}}
        yaml_data = {"interfaces": [{"name": "eth0", "type": "1000base-t"}]}
        changes = detector._compare_components(yaml_data, 1)
        assert any(c.component_name == "eth0" and c.change_type == ChangeType.COMPONENT_CHANGED for c in changes)

    def test_power_port_alias_merged(self):
        """'power-port' alias maps to same cache as 'power-ports'."""
        detector = self._make_detector()
        detector.device_types.cached_components = {"power_port_templates": {("device", 1): {}}}
        yaml_data = {"power-port": [{"name": "PSU1", "type": "iec-60320-c14"}]}
        changes = detector._compare_components(yaml_data, 1)
        assert any(c.component_name == "PSU1" and c.change_type == ChangeType.COMPONENT_ADDED for c in changes)

    def test_component_without_name_is_skipped(self):
        """YAML component entry with no 'name' key must be skipped (line 350 continue)."""
        detector = self._make_detector()
        detector.device_types.cached_components = {"interface_templates": {("device", 1): {}}}
        yaml_data = {"interfaces": [{"type": "virtual"}]}  # no 'name' key
        changes = detector._compare_components(yaml_data, 1)
        assert changes == []


class TestCompareComponentProperties:
    """Tests for TestCompareComponentProperties."""

    def _make_detector(self):
        return ChangeDetector(MagicMock(), MagicMock())

    def test_name_property_skipped(self):
        detector = self._make_detector()
        netbox_comp = MagicMock()
        changes = detector._compare_component_properties({"name": "eth0"}, netbox_comp, ["name"])
        assert changes == []

    def test_change_detected(self):
        detector = self._make_detector()
        netbox_comp = MagicMock()
        netbox_comp.type = "virtual"
        changes = detector._compare_component_properties({"type": "1000base-t"}, netbox_comp, ["name", "type"])
        assert len(changes) == 1
        assert changes[0].property_name == "type"

    def test_omitted_prop_not_compared(self):
        detector = self._make_detector()
        netbox_comp = MagicMock()
        netbox_comp.type = "virtual"
        changes = detector._compare_component_properties({}, netbox_comp, ["name", "type"])
        assert changes == []


class TestDetectChanges:
    """Tests for TestDetectChanges."""

    def _make_detector_with_cache(self, existing_by_model=None, existing_by_slug=None, cached_components=None):
        dt_instance = MagicMock()
        dt_instance.existing_device_types = existing_by_model or {}
        dt_instance.existing_device_types_by_slug = existing_by_slug or {}
        dt_instance.cached_components = cached_components or {}
        handle = MagicMock()
        return ChangeDetector(dt_instance, handle)

    def test_new_device_type(self):
        detector = self._make_detector_with_cache()
        dt_data = [{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x"}]
        report = detector.detect_changes(dt_data)
        assert len(report.new_device_types) == 1
        assert report.new_device_types[0].model == "X"

    def test_existing_unchanged_increments_count(self):
        existing = MagicMock()
        existing.id = 1
        detector = self._make_detector_with_cache(
            existing_by_model={("cisco", "X"): existing},
            cached_components={},
        )
        dt_data = [{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x"}]
        report = detector.detect_changes(dt_data)
        assert report.unchanged_count == 1
        assert len(report.modified_device_types) == 0

    def test_existing_with_change_goes_to_modified(self):
        existing = MagicMock()
        existing.id = 1
        existing.u_height = 1
        detector = self._make_detector_with_cache(
            existing_by_model={("cisco", "X"): existing},
            cached_components={},
        )
        dt_data = [{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x", "u_height": 2}]
        report = detector.detect_changes(dt_data)
        assert len(report.modified_device_types) == 1

    def test_slug_fallback_lookup(self):
        existing = MagicMock()
        existing.id = 1
        detector = self._make_detector_with_cache(
            existing_by_model={},
            existing_by_slug={("cisco", "x"): existing},
            cached_components={},
        )
        dt_data = [{"manufacturer": {"slug": "cisco"}, "model": "NewName", "slug": "x"}]
        report = detector.detect_changes(dt_data)
        assert report.unchanged_count == 1


class TestLogChangeReport:
    """Tests for TestLogChangeReport."""

    def _make_detector(self, verbose=False):
        dt_instance = MagicMock()
        dt_instance.existing_device_types = {}
        dt_instance.existing_device_types_by_slug = {}
        dt_instance.cached_components = {}
        handle = MagicMock()
        handle.args = SimpleNamespace(verbose=verbose)
        return ChangeDetector(dt_instance, handle)

    def test_empty_report_logs_zeros(self):
        detector = self._make_detector()
        report = ChangeReport(new_device_types=[], modified_device_types=[], unchanged_count=0)
        detector.log_change_report(report)
        detector.handle.log.assert_any_call("New device types: 0")

    def test_modified_with_removals_always_logged(self):
        detector = self._make_detector(verbose=False)
        dt_change = DeviceTypeChange(manufacturer_slug="cisco", model="X", slug="x")
        dt_change.component_changes = [ComponentChange("interfaces", "eth99", ChangeType.COMPONENT_REMOVED)]
        report = ChangeReport(modified_device_types=[dt_change])
        detector.log_change_report(report)
        # log() (not verbose_log) should be called for device identity with removals
        log_calls = [str(call) for call in detector.handle.log.call_args_list]
        assert any("cisco/X" in c for c in log_calls)

    def test_modified_with_property_change_logged(self):
        detector = self._make_detector()
        dt_change = DeviceTypeChange(manufacturer_slug="juniper", model="MX5", slug="mx5")
        dt_change.property_changes = [PropertyChange("u_height", 1, 2)]
        report = ChangeReport(modified_device_types=[dt_change])
        detector.log_change_report(report)
        detector.handle.log.assert_any_call("Modified device types: 1")

    def test_modified_with_image_and_component_changes(self):
        detector = self._make_detector()
        dt_change = DeviceTypeChange(manufacturer_slug="hp", model="Z", slug="z")
        dt_change.property_changes = [PropertyChange("front_image", None, True)]
        dt_change.component_changes = [
            ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED),
            ComponentChange("interfaces", "eth1", ChangeType.COMPONENT_CHANGED),
        ]
        report = ChangeReport(modified_device_types=[dt_change])
        detector.log_change_report(report)
        # Just verifying no crash and log called
        assert detector.handle.log.called

    def test_verbose_hint_logged_when_non_verbose(self):
        detector = self._make_detector(verbose=False)
        dt_change = DeviceTypeChange(manufacturer_slug="hp", model="Z", slug="z")
        dt_change.property_changes = [PropertyChange("u_height", 1, 2)]
        report = ChangeReport(modified_device_types=[dt_change])
        detector.log_change_report(report)
        log_calls = [str(call) for call in detector.handle.log.call_args_list]
        assert any("--verbose" in c for c in log_calls)


class TestCompareImageProperties:
    """Tests for ChangeDetector._compare_image_properties()."""

    def test_missing_front_image_detected(self):
        """YAML=true, NetBox=None → should report a missing image."""
        yaml_data = {"front_image": True}
        netbox_dt = MagicMock()
        netbox_dt.front_image = None

        changes = ChangeDetector._compare_image_properties(yaml_data, netbox_dt)

        assert len(changes) == 1
        assert changes[0].property_name == "front_image"
        assert changes[0].old_value is None
        assert changes[0].new_value is True

    def test_missing_rear_image_detected(self):
        """YAML=true, NetBox=None → should report a missing image."""
        yaml_data = {"rear_image": True}
        netbox_dt = MagicMock()
        netbox_dt.rear_image = None

        changes = ChangeDetector._compare_image_properties(yaml_data, netbox_dt)

        assert len(changes) == 1
        assert changes[0].property_name == "rear_image"
        assert changes[0].old_value is None
        assert changes[0].new_value is True

    def test_both_images_missing(self):
        """Both images defined in YAML but missing in NetBox."""
        yaml_data = {"front_image": True, "rear_image": True}
        netbox_dt = MagicMock()
        netbox_dt.front_image = None
        netbox_dt.rear_image = None

        changes = ChangeDetector._compare_image_properties(yaml_data, netbox_dt)

        assert len(changes) == 2
        names = {c.property_name for c in changes}
        assert names == {"front_image", "rear_image"}

    def test_existing_image_not_flagged(self):
        """YAML=true, NetBox=URL → no change reported."""
        yaml_data = {"front_image": True}
        netbox_dt = MagicMock()
        netbox_dt.front_image = "http://netbox/media/devicetypes/front.jpg"

        changes = ChangeDetector._compare_image_properties(yaml_data, netbox_dt)

        assert len(changes) == 0

    def test_yaml_false_no_change(self):
        """YAML=false → no change reported regardless of NetBox state."""
        yaml_data = {"front_image": False}
        netbox_dt = MagicMock()
        netbox_dt.front_image = None

        changes = ChangeDetector._compare_image_properties(yaml_data, netbox_dt)

        assert len(changes) == 0

    def test_yaml_omitted_no_change(self):
        """Image key omitted from YAML → no change reported."""
        yaml_data = {"model": "Test"}
        netbox_dt = MagicMock()
        netbox_dt.front_image = None
        netbox_dt.rear_image = None

        changes = ChangeDetector._compare_image_properties(yaml_data, netbox_dt)

        assert len(changes) == 0

    def test_empty_string_treated_as_missing(self):
        """NetBox returns empty string instead of None → still flagged as missing."""
        yaml_data = {"front_image": True}
        netbox_dt = MagicMock()
        netbox_dt.front_image = ""

        changes = ChangeDetector._compare_image_properties(yaml_data, netbox_dt)

        assert len(changes) == 1
        assert changes[0].property_name == "front_image"
