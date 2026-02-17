import pytest
from unittest.mock import MagicMock

from change_detector import ChangeDetector, PropertyChange


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
