"""Tests for core/nb_serializer.py — NetBox → DTL YAML serializer."""

from core.nb_serializer import _coerce_numeric, serialize_device_type, serialize_module_type, serialize_rack_type


def _dotdict(**kw):
    """Build a lightweight stub that only has attributes for the provided kwargs.

    Unlike MagicMock, accessing an attribute not in ``kw`` returns the default
    supplied to ``getattr(obj, attr, default)`` rather than a truthy Mock object.
    This exercises absent-field logic correctly.
    """

    class _Stub:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def get(self, key, default=None):
            return kw.get(key, default)

    return _Stub(**kw)


def _make_mfr(name="Acme", slug="acme"):
    return _dotdict(name=name, slug=slug)


class TestSerializeDeviceType:
    """Tests for serialize_device_type function."""

    def test_minimal_required_fields(self):
        record = _dotdict(
            id=1,
            model="My Switch",
            slug="acme-my-switch",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        result = serialize_device_type(record, components_by_dt_id={})
        assert result["manufacturer"] == "Acme"
        assert result["model"] == "My Switch"
        assert result["slug"] == "acme-my-switch"
        assert result["u_height"] == 1
        assert result["is_full_depth"] is True
        # None/empty fields must be absent
        assert "part_number" not in result
        assert "airflow" not in result
        assert "description" not in result

    def test_optional_scalar_fields_included_when_set(self):
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=2,
            is_full_depth=False,
            part_number="PN-123",
            airflow="front-to-rear",
            weight=10.5,
            weight_unit="kg",
            description="A switch",
            comments="note",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        result = serialize_device_type(record, components_by_dt_id={})
        assert result["part_number"] == "PN-123"
        assert result["airflow"] == "front-to-rear"
        assert result["weight"] == 10.5
        assert result["weight_unit"] == "kg"
        assert result["description"] == "A switch"
        assert result["comments"] == "note"
        assert result["is_full_depth"] is False

    def test_image_flags_set_when_urls_present(self):
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image="/media/devicetype-images/acme-x.front.png",
            rear_image="/media/devicetype-images/acme-x.rear.png",
        )
        result = serialize_device_type(record, components_by_dt_id={})
        assert result["front_image"] is True
        assert result["rear_image"] is True

    def test_interfaces_serialized(self):
        iface = _dotdict(
            id=10,
            name="eth0",
            type="1000base-t",
            label="",
            description="",
            mgmt_only=False,
            enabled=True,
            poe_mode=None,
            poe_type=None,
            rf_role=None,
            device_type=_dotdict(id=1),
        )
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        components = {1: {"interface_templates": [iface]}}
        result = serialize_device_type(record, components_by_dt_id=components)
        assert "interfaces" in result
        assert result["interfaces"][0]["name"] == "eth0"
        assert result["interfaces"][0]["type"] == "1000base-t"
        # defaults omitted
        assert "label" not in result["interfaces"][0]
        assert "mgmt_only" not in result["interfaces"][0]
        assert "enabled" not in result["interfaces"][0]

    def test_interface_with_mgmt_only_true_included(self):
        iface = _dotdict(
            id=11,
            name="mgmt0",
            type="1000base-t",
            label="",
            description="",
            mgmt_only=True,
            enabled=True,
            poe_mode=None,
            poe_type=None,
            rf_role=None,
            device_type=_dotdict(id=1),
        )
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        result = serialize_device_type(record, {1: {"interface_templates": [iface]}})
        assert result["interfaces"][0]["mgmt_only"] is True

    def test_float_u_height_coerced_to_int(self):
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1.0,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        result = serialize_device_type(record, {})
        assert result["u_height"] == 1
        assert isinstance(result["u_height"], int)

    def test_weight_as_numeric_string_coerced_to_float(self):
        """NetBox returns weight as a quoted decimal string e.g. '13.60' — must become float."""
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight="13.60",
            weight_unit="kg",
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        result = serialize_device_type(record, {})
        assert result["weight"] == 13.6
        assert isinstance(result["weight"], float)

    def test_weight_as_integer_string_coerced_to_int(self):
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight="14.00",
            weight_unit="kg",
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        result = serialize_device_type(record, {})
        assert result["weight"] == 14
        assert isinstance(result["weight"], int)

    def test_key_order(self):
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number="PN",
            airflow="front-to-rear",
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        result = serialize_device_type(record, {})
        keys = list(result.keys())
        assert keys.index("manufacturer") < keys.index("model")
        assert keys.index("model") < keys.index("slug")


class TestSerializeModuleType:
    """Tests for serialize_module_type function."""

    def test_minimal_fields(self):
        record = _dotdict(
            id=5,
            model="MyModule",
            manufacturer=_make_mfr(),
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
        )
        result = serialize_module_type(record, components_by_mt_id={})
        assert result["manufacturer"] == "Acme"
        assert result["model"] == "MyModule"
        assert "slug" not in result  # module types have no slug field
        assert "part_number" not in result

    def test_optional_fields(self):
        record = _dotdict(
            id=5,
            model="MyModule",
            manufacturer=_make_mfr(),
            part_number="MP-1",
            airflow="front-to-rear",
            weight=2.5,
            weight_unit="kg",
            description="desc",
            comments="comment",
        )
        result = serialize_module_type(record, {})
        assert result["part_number"] == "MP-1"
        assert result["airflow"] == "front-to-rear"


class TestSerializeRackType:
    """Tests for serialize_rack_type function."""

    def test_minimal_fields(self):
        record = _dotdict(
            id=7,
            model="MyRack",
            slug="acme-myrack",
            manufacturer=_make_mfr(),
            form_factor="4-post-cabinet",
            width=19,
            u_height=42,
            starting_unit=1,
            outer_width=None,
            outer_height=None,
            outer_depth=None,
            outer_unit=None,
            mounting_depth=None,
            weight=None,
            max_weight=None,
            weight_unit=None,
            desc_units=False,
            comments="",
            description="",
        )
        result = serialize_rack_type(record)
        assert result["manufacturer"] == "Acme"
        assert result["model"] == "MyRack"
        assert result["slug"] == "acme-myrack"
        assert result["form_factor"] == "4-post-cabinet"
        assert result["u_height"] == 42
        assert "outer_width" not in result
        assert result["desc_units"] is False

    def test_desc_units_true_included(self):
        record = _dotdict(
            id=7,
            model="R",
            slug="acme-r",
            manufacturer=_make_mfr(),
            form_factor="4-post-cabinet",
            width=19,
            u_height=10,
            starting_unit=1,
            outer_width=None,
            outer_height=None,
            outer_depth=None,
            outer_unit=None,
            mounting_depth=None,
            weight=None,
            max_weight=None,
            weight_unit=None,
            desc_units=True,
            comments="",
            description="",
        )
        result = serialize_rack_type(record)
        assert result["desc_units"] is True


def test_coerce_numeric_leaves_invalid_decimal_string_unchanged():
    assert _coerce_numeric("12.3.4") == "12.3.4"


class TestManufacturerSerialization:
    """Tests for manufacturer serialized as plain name string."""

    def test_device_type_manufacturer_as_name_string(self):
        record = _dotdict(
            id=1,
            model="My Switch",
            slug="acme-my-switch",
            manufacturer=_make_mfr("Nokia", "nokia"),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        result = serialize_device_type(record, components_by_dt_id={})
        assert result["manufacturer"] == "Nokia"

    def test_module_type_manufacturer_as_name_string(self):
        record = _dotdict(
            id=5,
            model="MyModule",
            manufacturer=_make_mfr("Arista", "arista"),
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
        )
        result = serialize_module_type(record, components_by_mt_id={})
        assert result["manufacturer"] == "Arista"

    def test_rack_type_manufacturer_as_name_string(self):
        record = _dotdict(
            id=7,
            model="MyRack",
            slug="acme-myrack",
            manufacturer=_make_mfr("Cisco", "cisco"),
            form_factor="4-post-cabinet",
            width=19,
            u_height=42,
            starting_unit=1,
            outer_width=None,
            outer_height=None,
            outer_depth=None,
            outer_unit=None,
            mounting_depth=None,
            weight=None,
            max_weight=None,
            weight_unit=None,
            desc_units=False,
            comments="",
            description="",
        )
        result = serialize_rack_type(record)
        assert result["manufacturer"] == "Cisco"


class TestFrontPortSerialization:
    """Tests for front port rear_port extraction."""

    def test_front_port_rear_port_extracted_from_mapping(self):
        from types import SimpleNamespace

        mapping = SimpleNamespace(rear_port=SimpleNamespace(name="RP1"), rear_port_position=1)
        fp = SimpleNamespace(name="FP1", type="8p8c", label="", description="", color="", mappings=[mapping])
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        components = {1: {"front_port_templates": [fp]}}
        result = serialize_device_type(record, components)
        assert result["front-ports"][0]["rear_port"] == "RP1"
        assert "rear_port_position" not in result["front-ports"][0]

    def test_front_port_rear_port_position_included_when_gt_1(self):
        from types import SimpleNamespace

        mapping = SimpleNamespace(rear_port=SimpleNamespace(name="RP1"), rear_port_position=3)
        fp = SimpleNamespace(name="FP1", type="8p8c", label="", description="", color="", mappings=[mapping])
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        components = {1: {"front_port_templates": [fp]}}
        result = serialize_device_type(record, components)
        assert result["front-ports"][0]["rear_port_position"] == 3

    def test_front_port_rear_port_position_zero_omitted(self):
        """Position 0 is not a valid DTL value and should be omitted."""
        from types import SimpleNamespace

        mapping = SimpleNamespace(rear_port=SimpleNamespace(name="RP1"), rear_port_position=0)
        fp = SimpleNamespace(name="FP1", type="8p8c", label="", description="", color="", mappings=[mapping])
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        components = {1: {"front_port_templates": [fp]}}
        result = serialize_device_type(record, components)
        assert "rear_port_position" not in result["front-ports"][0]

    def test_front_port_multiple_mappings_warns_and_uses_first(self):
        """When a front port has >1 mappings a UserWarning is raised and only the first is used."""
        import warnings
        from types import SimpleNamespace

        m1 = SimpleNamespace(rear_port=SimpleNamespace(name="RP1"), rear_port_position=1)
        m2 = SimpleNamespace(rear_port=SimpleNamespace(name="RP2"), rear_port_position=1)
        fp = SimpleNamespace(name="FP1", type="8p8c", label="", description="", color="", mappings=[m1, m2])
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        components = {1: {"front_port_templates": [fp]}}
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = serialize_device_type(record, components)
        assert result["front-ports"][0]["rear_port"] == "RP1"
        assert len(caught) == 1
        assert issubclass(caught[0].category, UserWarning)
        assert "FP1" in str(caught[0].message)
        assert "2 mappings" in str(caught[0].message)
        assert "issue #78" in str(caught[0].message)

    def test_front_port_legacy_rear_port_scalars(self):
        """pre-4.5 NetBox: record has rear_port/rear_port_position as direct attrs (no mappings)."""
        from types import SimpleNamespace

        fp = SimpleNamespace(
            name="FP1",
            type="8p8c",
            label="",
            description="",
            color="",
            mappings=None,
            rear_port=SimpleNamespace(name="RP1"),
            rear_port_position=3,
        )
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        components = {1: {"front_port_templates": [fp]}}
        result = serialize_device_type(record, components)
        assert result["front-ports"][0]["rear_port"] == "RP1"
        assert result["front-ports"][0]["rear_port_position"] == 3

    def test_front_port_legacy_rear_port_position_1_omitted(self):
        """pre-4.5: rear_port_position == 1 should be omitted (same as mappings path)."""
        from types import SimpleNamespace

        fp = SimpleNamespace(
            name="FP1",
            type="8p8c",
            label="",
            description="",
            color="",
            mappings=None,
            rear_port=SimpleNamespace(name="RP1"),
            rear_port_position=1,
        )
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        components = {1: {"front_port_templates": [fp]}}
        result = serialize_device_type(record, components)
        assert result["front-ports"][0]["rear_port"] == "RP1"
        assert "rear_port_position" not in result["front-ports"][0]

    def test_components_sorted_by_name(self):
        from types import SimpleNamespace

        iface_z = SimpleNamespace(
            name="eth9",
            type="1000base-t",
            label="",
            description="",
            mgmt_only=False,
            enabled=True,
            poe_mode=None,
            poe_type=None,
            rf_role=None,
        )
        iface_a = SimpleNamespace(
            name="eth0",
            type="1000base-t",
            label="",
            description="",
            mgmt_only=False,
            enabled=True,
            poe_mode=None,
            poe_type=None,
            rf_role=None,
        )
        record = _dotdict(
            id=1,
            model="X",
            slug="acme-x",
            manufacturer=_make_mfr(),
            u_height=1,
            is_full_depth=True,
            part_number=None,
            airflow=None,
            weight=None,
            weight_unit=None,
            description="",
            comments="",
            subdevice_role=None,
            front_image=None,
            rear_image=None,
        )
        components = {1: {"interface_templates": [iface_z, iface_a]}}
        result = serialize_device_type(record, components)
        names = [i["name"] for i in result["interfaces"]]
        assert names == sorted(names)
