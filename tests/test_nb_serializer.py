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
    """Front port scalars. The rear-port linkage lives in TestPortMappingsStanza."""

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


class TestRelationSerialization:
    """A module bay's restriction has to survive the trip back out to YAML."""

    @staticmethod
    def _bay(name, module_bay_types=None, **extra):
        """Build a module bay template as the GraphQL query returns it."""
        return _dotdict(
            name=name,
            position=None,
            label="",
            description="",
            module_bay_types=module_bay_types,
            **extra,
        )

    def test_a_bay_exports_the_names_of_its_classes(self):
        record = _dotdict(id=1, model="MX304", manufacturer=_make_mfr(), part_number=None)
        bay = self._bay("FPC 0", [_dotdict(id=9, name="MX304-LMIC"), _dotdict(id=8, name="QSFP-DD")])

        result = serialize_module_type(record, {1: {"module_bay_templates": [bay]}})

        assert result["module-bays"] == [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC", "QSFP-DD"]}]

    def test_a_bay_with_no_classes_writes_no_key(self):
        """An empty list here would add the key to every bay in the library.

        See test_an_empty_relation_does_not_make_every_definition_differ for the effect
        that has on the export diff.
        """
        record = _dotdict(id=1, model="MX304", manufacturer=_make_mfr(), part_number=None)

        result = serialize_module_type(record, {1: {"module_bay_templates": [self._bay("FPC 0", [])]}})

        assert result["module-bays"] == [{"name": "FPC 0"}]

    def test_a_server_that_never_returned_the_field_omits_the_key(self):
        """Below 4.7 the relation is not selected, and absent must not become empty."""
        record = _dotdict(id=1, model="MX304", manufacturer=_make_mfr(), part_number=None)
        bay = _dotdict(name="FPC 0", position=None, label="", description="")

        result = serialize_module_type(record, {1: {"module_bay_templates": [bay]}})

        assert result["module-bays"] == [{"name": "FPC 0"}]

    def test_a_module_type_exports_the_classes_it_belongs_to(self):
        record = _dotdict(
            id=5,
            model="JNP304-RE",
            manufacturer=_make_mfr(name="Juniper", slug="juniper"),
            part_number=None,
            module_bay_types=[_dotdict(id=9, name="MX304-RE")],
        )

        assert serialize_module_type(record, {})["module_bay_types"] == ["MX304-RE"]

    def test_a_device_type_bay_exports_its_classes_too(self):
        record = _dotdict(
            id=2, model="MX304", slug="mx304", manufacturer=_make_mfr(), u_height=None, is_full_depth=None
        )
        bay = self._bay("RE0", [_dotdict(id=9, name="MX304-RE")])

        result = serialize_device_type(record, {2: {"module_bay_templates": [bay]}})

        assert result["module-bays"] == [{"name": "RE0", "module_bay_types": ["MX304-RE"]}]


class TestPortMappingsStanza:
    """Export writes the NetBox 4.5 port-mappings stanza the DTL schema now requires."""

    @staticmethod
    def _mapping(rear_port, rear_position=1, front_position=1):
        from types import SimpleNamespace

        return SimpleNamespace(
            rear_port=SimpleNamespace(name=rear_port),
            rear_port_position=rear_position,
            front_port_position=front_position,
        )

    @staticmethod
    def _front_port(name, mappings=None, positions=1, **extra):
        from types import SimpleNamespace

        return SimpleNamespace(
            name=name,
            type="lc-upc",
            label="",
            description="",
            color="",
            positions=positions,
            mappings=mappings or [],
            **extra,
        )

    def _device(self):
        return _dotdict(
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

    def test_a_front_port_carries_positions_and_no_inline_rear_port(self):
        """The schema dropped rear_port from front-port entries and made positions required."""
        fp = self._front_port("FP1", [self._mapping("RP1")], positions=1)

        result = serialize_device_type(self._device(), {1: {"front_port_templates": [fp]}})

        assert result["front-ports"] == [{"name": "FP1", "type": "lc-upc", "positions": 1}]

    def test_every_mapping_reaches_the_stanza_not_just_the_first(self):
        """The issue: a crossover front port mapped to two rear ports lost the second."""
        fp = self._front_port("FP1", [self._mapping("RP1", 1), self._mapping("RP2", 3, front_position=2)], positions=2)

        result = serialize_device_type(self._device(), {1: {"front_port_templates": [fp]}})

        assert result["port-mappings"] == [
            {"front_port": "FP1", "front_port_position": 1, "rear_port": "RP1", "rear_port_position": 1},
            {"front_port": "FP1", "front_port_position": 2, "rear_port": "RP2", "rear_port_position": 3},
        ]

    def test_an_mpo_cassette_maps_every_front_port_to_its_rear_position(self):
        """The shape the library actually carries: many front ports onto one MPO rear port."""
        ports = [self._front_port(f"FP{i}", [self._mapping("MPO1", i)]) for i in (1, 2, 3)]

        result = serialize_device_type(self._device(), {1: {"front_port_templates": ports}})

        assert [(m["front_port"], m["rear_port_position"]) for m in result["port-mappings"]] == [
            ("FP1", 1),
            ("FP2", 2),
            ("FP3", 3),
        ]

    def test_a_pre_45_server_still_exports_its_mappings(self):
        """Below 4.5 NetBox returns rear_port scalars; dropping them would lose the linkage."""
        from types import SimpleNamespace

        fp = SimpleNamespace(
            name="FP1",
            type="8p8c",
            label="",
            description="",
            color="",
            rear_port=SimpleNamespace(name="RP1"),
            rear_port_position=4,
        )

        result = serialize_device_type(self._device(), {1: {"front_port_templates": [fp]}})

        assert result["port-mappings"] == [
            {"front_port": "FP1", "front_port_position": 1, "rear_port": "RP1", "rear_port_position": 4}
        ]

    def test_a_front_port_with_no_mapping_adds_no_stanza(self):
        result = serialize_device_type(self._device(), {1: {"front_port_templates": [self._front_port("FP1")]}})

        assert "port-mappings" not in result

    def test_a_type_without_front_ports_adds_no_stanza(self):
        assert "port-mappings" not in serialize_device_type(self._device(), {1: {}})

    def test_the_importer_reads_back_what_the_export_wrote(self):
        """Serializer to normalizer, both real: the stanza is the seam between them."""
        from core.repo import normalize_port_mappings

        ports = [
            self._front_port("1", [self._mapping("MPO1", 1)]),
            self._front_port("2", [self._mapping("MPO1", 2)]),
        ]
        exported = serialize_device_type(self._device(), {1: {"front_port_templates": ports}})

        assert normalize_port_mappings(exported) is None
        assert [fp["_mappings"] for fp in exported["front-ports"]] == [
            [{"rear_port": "MPO1", "front_port_position": 1, "rear_port_position": 1}],
            [{"rear_port": "MPO1", "front_port_position": 1, "rear_port_position": 2}],
        ]
        assert "port-mappings" not in exported, "the normalizer consumes the stanza"
