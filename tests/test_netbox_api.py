import pytest
from unittest.mock import MagicMock, patch
from netbox_api import NetBox, DeviceTypes


@pytest.fixture
def mock_settings():
    settings = MagicMock()
    settings.NETBOX_URL = "http://mock-netbox"
    settings.NETBOX_TOKEN = "mock-token"
    settings.IGNORE_SSL_ERRORS = False
    settings.handle = MagicMock()
    return settings


def test_netbox_init(mock_settings, mock_pynetbox):
    # Mock api call
    mock_pynetbox.api.return_value.version = "3.5"

    nb = NetBox(mock_settings, mock_settings.handle)
    assert nb.url == "http://mock-netbox"
    assert nb.token == "mock-token"
    # Verify module support detection
    assert nb.modules


def test_netbox_version_check(mock_settings, mock_pynetbox):
    # Test 5.0
    mock_pynetbox.api.return_value.version = "5.0"
    nb = NetBox(mock_settings, mock_settings.handle)
    assert nb.new_filters

    # Test 4.0
    mock_pynetbox.api.return_value.version = "4.0"
    nb = NetBox(mock_settings, mock_settings.handle)
    assert not nb.new_filters

    # Test 4.1
    mock_pynetbox.api.return_value.version = "4.1"
    nb = NetBox(mock_settings, mock_settings.handle)
    assert nb.new_filters


def test_create_manufacturers(mock_settings, mock_pynetbox):
    mock_pynetbox.api.return_value.version = "3.5"
    mock_pynetbox.api.return_value.dcim.manufacturers.all.return_value = []

    nb = NetBox(mock_settings, mock_settings.handle)

    vendors = [{"name": "Cisco", "slug": "cisco"}]
    nb.create_manufacturers(vendors)

    # Check if create was called
    nb.netbox.dcim.manufacturers.create.assert_called_with(vendors)


def test_create_manufacturers_no_new_is_verbose_only(mock_settings, mock_pynetbox):
    mock_pynetbox.api.return_value.version = "3.5"

    existing = MagicMock()
    existing.name = "Cisco"
    existing.slug = "cisco"
    mock_pynetbox.api.return_value.dcim.manufacturers.all.return_value = [existing]

    nb = NetBox(mock_settings, mock_settings.handle)
    mock_settings.handle.log.reset_mock()
    mock_settings.handle.verbose_log.reset_mock()

    nb.create_manufacturers([{"name": "Cisco", "slug": "cisco"}])

    nb.netbox.dcim.manufacturers.create.assert_not_called()
    mock_settings.handle.verbose_log.assert_any_call("No new manufacturers to create.")
    mock_settings.handle.log.assert_not_called()


def test_device_types_create_interfaces(mock_settings, mock_pynetbox):
    # Setup
    mock_nb_api = mock_pynetbox.api.return_value
    mock_settings.handle = MagicMock()
    mock_counter = MagicMock()

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, mock_counter, False, False)

    # Mock existing interfaces returns empty list
    mock_nb_api.dcim.interface_templates.filter.return_value = []

    interfaces = [{"name": "GigabitEthernet1", "type": "virtual"}]
    dt.create_interfaces(interfaces, device_type=1)

    # Verify create called
    call_args = mock_nb_api.dcim.interface_templates.create.call_args[0][0]
    assert len(call_args) == 1
    assert call_args[0]["name"] == "GigabitEthernet1"
    assert call_args[0]["device_type"] == 1


def test_redundant_image_upload(mock_settings, mock_pynetbox):
    # Setup
    mock_settings.handle = MagicMock()
    # Ensure modules check doesn't fail
    mock_pynetbox.api.return_value.version = "3.5"

    nb = NetBox(mock_settings, mock_settings.handle)
    nb.device_types = MagicMock()

    # Mock existing device type with an image
    mock_dt = MagicMock()
    mock_dt.id = 1
    mock_dt.model = "Test Model"
    mock_dt.manufacturer.name = "Test Manufacturer"
    # Simulate pynetbox returning an image object or string url
    mock_dt.front_image = "http://netbox/media/devicetypes/front_image.jpg"
    nb.device_types.existing_device_types = {("test-manufacturer", "Test Model"): mock_dt}
    nb.device_types.existing_device_types_by_slug = {("test-manufacturer", "test-model"): mock_dt}

    # Mock file glob to find a local image
    with patch("glob.glob", return_value=["/path/to/image.jpg"]):
        device_type_payload = {
            "manufacturer": {"slug": "test-manufacturer"},
            "model": "Test Model",
            "slug": "test-model",
            "front_image": True,  # triggers the check to look for local file
        }

        # We invoke create_device_types
        # We need to make sure 'src' key exists as per logic
        device_type_payload["src"] = "/tmp/device-types/test.yaml"

        nb.create_device_types([device_type_payload])

    # Expectation for FIX: upload_images should NOT be called because front_image exists on DT
    # If the bug exists (current state), this assertion will FAIL
    nb.device_types.upload_images.assert_not_called()


def test_preload_global_builds_component_cache(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value

    existing_dt = MagicMock()
    existing_dt.manufacturer.slug = "cisco"
    existing_dt.model = "ModelA"
    existing_dt.slug = "model-a"
    existing_dt.id = 1
    mock_nb_api.dcim.device_types.all.return_value = [existing_dt]

    iface = MagicMock()
    iface.name = "eth0"
    iface.device_type = MagicMock(id=1)
    iface.module_type = None
    mock_nb_api.dcim.interface_templates.all.return_value = [iface]

    for endpoint in [
        "power_port_templates",
        "console_port_templates",
        "console_server_port_templates",
        "power_outlet_templates",
        "rear_port_templates",
        "front_port_templates",
        "device_bay_templates",
        "module_bay_templates",
    ]:
        getattr(mock_nb_api.dcim, endpoint).all.return_value = []

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False)
    dt.preload_all_components(progress_wrapper=None)

    assert "interface_templates" in dt.cached_components
    assert ("device", 1) in dt.cached_components["interface_templates"]
    assert dt.cached_components["interface_templates"][("device", 1)]["eth0"] is iface


def test_fetch_global_endpoint_records_streams_from_all(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.dcim.device_types.all.return_value = []

    first = MagicMock()
    first.name = "xe-0/0/0"
    second = MagicMock()
    second.name = "xe-0/0/1"
    third = MagicMock()
    third.name = "xe-0/0/2"

    mock_nb_api.dcim.interface_templates.all.return_value = [first, second, third]

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False)
    updates = []

    records = dt._fetch_global_endpoint_records(
        "interface_templates",
        progress_callback=lambda endpoint, advance: updates.append((endpoint, advance)),
        expected_total=3,
    )

    assert records == [first, second, third]
    mock_nb_api.dcim.interface_templates.filter.assert_not_called()
    mock_nb_api.dcim.interface_templates.all.assert_called_once()
    assert updates == [("interface_templates", 3)]


def test_fetch_global_endpoint_records_falls_back_to_all_iteration(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.dcim.device_types.all.return_value = []

    records = []
    for idx in range(120):
        item = MagicMock()
        item.name = f"item-{idx}"
        records.append(item)
    mock_nb_api.dcim.interface_templates.all.return_value = records

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False)
    updates = []

    fetched = dt._fetch_global_endpoint_records(
        "interface_templates",
        progress_callback=lambda endpoint, advance: updates.append((endpoint, advance)),
        expected_total=0,
    )

    assert fetched == records
    assert updates
    assert all(endpoint == "interface_templates" for endpoint, _advance in updates)
    assert sum(advance for _endpoint, advance in updates) == 120


def test_preload_scoped_uses_vendor_subset(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value

    cisco_dt = MagicMock()
    cisco_dt.manufacturer.slug = "cisco"
    cisco_dt.model = "ModelA"
    cisco_dt.slug = "model-a"
    cisco_dt.id = 1

    juniper_dt = MagicMock()
    juniper_dt.manufacturer.slug = "juniper"
    juniper_dt.model = "ModelB"
    juniper_dt.slug = "model-b"
    juniper_dt.id = 2

    mock_nb_api.dcim.device_types.all.return_value = [cisco_dt, juniper_dt]

    iface_cisco = MagicMock()
    iface_cisco.name = "eth0"

    def interface_filter(**kwargs):
        return [iface_cisco] if kwargs.get("devicetype_id") == 1 else []

    mock_nb_api.dcim.interface_templates.filter.side_effect = interface_filter

    for endpoint in [
        "power_port_templates",
        "console_port_templates",
        "console_server_port_templates",
        "power_outlet_templates",
        "rear_port_templates",
        "front_port_templates",
        "device_bay_templates",
        "module_bay_templates",
    ]:
        getattr(mock_nb_api.dcim, endpoint).filter.return_value = []

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False)
    dt.preload_all_components(progress_wrapper=None, vendor_slugs=["cisco"])

    assert ("device", 1) in dt.cached_components["interface_templates"]
    assert ("device", 2) not in dt.cached_components["interface_templates"]


def test_resolve_existing_device_type_ids_uses_model_and_slug(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value

    by_model = MagicMock()
    by_model.manufacturer.slug = "juniper"
    by_model.model = "MX480"
    by_model.slug = "mx480"
    by_model.id = 10

    by_slug = MagicMock()
    by_slug.manufacturer.slug = "juniper"
    by_slug.model = "MX204"
    by_slug.slug = "mx204"
    by_slug.id = 20

    mock_nb_api.dcim.device_types.all.return_value = [by_model, by_slug]

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False)
    parsed = [
        {"manufacturer": {"slug": "juniper"}, "model": "MX480", "slug": "mx480"},
        {"manufacturer": {"slug": "juniper"}, "model": "MX204-Renamed", "slug": "mx204"},
        {"manufacturer": {"slug": "juniper"}, "model": "NewDevice", "slug": "newdevice"},
    ]

    ids = dt.resolve_existing_device_type_ids(parsed)

    assert ids == {10, 20}


def test_preload_explicit_ids_override_vendor_scope(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value

    cisco_dt = MagicMock()
    cisco_dt.manufacturer.slug = "cisco"
    cisco_dt.model = "ModelA"
    cisco_dt.slug = "model-a"
    cisco_dt.id = 1

    juniper_dt = MagicMock()
    juniper_dt.manufacturer.slug = "juniper"
    juniper_dt.model = "ModelB"
    juniper_dt.slug = "model-b"
    juniper_dt.id = 2

    mock_nb_api.dcim.device_types.all.return_value = [cisco_dt, juniper_dt]

    iface_juniper = MagicMock()
    iface_juniper.name = "xe-0/0/0"

    def interface_filter(**kwargs):
        return [iface_juniper] if kwargs.get("devicetype_id") == 2 else []

    mock_nb_api.dcim.interface_templates.filter.side_effect = interface_filter

    for endpoint in [
        "power_port_templates",
        "console_port_templates",
        "console_server_port_templates",
        "power_outlet_templates",
        "rear_port_templates",
        "front_port_templates",
        "device_bay_templates",
        "module_bay_templates",
    ]:
        getattr(mock_nb_api.dcim, endpoint).filter.return_value = []

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False)
    dt.preload_all_components(progress_wrapper=None, vendor_slugs=["cisco"], device_type_ids={2})

    assert ("device", 2) in dt.cached_components["interface_templates"]
    assert ("device", 1) not in dt.cached_components["interface_templates"]


def test_start_component_preload_global_job_can_be_consumed(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.dcim.device_types.all.return_value = []

    for endpoint in [
        "interface_templates",
        "power_port_templates",
        "console_port_templates",
        "console_server_port_templates",
        "power_outlet_templates",
        "rear_port_templates",
        "front_port_templates",
        "device_bay_templates",
        "module_bay_templates",
    ]:
        getattr(mock_nb_api.dcim, endpoint).all.return_value = []

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False)
    preload_job = dt.start_component_preload()

    assert preload_job["mode"] == "global"
    dt.preload_all_components(progress_wrapper=None, preload_job=preload_job)
    assert preload_job["executor"] is None


def test_upload_images_success_logs_verbose_only(mock_settings, mock_pynetbox, tmp_path):
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.dcim.device_types.all.return_value = []

    image_file = tmp_path / "front.jpg"
    image_file.write_bytes(b"fake")

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False)
    mock_settings.handle.log.reset_mock()
    mock_settings.handle.verbose_log.reset_mock()

    with patch("netbox_api.requests.patch") as mock_patch:
        response = MagicMock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        mock_patch.return_value = response

        dt.upload_images("http://mock-netbox", "token", {"front_image": str(image_file)}, 123)

    assert any("Images" in call.args[0] for call in mock_settings.handle.verbose_log.call_args_list)
    mock_settings.handle.log.assert_not_called()


def test_filter_new_module_types_returns_only_missing_items(mock_settings, mock_pynetbox):
    existing_a = MagicMock()
    existing_a.slug = "a"
    module_types = [
        {"manufacturer": {"slug": "cisco"}, "model": "A-Renamed", "slug": "a"},
        {"manufacturer": {"slug": "cisco"}, "model": "B"},
        {"manufacturer": {"slug": "juniper"}, "model": "X"},
    ]
    existing = {"cisco": {"A": existing_a}}

    filtered = NetBox.filter_new_module_types(module_types, existing)

    assert filtered == [
        {"manufacturer": {"slug": "cisco"}, "model": "B"},
        {"manufacturer": {"slug": "juniper"}, "model": "X"},
    ]


def test_filter_actionable_module_types_skips_unchanged_existing_module(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.version = "3.5"

    existing_module = MagicMock()
    existing_module.id = 42
    existing_module.model = "Linecard 1"
    existing_module.slug = "linecard-1"
    existing_module.manufacturer.slug = "juniper"

    existing_interface = MagicMock()
    existing_interface.name = "xe-0/0/0"
    existing_interface.module_type.id = 42

    mock_nb_api.dcim.module_types.all.return_value = [existing_module]
    mock_nb_api.extras.image_attachments.filter.return_value = []
    mock_nb_api.dcim.interface_templates.filter.return_value = [existing_interface]

    nb = NetBox(mock_settings, mock_settings.handle)
    module_types = [
        {
            "manufacturer": {"slug": "juniper"},
            "model": "Linecard 1",
            "slug": "linecard-1",
            "interfaces": [{"name": "xe-0/0/0"}],
            "src": "/tmp/repo/module-types/juniper/linecard-1.yaml",
        }
    ]

    with patch("glob.glob", return_value=[]):
        actionable, _ = nb.filter_actionable_module_types(
            module_types,
            nb.get_existing_module_types(),
            only_new=False,
        )

    assert actionable == []


def test_filter_actionable_module_types_includes_module_with_missing_component(mock_settings, mock_pynetbox):
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.version = "3.5"

    existing_module = MagicMock()
    existing_module.id = 42
    existing_module.model = "Linecard 1"
    existing_module.slug = "linecard-1"
    existing_module.manufacturer.slug = "juniper"

    mock_nb_api.dcim.module_types.all.return_value = [existing_module]
    mock_nb_api.extras.image_attachments.filter.return_value = []
    mock_nb_api.dcim.interface_templates.filter.return_value = []

    nb = NetBox(mock_settings, mock_settings.handle)
    module_type = {
        "manufacturer": {"slug": "juniper"},
        "model": "Linecard 1",
        "slug": "linecard-1",
        "interfaces": [{"name": "xe-0/0/0"}],
        "src": "/tmp/repo/module-types/juniper/linecard-1.yaml",
    }

    with patch("glob.glob", return_value=[]):
        actionable, _ = nb.filter_actionable_module_types(
            [module_type],
            nb.get_existing_module_types(),
            only_new=False,
        )

    assert actionable == [module_type]
