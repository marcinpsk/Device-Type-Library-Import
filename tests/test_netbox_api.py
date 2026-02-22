import pytest
from unittest.mock import MagicMock, patch
from netbox_api import NetBox, DeviceTypes
from helpers import paginate_dispatch

# All component list keys used by the GraphQL client for empty-response fallback.
_ALL_COMPONENT_KEYS = [
    "interface_template_list",
    "power_port_template_list",
    "console_port_template_list",
    "console_server_port_template_list",
    "power_outlet_template_list",
    "rear_port_template_list",
    "front_port_template_list",
    "device_bay_template_list",
    "module_bay_template_list",
]


def _make_graphql_dispatch(payloads_by_list_key):
    """Return a ``requests.post`` side-effect that dispatches by GraphQL list key.

    *payloads_by_list_key* maps a GraphQL list key (e.g. ``"device_type_list"``)
    to its full ``{"data": {...}}`` response dict.  Subsequent pages (offset > 0)
    always return empty data.  Any component endpoint not in the mapping returns
    ``{"data": {key: []}}``.
    """

    def _detect_list_key(query):
        """Extract the GraphQL list key from the query string."""
        all_keys = list(payloads_by_list_key.keys()) + _ALL_COMPONENT_KEYS
        return next((k for k in all_keys if k in query), "unknown_list")

    def dispatch(url, json=None, **kwargs):
        query = (json or {}).get("query", "")
        variables = (json or {}).get("variables", {})
        offset = (variables.get("pagination") or {}).get("offset", 0)
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        if offset > 0:
            list_key = _detect_list_key(query)
            resp.json.return_value = {"data": {list_key: []}}
            return resp
        for key, payload in payloads_by_list_key.items():
            if key in query:
                resp.json.return_value = payload
                return resp
        # Fall back: detect a known component key and return empty list
        key = next((k for k in _ALL_COMPONENT_KEYS if k in query), "unknown_list")
        resp.json.return_value = {"data": {key: []}}
        return resp

    return dispatch


@pytest.fixture
def mock_settings():
    settings = MagicMock()
    settings.NETBOX_URL = "http://mock-netbox"
    settings.NETBOX_TOKEN = "mock-token"
    settings.IGNORE_SSL_ERRORS = False
    settings.GRAPHQL_PAGE_SIZE = 5000
    settings.PRELOAD_THREADS = 8
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


def test_create_manufacturers_no_new_is_verbose_only(mock_settings, mock_pynetbox, mock_graphql_requests):
    mock_pynetbox.api.return_value.version = "3.5"

    mock_graphql_requests.side_effect = paginate_dispatch(
        {
            "manufacturer_list": [{"id": "1", "name": "Cisco", "slug": "cisco"}],
            "device_type_list": [],
        }
    )

    nb = NetBox(mock_settings, mock_settings.handle)
    mock_settings.handle.log.reset_mock()
    mock_settings.handle.verbose_log.reset_mock()

    nb.create_manufacturers([{"name": "Cisco", "slug": "cisco"}])

    nb.netbox.dcim.manufacturers.create.assert_not_called()
    mock_settings.handle.verbose_log.assert_any_call("No new manufacturers to create.")
    mock_settings.handle.log.assert_not_called()


def test_device_types_create_interfaces(mock_settings, mock_pynetbox, graphql_client):
    # Setup
    mock_nb_api = mock_pynetbox.api.return_value
    mock_settings.handle = MagicMock()
    mock_counter = MagicMock()

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, mock_counter, False, False, graphql=graphql_client)

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


def test_preload_global_builds_component_cache(mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client):
    mock_nb_api = mock_pynetbox.api.return_value

    mock_graphql_requests.side_effect = _make_graphql_dispatch(
        {
            "device_type_list": {
                "data": {
                    "device_type_list": [
                        {
                            "id": "1",
                            "model": "ModelA",
                            "slug": "model-a",
                            "manufacturer": {"id": "10", "name": "Cisco", "slug": "cisco"},
                            "front_image": None,
                            "rear_image": None,
                        }
                    ]
                }
            },
            "interface_template_list": {
                "data": {
                    "interface_template_list": [
                        {
                            "id": "100",
                            "name": "eth0",
                            "type": "1000base-t",
                            "label": "",
                            "mgmt_only": False,
                            "enabled": True,
                            "poe_mode": None,
                            "poe_type": None,
                            "device_type": {"id": "1"},
                            "module_type": None,
                        }
                    ]
                }
            },
        }
    )

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
    dt.preload_all_components(progress_wrapper=None)

    assert "interface_templates" in dt.cached_components
    assert ("device", 1) in dt.cached_components["interface_templates"]
    assert dt.cached_components["interface_templates"][("device", 1)]["eth0"].name == "eth0"


def test_fetch_global_endpoint_records_uses_graphql(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client
):
    mock_nb_api = mock_pynetbox.api.return_value

    mock_graphql_requests.side_effect = _make_graphql_dispatch(
        {
            "device_type_list": {"data": {"device_type_list": []}},
            "interface_template_list": {
                "data": {
                    "interface_template_list": [
                        {
                            "id": "1",
                            "name": "xe-0/0/0",
                            "type": "10gbase-x-sfpp",
                            "label": "",
                            "mgmt_only": False,
                            "enabled": True,
                            "poe_mode": None,
                            "poe_type": None,
                            "device_type": {"id": "5"},
                            "module_type": None,
                        },
                        {
                            "id": "2",
                            "name": "xe-0/0/1",
                            "type": "10gbase-x-sfpp",
                            "label": "",
                            "mgmt_only": False,
                            "enabled": True,
                            "poe_mode": None,
                            "poe_type": None,
                            "device_type": {"id": "5"},
                            "module_type": None,
                        },
                        {
                            "id": "3",
                            "name": "xe-0/0/2",
                            "type": "10gbase-x-sfpp",
                            "label": "",
                            "mgmt_only": False,
                            "enabled": True,
                            "poe_mode": None,
                            "poe_type": None,
                            "device_type": {"id": "5"},
                            "module_type": None,
                        },
                    ]
                }
            },
        }
    )

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
    updates = []

    records = dt._fetch_global_endpoint_records(
        "interface_templates",
        progress_callback=lambda endpoint, advance: updates.append((endpoint, advance)),
        expected_total=3,
    )

    assert len(records) == 3
    assert records[0].name == "xe-0/0/0"
    # REST endpoint should NOT be called
    mock_nb_api.dcim.interface_templates.all.assert_not_called()
    assert updates == [("interface_templates", 3)]


def test_fetch_global_endpoint_records_progress_skipped_when_empty(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client
):
    mock_nb_api = mock_pynetbox.api.return_value

    mock_graphql_requests.side_effect = _make_graphql_dispatch(
        {
            "device_type_list": {"data": {"device_type_list": []}},
            "interface_template_list": {"data": {"interface_template_list": []}},
        }
    )

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
    updates = []

    fetched = dt._fetch_global_endpoint_records(
        "interface_templates",
        progress_callback=lambda endpoint, advance: updates.append((endpoint, advance)),
        expected_total=0,
    )

    assert fetched == []
    assert updates == []


def test_preload_always_global_caches_all_vendors(mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client):
    """Preload always fetches all components globally, regardless of vendor filter."""
    mock_nb_api = mock_pynetbox.api.return_value

    mock_graphql_requests.side_effect = _make_graphql_dispatch(
        {
            "device_type_list": {
                "data": {
                    "device_type_list": [
                        {
                            "id": "1",
                            "model": "ModelA",
                            "slug": "model-a",
                            "manufacturer": {"id": "10", "name": "Cisco", "slug": "cisco"},
                            "front_image": None,
                            "rear_image": None,
                        },
                        {
                            "id": "2",
                            "model": "ModelB",
                            "slug": "model-b",
                            "manufacturer": {"id": "20", "name": "Juniper", "slug": "juniper"},
                            "front_image": None,
                            "rear_image": None,
                        },
                    ]
                }
            },
            "interface_template_list": {
                "data": {
                    "interface_template_list": [
                        {
                            "id": "100",
                            "name": "eth0",
                            "type": "1000base-t",
                            "label": "",
                            "mgmt_only": False,
                            "enabled": True,
                            "poe_mode": None,
                            "poe_type": None,
                            "device_type": {"id": "1"},
                            "module_type": None,
                        },
                        {
                            "id": "200",
                            "name": "xe-0/0/0",
                            "type": "10gbase-x-sfpp",
                            "label": "",
                            "mgmt_only": False,
                            "enabled": True,
                            "poe_mode": None,
                            "poe_type": None,
                            "device_type": {"id": "2"},
                            "module_type": None,
                        },
                    ]
                }
            },
        }
    )

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
    dt.preload_all_components(progress_wrapper=None)

    # Both vendors are cached because global fetch returns everything
    assert ("device", 1) in dt.cached_components["interface_templates"]
    assert ("device", 2) in dt.cached_components["interface_templates"]


def test_start_component_preload_global_job_can_be_consumed(mock_settings, mock_pynetbox, graphql_client):
    mock_nb_api = mock_pynetbox.api.return_value

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
    preload_job = dt.start_component_preload()

    assert preload_job["mode"] == "global"
    dt.preload_all_components(progress_wrapper=None, preload_job=preload_job)
    assert preload_job["executor"] is None


def test_upload_images_success_logs_verbose_only(mock_settings, mock_pynetbox, graphql_client, tmp_path):
    mock_nb_api = mock_pynetbox.api.return_value

    image_file = tmp_path / "front.jpg"
    image_file.write_bytes(b"fake")

    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
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
    module_types = [
        {"manufacturer": {"slug": "cisco"}, "model": "A"},  # found by model
        {"manufacturer": {"slug": "cisco"}, "model": "B"},  # not found → new
        {"manufacturer": {"slug": "juniper"}, "model": "X"},  # not found → new
    ]
    existing = {"cisco": {"A": existing_a}}

    filtered = NetBox.filter_new_module_types(module_types, existing)

    assert filtered == [
        {"manufacturer": {"slug": "cisco"}, "model": "B"},
        {"manufacturer": {"slug": "juniper"}, "model": "X"},
    ]


def test_filter_actionable_module_types_skips_unchanged_existing_module(
    mock_settings, mock_pynetbox, mock_graphql_requests
):
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.version = "3.5"

    mock_graphql_requests.side_effect = paginate_dispatch(
        {
            "manufacturer_list": [],
            "device_type_list": [],
            "module_type_list": [
                {
                    "id": "42",
                    "model": "Linecard 1",
                    "manufacturer": {"id": "20", "name": "Juniper", "slug": "juniper"},
                }
            ],
            "image_attachment_list": [],
        }
    )

    existing_interface = MagicMock()
    existing_interface.name = "xe-0/0/0"
    existing_interface.module_type.id = 42
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


def test_filter_actionable_module_types_includes_module_with_missing_component(
    mock_settings, mock_pynetbox, mock_graphql_requests
):
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.version = "3.5"

    mock_graphql_requests.side_effect = paginate_dispatch(
        {
            "manufacturer_list": [],
            "device_type_list": [],
            "module_type_list": [
                {
                    "id": "42",
                    "model": "Linecard 1",
                    "manufacturer": {"id": "20", "name": "Juniper", "slug": "juniper"},
                }
            ],
            "image_attachment_list": [],
        }
    )

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


def test_update_components_m2m_front_port_position(mock_settings, mock_pynetbox, graphql_client):
    """On NetBox 4.5+, rear_port_position updates should use the M2M rear_ports array format."""
    from change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
    dt.m2m_front_ports = True

    # Simulate an existing front port with M2M mapping.
    # Delete _record so getattr(comp, "_record", comp) falls through to comp itself.
    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"
    del existing_fp._record
    mapping = MagicMock()
    mapping.position = 1
    mapping.rear_port_position = 1
    rp = MagicMock()
    rp.id = 99
    mapping.rear_port = rp
    existing_fp.rear_ports = [mapping]

    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
    }

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("rear_port_position", 1, 2)],
        ),
    ]

    endpoint = mock_nb_api.dcim.front_port_templates
    dt.update_components({}, 1, changes, parent_type="device")

    endpoint.update.assert_called_once()
    update_payload = endpoint.update.call_args[0][0][0]
    assert update_payload["id"] == 10
    assert "rear_port_position" not in update_payload, "Should not have flat rear_port_position"
    assert update_payload["rear_ports"] == [{"position": 1, "rear_port": 99, "rear_port_position": 2}]


def test_update_components_m2m_no_mapping_warns(mock_settings, mock_pynetbox, graphql_client):
    """On NetBox 4.5+, a rear_port_position update with no existing M2M mapping should warn, not update."""
    from change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
    dt.m2m_front_ports = True

    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"
    del existing_fp._record
    existing_fp.rear_ports = []  # No M2M mapping

    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
    }

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("rear_port_position", 1, 2)],
        ),
    ]

    endpoint = mock_nb_api.dcim.front_port_templates
    mock_settings.handle.log.reset_mock()
    dt.update_components({}, 1, changes, parent_type="device")

    endpoint.update.assert_not_called()
    mock_settings.handle.log.assert_any_call(
        'Cannot update rear_port_position for "FP1" — no existing M2M mapping found.'
    )
