import queue
import pytest
from unittest.mock import MagicMock, patch
from core.netbox_api import NetBox, DeviceTypes, _FrontPortRecord45
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

    with patch("core.netbox_api.requests.patch") as mock_patch:
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
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

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
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

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


class TestNetBoxConnectApi:
    """Tests for TestNetBoxConnectApi."""

    def test_ssl_ignore_sets_verify_false(self, mock_settings, mock_pynetbox):
        mock_settings.IGNORE_SSL_ERRORS = True
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        assert nb.netbox.http_session.verify is False

    def test_get_api_returns_netbox(self, mock_settings, mock_pynetbox):
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        assert nb.get_api() is nb.netbox

    def test_get_counter_returns_counter(self, mock_settings, mock_pynetbox):
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        assert nb.get_counter() is nb.counter


class TestCreateManufacturersError:
    """Tests for TestCreateManufacturersError."""

    def test_request_error_logged(self, mock_settings, mock_pynetbox):
        import pynetbox as real_pynb

        mock_pynetbox.api.return_value.version = "3.5"
        # Make pynetbox.RequestError in the module under test be the real exception class
        mock_pynetbox.RequestError = real_pynb.RequestError
        nb = NetBox(mock_settings, mock_settings.handle)

        err = real_pynb.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        nb.netbox.dcim.manufacturers.create.side_effect = err

        nb.create_manufacturers([{"name": "Cisco", "slug": "cisco"}])
        mock_settings.handle.log.assert_called()


class TestFrontPortRecord45:
    """Tests for TestFrontPortRecord45."""

    def test_exposes_rear_port_position_from_mapping(self):
        record = MagicMock()
        mapping = MagicMock()
        mapping.rear_port_position = 3
        record.rear_ports = [mapping]
        wrapped = _FrontPortRecord45(record)
        assert wrapped.rear_port_position == 3

    def test_none_when_no_mappings(self):
        record = MagicMock()
        record.rear_ports = []
        wrapped = _FrontPortRecord45(record)
        assert wrapped.rear_port_position is None

    def test_delegates_unknown_attr_to_record(self):
        record = MagicMock()
        record.name = "fp1"
        record.rear_ports = []
        wrapped = _FrontPortRecord45(record)
        assert wrapped.name == "fp1"


class TestStopComponentPreload:
    """Tests for TestStopComponentPreload."""

    def test_noop_on_none(self):
        DeviceTypes.stop_component_preload(None)  # should not raise

    def test_cancels_pending_futures_and_shuts_down(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)

        future = MagicMock()
        future.done.return_value = False
        executor = MagicMock()
        preload_job = {
            "futures": {"interface_templates": future},
            "executor": executor,
        }
        DeviceTypes.stop_component_preload(preload_job)
        future.cancel.assert_called_once()
        executor.shutdown.assert_called_once()
        assert preload_job["executor"] is None


class TestApplyProgressUpdates:
    """Tests for TestApplyProgressUpdates."""

    def test_returns_false_when_no_progress(self):
        result = DeviceTypes._apply_progress_updates(None, None, None)
        assert result is False

    def test_drains_queue_and_advances(self):
        progress = MagicMock()
        task_ids = {"interface_templates": 1}
        q = queue.Queue()
        q.put(("interface_templates", 5))
        result = DeviceTypes._apply_progress_updates(q, progress, task_ids)
        assert result is True
        progress.update.assert_called_once_with(1, advance=5)

    def test_drops_disallowed_endpoints(self):
        progress = MagicMock()
        task_ids = {"interface_templates": 1}
        q = queue.Queue()
        q.put(("other_endpoint", 5))
        result = DeviceTypes._apply_progress_updates(q, progress, task_ids, allowed_endpoints={"interface_templates"})
        assert result is False


class TestBuildComponentCache:
    """Tests for TestBuildComponentCache."""

    def test_device_type_indexed(self):
        item = MagicMock()
        item.device_type = MagicMock(id=10)
        item.module_type = None
        item.name = "eth0"
        cache, count = DeviceTypes._build_component_cache([item])
        assert ("device", 10) in cache
        assert "eth0" in cache[("device", 10)]
        assert count == 1

    def test_module_type_indexed(self):
        item = MagicMock()
        item.device_type = None
        item.module_type = MagicMock(id=20)
        item.name = "xe-0"
        cache, count = DeviceTypes._build_component_cache([item])
        assert ("module", 20) in cache
        assert count == 1

    def test_item_without_parent_skipped(self):
        item = MagicMock()
        item.device_type = None
        item.module_type = None
        cache, count = DeviceTypes._build_component_cache([item])
        assert count == 0


class TestGetFilterKwargs:
    """Tests for TestGetFilterKwargs."""

    def test_device_old_filter(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.new_filters = False
        assert dt._get_filter_kwargs(1, "device") == {"devicetype_id": 1}

    def test_device_new_filter(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.new_filters = True
        assert dt._get_filter_kwargs(1, "device") == {"device_type_id": 1}

    def test_module_new_filter(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.new_filters = True
        assert dt._get_filter_kwargs(5, "module") == {"module_type_id": 5}

    def test_module_old_filter(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.new_filters = False
        assert dt._get_filter_kwargs(5, "module") == {"moduletype_id": 5}


class TestCreateGenericError:
    """Tests for TestCreateGenericError."""

    def test_list_error_logs_each_item(self, mock_settings, mock_pynetbox, graphql_client):
        import pynetbox as real_pynb

        mock_pynetbox.RequestError = real_pynb.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        endpoint = MagicMock()
        err = real_pynb.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        err.error = ["Name already exists", ""]
        endpoint.create.side_effect = err

        dt._create_generic(
            [{"name": "eth0"}, {"name": "eth1"}],
            1,
            endpoint,
            "Interface",
            parent_type="device",
            cache_name="interface_templates",
        )
        mock_settings.handle.log.assert_called()

    def test_string_error_logs_failed_items(self, mock_settings, mock_pynetbox, graphql_client):
        import pynetbox as real_pynb

        mock_pynetbox.RequestError = real_pynb.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        endpoint = MagicMock()
        err = real_pynb.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        err.error = "Something went wrong"
        endpoint.create.side_effect = err

        dt._create_generic(
            [{"name": "eth0"}],
            1,
            endpoint,
            "Interface",
            parent_type="device",
            cache_name="interface_templates",
        )
        mock_settings.handle.log.assert_called()


class TestRemoveComponents:
    """Tests for TestRemoveComponents."""

    def test_removes_existing_component(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)

        existing_comp = MagicMock()
        existing_comp.id = 99
        dt.cached_components = {"interface_templates": {("device", 1): {"eth0": existing_comp}}}

        from core.change_detector import ChangeType, ComponentChange

        changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_REMOVED)]
        dt.remove_components(1, changes)

        mock_nb_api.dcim.interface_templates.delete.assert_called_once_with([99])
        mock_settings.handle.log.assert_called()

    def test_skips_component_not_in_cache(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        from core.change_detector import ChangeType, ComponentChange

        changes = [ComponentChange("interfaces", "eth99", ChangeType.COMPONENT_REMOVED)]
        dt.remove_components(1, changes)

        mock_nb_api.dcim.interface_templates.delete.assert_not_called()

    def test_no_changes_is_noop(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.remove_components(1, [])
        mock_nb_api.dcim.interface_templates.delete.assert_not_called()


class TestCreatePowerConsolePorts:
    """Tests for TestCreatePowerConsolePorts."""

    def test_create_power_ports_calls_create_generic(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"power_port_templates": {("device", 1): {}}}
        dt.create_power_ports([{"name": "PSU1"}], 1)
        mock_nb_api.dcim.power_port_templates.create.assert_called_once()

    def test_create_console_ports_calls_create_generic(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"console_port_templates": {("device", 1): {}}}
        dt.create_console_ports([{"name": "Con1"}], 1)
        mock_nb_api.dcim.console_port_templates.create.assert_called_once()

    def test_create_rear_ports_calls_create_generic(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"rear_port_templates": {("device", 1): {}}}
        dt.create_rear_ports([{"name": "RP1", "type": "8p8c", "positions": 1}], 1)
        mock_nb_api.dcim.rear_port_templates.create.assert_called_once()

    def test_create_device_bays_calls_create_generic(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"device_bay_templates": {("device", 1): {}}}
        dt.create_device_bays([{"name": "Bay1"}], 1)
        mock_nb_api.dcim.device_bay_templates.create.assert_called_once()


class TestCreateDeviceTypesNewDT:
    """Tests for TestCreateDeviceTypesNewDT."""

    def test_creates_new_device_type_with_components(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        mock_settings.handle = MagicMock()
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)

        created_dt = MagicMock()
        created_dt.id = 1
        created_dt.manufacturer.name = "Cisco"
        created_dt.model = "TestSwitch"
        mock_nb_api.dcim.device_types.create.return_value = created_dt

        dt.cached_components = {
            "interface_templates": {("device", 1): {}},
            "power_port_templates": {("device", 1): {}},
        }

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "interfaces": [{"name": "eth0", "type": "virtual"}],
            "power-ports": [{"name": "PSU1", "type": "iec-60320-c14"}],
            "src": "/repo/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type])

        mock_nb_api.dcim.device_types.create.assert_called_once()
        mock_nb_api.dcim.interface_templates.create.assert_called_once()
        mock_nb_api.dcim.power_port_templates.create.assert_called_once()


class TestUploadImageAttachment:
    """Tests for TestUploadImageAttachment."""

    def test_success_returns_true(self, mock_settings, mock_pynetbox, graphql_client, tmp_path):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)

        img_path = tmp_path / "img.png"
        img_path.write_bytes(b"fake")

        with patch("core.netbox_api.requests.post") as mock_post:
            resp = MagicMock()
            resp.status_code = 201
            resp.raise_for_status.return_value = None
            mock_post.return_value = resp
            result = dt.upload_image_attachment("http://nb", "token", str(img_path), "dcim.moduletype", 42)

        assert result is True

    def test_request_error_returns_false(self, mock_settings, mock_pynetbox, graphql_client, tmp_path):
        import requests as req_lib

        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)

        img_path = tmp_path / "img.png"
        img_path.write_bytes(b"fake")

        with patch("core.netbox_api.requests.post") as mock_post:
            mock_post.side_effect = req_lib.RequestException("timeout")
            result = dt.upload_image_attachment("http://nb", "token", str(img_path), "dcim.moduletype", 42)

        assert result is False

    def test_os_error_returns_false(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        result = dt.upload_image_attachment("http://nb", "token", "/nonexistent/img.png", "dcim.moduletype", 42)
        assert result is False


class TestDiscoverModuleImageFiles:
    """Tests for TestDiscoverModuleImageFiles."""

    def test_returns_empty_for_unknown_src(self):
        from core.netbox_api import NetBox

        result = NetBox._discover_module_image_files("Unknown")
        assert result == []

    def test_returns_empty_when_module_types_not_in_path(self):
        from core.netbox_api import NetBox

        result = NetBox._discover_module_image_files("/some/path/without/that-dir/file.yaml")
        assert result == []

    def test_returns_image_files(self, tmp_path):
        from core.netbox_api import NetBox

        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "mymodule.yaml"
        src.write_text("model: X")

        img_dir = tmp_path / "module-images" / "vendor" / "mymodule"
        img_dir.mkdir(parents=True)
        (img_dir / "front.jpg").write_bytes(b"img")

        result = NetBox._discover_module_image_files(str(src))
        assert any("front.jpg" in r for r in result)


class TestCreateModuleTypes:
    """Tests for TestCreateModuleTypes."""

    def test_empty_module_types_returns_immediately(self, mock_settings, mock_pynetbox):
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        # Should not raise and should not call create
        nb.create_module_types([])
        nb.netbox.dcim.module_types.create.assert_not_called()

    def test_creates_new_module_type(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        mock_pynetbox.api.return_value.version = "3.5"
        mock_graphql_requests.side_effect = paginate_dispatch(
            {
                "manufacturer_list": [],
                "device_type_list": [],
                "module_type_list": [],
                "image_attachment_list": [],
            }
        )
        nb = NetBox(mock_settings, mock_settings.handle)

        created_mt = MagicMock()
        created_mt.id = 5
        created_mt.manufacturer.name = "Cisco"
        created_mt.model = "LC"
        nb.netbox.dcim.module_types.create.return_value = created_mt

        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "LC",
            "src": "/repo/module-types/cisco/lc.yaml",
        }
        nb.create_module_types([module_type], all_module_types={}, module_type_existing_images={})
        nb.netbox.dcim.module_types.create.assert_called_once()


class TestUpdateComponentsAdditions:
    """Tests for TestUpdateComponentsAdditions."""

    def test_adds_new_interface_via_create(self, mock_settings, mock_pynetbox, graphql_client):
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)]
        yaml_data = {"interfaces": [{"name": "eth0", "type": "virtual"}]}
        dt.update_components(yaml_data, 1, changes, parent_type="device")

        mock_nb_api.dcim.interface_templates.create.assert_called_once()


class TestFetchGlobalEndpointRestPath:
    """Tests for TestFetchGlobalEndpointRestPath."""

    def test_m2m_front_ports_uses_rest(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.m2m_front_ports = True

        raw_fp = MagicMock()
        raw_fp.rear_ports = []
        mock_nb_api.dcim.front_port_templates.all.return_value = [raw_fp]

        records = dt._fetch_global_endpoint_records("front_port_templates")
        mock_nb_api.dcim.front_port_templates.all.assert_called_once()
        assert len(records) == 1
        assert isinstance(records[0], _FrontPortRecord45)

    def test_rest_only_endpoint_with_progress_callback(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.REST_ONLY_ENDPOINTS = frozenset(["interface_templates"])

        raw = MagicMock()
        mock_nb_api.dcim.interface_templates.all.return_value = [raw]

        updates = []
        dt._fetch_global_endpoint_records(
            "interface_templates",
            progress_callback=lambda e, n: updates.append((e, n)),
        )
        assert updates == [("interface_templates", 1)]


class TestCountDeviceTypeImages:
    """Tests for TestCountDeviceTypeImages."""

    def test_counts_new_image_when_no_existing_dt(self, mock_settings, mock_pynetbox, graphql_client, tmp_path):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)

        # Create a temporary directory structure mimicking device-types
        dev_types_dir = tmp_path / "device-types" / "cisco"
        dev_types_dir.mkdir(parents=True)
        elevation_dir = tmp_path / "elevation-images" / "cisco"
        elevation_dir.mkdir(parents=True)
        (elevation_dir / "myswitch.front.png").write_bytes(b"img")

        src_file = str(dev_types_dir / "myswitch.yaml")

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        device_types = [
            {
                "manufacturer": {"slug": "cisco"},
                "model": "MySwitch",
                "slug": "myswitch",
                "front_image": True,
                "src": src_file,
            }
        ]

        with patch("glob.glob", return_value=[str(elevation_dir / "myswitch.front.png")]):
            count = nb.count_device_type_images(device_types)
        assert count == 1

    def test_skips_existing_dt_with_image(self, mock_settings, mock_pynetbox, graphql_client, tmp_path):
        mock_nb_api = mock_pynetbox.api.return_value

        existing_dt = MagicMock()
        existing_dt.front_image = "http://netbox/media/front.jpg"

        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.existing_device_types = {("cisco", "MySwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        dev_types_dir = tmp_path / "device-types" / "cisco"
        dev_types_dir.mkdir(parents=True)
        src_file = str(dev_types_dir / "myswitch.yaml")

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        device_types = [
            {
                "manufacturer": {"slug": "cisco"},
                "model": "MySwitch",
                "slug": "myswitch",
                "front_image": True,
                "src": src_file,
            }
        ]

        with patch("glob.glob", return_value=[str(tmp_path / "elevation-images" / "cisco" / "myswitch.front.png")]):
            count = nb.count_device_type_images(device_types)
        assert count == 0

    def test_no_src_skipped(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        count = nb.count_device_type_images([{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x"}])
        assert count == 0


class TestCreateModuleTypesBody:
    """Tests for TestCreateModuleTypesBody."""

    def test_cached_module_type_skips_creation(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        mock_pynetbox.api.return_value.version = "3.5"
        mock_graphql_requests.side_effect = paginate_dispatch(
            {
                "manufacturer_list": [],
                "device_type_list": [],
                "module_type_list": [],
                "image_attachment_list": [],
            }
        )
        nb = NetBox(mock_settings, mock_settings.handle)

        existing_mt = MagicMock()
        existing_mt.id = 5
        existing_mt.manufacturer.name = "Cisco"
        existing_mt.model = "LC"
        all_module_types = {"cisco": {"LC": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "LC",
            "src": "/repo/module-types/cisco/lc.yaml",
        }
        nb.create_module_types([module_type], all_module_types=all_module_types, module_type_existing_images={})
        nb.netbox.dcim.module_types.create.assert_not_called()

    def test_create_module_type_request_error_logged(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        import pynetbox as real_pynb

        mock_pynetbox.RequestError = real_pynb.RequestError
        mock_pynetbox.api.return_value.version = "3.5"
        mock_graphql_requests.side_effect = paginate_dispatch(
            {
                "manufacturer_list": [],
                "device_type_list": [],
                "module_type_list": [],
                "image_attachment_list": [],
            }
        )
        nb = NetBox(mock_settings, mock_settings.handle)

        err = real_pynb.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        nb.netbox.dcim.module_types.create.side_effect = err

        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "LC",
            "src": "/repo/module-types/cisco/lc.yaml",
        }
        nb.create_module_types([module_type], all_module_types={}, module_type_existing_images={})
        mock_settings.handle.log.assert_called()

    def test_creates_module_type_with_components(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client
    ):
        mock_pynetbox.api.return_value.version = "3.5"
        mock_graphql_requests.side_effect = paginate_dispatch(
            {
                "manufacturer_list": [],
                "device_type_list": [],
                "module_type_list": [],
                "image_attachment_list": [],
            }
        )
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types.graphql = graphql_client

        created_mt = MagicMock()
        created_mt.id = 5
        created_mt.manufacturer.name = "Cisco"
        created_mt.model = "LC"
        nb.netbox.dcim.module_types.create.return_value = created_mt

        nb.device_types.cached_components = {
            "interface_templates": {("module", 5): {}},
            "power_port_templates": {("module", 5): {}},
            "console_port_templates": {("module", 5): {}},
            "power_outlet_templates": {("module", 5): {}},
            "console_server_port_templates": {("module", 5): {}},
            "rear_port_templates": {("module", 5): {}},
            "front_port_templates": {("module", 5): {}},
        }

        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "LC",
            "interfaces": [{"name": "xe-0/0/0", "type": "10gbase-x-sfpp"}],
            "power-ports": [{"name": "PSU1"}],
            "console-ports": [{"name": "Con1"}],
            "rear-ports": [{"name": "RP1", "type": "8p8c", "positions": 1}],
            "src": "/repo/module-types/cisco/lc.yaml",
        }
        nb.create_module_types([module_type], all_module_types={}, module_type_existing_images={})
        nb.netbox.dcim.module_types.create.assert_called_once()
        nb.netbox.dcim.interface_templates.create.assert_called_once()


class TestCreateModuleComponents:
    """Tests for TestCreateModuleComponents."""

    def test_create_module_interfaces(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"interface_templates": {("module", 1): {}}}
        dt.create_module_interfaces([{"name": "xe-0"}], 1)
        mock_nb_api.dcim.interface_templates.create.assert_called_once()

    def test_create_module_power_ports(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"power_port_templates": {("module", 1): {}}}
        dt.create_module_power_ports([{"name": "PSU1"}], 1)
        mock_nb_api.dcim.power_port_templates.create.assert_called_once()

    def test_create_module_console_ports(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"console_port_templates": {("module", 1): {}}}
        dt.create_module_console_ports([{"name": "Con1"}], 1)
        mock_nb_api.dcim.console_port_templates.create.assert_called_once()

    def test_create_module_console_server_ports(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"console_server_port_templates": {("module", 1): {}}}
        dt.create_module_console_server_ports([{"name": "CSP1"}], 1)
        mock_nb_api.dcim.console_server_port_templates.create.assert_called_once()

    def test_create_module_rear_ports(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"rear_port_templates": {("module", 1): {}}}
        dt.create_module_rear_ports([{"name": "RP1", "type": "8p8c", "positions": 1}], 1)
        mock_nb_api.dcim.rear_port_templates.create.assert_called_once()


class TestCreateDeviceTypesImagePaths:
    """Tests for TestCreateDeviceTypesImagePaths."""

    def test_existing_dt_with_image_not_reuploaded(self, mock_settings, mock_pynetbox, graphql_client, tmp_path):
        mock_nb_api = mock_pynetbox.api.return_value
        mock_settings.handle = MagicMock()
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        existing_dt.front_image = "http://netbox/media/front.jpg"
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        dev_types_dir = tmp_path / "device-types" / "cisco"
        dev_types_dir.mkdir(parents=True)
        elevation_dir = tmp_path / "elevation-images" / "cisco"
        elevation_dir.mkdir(parents=True)
        img = elevation_dir / "testswitch.front.png"
        img.write_bytes(b"img")

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "front_image": True,
            "src": str(dev_types_dir / "testswitch.yaml"),
        }

        with patch("glob.glob", return_value=[str(img)]):
            nb.create_device_types([device_type])
        dt.upload_images = MagicMock()
        # Existing front_image present → verbose_log called, no re-upload
        mock_settings.handle.verbose_log.assert_any_call(
            f"Front image already exists for {existing_dt.model}, skipping upload."
        )


class TestUploadImagesProgress:
    """Tests for TestUploadImagesProgress."""

    def test_image_progress_callback_called(self, mock_settings, mock_pynetbox, graphql_client, tmp_path):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)

        img_path = tmp_path / "front.jpg"
        img_path.write_bytes(b"fake")

        progress_calls = []
        dt._image_progress = lambda n: progress_calls.append(n)

        with patch("core.netbox_api.requests.patch") as mock_patch:
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status.return_value = None
            mock_patch.return_value = resp
            dt.upload_images("http://nb", "token", {"front_image": str(img_path)}, 1)

        assert progress_calls == [1]

    def test_upload_images_os_error_logged(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.upload_images("http://nb", "token", {"front_image": "/nonexistent/img.jpg"}, 1)
        mock_settings.handle.log.assert_called()


class TestCountDeviceTypeImagesEdge:
    """Tests for TestCountDeviceTypeImagesEdge."""

    def test_no_device_types_path_skipped(self, mock_settings, mock_pynetbox, graphql_client, tmp_path):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        # src path that doesn't contain "device-types" → triggers ValueError → continue
        count = nb.count_device_type_images(
            [
                {
                    "manufacturer": {"slug": "cisco"},
                    "model": "X",
                    "slug": "x",
                    "front_image": True,
                    "src": "/some/other/path/file.yaml",
                }
            ]
        )
        assert count == 0


class TestCountModuleTypeImages:
    """Tests for TestCountModuleTypeImages."""

    def test_new_module_counts_all_images(self, tmp_path):
        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "mymodule.yaml"
        src.write_text("model: X")

        img_dir = tmp_path / "module-images" / "vendor" / "mymodule"
        img_dir.mkdir(parents=True)
        (img_dir / "front.jpg").write_bytes(b"img")

        from core.netbox_api import NetBox as NB

        with patch("glob.glob", return_value=[str(img_dir / "front.jpg")]):
            count = NB.count_module_type_images([{"manufacturer": {"slug": "vendor"}, "model": "X", "src": str(src)}])
        assert count == 1

    def test_existing_module_with_image_not_counted(self, tmp_path):
        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "mymodule.yaml"
        src.write_text("model: X")

        img_dir = tmp_path / "module-images" / "vendor" / "mymodule"
        img_dir.mkdir(parents=True)
        (img_dir / "front.jpg").write_bytes(b"img")

        existing_mt = MagicMock()
        existing_mt.id = 10
        all_mts = {"vendor": {"X": existing_mt}}
        existing_images = {10: {"front"}}

        from core.netbox_api import NetBox as NB

        with patch("glob.glob", return_value=[str(img_dir / "front.jpg")]):
            count = NB.count_module_type_images(
                [{"manufacturer": {"slug": "vendor"}, "model": "X", "src": str(src)}],
                all_module_types=all_mts,
                module_type_existing_images=existing_images,
            )
        assert count == 0

    def test_no_src_returns_zero(self):
        from core.netbox_api import NetBox as NB

        count = NB.count_module_type_images([{"manufacturer": {"slug": "vendor"}, "model": "X", "src": "Unknown"}])
        assert count == 0


class TestCreateConsoleServerPorts:
    """Tests for TestCreateConsoleServerPorts."""

    def test_create_console_server_ports_calls_create_generic(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"console_server_port_templates": {("device", 1): {}}}
        dt.create_console_server_ports([{"name": "CSP1"}], 1)
        mock_nb_api.dcim.console_server_port_templates.create.assert_called_once()


class TestCreateModuleBays:
    """Tests for TestCreateModuleBays."""

    def test_create_module_bays_calls_create_generic(self, mock_settings, mock_pynetbox, graphql_client):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = DeviceTypes(mock_nb_api, mock_settings.handle, MagicMock(), False, False, graphql=graphql_client)
        dt.cached_components = {"module_bay_templates": {("device", 1): {}}}
        dt.create_module_bays([{"name": "MB1"}], 1)
        mock_nb_api.dcim.module_bay_templates.create.assert_called_once()
