import queue
import pytest
from unittest.mock import MagicMock, patch
from core.netbox_api import (
    NetBox,
    DeviceTypes,
    _FrontPortRecordWithMappings,
)
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


@pytest.fixture
def make_device_types(mock_settings, graphql_client):
    """Create DeviceTypes test instances with standard defaults."""

    def _factory(nb_api=None, handle=None, counter=None, **kwargs):
        return DeviceTypes(
            nb_api if nb_api is not None else MagicMock(),
            handle if handle is not None else mock_settings.handle,
            counter if counter is not None else MagicMock(),
            False,
            False,
            graphql=kwargs.pop("graphql", graphql_client),
            **kwargs,
        )

    return _factory


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


def test_device_types_create_interfaces(mock_settings, mock_pynetbox, graphql_client, make_device_types):
    # Setup
    mock_nb_api = mock_pynetbox.api.return_value
    mock_settings.handle = MagicMock()
    mock_counter = MagicMock()

    dt = make_device_types(nb_api=mock_nb_api, counter=mock_counter)

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


def test_preload_global_builds_component_cache(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
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
                            "manufacturer": {
                                "id": "10",
                                "name": "Cisco",
                                "slug": "cisco",
                            },
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

    dt = make_device_types(nb_api=mock_nb_api)
    dt.preload_all_components(progress_wrapper=None)

    assert "interface_templates" in dt.cached_components
    assert ("device", 1) in dt.cached_components["interface_templates"]
    assert dt.cached_components["interface_templates"][("device", 1)]["eth0"].name == "eth0"


def test_fetch_global_endpoint_records_uses_graphql(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
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

    dt = make_device_types(nb_api=mock_nb_api)
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


def test_fetch_global_endpoint_records_progress_emits_live_per_page(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """Progress callback must fire per page during the fetch, not in one batch at the end.

    Regression: an earlier implementation buffered per-attempt advances and only
    flushed them after the fetch completed.  For large endpoints (e.g. 100k+
    interfaces) the bar appeared frozen at 0 for the whole fetch, then jumped
    to 100% at the end.
    """
    from unittest.mock import patch as _patch
    from core.graphql_client import DotDict

    mock_nb_api = mock_pynetbox.api.return_value
    dt = make_device_types(nb_api=mock_nb_api)

    pages = [
        [DotDict({"id": "1", "name": "a", "device_type": {"id": "5"}, "module_type": None})],
        [DotDict({"id": "2", "name": "b", "device_type": {"id": "5"}, "module_type": None})],
        [DotDict({"id": "3", "name": "c", "device_type": {"id": "5"}, "module_type": None})],
    ]

    advances_during_fetch = []

    def fake_get(endpoint_name, on_page=None):
        # Stream pages and verify that the consumer-facing callback was invoked
        # before the next page is yielded.
        all_records = []
        for idx, page in enumerate(pages, start=1):
            all_records.extend(page)
            if on_page is not None:
                on_page(len(page))
                assert len(advances_during_fetch) == idx
        return all_records

    def progress_cb(endpoint, advance):
        advances_during_fetch.append((endpoint, advance))

    with _patch.object(dt.graphql, "get_component_templates", side_effect=fake_get):
        records = dt._fetch_global_endpoint_records(
            "interface_templates",
            progress_callback=progress_cb,
            expected_total=3,
        )

    assert len(records) == 3
    # Live emission: one callback per page, not a single batched flush.
    assert advances_during_fetch == [
        ("interface_templates", 1),
        ("interface_templates", 1),
        ("interface_templates", 1),
    ]


def test_fetch_global_endpoint_records_emits_rewind_on_retry(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """When a count-mismatch triggers a retry, a negative-advance "rewind" must be emitted.

    Without the rewind, the next attempt's live advances would double-count on
    top of the failed attempt's leftover ones.
    """
    from unittest.mock import patch as _patch
    from core.graphql_client import DotDict

    mock_nb_api = mock_pynetbox.api.return_value
    dt = make_device_types(nb_api=mock_nb_api)

    iface1 = DotDict({"id": "1", "name": "a", "device_type": {"id": "5"}, "module_type": None})
    iface2 = DotDict({"id": "2", "name": "b", "device_type": {"id": "5"}, "module_type": None})

    call_count = {"n": 0}

    def fake_get(endpoint_name, on_page=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            if on_page is not None:
                on_page(1)
            return [iface1]
        if on_page is not None:
            on_page(1)
            on_page(1)
        return [iface1, iface2]

    advances = []

    def progress_cb(endpoint, advance):
        advances.append(advance)

    with _patch("core.netbox_api.time.sleep"):
        with _patch.object(dt.graphql, "get_component_templates", side_effect=fake_get):
            records = dt._fetch_global_endpoint_records(
                "interface_templates",
                progress_callback=progress_cb,
                expected_total=2,
            )

    assert len(records) == 2
    # Live: +1 (failed attempt page), -1 (rewind), +1 + +1 (successful retry pages).
    assert advances == [1, -1, 1, 1]
    assert sum(advances) == 2


def test_fetch_global_endpoint_records_progress_skipped_when_empty(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    mock_nb_api = mock_pynetbox.api.return_value

    mock_graphql_requests.side_effect = _make_graphql_dispatch(
        {
            "device_type_list": {"data": {"device_type_list": []}},
            "interface_template_list": {"data": {"interface_template_list": []}},
        }
    )

    dt = make_device_types(nb_api=mock_nb_api)
    updates = []

    fetched = dt._fetch_global_endpoint_records(
        "interface_templates",
        progress_callback=lambda endpoint, advance: updates.append((endpoint, advance)),
        expected_total=0,
    )

    assert fetched == []
    assert updates == []


def test_fetch_global_endpoint_records_retries_and_aborts_on_count_mismatch(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """After _MAX_RETRIES mismatches a GraphQLCountMismatchError is raised; each attempt logs a warning."""
    from unittest.mock import patch as _patch
    from core.graphql_client import GraphQLCountMismatchError

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
                        }
                    ]
                }
            },
        }
    )

    dt = make_device_types(nb_api=mock_nb_api)
    logged = []
    dt.handle.log = lambda msg: logged.append(msg)

    with _patch("core.netbox_api.time.sleep") as mock_sleep:
        with pytest.raises(GraphQLCountMismatchError, match="interface_templates"):
            dt._fetch_global_endpoint_records(
                "interface_templates",
                progress_callback=None,
                expected_total=113259,
            )

    from core.netbox_api import _MAX_RETRIES, _RETRY_BACKOFF

    # One sleep per retry attempt
    assert mock_sleep.call_count == _MAX_RETRIES
    # Backoff durations must match the configured sequence — guards against a
    # regression that silently changes the wait pattern.
    assert [call.args[0] for call in mock_sleep.call_args_list] == list(_RETRY_BACKOFF[:_MAX_RETRIES])
    # A WARNING is logged for each retry
    warnings = [m for m in logged if "WARNING" in m and "interface_templates" in m]
    assert len(warnings) == _MAX_RETRIES


def test_fetch_global_endpoint_records_detects_mismatch_when_rest_returns_zero(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """A REST count of 0 must NOT silently skip validation when GraphQL returns records.

    Regression: previously ``if expected_total and ...`` treated ``0`` as "skip
    validation", meaning a real REST count of 0 paired with a GraphQL response that
    leaked records would go unnoticed.  The check now uses ``is not None`` so 0 is a
    legitimate expected value and any mismatch (including 0 vs N>0) is flagged.
    """
    from unittest.mock import patch as _patch
    from core.graphql_client import GraphQLCountMismatchError

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
                        }
                    ]
                }
            },
        }
    )

    dt = make_device_types(nb_api=mock_nb_api)

    with _patch("core.netbox_api.time.sleep"):
        with pytest.raises(GraphQLCountMismatchError, match="interface_templates"):
            dt._fetch_global_endpoint_records(
                "interface_templates",
                progress_callback=None,
                expected_total=0,
            )


def test_fetch_global_endpoint_records_succeeds_on_retry(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """When the first fetch is truncated but a retry returns the full count, the records are returned."""
    from unittest.mock import patch as _patch
    from core.graphql_client import DotDict

    mock_nb_api = mock_pynetbox.api.return_value
    dt = make_device_types(nb_api=mock_nb_api)

    iface1 = DotDict({"id": "1", "name": "xe-0/0/0", "device_type": {"id": "5"}, "module_type": None})
    iface2 = DotDict({"id": "2", "name": "xe-0/0/1", "device_type": {"id": "5"}, "module_type": None})

    call_count = {"n": 0}

    def fake_get(endpoint_name, on_page=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return [iface1]  # truncated
        return [iface1, iface2]  # full on retry

    with _patch("core.netbox_api.time.sleep"):
        with _patch.object(dt.graphql, "get_component_templates", side_effect=fake_get):
            records = dt._fetch_global_endpoint_records(
                "interface_templates",
                progress_callback=None,
                expected_total=2,
            )

    assert len(records) == 2
    assert call_count["n"] == 2  # initial attempt + 1 retry


def test_fetch_global_endpoint_records_progress_not_double_counted_on_retry(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """A mismatched-then-retried fetch must not double-advance the progress bar.

    If page advances were published during the failing attempt and again during
    the successful retry, the progress callback would receive more advances than
    the final expected total.  Only the successful attempt should publish.
    """
    from unittest.mock import patch as _patch
    from core.graphql_client import DotDict

    mock_nb_api = mock_pynetbox.api.return_value
    dt = make_device_types(nb_api=mock_nb_api)

    iface1 = DotDict({"id": "1", "name": "xe-0/0/0", "device_type": {"id": "5"}, "module_type": None})
    iface2 = DotDict({"id": "2", "name": "xe-0/0/1", "device_type": {"id": "5"}, "module_type": None})

    call_count = {"n": 0}

    def fake_get(endpoint_name, on_page=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First attempt: emit one page advance, but return truncated list -> mismatch
            if on_page is not None:
                on_page(1)
            return [iface1]
        # Retry attempt: emit two page advances, return full list -> success
        if on_page is not None:
            on_page(1)
            on_page(1)
        return [iface1, iface2]

    advances = []

    def progress_cb(endpoint, advance):
        advances.append((endpoint, advance))

    with _patch("core.netbox_api.time.sleep"):
        with _patch.object(dt.graphql, "get_component_templates", side_effect=fake_get):
            records = dt._fetch_global_endpoint_records(
                "interface_templates",
                progress_callback=progress_cb,
                expected_total=2,
            )

    assert len(records) == 2
    assert call_count["n"] == 2
    # Total advances must equal expected_total (2), not 1 + 2 == 3.
    total_advance = sum(n for _, n in advances)
    assert total_advance == 2, f"progress callback double-counted retry advances: got {total_advance}, expected 2"


def test_fetch_global_endpoint_records_no_warning_on_count_match(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """No warning is logged when GraphQL returns the expected number of records."""
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
                        }
                    ]
                }
            },
        }
    )

    dt = make_device_types(nb_api=mock_nb_api)
    logged = []
    dt.handle.log = lambda msg: logged.append(msg)

    records = dt._fetch_global_endpoint_records(
        "interface_templates",
        progress_callback=None,
        expected_total=1,
    )

    assert len(records) == 1
    assert not any("WARNING" in m for m in logged)


def test_get_rest_component_count_returns_count(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """_get_rest_component_count returns the integer count from pynetbox."""
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.dcim.interface_templates.count.return_value = 42

    dt = make_device_types(nb_api=mock_nb_api)
    assert dt._get_rest_component_count("interface_templates") == 42


def test_get_rest_component_count_returns_none_on_error(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """_get_rest_component_count returns None if the REST call fails."""
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.dcim.interface_templates.count.side_effect = Exception("connection failed")

    dt = make_device_types(nb_api=mock_nb_api)
    assert dt._get_rest_component_count("interface_templates") is None


def test_get_endpoint_totals_fetches_rest_counts(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """_get_endpoint_totals fetches actual REST counts for graphql endpoints."""
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.dcim.interface_templates.count.return_value = 100
    mock_nb_api.dcim.power_port_templates.count.return_value = 50

    dt = make_device_types(nb_api=mock_nb_api)
    components = [("interface_templates", "Interfaces"), ("power_port_templates", "Power Ports")]
    totals = dt._get_endpoint_totals(components)

    assert totals["interface_templates"] == 100
    assert totals["power_port_templates"] == 50


def test_get_endpoint_totals_tolerates_count_failure(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
    """_get_endpoint_totals preserves None sentinel when a REST count fails."""
    mock_nb_api = mock_pynetbox.api.return_value
    mock_nb_api.dcim.interface_templates.count.side_effect = Exception("timeout")
    mock_nb_api.dcim.power_port_templates.count.return_value = 20

    dt = make_device_types(nb_api=mock_nb_api)
    components = [("interface_templates", "Interfaces"), ("power_port_templates", "Power Ports")]
    totals = dt._get_endpoint_totals(components)

    assert totals["interface_templates"] is None
    assert totals["power_port_templates"] == 20


def test_preload_always_global_caches_all_vendors(
    mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
):
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
                            "manufacturer": {
                                "id": "10",
                                "name": "Cisco",
                                "slug": "cisco",
                            },
                            "front_image": None,
                            "rear_image": None,
                        },
                        {
                            "id": "2",
                            "model": "ModelB",
                            "slug": "model-b",
                            "manufacturer": {
                                "id": "20",
                                "name": "Juniper",
                                "slug": "juniper",
                            },
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

    dt = make_device_types(nb_api=mock_nb_api)
    dt.preload_all_components(progress_wrapper=None)

    # Both vendors are cached because global fetch returns everything
    assert ("device", 1) in dt.cached_components["interface_templates"]
    assert ("device", 2) in dt.cached_components["interface_templates"]


def test_start_component_preload_global_job_can_be_consumed(
    mock_settings, mock_pynetbox, graphql_client, make_device_types
):
    mock_nb_api = mock_pynetbox.api.return_value

    dt = make_device_types(nb_api=mock_nb_api)
    preload_job = dt.start_component_preload()

    assert preload_job["mode"] == "global"
    dt.preload_all_components(progress_wrapper=None, preload_job=preload_job)
    assert preload_job["executor"] is None


def test_preload_tolerates_none_endpoint_totals(mock_settings, mock_pynetbox, graphql_client, make_device_types):
    """``_preload_track_progress`` must not raise TypeError when a total is ``None``.

    Regression: ``_get_endpoint_totals`` now returns ``None`` for endpoints whose
    REST count failed (preserving the "count unavailable" sentinel).  Internal
    ``max(endpoint_totals.get(name, 0), ...)`` calls would raise ``TypeError`` on
    ``None`` because ``dict.get`` returns the stored ``None`` instead of the default.
    The fix uses ``endpoint_totals.get(name) or 0`` to coerce ``None`` to ``0`` for
    the ``max()`` comparison while still letting ``None`` flow through as
    ``expected_total`` to ``_fetch_global_endpoint_records``.
    """
    from concurrent.futures import Future

    dt = make_device_types(nb_api=mock_pynetbox.api.return_value)

    components = [("interface_templates", "Interfaces")]
    fut = Future()
    fut.set_result([])
    futures = {"interface_templates": fut}

    progress = MagicMock()
    task_ids = {"interface_templates": "task-1"}
    endpoint_totals = {"interface_templates": None}

    import queue

    progress_updates = queue.Queue()
    # Exercise BOTH branches: the already-finished branch (where the
    # endpoint_totals.get(name) or 0 fallback runs) and the pending-future
    # branch (covered by another test).  Marking interface_templates finished
    # routes through the already_done code path with a None total.
    preload_job = {"finished_endpoints": {"interface_templates"}}

    # Must not raise TypeError on max(None, ...).
    result = dt._preload_track_progress(
        components,
        futures,
        progress,
        task_ids,
        preload_job,
        progress_updates,
        endpoint_totals,
    )

    assert result == {"interface_templates": []}
    # The already_done branch must update the task to completed==total.
    # With an empty result list and a None REST count, final_total = max(0, 0, 1) = 1
    # (the max(..., 1) floor prevents a 0/0 bar in the Rich progress UI).
    progress.update.assert_called_once_with("task-1", total=1, completed=1)


def test_upload_images_success_logs_verbose_only(
    mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
):
    mock_nb_api = mock_pynetbox.api.return_value

    image_file = tmp_path / "front.jpg"
    image_file.write_bytes(b"fake")

    dt = make_device_types(nb_api=mock_nb_api)
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

    nb = NetBox(mock_settings, mock_settings.handle)
    # Simulate the global GraphQL preload having already populated the cache for module 42.
    nb.device_types._global_preload_done = True
    nb.device_types.cached_components["interface_templates"] = {("module", 42): {"xe-0/0/0": existing_interface}}

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
        actionable, _, _ = nb.filter_actionable_module_types(
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

    nb = NetBox(mock_settings, mock_settings.handle)
    # Global preload done; module 42 has no interfaces cached → component is missing.
    nb.device_types._global_preload_done = True
    nb.device_types.cached_components["interface_templates"] = {("module", 42): {}}

    module_type = {
        "manufacturer": {"slug": "juniper"},
        "model": "Linecard 1",
        "slug": "linecard-1",
        "interfaces": [{"name": "xe-0/0/0"}],
        "src": "/tmp/repo/module-types/juniper/linecard-1.yaml",
    }

    with patch("glob.glob", return_value=[]):
        actionable, _, _ = nb.filter_actionable_module_types(
            [module_type],
            nb.get_existing_module_types(),
            only_new=False,
        )

    assert actionable == [module_type]


def test_update_components_m2m_front_port_mappings(mock_settings, mock_pynetbox, graphql_client, make_device_types):
    """On NetBox 4.5+, _mappings updates should rebuild the full M2M rear_ports array."""
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = make_device_types(nb_api=mock_nb_api)
    dt.m2m_front_ports = True

    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"

    rp = MagicMock()
    rp.id = 99

    # Cache both front port templates and rear port templates
    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
        "rear_port_templates": {("device", 1): {"RP1": rp}},
    }

    # new_value is a frozenset of (rear_port_name, fp_pos, rp_pos) tuples
    new_mappings_set = frozenset({("RP1", 1, 2), ("RP1", 2, 1)})
    old_mappings_set = frozenset({("RP1", 1, 1)})

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("_mappings", old_mappings_set, new_mappings_set)],
        ),
    ]

    endpoint = mock_nb_api.dcim.front_port_templates
    dt.update_components({}, 1, changes, parent_type="device")

    endpoint.update.assert_called_once()
    update_payload = endpoint.update.call_args[0][0][0]
    assert update_payload["id"] == 10
    assert "_mappings" not in update_payload, "Should not have raw _mappings key"
    assert sorted(update_payload["rear_ports"], key=lambda item: item["position"]) == [
        {"position": 1, "rear_port": 99, "rear_port_position": 2},
        {"position": 2, "rear_port": 99, "rear_port_position": 1},
    ]


def test_update_components_m2m_no_mapping_warns(mock_settings, mock_pynetbox, graphql_client, make_device_types):
    """On NetBox 4.5+, a _mappings update referencing unknown rear port should warn, not update."""
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = make_device_types(nb_api=mock_nb_api)
    dt.m2m_front_ports = True

    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"

    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
        "rear_port_templates": {("device", 1): {}},  # Empty: rear port missing
    }

    new_mappings_set = frozenset({("MISSING_RP", 1, 1)})
    old_mappings_set = frozenset()

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("_mappings", old_mappings_set, new_mappings_set)],
        ),
    ]

    endpoint = mock_nb_api.dcim.front_port_templates
    mock_settings.handle.log.reset_mock()
    dt.update_components({}, 1, changes, parent_type="device")

    endpoint.update.assert_not_called()
    assert any("MISSING_RP" in str(c) for c in mock_settings.handle.log.call_args_list)


def test_update_components_legacy_mapping_translates_to_fields(
    mock_settings, mock_pynetbox, graphql_client, make_device_types
):
    """On legacy NetBox (<4.5), _mappings update should send rear_port + rear_port_position."""
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = make_device_types(nb_api=mock_nb_api)
    dt.m2m_front_ports = False  # Legacy path

    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"

    rp = MagicMock()
    rp.id = 99

    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
        "rear_port_templates": {("device", 1): {"RP1": rp}},
    }

    new_mappings_set = frozenset({("RP1", 1, 3)})
    old_mappings_set = frozenset({("RP1", 1, 1)})

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("_mappings", old_mappings_set, new_mappings_set)],
        ),
    ]

    endpoint = mock_nb_api.dcim.front_port_templates
    dt.update_components({}, 1, changes, parent_type="device")

    endpoint.update.assert_called_once()
    update_payload = endpoint.update.call_args[0][0][0]
    assert update_payload["id"] == 10
    assert "_mappings" not in update_payload
    assert "rear_ports" not in update_payload  # Not the M2M key
    assert update_payload["rear_port"] == 99
    assert update_payload["rear_port_position"] == 3


def test_update_components_legacy_mapping_missing_rear_port_warns(
    mock_settings, mock_pynetbox, graphql_client, make_device_types
):
    """On legacy NetBox (<4.5), _mappings update with missing rear port warns and skips."""
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = make_device_types(nb_api=mock_nb_api)
    dt.m2m_front_ports = False

    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"

    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
        "rear_port_templates": {("device", 1): {}},  # Empty cache
    }

    new_mappings_set = frozenset({("MISSING_RP", 1, 1)})
    old_mappings_set = frozenset()

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("_mappings", old_mappings_set, new_mappings_set)],
        ),
    ]

    endpoint = mock_nb_api.dcim.front_port_templates
    mock_settings.handle.log.reset_mock()
    dt.update_components({}, 1, changes, parent_type="device")

    endpoint.update.assert_not_called()
    assert any("MISSING_RP" in str(c) for c in mock_settings.handle.log.call_args_list)


def test_update_components_legacy_mapping_two_tuple_warns_and_skips(
    mock_settings, mock_pynetbox, graphql_client, make_device_types
):
    """On legacy NetBox (<4.5), ChangeDetector emits 2-tuples (fp_pos, rp_pos).

    When no YAML _mappings are available, _apply_mappings_change must warn and skip
    rather than crash with ValueError.
    """
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = make_device_types(nb_api=mock_nb_api)
    dt.m2m_front_ports = False

    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"
    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
        "rear_port_templates": {("device", 1): {}},
    }

    # 2-tuple: legacy ChangeDetector cannot include rp_name
    new_mappings_set = frozenset({(1, 3)})
    old_mappings_set = frozenset({(1, 1)})

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("_mappings", old_mappings_set, new_mappings_set)],
        ),
    ]

    endpoint = mock_nb_api.dcim.front_port_templates
    mock_settings.handle.log.reset_mock()
    # Pass {} (no front-ports in yaml_data) → yaml_mappings is [] → warn and skip
    dt.update_components({}, 1, changes, parent_type="device")

    endpoint.update.assert_not_called()
    assert any("NetBox < 4.5" in str(c) for c in mock_settings.handle.log.call_args_list)


def test_update_components_legacy_mapping_two_tuple_uses_yaml_fallback(
    mock_settings, mock_pynetbox, graphql_client, make_device_types
):
    """On legacy NetBox (<4.5), 2-tuple ChangeDetector output uses YAML _mappings fallback.

    When ChangeDetector gives 2-tuples but YAML has _mappings, use the rear port
    name from the YAML entry as a fallback.
    """
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = make_device_types(nb_api=mock_nb_api)
    dt.m2m_front_ports = False

    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"

    rp = MagicMock()
    rp.id = 99

    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
        "rear_port_templates": {("device", 1): {"RP1": rp}},
    }

    # 2-tuple: legacy ChangeDetector cannot include rp_name
    new_mappings_set = frozenset({(1, 3)})
    old_mappings_set = frozenset({(1, 1)})

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("_mappings", old_mappings_set, new_mappings_set)],
        ),
    ]

    yaml_data = {
        "front-ports": [
            {
                "name": "FP1",
                "_mappings": [{"rear_port": "RP1", "front_port_position": 1, "rear_port_position": 3}],
            }
        ]
    }

    endpoint = mock_nb_api.dcim.front_port_templates
    dt.update_components(yaml_data, 1, changes, parent_type="device")

    endpoint.update.assert_called_once()
    update_payload = endpoint.update.call_args[0][0][0]
    assert update_payload["id"] == 10
    assert "_mappings" not in update_payload
    assert "rear_ports" not in update_payload
    assert update_payload["rear_port"] == 99
    assert update_payload["rear_port_position"] == 3


def test_update_components_legacy_mapping_empty_clears_rear_port(
    mock_settings, mock_pynetbox, graphql_client, make_device_types
):
    """On legacy NetBox (<4.5), empty _mappings frozenset should clear rear_port/rear_port_position."""
    from core.change_detector import ChangeType, ComponentChange, PropertyChange

    mock_nb_api = MagicMock()
    dt = make_device_types(nb_api=mock_nb_api)
    dt.m2m_front_ports = False

    existing_fp = MagicMock()
    existing_fp.id = 10
    existing_fp.name = "FP1"
    dt.cached_components = {
        "front_port_templates": {("device", 1): {"FP1": existing_fp}},
    }

    changes = [
        ComponentChange(
            component_type="front-ports",
            component_name="FP1",
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange("_mappings", frozenset({("RP1", 1, 1)}), frozenset())],
        ),
    ]

    endpoint = mock_nb_api.dcim.front_port_templates
    dt.update_components({}, 1, changes, parent_type="device")

    endpoint.update.assert_called_once()
    update_payload = endpoint.update.call_args[0][0][0]
    assert update_payload["id"] == 10
    assert update_payload["rear_port"] is None
    assert update_payload["rear_port_position"] is None


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


class TestFrontPortRecordWithMappings:
    """Tests for _FrontPortRecordWithMappings."""

    def test_45_path_builds_canonical_from_mappings(self):
        """NetBox >= 4.5: canonical list is built from the mappings attribute."""
        from core.graphql_client import DotDict

        rp = DotDict({"id": 7, "name": "RP1"})
        mapping = DotDict(
            {
                "id": 9,
                "front_port_position": 2,
                "rear_port_position": 3,
                "rear_port": rp,
            }
        )
        record = DotDict({"id": 1, "name": "FP1", "type": "8p8c", "mappings": [mapping]})
        wrapped = _FrontPortRecordWithMappings(record)
        assert wrapped._mappings_canonical == [
            {"rear_port_name": "RP1", "front_port_position": 2, "rear_port_position": 3}
        ]

    def test_45_path_empty_mappings_gives_empty_canonical(self):
        """NetBox >= 4.5: empty mappings list → empty canonical."""
        from core.graphql_client import DotDict

        record = DotDict({"id": 1, "name": "FP1", "mappings": []})
        wrapped = _FrontPortRecordWithMappings(record)
        assert wrapped._mappings_canonical == []

    def test_legacy_path_uses_rear_port_position_scalar(self):
        """NetBox < 4.5: rear_port_position scalar → single canonical entry with rear_port_name=None."""
        record = MagicMock(spec=[])  # no mappings attr
        record.rear_port_position = 3
        wrapped = _FrontPortRecordWithMappings(record)
        assert wrapped._mappings_canonical == [
            {"rear_port_name": None, "front_port_position": 1, "rear_port_position": 3}
        ]

    def test_legacy_path_no_rear_port_position_gives_none_canonical(self):
        """NetBox < 4.5 with no rear_port_position → None sentinel (fields unavailable, skip comparison)."""
        record = MagicMock(spec=[])
        wrapped = _FrontPortRecordWithMappings(record)
        assert wrapped._mappings_canonical is None

    def test_delegates_unknown_attr_to_record(self):
        """Attribute access falls through to the underlying record."""
        from core.graphql_client import DotDict

        record = DotDict({"id": 1, "name": "FP1", "type": "8p8c", "mappings": []})
        wrapped = _FrontPortRecordWithMappings(record)
        assert wrapped.name == "FP1"


class TestStopComponentPreload:
    """Tests for TestStopComponentPreload."""

    def test_noop_on_none(self):
        DeviceTypes.stop_component_preload(None)  # should not raise

    def test_cancels_pending_futures_and_shuts_down(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        make_device_types(nb_api=mock_nb_api)

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

    def test_device_old_filter(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.new_filters = False
        assert dt._get_filter_kwargs(1, "device") == {"devicetype_id": 1}

    def test_device_new_filter(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.new_filters = True
        assert dt._get_filter_kwargs(1, "device") == {"device_type_id": 1}

    def test_module_new_filter(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.new_filters = True
        assert dt._get_filter_kwargs(5, "module") == {"module_type_id": 5}

    def test_module_old_filter(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.new_filters = False
        assert dt._get_filter_kwargs(5, "module") == {"moduletype_id": 5}


class TestCreateGenericError:
    """Tests for TestCreateGenericError."""

    def test_list_error_logs_each_item(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        import pynetbox as real_pynb

        mock_pynetbox.RequestError = real_pynb.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
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

    def test_string_error_logs_failed_items(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        import pynetbox as real_pynb

        mock_pynetbox.RequestError = real_pynb.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
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

    def test_removes_existing_component(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_comp = MagicMock()
        existing_comp.id = 99
        dt.cached_components = {"interface_templates": {("device", 1): {"eth0": existing_comp}}}

        from core.change_detector import ChangeType, ComponentChange

        changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_REMOVED)]
        dt.remove_components(1, changes)

        mock_nb_api.dcim.interface_templates.delete.assert_called_once_with([99])
        mock_settings.handle.log.assert_called()

    def test_skips_component_not_in_cache(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        from core.change_detector import ChangeType, ComponentChange

        changes = [ComponentChange("interfaces", "eth99", ChangeType.COMPONENT_REMOVED)]
        dt.remove_components(1, changes)

        mock_nb_api.dcim.interface_templates.delete.assert_not_called()

    def test_no_changes_is_noop(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.remove_components(1, [])
        mock_nb_api.dcim.interface_templates.delete.assert_not_called()


class TestCreatePowerConsolePorts:
    """Tests for TestCreatePowerConsolePorts."""

    def test_create_power_ports_calls_create_generic(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"power_port_templates": {("device", 1): {}}}
        dt.create_power_ports([{"name": "PSU1"}], 1)
        mock_nb_api.dcim.power_port_templates.create.assert_called_once()

    def test_create_console_ports_calls_create_generic(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"console_port_templates": {("device", 1): {}}}
        dt.create_console_ports([{"name": "Con1"}], 1)
        mock_nb_api.dcim.console_port_templates.create.assert_called_once()

    def test_create_rear_ports_calls_create_generic(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"rear_port_templates": {("device", 1): {}}}
        dt.create_rear_ports([{"name": "RP1", "type": "8p8c", "positions": 1}], 1)
        mock_nb_api.dcim.rear_port_templates.create.assert_called_once()

    def test_create_device_bays_calls_create_generic(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"device_bay_templates": {("device", 1): {}}}
        dt.create_device_bays([{"name": "Bay1"}], 1)
        mock_nb_api.dcim.device_bay_templates.create.assert_called_once()


class TestCreateDeviceTypesNewDT:
    """Tests for TestCreateDeviceTypesNewDT."""

    def test_creates_new_device_type_with_components(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        mock_settings.handle = MagicMock()
        dt = make_device_types(nb_api=mock_nb_api)

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

    def test_success_returns_true(self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        img_path = tmp_path / "img.png"
        img_path.write_bytes(b"fake")

        with patch("core.netbox_api.requests.post") as mock_post:
            resp = MagicMock()
            resp.status_code = 201
            resp.raise_for_status.return_value = None
            mock_post.return_value = resp
            result = dt.upload_image_attachment("http://nb", "token", str(img_path), "dcim.moduletype", 42)

        assert result is True

    def test_request_error_returns_false(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        import requests as req_lib

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        img_path = tmp_path / "img.png"
        img_path.write_bytes(b"fake")

        with patch("core.netbox_api.requests.post") as mock_post:
            mock_post.side_effect = req_lib.RequestException("timeout")
            result = dt.upload_image_attachment("http://nb", "token", str(img_path), "dcim.moduletype", 42)

        assert result is False

    def test_os_error_returns_false(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        result = dt.upload_image_attachment("http://nb", "token", "/nonexistent/img.png", "dcim.moduletype", 42)
        assert result is False


class TestImageDirForYaml:
    """Tests for the _image_dir_for_yaml module-level helper."""

    def test_empty_src_returns_none(self):
        from core.netbox_api import _image_dir_for_yaml

        assert _image_dir_for_yaml("", "device-types", "elevation-images") is None

    def test_unknown_src_returns_none(self):
        from core.netbox_api import _image_dir_for_yaml, _UNKNOWN_SRC

        assert _image_dir_for_yaml(_UNKNOWN_SRC, "device-types", "elevation-images") is None

    def test_missing_segment_returns_none(self):
        from core.netbox_api import _image_dir_for_yaml

        assert _image_dir_for_yaml("/some/path/without/segment/file.yaml", "device-types", "elevation-images") is None

    def test_replaces_segment(self, tmp_path):
        from core.netbox_api import _image_dir_for_yaml

        src = str(tmp_path / "device-types" / "vendor" / "file.yaml")
        result = _image_dir_for_yaml(src, "device-types", "elevation-images")
        expected = tmp_path / "elevation-images" / "vendor"
        assert result == expected

    def test_replaces_last_occurrence_when_segment_appears_twice(self, tmp_path):
        from core.netbox_api import _image_dir_for_yaml

        src = str(tmp_path / "device-types" / "device-types" / "vendor" / "file.yaml")
        result = _image_dir_for_yaml(src, "device-types", "elevation-images")
        expected = tmp_path / "device-types" / "elevation-images" / "vendor"
        assert result == expected

    def test_module_types_segment(self, tmp_path):
        from core.netbox_api import _image_dir_for_yaml

        src = str(tmp_path / "module-types" / "vendor" / "file.yaml")
        result = _image_dir_for_yaml(src, "module-types", "module-images")
        expected = tmp_path / "module-images" / "vendor"
        assert result == expected


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

        img_dir = tmp_path / "module-images" / "vendor"
        img_dir.mkdir(parents=True)
        (img_dir / "mymodule.front.jpg").write_bytes(b"img")
        (img_dir / "mymodule.rear.jpg").write_bytes(b"img")

        result = NetBox._discover_module_image_files(str(src))
        assert any("mymodule.front.jpg" in r for r in result)
        assert any("mymodule.rear.jpg" in r for r in result)

    def test_does_not_match_other_modules_with_shared_prefix(self, tmp_path):
        """Globbing must not bleed across modules whose names share a prefix."""
        from core.netbox_api import NetBox

        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "LC.yaml"
        src.write_text("model: LC")

        img_dir = tmp_path / "module-images" / "vendor"
        img_dir.mkdir(parents=True)
        (img_dir / "LC.front.png").write_bytes(b"img")
        (img_dir / "LC-TR.front.png").write_bytes(b"img")  # different module

        result = NetBox._discover_module_image_files(str(src))
        assert any("LC.front.png" in r for r in result)
        assert not any("LC-TR.front.png" in r for r in result)

    def test_matches_legacy_bare_name(self, tmp_path):
        """Backwards-compat: bare `<stem>.<ext>` (pre-3944) is still discovered."""
        from core.netbox_api import NetBox

        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "legacy.yaml"
        src.write_text("model: legacy")

        img_dir = tmp_path / "module-images" / "vendor"
        img_dir.mkdir(parents=True)
        (img_dir / "legacy.png").write_bytes(b"img")

        result = NetBox._discover_module_image_files(str(src))
        assert any("legacy.png" in r for r in result)


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

    def test_adds_new_interface_via_create(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)]
        yaml_data = {"interfaces": [{"name": "eth0", "type": "virtual"}]}
        dt.update_components(yaml_data, 1, changes, parent_type="device")

        mock_nb_api.dcim.interface_templates.create.assert_called_once()


class TestFetchGlobalEndpointRestPath:
    """Tests for TestFetchGlobalEndpointRestPath."""

    def test_front_port_templates_uses_graphql_and_wraps(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, mock_graphql_requests
    ):
        """front_port_templates always uses GraphQL and wraps records with _FrontPortRecordWithMappings."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.m2m_front_ports = True  # no longer affects front_port_templates path

        fp_record = {
            "id": "1",
            "name": "FP1",
            "type": "8p8c",
            "label": "",
            "mappings": [],
            "device_type": {"id": "42"},
            "module_type": None,
        }

        # First call returns one record; second call returns empty to stop pagination.
        resp1 = MagicMock()
        resp1.raise_for_status = MagicMock()
        resp1.json.return_value = {"data": {"front_port_template_list": [fp_record]}}
        resp2 = MagicMock()
        resp2.raise_for_status = MagicMock()
        resp2.json.return_value = {"data": {"front_port_template_list": []}}
        mock_graphql_requests.side_effect = [resp1, resp2]

        records = dt._fetch_global_endpoint_records("front_port_templates")
        # REST endpoint should NOT be called
        mock_nb_api.dcim.front_port_templates.all.assert_not_called()
        assert len(records) == 1
        assert isinstance(records[0], _FrontPortRecordWithMappings)

    def test_rest_only_endpoint_with_progress_callback(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
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

    def test_counts_new_image_when_no_existing_dt(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

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

    def test_skips_existing_dt_with_image(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        mock_nb_api = mock_pynetbox.api.return_value

        existing_dt = MagicMock()
        existing_dt.front_image = "http://netbox/media/front.jpg"

        dt = make_device_types(nb_api=mock_nb_api)
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

        with patch(
            "glob.glob",
            return_value=[str(tmp_path / "elevation-images" / "cisco" / "myswitch.front.png")],
        ):
            count = nb.count_device_type_images(device_types)
        assert count == 0

    def test_no_src_skipped(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
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
        nb.create_module_types(
            [module_type],
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
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

    def test_create_module_interfaces(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"interface_templates": {("module", 1): {}}}
        dt.create_module_interfaces([{"name": "xe-0"}], 1)
        mock_nb_api.dcim.interface_templates.create.assert_called_once()

    def test_create_module_power_ports(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"power_port_templates": {("module", 1): {}}}
        dt.create_module_power_ports([{"name": "PSU1"}], 1)
        mock_nb_api.dcim.power_port_templates.create.assert_called_once()

    def test_create_module_console_ports(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"console_port_templates": {("module", 1): {}}}
        dt.create_module_console_ports([{"name": "Con1"}], 1)
        mock_nb_api.dcim.console_port_templates.create.assert_called_once()

    def test_create_module_console_server_ports(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"console_server_port_templates": {("module", 1): {}}}
        dt.create_module_console_server_ports([{"name": "CSP1"}], 1)
        mock_nb_api.dcim.console_server_port_templates.create.assert_called_once()

    def test_create_module_rear_ports(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"rear_port_templates": {("module", 1): {}}}
        dt.create_module_rear_ports([{"name": "RP1", "type": "8p8c", "positions": 1}], 1)
        mock_nb_api.dcim.rear_port_templates.create.assert_called_once()


class TestCreateDeviceTypesImagePaths:
    """Tests for TestCreateDeviceTypesImagePaths."""

    def test_existing_dt_with_image_not_reuploaded(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        mock_settings.handle = MagicMock()
        dt = make_device_types(nb_api=mock_nb_api)

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

    def test_image_progress_callback_called(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

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

    def test_upload_images_os_error_logged(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.upload_images("http://nb", "token", {"front_image": "/nonexistent/img.jpg"}, 1)
        mock_settings.handle.log.assert_called()


class TestCountDeviceTypeImagesEdge:
    """Tests for TestCountDeviceTypeImagesEdge."""

    def test_no_device_types_path_skipped(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
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

        img_dir = tmp_path / "module-images" / "vendor"
        img_dir.mkdir(parents=True)
        (img_dir / "mymodule.front.jpg").write_bytes(b"img")

        from core.netbox_api import NetBox as NB

        count = NB.count_module_type_images([{"manufacturer": {"slug": "vendor"}, "model": "X", "src": str(src)}])
        assert count == 1

    def test_existing_module_with_image_not_counted(self, tmp_path):
        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "mymodule.yaml"
        src.write_text("model: X")

        img_dir = tmp_path / "module-images" / "vendor"
        img_dir.mkdir(parents=True)
        (img_dir / "mymodule.front.jpg").write_bytes(b"img")

        existing_mt = MagicMock()
        existing_mt.id = 10
        all_mts = {"vendor": {"X": existing_mt}}
        # NetBox stores the basename sans final extension → "mymodule.front"
        existing_images = {10: {"mymodule.front"}}

        from core.netbox_api import NetBox as NB

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

    def test_create_console_server_ports_calls_create_generic(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"console_server_port_templates": {("device", 1): {}}}
        dt.create_console_server_ports([{"name": "CSP1"}], 1)
        mock_nb_api.dcim.console_server_port_templates.create.assert_called_once()


class TestCreateModuleBays:
    """Tests for TestCreateModuleBays."""

    def test_create_module_bays_calls_create_generic(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"module_bay_templates": {("device", 1): {}}}
        dt.create_module_bays([{"name": "MB1"}], 1)
        mock_nb_api.dcim.module_bay_templates.create.assert_called_once()


# ---------------------------------------------------------------------------
# Tests added to achieve 100% coverage of core/netbox_api.py
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# connect_api exception (lines 102-103)
# ---------------------------------------------------------------------------


class TestConnectApiException:
    """Tests for connect_api exception handling."""

    def test_exception_is_caught_and_logged(self, mock_settings, mock_pynetbox):
        """When pynetbox.api raises, handle.exception should be called."""
        mock_pynetbox.api.side_effect = Exception("connection failed")
        # NetBox.__init__ calls connect_api; the exception should be swallowed.
        try:
            NetBox(mock_settings, mock_settings.handle)
        except Exception:
            pass
        mock_settings.handle.exception.assert_called()


# ---------------------------------------------------------------------------
# create_manufacturers verbose_log on successful creation (lines 178-179)
# ---------------------------------------------------------------------------


class TestCreateManufacturersSuccessLog:
    """Tests for successful manufacturer creation logging."""

    def test_verbose_log_per_created_manufacturer(self, mock_settings, mock_pynetbox):
        """verbose_log should be called for each created manufacturer."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)

        created_m = MagicMock()
        created_m.name = "Cisco"
        created_m.id = 1
        nb.netbox.dcim.manufacturers.create.return_value = [created_m]

        mock_settings.handle.verbose_log.reset_mock()
        nb.create_manufacturers([{"name": "Cisco", "slug": "cisco"}])

        assert any("Cisco" in str(call) for call in mock_settings.handle.verbose_log.call_args_list)


# ---------------------------------------------------------------------------
# create_device_types image paths (lines 235-247, 265, 278-282, 285-289)
# ---------------------------------------------------------------------------


class TestCreateDeviceTypesImagePaths2:
    """Tests for image discovery/upload branches in create_device_types."""

    def test_no_device_types_in_src_path_sets_image_base_none(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Source path without 'device-types' → image_base = None; no image lookup."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        created_dt = MagicMock()
        created_dt.id = 1
        created_dt.manufacturer.name = "Cisco"
        created_dt.model = "TestSwitch"
        mock_nb_api.dcim.device_types.create.return_value = created_dt

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/some/other/path/testswitch.yaml",  # no "device-types" component
        }
        nb.create_device_types([device_type])
        # Should complete without error; image lookup skipped
        mock_nb_api.dcim.device_types.create.assert_called_once()

    def test_image_base_none_with_front_image_flag_logs_verbose(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """When image_base is None but front_image flag is set, verbose_log is called."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        created_dt = MagicMock()
        created_dt.id = 1
        created_dt.manufacturer.name = "Cisco"
        created_dt.model = "TestSwitch"
        mock_nb_api.dcim.device_types.create.return_value = created_dt
        mock_settings.handle.verbose_log.reset_mock()

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "front_image": True,
            "src": "/some/other/path/testswitch.yaml",
        }
        nb.create_device_types([device_type])
        assert any("Skipping image discovery" in str(call) for call in mock_settings.handle.verbose_log.call_args_list)

    def test_slug_fallback_verbose_log(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """When model lookup fails but slug lookup succeeds, verbose_log is called."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "OldModel"
        existing_dt.manufacturer.name = "Cisco"
        # model lookup misses; slug lookup hits
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {("cisco", "testswitch"): existing_dt}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        mock_settings.handle.verbose_log.reset_mock()

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type])
        assert any("Device Type found by slug" in str(call) for call in mock_settings.handle.verbose_log.call_args_list)

    def test_rear_image_already_exists_skips_upload(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        """Rear image already present on existing DT → verbose_log + skip upload."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.upload_images = MagicMock()

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        existing_dt.front_image = None
        existing_dt.rear_image = "http://netbox/media/rear.jpg"
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        dev_dir = tmp_path / "device-types" / "cisco"
        dev_dir.mkdir(parents=True)
        img = tmp_path / "elevation-images" / "cisco" / "testswitch.rear.png"
        img.parent.mkdir(parents=True)
        img.write_bytes(b"img")

        mock_settings.handle.verbose_log.reset_mock()

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "rear_image": True,
            "src": str(dev_dir / "testswitch.yaml"),
        }
        with patch("glob.glob", return_value=[str(img)]):
            nb.create_device_types([device_type])

        assert any("Rear image already exists" in str(call) for call in mock_settings.handle.verbose_log.call_args_list)
        dt.upload_images.assert_not_called()

    def test_saved_images_uploaded_for_existing_dt_when_not_present(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        """When existing DT has no image and a local image is found, upload_images is called."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.upload_images = MagicMock()

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        existing_dt.front_image = None
        existing_dt.rear_image = None
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        dev_dir = tmp_path / "device-types" / "cisco"
        dev_dir.mkdir(parents=True)
        img = tmp_path / "elevation-images" / "cisco" / "testswitch.front.png"
        img.parent.mkdir(parents=True)
        img.write_bytes(b"img")

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "front_image": True,
            "src": str(dev_dir / "testswitch.yaml"),
        }
        with patch("glob.glob", return_value=[str(img)]):
            nb.create_device_types([device_type])

        dt.upload_images.assert_called_once()

    def test_only_new_existing_dt_verbose_log_and_skip(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """only_new=True with existing DT → verbose_log containing 'Cached' and skip."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        mock_settings.handle.verbose_log.reset_mock()

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type], only_new=True)
        assert any("Skipping updates" in str(call) for call in mock_settings.handle.verbose_log.call_args_list)
        mock_nb_api.dcim.device_types.create.assert_not_called()


# ---------------------------------------------------------------------------
# create_device_types update path (lines 295-323)
# ---------------------------------------------------------------------------


class TestCreateDeviceTypesUpdatePath:
    """Tests for the update=True code path in create_device_types."""

    def _make_nb_with_existing_dt(self, mock_settings, mock_pynetbox, graphql_client, existing_dt, dt):
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        return nb

    def test_update_applies_property_changes(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """update=True with a matching change_report entry applies property changes."""
        from core.change_detector import ChangeReport, DeviceTypeChange, PropertyChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        mock_settings.handle.verbose_log.reset_mock()

        change = DeviceTypeChange(
            manufacturer_slug="cisco",
            model="TestSwitch",
            slug="testswitch",
            property_changes=[PropertyChange("u_height", 1, 2)],
        )
        report = ChangeReport(modified_device_types=[change])

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type], update=True, change_report=report)
        mock_nb_api.dcim.device_types.update.assert_called()

    def test_update_property_change_request_error_logged(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """RequestError during property update is caught and logged.

        Regression: when the property PATCH fails AND there are no component
        changes, ``device_types_failed`` must be incremented and the misleading
        "Device Type Updated" log MUST NOT be emitted.
        """
        import pynetbox as real_pynb2
        from core.change_detector import ChangeReport, DeviceTypeChange, PropertyChange

        mock_pynetbox.RequestError = real_pynb2.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        err = real_pynb2.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        mock_nb_api.dcim.device_types.update.side_effect = err

        change = DeviceTypeChange(
            manufacturer_slug="cisco",
            model="TestSwitch",
            slug="testswitch",
            property_changes=[PropertyChange("u_height", 1, 2)],
        )
        report = ChangeReport(modified_device_types=[change])

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        mock_settings.handle.log.reset_mock()
        mock_settings.handle.verbose_log.reset_mock()
        nb.create_device_types([device_type], update=True, change_report=report)
        # Error path was logged.
        mock_settings.handle.log.assert_called()
        # Failure surfaced via dedicated counter so summary can show it.
        assert nb.counter["device_types_failed"] == 1
        # Counters that imply a successful PATCH must NOT be bumped.
        assert nb.counter["properties_updated"] == 0
        # "Device Type Updated" is misleading when nothing was applied — must
        # NOT appear on either the verbose or non-verbose log.
        all_calls = [c.args[0] for c in mock_settings.handle.log.call_args_list]
        all_calls += [c.args[0] for c in mock_settings.handle.verbose_log.call_args_list]
        assert not any("Device Type Updated" in msg for msg in all_calls), (
            f"Misleading 'Device Type Updated' log emitted after failure: {all_calls}"
        )
        # The failure log must surface the model so operators can find it.
        assert any("Device Type Update Failed" in msg and "TestSwitch" in msg for msg in all_calls)
        # Outcome.FAILED must also be recorded in the registry so the end-of-run report reflects it.
        from core.outcomes import EntityKind, Outcome

        failures = nb.outcomes.failures()
        assert len(failures) == 1
        assert failures[0].kind == EntityKind.DEVICE_TYPE
        assert failures[0].outcome == Outcome.FAILED
        assert "TestSwitch" in failures[0].identity

    def _build_subdevice_role_flip_setup(self, mock_settings, mock_pynetbox, make_device_types, *, force=False):
        """Shared scaffolding for force-resolve-conflicts integration tests.

        Returns ``(nb, dt, mock_nb_api, change, device_type, blocking_template, error)``
        where the device-type update is wired to fail with the parent->child
        device-bay constraint and the resolver query path is pre-stubbed to
        report zero dependent devices and one blocking device-bay template.
        """
        import pynetbox as real_pynb2
        from core.change_detector import ChangeReport, DeviceTypeChange, PropertyChange

        mock_pynetbox.RequestError = real_pynb2.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 99
        existing_dt.model = "SuperServer"
        existing_dt.manufacturer.name = "Supermicro"
        dt.existing_device_types = {("supermicro", "SuperServer"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        nb.force_resolve_conflicts = force

        # Pre-stub resolver-side queries: zero dependent devices, one blocking template.
        mock_nb_api.dcim.devices.filter.return_value = []
        mock_nb_api.dcim.devices.count.return_value = 0
        blocking_template = MagicMock()
        blocking_template.name = "module-bay-1"
        mock_nb_api.dcim.device_bay_templates.filter.return_value = [blocking_template]

        # Build a real RequestError carrying the constraint message.
        constraint_body = (
            b'{"subdevice_role": ["Must delete all device bay templates associated with '
            b'this device before declassifying it as a parent device."]}'
        )
        err = real_pynb2.RequestError(MagicMock(status_code=400, content=constraint_body))
        # Force the .error property to return the parsed dict (pynetbox usually does this).
        err.error = {
            "subdevice_role": [
                "Must delete all device bay templates associated with this device "
                "before declassifying it as a parent device."
            ]
        }

        change = DeviceTypeChange(
            manufacturer_slug="supermicro",
            model="SuperServer",
            slug="superserver",
            property_changes=[PropertyChange("subdevice_role", "parent", "child")],
        )
        report = ChangeReport(modified_device_types=[change])

        device_type = {
            "manufacturer": {"slug": "supermicro"},
            "model": "SuperServer",
            "slug": "superserver",
            "src": "/tmp/device-types/supermicro/superserver.yaml",
        }
        return nb, dt, mock_nb_api, report, device_type, blocking_template, err

    def test_constraint_failure_logs_hint_when_flag_off(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Without --force-resolve-conflicts, classifier hint is logged but no auto-resolve runs."""
        nb, dt, mock_nb_api, report, device_type, blocking_template, err = self._build_subdevice_role_flip_setup(
            mock_settings, mock_pynetbox, make_device_types, force=False
        )
        mock_nb_api.dcim.device_types.update.side_effect = err

        mock_settings.handle.log.reset_mock()
        nb.create_device_types([device_type], update=True, change_report=report)

        # Auto-resolve must NOT have run (no template delete attempted).
        blocking_template.delete.assert_not_called()
        # PATCH must have been attempted exactly once (no retry).
        mock_nb_api.dcim.device_types.update.assert_called_once()
        # Failure counter bumped, success counter not.
        assert nb.counter["device_types_failed"] == 1
        assert nb.counter["properties_updated"] == 0
        # Hint mentions the flag and the blocking template.
        all_logs = [c.args[0] for c in mock_settings.handle.log.call_args_list]
        assert any("--force-resolve-conflicts" in m for m in all_logs), all_logs
        assert any("module-bay-1" in m for m in all_logs), all_logs
        # Failure recorded into the OutcomeRegistry with structured context.
        from core.outcomes import EntityKind, Outcome

        failures = nb.outcomes.failures()
        assert len(failures) == 1
        assert failures[0].kind == EntityKind.DEVICE_TYPE
        assert failures[0].outcome == Outcome.FAILED
        assert "SuperServer" in failures[0].identity
        assert "module-bay-1" in failures[0].blocking_objects
        assert failures[0].hint and "--force-resolve-conflicts" in failures[0].hint

    def test_constraint_failure_auto_resolves_when_flag_on_and_safe(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """With flag on + zero dependents, blocking templates are deleted and PATCH retried."""
        nb, dt, mock_nb_api, report, device_type, blocking_template, err = self._build_subdevice_role_flip_setup(
            mock_settings, mock_pynetbox, make_device_types, force=True
        )
        # First update call fails; second (after auto-resolve) succeeds.
        mock_nb_api.dcim.device_types.update.side_effect = [err, MagicMock()]

        nb.create_device_types([device_type], update=True, change_report=report)

        blocking_template.delete.assert_called_once()
        assert mock_nb_api.dcim.device_types.update.call_count == 2
        assert nb.counter["properties_updated"] == 1
        assert nb.counter["device_types_failed"] == 0
        # Successful retry path must NOT record a failure into the registry.
        assert nb.outcomes.failures() == []

    def test_constraint_failure_auto_resolve_retry_still_fails(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """If the retried PATCH after auto-resolve still fails, count it as a failure exactly once."""
        import pynetbox as real_pynb2

        nb, dt, mock_nb_api, report, device_type, blocking_template, err = self._build_subdevice_role_flip_setup(
            mock_settings, mock_pynetbox, make_device_types, force=True
        )
        err2 = real_pynb2.RequestError(MagicMock(status_code=500, content=b'{"detail":"still bad"}'))
        mock_nb_api.dcim.device_types.update.side_effect = [err, err2]

        nb.create_device_types([device_type], update=True, change_report=report)

        blocking_template.delete.assert_called_once()
        assert mock_nb_api.dcim.device_types.update.call_count == 2
        assert nb.counter["properties_updated"] == 0
        assert nb.counter["device_types_failed"] == 1
        # The failed retry must surface in the structured failure report exactly once.
        failures = nb.outcomes.failures()
        assert len(failures) == 1
        assert "SuperServer" in failures[0].identity

    def test_constraint_failure_blocked_when_devices_in_use(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """With flag on but live devices reference the type, no remediation runs (safety gate)."""
        nb, dt, mock_nb_api, report, device_type, blocking_template, err = self._build_subdevice_role_flip_setup(
            mock_settings, mock_pynetbox, make_device_types, force=True
        )
        live_device = MagicMock()
        live_device.name = "router-1"
        mock_nb_api.dcim.devices.filter.return_value = [live_device]
        mock_nb_api.dcim.devices.count.return_value = 1
        mock_nb_api.dcim.device_types.update.side_effect = err

        mock_settings.handle.log.reset_mock()
        nb.create_device_types([device_type], update=True, change_report=report)

        # Safety gate honoured: no delete, no retry.
        blocking_template.delete.assert_not_called()
        mock_nb_api.dcim.device_types.update.assert_called_once()
        assert nb.counter["device_types_failed"] == 1
        all_logs = [c.args[0] for c in mock_settings.handle.log.call_args_list]
        assert any("router-1" in m for m in all_logs), all_logs

    def test_update_applies_component_changes(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """update=True with component_changes calls update_components (and optionally remove_components)."""
        from core.change_detector import (
            ChangeReport,
            ChangeType,
            ComponentChange,
            DeviceTypeChange,
        )

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.remove_components = MagicMock()

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        def fake_update_components(*args, **kwargs):
            nb.counter.update({"components_added": 1})

        dt.update_components = MagicMock(side_effect=fake_update_components)

        change = DeviceTypeChange(
            manufacturer_slug="cisco",
            model="TestSwitch",
            slug="testswitch",
            component_changes=[ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)],
        )
        report = ChangeReport(modified_device_types=[change])

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type], update=True, change_report=report, remove_components=True)
        dt.update_components.assert_called()
        assert nb.counter["device_types_component_updates"] == 1
        assert nb.counter.get("properties_updated", 0) == 0

    def test_component_changes_all_fail_increments_device_types_failed(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """When component API calls are issued but all fail, device_types_failed must be incremented.

        Regression: the old code set component_attempted by comparing counters
        before/after the API calls, so a total component failure was silently
        swallowed (counters didn't move → component_attempted=False → CACHED).
        """
        from core.change_detector import (
            ChangeReport,
            ChangeType,
            ComponentChange,
            DeviceTypeChange,
        )
        from core.outcomes import EntityKind, Outcome

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 7
        existing_dt.model = "FailSwitch"
        existing_dt.manufacturer.name = "Acme"
        dt.existing_device_types = {("acme", "FailSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        # update_components is called but intentionally moves no counters
        # (simulates every per-component API call failing internally).
        dt.update_components = MagicMock()

        change = DeviceTypeChange(
            manufacturer_slug="acme",
            model="FailSwitch",
            slug="failswitch",
            component_changes=[ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)],
        )
        report = ChangeReport(modified_device_types=[change])
        device_type = {
            "manufacturer": {"slug": "acme"},
            "model": "FailSwitch",
            "slug": "failswitch",
            "src": "/tmp/device-types/acme/failswitch.yaml",
        }
        nb.create_device_types([device_type], update=True, change_report=report)

        dt.update_components.assert_called_once()
        assert nb.counter["device_types_failed"] == 1
        assert nb.counter.get("device_types_component_updates", 0) == 0
        failures = nb.outcomes.failures()
        assert len(failures) == 1
        assert failures[0].kind == EntityKind.DEVICE_TYPE
        assert failures[0].outcome == Outcome.FAILED
        assert "FailSwitch" in failures[0].identity

    def test_component_changes_partial_success_records_partial_outcome(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """When only some component API calls succeed, a PARTIAL outcome must be recorded.

        Regression: before the delta/count comparison, any non-zero counter
        movement was treated as full success regardless of how many changes
        were attempted.
        """
        from core.change_detector import (
            ChangeReport,
            ChangeType,
            ComponentChange,
            DeviceTypeChange,
        )
        from core.outcomes import EntityKind, Outcome

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 9
        existing_dt.model = "PartialSwitch"
        existing_dt.manufacturer.name = "Acme"
        dt.existing_device_types = {("acme", "PartialSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        # Simulate 1 of 3 component additions succeeding: the mock increments
        # components_added by 1, leaving actionable_count=3 vs delta=1.
        def partial_update(*args, **kwargs):
            nb.counter.update({"components_added": 1})

        dt.update_components = MagicMock(side_effect=partial_update)

        change = DeviceTypeChange(
            manufacturer_slug="acme",
            model="PartialSwitch",
            slug="partialswitch",
            component_changes=[
                ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED),
                ComponentChange("interfaces", "eth1", ChangeType.COMPONENT_ADDED),
                ComponentChange("interfaces", "eth2", ChangeType.COMPONENT_ADDED),
            ],
        )
        report = ChangeReport(modified_device_types=[change])
        device_type = {
            "manufacturer": {"slug": "acme"},
            "model": "PartialSwitch",
            "slug": "partialswitch",
            "src": "/tmp/device-types/acme/partialswitch.yaml",
        }
        nb.create_device_types([device_type], update=True, change_report=report)

        dt.update_components.assert_called_once()
        assert nb.counter["device_types_failed"] == 0
        assert nb.counter.get("device_types_component_updates", 0) == 1
        partials = nb.outcomes.partials()
        assert len(partials) == 1
        assert partials[0].kind == EntityKind.DEVICE_TYPE
        assert partials[0].outcome == Outcome.PARTIAL
        assert "PartialSwitch" in partials[0].identity
        assert "1 of 3" in (partials[0].reason or "")

    def test_component_only_update_does_not_count_as_property_update(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Component-only change must NOT increment properties_updated."""
        from core.change_detector import (
            ChangeReport,
            ChangeType,
            ComponentChange,
            DeviceTypeChange,
        )

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.remove_components = MagicMock()

        existing_dt = MagicMock()
        existing_dt.id = 42
        existing_dt.model = "MySwitch"
        existing_dt.manufacturer.name = "Acme"
        dt.existing_device_types = {("acme", "MySwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        def fake_update_components(*args, **kwargs):
            nb.counter.update({"components_added": 1})

        dt.update_components = MagicMock(side_effect=fake_update_components)

        change = DeviceTypeChange(
            manufacturer_slug="acme",
            model="MySwitch",
            slug="myswitch",
            component_changes=[ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)],
        )
        report = ChangeReport(modified_device_types=[change])
        device_type = {
            "manufacturer": {"slug": "acme"},
            "model": "MySwitch",
            "slug": "myswitch",
            "src": "/tmp/device-types/acme/myswitch.yaml",
        }
        nb.create_device_types([device_type], update=True, change_report=report)
        assert nb.counter.get("properties_updated", 0) == 0
        assert nb.counter["device_types_component_updates"] == 1

    def test_update_verbose_log_when_change_applied(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """verbose_log with 'Device Type Updated' when dt_change is not None."""
        from core.change_detector import ChangeReport, DeviceTypeChange, PropertyChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        mock_settings.handle.verbose_log.reset_mock()

        change = DeviceTypeChange(
            manufacturer_slug="cisco",
            model="TestSwitch",
            slug="testswitch",
            property_changes=[PropertyChange("u_height", 1, 2)],
        )
        report = ChangeReport(modified_device_types=[change])

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type], update=True, change_report=report)
        assert any(
            "Device Type Updated" in str(call) or "Applied" in str(call)
            for call in mock_settings.handle.verbose_log.call_args_list
        )

    def test_no_change_entry_logs_cached_no_pending_updates(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """When update=True but no change_report entry, logs 'No pending updates'."""
        from core.change_detector import ChangeReport

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_dt = MagicMock()
        existing_dt.id = 1
        existing_dt.model = "TestSwitch"
        existing_dt.manufacturer.name = "Cisco"
        dt.existing_device_types = {("cisco", "TestSwitch"): existing_dt}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        mock_settings.handle.verbose_log.reset_mock()

        # Empty report: no modified_device_types matching our DT
        report = ChangeReport(modified_device_types=[])

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type], update=True, change_report=report)
        assert any("No pending updates" in str(call) for call in mock_settings.handle.verbose_log.call_args_list)


# ---------------------------------------------------------------------------
# create_device_types RequestError + all component type branches (343-374)
# ---------------------------------------------------------------------------


class TestCreateDeviceTypesRequestErrorAndComponents:
    """Tests for RequestError on create and all component creation branches."""

    def test_request_error_logs_and_continues(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """RequestError on device_types.create is logged and the DT is skipped."""
        import pynetbox as real_pynb2

        mock_pynetbox.RequestError = real_pynb2.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        err = real_pynb2.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        mock_nb_api.dcim.device_types.create.side_effect = err
        mock_settings.handle.log.reset_mock()

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type])
        mock_settings.handle.log.assert_called()

    def test_creates_all_component_types(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """All component type branches are called.

        Covers power-ports, console-ports, power-outlets,
        console-server-ports, rear-ports, front-ports, device-bays,
        and module-bays.
        """
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {}
        # Patch all create_* methods on dt
        dt.create_power_ports = MagicMock()
        dt.create_console_ports = MagicMock()
        dt.create_power_outlets = MagicMock()
        dt.create_console_server_ports = MagicMock()
        dt.create_rear_ports = MagicMock()
        dt.create_front_ports = MagicMock()
        dt.create_device_bays = MagicMock()
        dt.create_module_bays = MagicMock()
        dt.create_interfaces = MagicMock()
        dt.upload_images = MagicMock()

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        nb.modules = True

        created_dt = MagicMock()
        created_dt.id = 1
        created_dt.manufacturer.name = "Cisco"
        created_dt.model = "TestSwitch"
        mock_nb_api.dcim.device_types.create.return_value = created_dt

        dev_dir = "/tmp/device-types/cisco"
        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "power-ports": [{"name": "PSU1"}],
            "console-ports": [{"name": "Con1"}],
            "power-outlets": [{"name": "PO1"}],
            "console-server-ports": [{"name": "CSP1"}],
            "rear-ports": [{"name": "RP1"}],
            "front-ports": [{"name": "FP1"}],
            "device-bays": [{"name": "Bay1"}],
            "module-bays": [{"name": "MB1"}],
            "src": f"{dev_dir}/testswitch.yaml",
        }
        with patch("glob.glob", return_value=[]):
            nb.create_device_types([device_type])

        dt.create_power_ports.assert_called()
        dt.create_console_ports.assert_called()
        dt.create_power_outlets.assert_called()
        dt.create_console_server_ports.assert_called()
        dt.create_rear_ports.assert_called()
        dt.create_front_ports.assert_called()
        dt.create_device_bays.assert_called()
        dt.create_module_bays.assert_called()

    def test_upload_images_called_for_new_dt(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        """upload_images is called for newly created DT when saved_images is populated."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {}
        dt.upload_images = MagicMock()

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        created_dt = MagicMock()
        created_dt.id = 1
        created_dt.manufacturer.name = "Cisco"
        created_dt.model = "TestSwitch"
        mock_nb_api.dcim.device_types.create.return_value = created_dt

        dev_dir = tmp_path / "device-types" / "cisco"
        dev_dir.mkdir(parents=True)
        img = tmp_path / "elevation-images" / "cisco" / "testswitch.front.png"
        img.parent.mkdir(parents=True)
        img.write_bytes(b"img")

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "front_image": True,
            "src": str(dev_dir / "testswitch.yaml"),
        }
        with patch("glob.glob", return_value=[str(img)]):
            nb.create_device_types([device_type])

        dt.upload_images.assert_called_once()


# ---------------------------------------------------------------------------
# filter_actionable_module_types edge cases (lines 433, 436, 466-467, 472-473)
# ---------------------------------------------------------------------------


class TestFilterActionableModuleTypesEdge:
    """Tests for filter_actionable_module_types edge cases."""

    def test_empty_module_types_returns_empty(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        """Empty module_types list returns [], {} immediately."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        result, images, _ = nb.filter_actionable_module_types([], {}, only_new=False)
        assert result == []
        assert images == {}

    def test_only_new_delegates_to_filter_new(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        """only_new=True returns only genuinely new module types."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        existing_mt = MagicMock()
        all_mts = {"cisco": {"LC": existing_mt}}
        module_types = [
            {"manufacturer": {"slug": "cisco"}, "model": "LC"},
            {"manufacturer": {"slug": "cisco"}, "model": "NEW"},
        ]
        result, images, _ = nb.filter_actionable_module_types(module_types, all_mts, only_new=True)
        assert len(result) == 1
        assert result[0]["model"] == "NEW"
        assert images == {}

    def test_new_module_type_added_to_actionable(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        """Module type not in all_module_types is added to actionable."""
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
        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "NEW",
            "src": "/repo/module-types/cisco/new.yaml",
        }
        with patch("glob.glob", return_value=[]):
            result, _, _ = nb.filter_actionable_module_types([module_type], {}, only_new=False)
        assert result == [module_type]

    def test_existing_module_with_new_image_is_actionable(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, tmp_path
    ):
        """Existing module type with an image not yet in NetBox is actionable."""
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
        nb.device_types._global_preload_done = True  # isolate from preload side-effects

        existing_mt = MagicMock()
        existing_mt.id = 42
        all_mts = {"cisco": {"LC": existing_mt}}

        module_dir = tmp_path / "module-types" / "cisco"
        module_dir.mkdir(parents=True)
        src = module_dir / "lc.yaml"
        src.write_text("model: LC")

        img_dir = tmp_path / "module-images" / "cisco"
        img_dir.mkdir(parents=True)
        img = img_dir / "lc.front.jpg"
        img.write_bytes(b"img")

        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "LC",
            "src": str(src),
        }

        # existing images are empty → the image is "new" → actionable
        with patch.object(nb, "_fetch_module_type_existing_images", return_value={42: set()}):
            with patch(
                "core.netbox_api.NetBox._discover_module_image_files",
                return_value=[str(img)],
            ):
                result, existing_images_map, _ = nb.filter_actionable_module_types(
                    [module_type], all_mts, only_new=False
                )
        assert result == [module_type]
        # Verify the upload worklist is propagated so create_module_types can upload the image.
        assert existing_images_map == {42: set()}

    def test_existing_module_with_changed_property_is_actionable(
        self, mock_settings, mock_pynetbox, mock_graphql_requests
    ):
        """Existing module type with a changed scalar property (e.g. part_number) is actionable."""
        from core.graphql_client import DotDict

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
        # Skip the GraphQL preload — these tests isolate scalar/image diffs.
        nb.device_types._global_preload_done = True

        existing_mt = DotDict(
            {"id": 42, "model": "IOM-s-3.0T", "part_number": "OLD_PN", "manufacturer": {"slug": "nokia"}}
        )
        all_mts = {"nokia": {"IOM-s-3.0T": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "src": "/tmp/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }

        with patch("glob.glob", return_value=[]):
            with patch.object(nb, "_fetch_module_type_existing_images", return_value={}):
                actionable, _, changed_property_log = nb.filter_actionable_module_types(
                    [module_type],
                    all_mts,
                    only_new=False,
                )

        assert actionable == [module_type]
        # Verify the scalar diff is captured for the modified-summary log path.
        assert len(changed_property_log) == 1
        mfr_slug, model, fields_info, _ = changed_property_log[0]
        assert mfr_slug == "nokia"
        assert model == "IOM-s-3.0T"
        assert any(name == "part_number" and old == "OLD_PN" and new == "3HE16474AA" for name, old, new in fields_info)

    def test_existing_module_with_missing_image_and_property_change_logs_both(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, tmp_path
    ):
        """Mixed image + property change: image change must NOT short-circuit property/component diff.

        Regression: an early ``continue`` after detecting a missing image meant scalar/component
        comparison was skipped; the module ended up actionable but absent from
        ``changed_property_log``, so ``log_module_type_changes`` never showed the property diff
        and the "Modified module types" count was wrong.
        """
        from core.graphql_client import DotDict

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
        # Skip the GraphQL preload — these tests isolate scalar/image diffs.
        nb.device_types._global_preload_done = True

        existing_mt = DotDict(
            {"id": 42, "model": "IOM-s-3.0T", "part_number": "OLD_PN", "manufacturer": {"slug": "nokia"}}
        )
        all_mts = {"nokia": {"IOM-s-3.0T": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "src": "/tmp/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }

        # NetBox has no image attachments for this module → missing image triggers image_changed.
        with patch.object(nb, "_discover_module_image_files", return_value=["/tmp/IOM-s-3.0T.front.png"]):
            with patch.object(nb, "_fetch_module_type_existing_images", return_value={42: set()}):
                actionable, existing_images_map, changed_property_log = nb.filter_actionable_module_types(
                    [module_type],
                    all_mts,
                    only_new=False,
                )

        assert actionable == [module_type]
        # Existing-images map drives the upload diff in create_module_types — assert it
        # records the empty set for module 42 so a regression that drops the second
        # return value is caught.
        assert existing_images_map == {42: set()}
        # Property diff MUST still be captured even though images also changed.
        assert len(changed_property_log) == 1
        mfr_slug, model, fields_info, _ = changed_property_log[0]
        assert mfr_slug == "nokia"
        assert model == "IOM-s-3.0T"
        assert any(f == "part_number" for f, _, _ in fields_info)

    def test_existing_module_with_only_missing_image_is_actionable_but_not_logged(
        self, mock_settings, mock_pynetbox, mock_graphql_requests
    ):
        """Image-only change: actionable (so the image is uploaded) but NOT in changed_property_log.

        Image-only updates are handled in default mode and must not appear as "Modified
        module types" or trigger the misleading ``--update`` hint.
        """
        from core.graphql_client import DotDict

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
        # Skip the GraphQL preload — these tests isolate scalar/image diffs.
        nb.device_types._global_preload_done = True

        existing_mt = DotDict(
            {"id": 42, "model": "IOM-s-3.0T", "part_number": "3HE16474AA", "manufacturer": {"slug": "nokia"}}
        )
        all_mts = {"nokia": {"IOM-s-3.0T": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "src": "/tmp/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }

        with patch.object(nb, "_discover_module_image_files", return_value=["/tmp/IOM-s-3.0T.front.png"]):
            with patch.object(nb, "_fetch_module_type_existing_images", return_value={42: set()}):
                actionable, existing_images_map, changed_property_log = nb.filter_actionable_module_types(
                    [module_type],
                    all_mts,
                    only_new=False,
                )

        assert actionable == [module_type]
        # Image-only change must surface the existing-images map (drives upload diff)
        # without polluting the property log.
        assert existing_images_map == {42: set()}
        assert changed_property_log == []

    def test_existing_module_with_unchanged_property_is_not_actionable(
        self, mock_settings, mock_pynetbox, mock_graphql_requests
    ):
        """Existing module type whose properties all match NetBox is not actionable."""
        from core.graphql_client import DotDict

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
        # Skip the GraphQL preload — these tests isolate scalar/image diffs.
        nb.device_types._global_preload_done = True

        existing_mt = DotDict(
            {"id": 42, "model": "IOM-s-3.0T", "part_number": "3HE16474AA", "manufacturer": {"slug": "nokia"}}
        )
        all_mts = {"nokia": {"IOM-s-3.0T": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "src": "/tmp/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }

        with patch("glob.glob", return_value=[]):
            with patch.object(nb, "_fetch_module_type_existing_images", return_value={}):
                actionable, _, _ = nb.filter_actionable_module_types(
                    [module_type],
                    all_mts,
                    only_new=False,
                )

        assert actionable == []


class TestCreateModuleTypesEdge:
    """Edge-case tests for create_module_types."""

    def test_existing_module_type_verbose_logged(self, mock_settings, mock_pynetbox):
        """When a module type already exists, verbose_log is called with 'Cached'."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)

        existing_mt = MagicMock()
        existing_mt.id = 5
        existing_mt.manufacturer.name = "Cisco"
        existing_mt.model = "LC"
        all_module_types = {"cisco": {"LC": existing_mt}}

        mock_settings.handle.verbose_log.reset_mock()
        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "LC",
            "src": "/repo/module-types/cisco/lc.yaml",
        }
        nb.create_module_types(
            [module_type],
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
        assert any("Module Type Cached" in str(c) for c in mock_settings.handle.verbose_log.call_args_list)

    def test_only_new_skips_existing_module_component_creation(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """only_new=True + existing module → skip component creation."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = make_device_types(nb_api=mock_pynetbox.api.return_value)
        nb.device_types.create_module_interfaces = MagicMock()

        existing_mt = MagicMock()
        existing_mt.id = 5
        existing_mt.manufacturer.name = "Cisco"
        existing_mt.model = "LC"
        all_module_types = {"cisco": {"LC": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "LC",
            "interfaces": [{"name": "xe-0"}],
            "src": "/repo/module-types/cisco/lc.yaml",
        }
        nb.create_module_types(
            [module_type],
            only_new=True,
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
        nb.device_types.create_module_interfaces.assert_not_called()

    def test_creates_module_type_with_power_outlets_console_server_ports_front_ports(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """power-outlets, console-server-ports, front-ports branches in create_module_types."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = make_device_types(nb_api=mock_pynetbox.api.return_value)
        nb.device_types.create_module_power_outlets = MagicMock()
        nb.device_types.create_module_console_server_ports = MagicMock()
        nb.device_types.create_module_front_ports = MagicMock()

        created_mt = MagicMock()
        created_mt.id = 5
        created_mt.manufacturer.name = "Cisco"
        created_mt.model = "LC"
        mock_pynetbox.api.return_value.dcim.module_types.create.return_value = created_mt

        module_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "LC",
            "power-outlets": [{"name": "PO1"}],
            "console-server-ports": [{"name": "CSP1"}],
            "front-ports": [{"name": "FP1"}],
            "src": "/repo/module-types/cisco/lc.yaml",
        }
        nb.create_module_types([module_type], all_module_types={}, module_type_existing_images={})
        nb.device_types.create_module_power_outlets.assert_called_once()
        nb.device_types.create_module_console_server_ports.assert_called_once()
        nb.device_types.create_module_front_ports.assert_called_once()

    def test_existing_module_type_property_update_calls_api(self, mock_settings, mock_pynetbox):
        """Existing module type with changed part_number calls module_types.update and increments counter."""
        from core.graphql_client import DotDict

        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)

        existing_mt = DotDict(
            {
                "id": 5,
                "model": "IOM-s-3.0T",
                "part_number": "OLD_PN",
                "manufacturer": {"name": "Nokia", "slug": "nokia"},
            }
        )
        all_module_types = {"nokia": {"IOM-s-3.0T": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "src": "/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }
        nb.create_module_types(
            [module_type],
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
        mock_pynetbox.api.return_value.dcim.module_types.update.assert_called_once()
        # Verify the PATCH payload targets the right resource and field — guards
        # against a regression that updates the wrong module or omits part_number.
        update_payload = mock_pynetbox.api.return_value.dcim.module_types.update.call_args.args[0][0]
        assert update_payload["id"] == 5
        assert update_payload["part_number"] == "3HE16474AA"
        assert nb.counter["module_updated"] == 1

    def test_existing_module_type_property_unchanged_no_api_call(self, mock_settings, mock_pynetbox):
        """Existing module type with matching part_number does not call module_types.update."""
        from core.graphql_client import DotDict

        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)

        existing_mt = DotDict(
            {
                "id": 5,
                "model": "IOM-s-3.0T",
                "part_number": "3HE16474AA",
                "manufacturer": {"name": "Nokia", "slug": "nokia"},
            }
        )
        all_module_types = {"nokia": {"IOM-s-3.0T": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "src": "/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }
        nb.create_module_types(
            [module_type],
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
        mock_pynetbox.api.return_value.dcim.module_types.update.assert_not_called()
        assert nb.counter["module_updated"] == 0

    def test_existing_module_type_only_new_skips_property_update(self, mock_settings, mock_pynetbox):
        """only_new=True skips property update even when part_number differs."""
        from core.graphql_client import DotDict

        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)

        existing_mt = DotDict(
            {
                "id": 5,
                "model": "IOM-s-3.0T",
                "part_number": "OLD_PN",
                "manufacturer": {"name": "Nokia", "slug": "nokia"},
            }
        )
        all_module_types = {"nokia": {"IOM-s-3.0T": existing_mt}}

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "src": "/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }
        nb.create_module_types(
            [module_type],
            only_new=True,
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
        mock_pynetbox.api.return_value.dcim.module_types.update.assert_not_called()
        assert nb.counter["module_updated"] == 0

    def test_existing_module_type_component_update_calls_update_components(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Existing module type with changed component property calls update_components and increments counter."""
        from core.graphql_client import DotDict

        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = make_device_types(nb_api=mock_pynetbox.api.return_value)

        # Simulate update_components actually updating a component (increments components_updated)
        def _do_update(*args, **kwargs):
            nb.counter["components_updated"] += 1

        nb.device_types.update_components = MagicMock(side_effect=_do_update)

        existing_mt = DotDict(
            {
                "id": 5,
                "model": "IOM-s-3.0T",
                "part_number": "3HE16474AA",
                "manufacturer": {"name": "Nokia", "slug": "nokia"},
            }
        )
        all_module_types = {"nokia": {"IOM-s-3.0T": existing_mt}}

        # Cache shows interface with no description; YAML has a description → COMPONENT_CHANGED
        nb.device_types.cached_components = {
            "interface_templates": {
                ("module", 5): {
                    "xe-0": DotDict(
                        {
                            "id": "10",
                            "name": "xe-0",
                            "description": "",
                            "type": {"value": "10gbase-x-sfpp"},
                        }
                    )
                }
            },
        }

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "interfaces": [{"name": "xe-0", "type": "10gbase-x-sfpp", "description": "Uplink"}],
            "src": "/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }
        nb.create_module_types(
            [module_type],
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
        nb.device_types.update_components.assert_called_once()
        # Scalar PATCH must NOT fire here — part_number already matches NetBox.
        # A regression that always issues the PATCH would slip past the existing
        # counter assertion below.
        mock_pynetbox.api.return_value.dcim.module_types.update.assert_not_called()
        # Inspect the diff payload: must contain a COMPONENT_CHANGED for "xe-0"
        # carrying a PropertyChange for "description".
        from core.change_detector import ChangeType

        component_changes = nb.device_types.update_components.call_args.args[2]
        changed = [c for c in component_changes if c.change_type == ChangeType.COMPONENT_CHANGED]
        assert len(changed) == 1
        assert changed[0].component_name == "xe-0"
        prop_names = {pc.property_name for pc in changed[0].property_changes}
        assert prop_names == {"description"}
        assert nb.counter["module_updated"] == 1

    def test_existing_module_type_property_and_component_update_increments_once(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Both property and component change → module_updated incremented only once."""
        from core.graphql_client import DotDict

        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = make_device_types(nb_api=mock_pynetbox.api.return_value)

        # Simulate update_components actually updating a component
        def _do_update(*args, **kwargs):
            nb.counter["components_updated"] += 1

        nb.device_types.update_components = MagicMock(side_effect=_do_update)

        existing_mt = DotDict(
            {
                "id": 5,
                "model": "IOM-s-3.0T",
                "part_number": "OLD_PN",
                "manufacturer": {"name": "Nokia", "slug": "nokia"},
            }
        )
        all_module_types = {"nokia": {"IOM-s-3.0T": existing_mt}}

        nb.device_types.cached_components = {
            "interface_templates": {
                ("module", 5): {
                    "xe-0": DotDict(
                        {
                            "id": "10",
                            "name": "xe-0",
                            "description": "",
                            "type": {"value": "10gbase-x-sfpp"},
                        }
                    )
                }
            },
        }

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "interfaces": [{"name": "xe-0", "type": "10gbase-x-sfpp", "description": "Uplink"}],
            "src": "/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }
        nb.create_module_types(
            [module_type],
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
        nb.device_types.update_components.assert_called_once()
        # Verify the scalar PATCH (module-type property) was actually attempted
        # for the right module — guards against a regression where the property
        # diff is missed but the component diff still fires.
        scalar_update = mock_pynetbox.api.return_value.dcim.module_types.update
        scalar_update.assert_called_once()
        scalar_payload = scalar_update.call_args.args[0][0]
        assert scalar_payload["id"] == 5
        assert scalar_payload["part_number"] == "3HE16474AA"
        # Inspect the diff payload: must contain a COMPONENT_CHANGED for "xe-0"
        # property and is applied via the module-type PATCH path, not via the
        # component diff).
        from core.change_detector import ChangeType

        component_changes = nb.device_types.update_components.call_args.args[2]
        changed = [c for c in component_changes if c.change_type == ChangeType.COMPONENT_CHANGED]
        assert len(changed) == 1
        assert changed[0].component_name == "xe-0"
        assert {pc.property_name for pc in changed[0].property_changes} == {"description"}
        # property update already incremented; component path should NOT double-count
        assert nb.counter["module_updated"] == 1

    def test_existing_module_type_removal_only_no_counter_increment(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """COMPONENT_REMOVED-only changes call update_components but do NOT increment module_updated."""
        from core.graphql_client import DotDict

        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = make_device_types(nb_api=mock_pynetbox.api.return_value)
        # update_components is a no-op for removals (no counter change)
        nb.device_types.update_components = MagicMock()

        existing_mt = DotDict(
            {
                "id": 5,
                "model": "IOM-s-3.0T",
                "part_number": "3HE16474AA",
                "manufacturer": {"name": "Nokia", "slug": "nokia"},
            }
        )
        all_module_types = {"nokia": {"IOM-s-3.0T": existing_mt}}

        # Cache has an interface that YAML doesn't have → COMPONENT_REMOVED
        nb.device_types.cached_components = {
            "interface_templates": {
                ("module", 5): {
                    "xe-0": DotDict(
                        {"id": "10", "name": "xe-0", "description": "", "type": {"value": "10gbase-x-sfpp"}}
                    ),
                    "xe-extra": DotDict({"id": "11", "name": "xe-extra", "description": ""}),
                }
            },
        }

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",
            "interfaces": [{"name": "xe-0", "type": "10gbase-x-sfpp", "description": ""}],
            "src": "/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }
        nb.create_module_types(
            [module_type],
            all_module_types=all_module_types,
            module_type_existing_images={},
        )
        nb.device_types.update_components.assert_called_once()
        # Inspect the diff payload: must contain only a COMPONENT_REMOVED for
        # "xe-extra" — no PropertyChanges, no other change types.
        from core.change_detector import ChangeType

        component_changes = nb.device_types.update_components.call_args.args[2]
        removed = [c for c in component_changes if c.change_type == ChangeType.COMPONENT_REMOVED]
        non_removed = [c for c in component_changes if c.change_type != ChangeType.COMPONENT_REMOVED]
        assert len(removed) == 1
        assert removed[0].component_name == "xe-extra"
        assert removed[0].property_changes == []
        assert non_removed == []
        # removal-only: update_components did nothing (no counter bumps) → module_updated stays 0
        assert nb.counter["module_updated"] == 0

    def test_property_update_plus_removal_only_remove_false_counts_as_updated(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Properties changed + removal-only diff with remove_components=False → module_updated incremented."""
        from core.graphql_client import DotDict

        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = make_device_types(nb_api=mock_pynetbox.api.return_value)
        nb.device_types.update_components = MagicMock()
        nb.device_types.remove_components = MagicMock()

        existing_mt = DotDict(
            {
                "id": 5,
                "model": "IOM-s-3.0T",
                "part_number": "OLD_PN",
                "manufacturer": {"name": "Nokia", "slug": "nokia"},
            }
        )
        all_module_types = {"nokia": {"IOM-s-3.0T": existing_mt}}

        # Cache has an extra interface not in YAML → COMPONENT_REMOVED
        nb.device_types.cached_components = {
            "interface_templates": {
                ("module", 5): {
                    "xe-extra": DotDict({"id": "11", "name": "xe-extra", "description": ""}),
                }
            },
        }

        module_type = {
            "manufacturer": {"slug": "nokia"},
            "model": "IOM-s-3.0T",
            "part_number": "3HE16474AA",  # changed from OLD_PN
            "interfaces": [],  # xe-extra absent → COMPONENT_REMOVED
            "src": "/repo/module-types/Nokia/IOM-s-3.0T.yaml",
        }
        # remove_components=False: the removal-only diff is not actionable,
        # but the scalar PATCH succeeded → module_updated must be incremented.
        nb.create_module_types(
            [module_type],
            all_module_types=all_module_types,
            module_type_existing_images={},
            remove_components=False,
        )
        mock_pynetbox.api.return_value.dcim.module_types.update.assert_called_once()
        nb.device_types.remove_components.assert_not_called()
        assert nb.counter["module_updated"] == 1
        assert nb.counter.get("module_update_failed", 0) == 0

    def test_existing_module_new_image_counted(self, tmp_path):
        """Existing MT whose image name is NOT in existing_names increments count."""
        from core.netbox_api import NetBox as NB

        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "mymodule.yaml"
        src.write_text("model: X")

        img_dir = tmp_path / "module-images" / "vendor"
        img_dir.mkdir(parents=True)
        (img_dir / "mymodule.front.jpg").write_bytes(b"img")

        existing_mt = MagicMock()
        existing_mt.id = 10
        all_mts = {"vendor": {"X": existing_mt}}
        # existing_images does NOT contain "mymodule.front"
        existing_images = {10: {"mymodule.rear"}}

        count = NB.count_module_type_images(
            [{"manufacturer": {"slug": "vendor"}, "model": "X", "src": str(src)}],
            all_module_types=all_mts,
            module_type_existing_images=existing_images,
        )
        assert count == 1


# ---------------------------------------------------------------------------
# _upload_module_type_images: existing image skipped (lines 735-746)
# ---------------------------------------------------------------------------


class TestUploadModuleTypeImages:
    """Tests for _upload_module_type_images skipping existing images."""

    def test_existing_image_is_skipped(self, mock_settings, mock_pynetbox, mock_graphql_requests, tmp_path):
        """If the image name is already in module_type_existing_images, upload is skipped."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)

        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "mymodule.yaml"
        src.write_text("model: X")

        img_dir = tmp_path / "module-images" / "vendor"
        img_dir.mkdir(parents=True)
        (img_dir / "mymodule.front.jpg").write_bytes(b"img")

        mt_res = MagicMock()
        mt_res.id = 10
        mt_res.model = "X"

        nb.device_types.upload_image_attachment = MagicMock(return_value=True)
        # "mymodule.front" already uploaded (NetBox stores basename sans last extension)
        existing_images = {10: {"mymodule.front"}}

        mock_settings.handle.verbose_log.reset_mock()
        nb._upload_module_type_images(mt_res, str(src), existing_images)

        nb.device_types.upload_image_attachment.assert_not_called()
        assert any("already exists" in str(c) for c in mock_settings.handle.verbose_log.call_args_list)

    def test_new_image_is_uploaded_and_tracked(self, mock_settings, mock_pynetbox, mock_graphql_requests, tmp_path):
        """When image is not yet in existing_images, upload_image_attachment is called."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)

        module_dir = tmp_path / "module-types" / "vendor"
        module_dir.mkdir(parents=True)
        src = module_dir / "mymodule.yaml"
        src.write_text("model: X")

        img_dir = tmp_path / "module-images" / "vendor"
        img_dir.mkdir(parents=True)
        (img_dir / "mymodule.front.jpg").write_bytes(b"img")

        mt_res = MagicMock()
        mt_res.id = 10
        mt_res.model = "X"

        nb.device_types.upload_image_attachment = MagicMock(return_value=True)
        existing_images = {}

        nb._upload_module_type_images(mt_res, str(src), existing_images)

        nb.device_types.upload_image_attachment.assert_called_once()
        assert "mymodule.front" in existing_images.get(10, set())


# ---------------------------------------------------------------------------
# start_component_preload with progress (lines 892, 901, 922-924)
# ---------------------------------------------------------------------------


class TestStartComponentPreloadProgress:
    """Tests for start_component_preload with a progress object."""

    def test_with_progress_creates_task_ids(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """start_component_preload with a progress object creates task IDs."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        progress = MagicMock()
        progress.add_task.return_value = 1

        preload_job = dt.start_component_preload(progress=progress)
        assert preload_job["task_ids"] is not None
        progress.add_task.assert_called()
        dt.stop_component_preload(preload_job)

    def test_exception_shuts_down_executor(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """If _get_endpoint_totals raises, executor is shut down and exception re-raised."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        with patch.object(dt, "_get_endpoint_totals", side_effect=RuntimeError("oops")):
            with pytest.raises(RuntimeError, match="oops"):
                dt.start_component_preload()


# ---------------------------------------------------------------------------
# pump_preload_progress (lines 996-1025)
# ---------------------------------------------------------------------------


class TestPumpPreloadProgress:
    """Tests for pump_preload_progress."""

    def test_returns_false_when_no_preload_job(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """pump_preload_progress returns False when preload_job is None."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        assert dt.pump_preload_progress(None, MagicMock()) is False

    def test_marks_done_futures(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Completed futures are moved to finished_endpoints and advanced=True returned."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        future.done.return_value = True
        future.result.return_value = [MagicMock(), MagicMock()]

        progress = MagicMock()
        task_id = 99
        preload_job = {
            "futures": {"interface_templates": future},
            "progress_updates": queue.Queue(),
            "task_ids": {"interface_templates": task_id},
            "finished_endpoints": set(),
        }
        result = dt.pump_preload_progress(preload_job, progress)
        assert result is True
        assert "interface_templates" in preload_job["finished_endpoints"]
        progress.stop_task.assert_called_with(task_id)

    def test_future_exception_sets_final_total_1(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """When future.result() raises, final_total defaults to 1."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        future.done.return_value = True
        future.result.side_effect = RuntimeError("fetch failed")

        progress = MagicMock()
        preload_job = {
            "futures": {"interface_templates": future},
            "progress_updates": queue.Queue(),
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": set(),
        }
        result = dt.pump_preload_progress(preload_job, progress)
        assert result is True
        progress.update.assert_called()


# ---------------------------------------------------------------------------
# _preload_global with progress (lines 1076-1081, 1102-1181, 1191-1193)
# ---------------------------------------------------------------------------


class TestPreloadGlobalWithProgress:
    """Tests for _preload_global with various progress/preload_job configurations."""

    def test_own_executor_with_progress(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """_preload_global with progress and no preload_job (own executor path)."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_graphql_requests.side_effect = _make_graphql_dispatch(
            {
                "device_type_list": {"data": {"device_type_list": []}},
                "interface_template_list": {"data": {"interface_template_list": []}},
            }
        )
        dt = make_device_types(nb_api=mock_nb_api)

        progress = MagicMock()
        progress.add_task.return_value = 1
        # Run only one component to keep the test fast
        components = [("interface_templates", "Interface Templates")]
        with patch.object(dt, "_get_endpoint_totals", return_value={"interface_templates": 0}):
            dt._preload_global(components, progress_wrapper=None, progress=progress)
        progress.add_task.assert_called()

    def test_preload_global_no_progress_future_failure(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """When no progress and a future raises, the exception is logged and re-raised."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        broken_future = MagicMock()
        broken_future.result.side_effect = RuntimeError("network error")

        mock_settings.handle.log.reset_mock()
        mock_settings.handle.verbose_log.reset_mock()

        with patch.object(dt, "_get_endpoint_totals", return_value={}):
            preload_job = {
                "executor": None,
                "futures": {"interface_templates": broken_future},
                "progress_updates": None,
                "endpoint_totals": {},
                "task_ids": None,
                "finished_endpoints": set(),
            }
            components = [("interface_templates", "Interface Templates")]
            with pytest.raises(RuntimeError, match="network error"):
                dt._preload_global(components, preload_job=preload_job, progress=None)

        mock_settings.handle.log.assert_any_call("Preload failed for Interface Templates: network error")

    def test_preload_global_with_preload_job_already_finished(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """_preload_global with preload_job that has already-finished endpoints."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_graphql_requests.side_effect = _make_graphql_dispatch(
            {"device_type_list": {"data": {"device_type_list": []}}}
        )
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        future.done.return_value = True
        future.result.return_value = []

        progress = MagicMock()
        progress.add_task.return_value = 1

        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": queue.Queue(),
            "endpoint_totals": {"interface_templates": 0},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": {"interface_templates"},  # already done
        }
        components = [("interface_templates", "Interface Templates")]
        dt._preload_global(components, preload_job=preload_job, progress=progress)
        # Already-done endpoint should still have its task stopped
        progress.stop_task.assert_called()


# ---------------------------------------------------------------------------
# preload_module_type_components (lines 1346, 1353, 1370)
# ---------------------------------------------------------------------------


class TestPreloadModuleTypeComponents:
    """Tests for preload_module_type_components edge cases."""

    def test_empty_ids_returns_immediately(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Empty module_type_ids → return immediately."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.preload_module_type_components(set(), ["interfaces"])
        mock_nb_api.dcim.interface_templates.filter.assert_not_called()

    def test_item_with_no_module_type_skipped(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Items where item.module_type is None are skipped."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        item_no_mt = MagicMock()
        item_no_mt.module_type = None
        item_no_mt.name = "xe-0"
        mock_nb_api.dcim.interface_templates.filter.return_value = [item_no_mt]

        dt.preload_module_type_components({1}, ["interfaces"])
        # No item indexed; cache entry is empty dict
        assert dt.cached_components["interface_templates"][("module", 1)] == {}


# ---------------------------------------------------------------------------
# _create_generic post_process called (line 1411)
# ---------------------------------------------------------------------------


class TestCreateGenericPostProcess:
    """Tests for _create_generic post_process callback."""

    def test_post_process_is_called(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """post_process callback is invoked before endpoint.create."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"power_outlet_templates": {("device", 1): {}}}

        post_calls = []

        def my_post_process(items, pid):
            post_calls.append((len(items), pid))

        dt._create_generic(
            [{"name": "PO1"}],
            1,
            mock_nb_api.dcim.power_outlet_templates,
            "Power Outlet",
            parent_type="device",
            post_process=my_post_process,
            cache_name="power_outlet_templates",
        )
        assert len(post_calls) == 1
        assert post_calls[0] == (1, 1)


# ---------------------------------------------------------------------------
# update_components: no mapping, no endpoint, property update, RequestError
# (lines 1466, 1470, 1508, 1518-1519)
# ---------------------------------------------------------------------------


class TestUpdateComponentsMiscBranches:
    """Tests for miscellaneous branches in update_components."""

    def test_no_mapping_for_comp_type_continues(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Unknown comp_type (no ENDPOINT_CACHE_MAP entry) is silently skipped."""
        from core.change_detector import ChangeType, ComponentChange, PropertyChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        changes = [
            ComponentChange(
                component_type="nonexistent-type",
                component_name="x",
                change_type=ChangeType.COMPONENT_CHANGED,
                property_changes=[PropertyChange("label", "a", "b")],
            )
        ]
        # Should not raise
        dt.update_components({}, 1, changes, parent_type="device")

    def test_no_endpoint_attr_continues(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """If dcim has no attribute for endpoint_attr, the update loop is skipped."""
        from core.change_detector import ChangeType, ComponentChange, PropertyChange

        mock_nb_api = MagicMock(spec=[])  # no attributes on dcim
        mock_nb_api.dcim = MagicMock(spec=[])
        dt = make_device_types(nb_api=mock_nb_api)

        changes = [
            ComponentChange(
                component_type="interfaces",
                component_name="eth0",
                change_type=ChangeType.COMPONENT_CHANGED,
                property_changes=[PropertyChange("label", "a", "b")],
            )
        ]
        # Should not raise
        dt.update_components({}, 1, changes, parent_type="device")

    def test_property_update_success_counter_incremented(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Successful property update increments components_updated counter."""
        from collections import Counter as _Counter
        from core.change_detector import ChangeType, ComponentChange, PropertyChange

        mock_nb_api = mock_pynetbox.api.return_value
        counter = _Counter(components_updated=0)
        dt = make_device_types(nb_api=mock_nb_api, counter=counter)
        dt.m2m_front_ports = False

        existing = MagicMock()
        existing.id = 10
        dt.cached_components = {"interface_templates": {("device", 1): {"eth0": existing}}}

        changes = [
            ComponentChange(
                component_type="interfaces",
                component_name="eth0",
                change_type=ChangeType.COMPONENT_CHANGED,
                property_changes=[PropertyChange("label", "old", "new")],
            )
        ]
        dt.update_components({}, 1, changes)
        mock_nb_api.dcim.interface_templates.update.assert_called()
        assert counter["components_updated"] >= 1

    def test_property_update_request_error_logged(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """RequestError during property update is caught and logged."""
        import pynetbox as real_pynb2
        from core.change_detector import ChangeType, ComponentChange, PropertyChange

        mock_pynetbox.RequestError = real_pynb2.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.m2m_front_ports = False

        existing = MagicMock()
        existing.id = 10
        dt.cached_components = {"interface_templates": {("device", 1): {"eth0": existing}}}

        err = real_pynb2.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        mock_nb_api.dcim.interface_templates.update.side_effect = err
        mock_settings.handle.log.reset_mock()

        changes = [
            ComponentChange(
                component_type="interfaces",
                component_name="eth0",
                change_type=ChangeType.COMPONENT_CHANGED,
                property_changes=[PropertyChange("label", "old", "new")],
            )
        ]
        dt.update_components({}, 1, changes)
        mock_settings.handle.log.assert_called()


# ---------------------------------------------------------------------------
# update_components additions: alias resolution, missing yaml_key,
# no mapping, no endpoint, no components_to_add, front-ports delegation
# (lines 1537-1567)
# ---------------------------------------------------------------------------


class TestUpdateComponentsAdditionsBranches:
    """Tests for component-addition branches inside update_components."""

    def test_yaml_key_none_continues(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """If component_type not in yaml_data (neither canonical nor alias), skip."""
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)]
        # yaml_data has no "interfaces" key
        dt.update_components({}, 1, changes, parent_type="device")
        mock_nb_api.dcim.interface_templates.create.assert_not_called()

    def test_no_mapping_for_added_comp_type(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Unknown comp_type in addition changes is skipped."""
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        changes = [ComponentChange("nonexistent-type", "x", ChangeType.COMPONENT_ADDED)]
        yaml_data = {"nonexistent-type": [{"name": "x"}]}
        # Should not raise
        dt.update_components(yaml_data, 1, changes)

    def test_no_components_to_add_continues(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """If no components in yaml match the change names, skip."""
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        # yaml has "interfaces" but the name doesn't match the change
        changes = [ComponentChange("interfaces", "nonexistent", ChangeType.COMPONENT_ADDED)]
        yaml_data = {"interfaces": [{"name": "eth0"}]}
        dt.update_components(yaml_data, 1, changes)
        mock_nb_api.dcim.interface_templates.create.assert_not_called()

    def test_front_ports_addition_delegates_to_create_front_ports(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """front-ports COMPONENT_ADDED delegates to create_front_ports."""
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.create_front_ports = MagicMock()
        dt.cached_components = {"front_port_templates": {("device", 1): {}}}

        changes = [ComponentChange("front-ports", "FP1", ChangeType.COMPONENT_ADDED)]
        yaml_data = {"front-ports": [{"name": "FP1"}]}
        dt.update_components(yaml_data, 1, changes, parent_type="device")
        dt.create_front_ports.assert_called_once()

    def test_front_ports_addition_module_delegates_to_create_module_front_ports(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """front-ports COMPONENT_ADDED for module delegates to create_module_front_ports."""
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.create_module_front_ports = MagicMock()
        dt.cached_components = {"front_port_templates": {("module", 1): {}}}

        changes = [ComponentChange("front-ports", "FP1", ChangeType.COMPONENT_ADDED)]
        yaml_data = {"front-ports": [{"name": "FP1"}]}
        dt.update_components(yaml_data, 1, changes, parent_type="module")
        dt.create_module_front_ports.assert_called_once()


# ---------------------------------------------------------------------------
# remove_components: no mapping, no endpoint (lines 1603, 1607)
# ---------------------------------------------------------------------------


class TestRemoveComponentsBranches:
    """Tests for missing branches in remove_components."""

    def test_unknown_comp_type_skipped(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """comp_type with no ENDPOINT_CACHE_MAP entry is silently skipped."""
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        changes = [ComponentChange("nonexistent-type", "x", ChangeType.COMPONENT_REMOVED)]
        dt.remove_components(1, changes)
        # No exception; no delete called

    def test_missing_endpoint_attr_skipped(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """If dcim has no attribute for endpoint_attr, deletion is skipped."""
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = MagicMock(spec=[])
        mock_nb_api.dcim = MagicMock(spec=[])
        dt = make_device_types(nb_api=mock_nb_api)

        changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_REMOVED)]
        dt.remove_components(1, changes)

    def test_request_error_on_delete_is_logged(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """RequestError during component deletion is caught and logged."""
        import pynetbox as real_pynb2
        from core.change_detector import ChangeType, ComponentChange

        mock_pynetbox.RequestError = real_pynb2.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        existing_comp = MagicMock()
        existing_comp.id = 99
        dt.cached_components = {"interface_templates": {("device", 1): {"eth0": existing_comp}}}

        err = real_pynb2.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        mock_nb_api.dcim.interface_templates.delete.side_effect = err
        mock_settings.handle.log.reset_mock()

        changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_REMOVED)]
        dt.remove_components(1, changes)
        mock_settings.handle.log.assert_called()


# ---------------------------------------------------------------------------
# create_interfaces bridge paths (lines 1624-1625, 1651-1682)
# ---------------------------------------------------------------------------


class TestCreateInterfacesBridge:
    """Tests for bridge-related code paths in create_interfaces."""

    def test_bridge_interface_not_found_logs_error(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """If bridge target interface is not found, handle.log is called."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        # The created interface will be in cache; bridge target will not be.
        created = MagicMock()
        created.name = "eth0"
        mock_nb_api.dcim.interface_templates.create.return_value = [created]
        mock_nb_api.dcim.interface_templates.filter.return_value = []
        mock_settings.handle.log.reset_mock()

        interfaces = [
            {"name": "eth0", "type": "virtual", "bridge": "eth1"},
        ]
        dt.create_interfaces(interfaces, device_type=1, context="test.yaml")
        mock_settings.handle.log.assert_called()
        assert any("Error bridging" in str(c) for c in mock_settings.handle.log.call_args_list)

    def test_bridge_extracts_and_removes_from_interface(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Bridge key is extracted before _create_generic and removed from the dict."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"interface_templates": {("device", 1): {}}}

        mock_nb_api.dcim.interface_templates.create.return_value = []
        mock_nb_api.dcim.interface_templates.filter.return_value = []

        iface = {"name": "eth0", "type": "virtual", "bridge": "eth1"}
        dt.create_interfaces([iface], device_type=1)
        # "bridge" key should have been removed from the dict
        assert "bridge" not in iface

    def test_bridge_update_success(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Successful bridge update calls verbose_log."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        eth0 = MagicMock()
        eth0.id = 10
        eth1 = MagicMock()
        eth1.id = 20
        dt.cached_components = {"interface_templates": {("device", 1): {"eth0": eth0, "eth1": eth1}}}

        mock_nb_api.dcim.interface_templates.create.return_value = []
        mock_settings.handle.verbose_log.reset_mock()

        interfaces = [
            {"name": "eth0", "type": "virtual", "bridge": "eth1"},
            {"name": "eth1", "type": "virtual"},
        ]
        dt.create_interfaces(interfaces, device_type=1)
        mock_nb_api.dcim.interface_templates.update.assert_called_once_with([{"id": 10, "bridge": 20}])
        assert any("Bridged" in str(c) for c in mock_settings.handle.verbose_log.call_args_list)

    def test_bridge_update_request_error_logged(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """RequestError during bridge update is caught and logged."""
        import pynetbox as real_pynb2

        mock_pynetbox.RequestError = real_pynb2.RequestError
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        eth0 = MagicMock()
        eth0.id = 10
        eth1 = MagicMock()
        eth1.id = 20
        dt.cached_components = {"interface_templates": {("device", 1): {"eth0": eth0, "eth1": eth1}}}

        mock_nb_api.dcim.interface_templates.create.return_value = []
        err = real_pynb2.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        mock_nb_api.dcim.interface_templates.update.side_effect = err
        mock_settings.handle.log.reset_mock()

        interfaces = [
            {"name": "eth0", "type": "virtual", "bridge": "eth1"},
            {"name": "eth1", "type": "virtual"},
        ]
        dt.create_interfaces(interfaces, device_type=1, context="test.yaml")
        mock_settings.handle.log.assert_called()
        assert any("Error bridging" in str(c) for c in mock_settings.handle.log.call_args_list)


# ---------------------------------------------------------------------------
# create_power_outlets with invalid power_port (lines 1715-1749)
# ---------------------------------------------------------------------------


class TestCreatePowerOutletsInvalidPort:
    """Tests for power outlet creation with missing power_port reference."""

    def test_invalid_power_port_logged_and_outlet_skipped(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Power outlet referencing unknown power_port is logged and skipped."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {
            "power_port_templates": {("device", 1): {}},  # no power ports
            "power_outlet_templates": {("device", 1): {}},
        }
        mock_nb_api.dcim.power_port_templates.filter.return_value = []
        mock_settings.handle.log.reset_mock()

        power_outlets = [{"name": "PO1", "power_port": "PSU1"}]
        dt.create_power_outlets(power_outlets, 1, context="test.yaml")
        mock_settings.handle.log.assert_called()
        assert any("Could not find Power Port" in str(c) for c in mock_settings.handle.log.call_args_list)

    def test_multiple_outlets_one_invalid_skips_bad_only(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Only the outlet with an invalid power_port is removed; valid one proceeds."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        psu1 = MagicMock()
        psu1.id = 99
        dt.cached_components = {
            "power_port_templates": {("device", 1): {"PSU1": psu1}},
            "power_outlet_templates": {("device", 1): {}},
        }
        mock_settings.handle.log.reset_mock()

        power_outlets = [
            {"name": "PO1", "power_port": "PSU1"},  # valid
            {"name": "PO2", "power_port": "MISSING"},  # invalid
        ]
        dt.create_power_outlets(power_outlets, 1)
        # The "Skipped" log should mention PO2
        assert any("PO2" in str(c) or "Skipped" in str(c) for c in mock_settings.handle.log.call_args_list)


# ---------------------------------------------------------------------------
# _build_link_rear_ports paths (lines 1797-1841)
# ---------------------------------------------------------------------------


class TestBuildLinkRearPorts:
    """Tests for _build_link_rear_ports and create_front_ports."""

    def test_rear_port_not_found_logs_and_skips(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Front port whose rear_port cannot be resolved is removed and logged."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {
            "rear_port_templates": {("device", 1): {}},  # no rear ports
            "front_port_templates": {("device", 1): {}},
        }
        mock_nb_api.dcim.rear_port_templates.filter.return_value = []
        mock_settings.handle.log.reset_mock()

        front_ports = [{"name": "FP1", "type": "8p8c", "rear_port": "RP1"}]
        dt.create_front_ports(front_ports, 1, context="test.yaml")
        assert any("Could not find Rear Port" in str(c) for c in mock_settings.handle.log.call_args_list)

    def test_rear_port_found_non_m2m(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Non-M2M path: rear_port is replaced with its ID."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.m2m_front_ports = False

        rp = MagicMock()
        rp.id = 77
        dt.cached_components = {
            "rear_port_templates": {("device", 1): {"RP1": rp}},
            "front_port_templates": {("device", 1): {}},
        }
        mock_nb_api.dcim.front_port_templates.create.return_value = []

        front_ports = [{"name": "FP1", "type": "8p8c", "rear_port": "RP1", "rear_port_position": 1}]
        dt.create_front_ports(front_ports, 1)
        call_args = mock_nb_api.dcim.front_port_templates.create.call_args[0][0]
        assert call_args[0]["rear_port"] == 77

    def test_rear_port_found_m2m(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """M2M path: rear_ports list is built with position and rear_port_position."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.m2m_front_ports = True

        rp = MagicMock()
        rp.id = 77
        dt.cached_components = {
            "rear_port_templates": {("device", 1): {"RP1": rp}},
            "front_port_templates": {("device", 1): {}},
        }
        mock_nb_api.dcim.front_port_templates.create.return_value = []

        front_ports = [{"name": "FP1", "type": "8p8c", "rear_port": "RP1", "rear_port_position": 2}]
        dt.create_front_ports(front_ports, 1)
        call_args = mock_nb_api.dcim.front_port_templates.create.call_args[0][0]
        assert call_args[0]["rear_ports"] == [{"position": 1, "rear_port": 77, "rear_port_position": 2}]
        assert "rear_port" not in call_args[0]

    def test_multiple_front_ports_one_invalid(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Only invalid front port is skipped; valid one is created."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.m2m_front_ports = False

        rp = MagicMock()
        rp.id = 77
        dt.cached_components = {
            "rear_port_templates": {("device", 1): {"RP1": rp}},
            "front_port_templates": {("device", 1): {}},
        }
        mock_nb_api.dcim.front_port_templates.create.return_value = []
        mock_settings.handle.log.reset_mock()

        front_ports = [
            {"name": "FP1", "type": "8p8c", "rear_port": "RP1"},
            {"name": "FP2", "type": "8p8c", "rear_port": "MISSING"},
        ]
        dt.create_front_ports(front_ports, 1, context="test.yaml")
        assert any("Skipped" in str(c) for c in mock_settings.handle.log.call_args_list)
        call_args = mock_nb_api.dcim.front_port_templates.create.call_args[0][0]
        names = [x["name"] for x in call_args]
        assert "FP1" in names
        assert "FP2" not in names


# ---------------------------------------------------------------------------
# create_module_front_ports (line 1845 / 1994-2005)
# ---------------------------------------------------------------------------


class TestCreateModuleFrontPorts:
    """Tests for create_module_front_ports."""

    def test_delegates_to_create_generic(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """create_module_front_ports calls _create_generic with module parent_type."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.m2m_front_ports = False

        rp = MagicMock()
        rp.id = 55
        dt.cached_components = {
            "rear_port_templates": {("module", 5): {"RP1": rp}},
            "front_port_templates": {("module", 5): {}},
        }
        mock_nb_api.dcim.front_port_templates.create.return_value = []

        front_ports = [{"name": "FP1", "type": "8p8c", "rear_port": "RP1"}]
        dt.create_module_front_ports(front_ports, 5, context="test.yaml")
        call_args = mock_nb_api.dcim.front_port_templates.create.call_args[0][0]
        assert call_args[0]["module_type"] == 5


# ---------------------------------------------------------------------------
# create_module_power_outlets invalid power_port (lines 1917-1950)
# ---------------------------------------------------------------------------


class TestCreateModulePowerOutletsInvalidPort:
    """Tests for module power outlet creation with missing power_port."""

    def test_invalid_power_port_logged_and_skipped(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Module power outlet with unknown power_port is logged and skipped."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {
            "power_port_templates": {("module", 1): {}},
            "power_outlet_templates": {("module", 1): {}},
        }
        mock_nb_api.dcim.power_port_templates.filter.return_value = []
        mock_settings.handle.log.reset_mock()

        power_outlets = [{"name": "PO1", "power_port": "PSU1"}]
        dt.create_module_power_outlets(power_outlets, 1, context="test.yaml")
        assert any("Could not find Power Port" in str(c) for c in mock_settings.handle.log.call_args_list)

    def test_multiple_outlets_one_invalid(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Only the module outlet with an invalid power_port is removed."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        psu1 = MagicMock()
        psu1.id = 88
        dt.cached_components = {
            "power_port_templates": {("module", 1): {"PSU1": psu1}},
            "power_outlet_templates": {("module", 1): {}},
        }
        mock_settings.handle.log.reset_mock()

        power_outlets = [
            {"name": "PO1", "power_port": "PSU1"},
            {"name": "PO2", "power_port": "MISSING"},
        ]
        dt.create_module_power_outlets(power_outlets, 1)
        assert any("PO2" in str(c) or "Skipped" in str(c) for c in mock_settings.handle.log.call_args_list)


# ---------------------------------------------------------------------------
# create_module_rear_ports (line 1996)
# ---------------------------------------------------------------------------


class TestCreateModuleRearPorts:
    """Tests for create_module_rear_ports."""

    def test_calls_create_generic_with_module_parent(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """create_module_rear_ports creates rear ports with module_type parent."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {"rear_port_templates": {("module", 3): {}}}

        rear_ports = [{"name": "RP1", "type": "8p8c", "positions": 8}]
        dt.create_module_rear_ports(rear_ports, 3, context="test.yaml")
        call_args = mock_nb_api.dcim.rear_port_templates.create.call_args[0][0]
        assert call_args[0]["module_type"] == 3


# ---------------------------------------------------------------------------
# upload_images RequestException and file-close exception (lines 2039-2046)
# ---------------------------------------------------------------------------


class TestUploadImagesErrors:
    """Tests for error branches in upload_images."""

    def test_request_exception_logged(self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path):
        """requests.RequestException during upload is caught and logged."""
        import requests as _req2

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        img = tmp_path / "front.jpg"
        img.write_bytes(b"fake")
        mock_settings.handle.log.reset_mock()

        with patch("core.netbox_api.requests") as mock_req:
            mock_req.RequestException = _req2.RequestException
            mock_req.patch.side_effect = _req2.RequestException("timeout")
            dt.upload_images("http://nb", "token", {"front_image": str(img)}, 1)

        assert mock_settings.handle.log.called

    def test_file_close_exception_swallowed(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        """Exception from fh.close() in the finally block is silently swallowed."""
        import requests as _req2

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        img = tmp_path / "front.jpg"
        img.write_bytes(b"fake")
        mock_settings.handle.log.reset_mock()

        # Make the file object's close() raise an exception
        fake_fh = MagicMock()
        fake_fh.close.side_effect = OSError("cannot close")

        with patch("builtins.open", return_value=fake_fh):
            with patch("core.netbox_api.requests") as mock_req:
                mock_req.RequestException = _req2.RequestException
                mock_req.patch.side_effect = _req2.RequestException("server error")
                # Should NOT raise despite close() raising
                dt.upload_images("http://nb", "token", {"front_image": str(img)}, 1)

        # The RequestException log should still have been called
        assert mock_settings.handle.log.called


# ---------------------------------------------------------------------------
# upload_image_attachment: _image_progress callback, OSError (lines 2090, 2095-2097)
# ---------------------------------------------------------------------------


class TestUploadImageAttachmentProgress:
    """Tests for upload_image_attachment _image_progress and error paths."""

    def test_image_progress_callback_called_on_success(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        """_image_progress is called with 1 on a successful upload."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        img = tmp_path / "img.png"
        img.write_bytes(b"fake")

        progress_calls = []
        dt._image_progress = lambda n: progress_calls.append(n)

        with patch("core.netbox_api.requests.post") as mock_post:
            resp = MagicMock()
            resp.status_code = 201
            resp.raise_for_status.return_value = None
            mock_post.return_value = resp
            result = dt.upload_image_attachment("http://nb", "token", str(img), "dcim.moduletype", 42)

        assert result is True
        assert progress_calls == [1]


# ---------------------------------------------------------------------------
# Corner-case tests for high-complexity functions (cognitive complexity > 15)
# ---------------------------------------------------------------------------


class TestCreateDeviceTypesCornerCases:
    """Corner-case tests for create_device_types (cognitive complexity 35)."""

    def test_progress_iterator_used_when_provided(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """When a progress object is supplied, iteration goes through it."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt

        created_dt = MagicMock()
        created_dt.id = 1
        created_dt.manufacturer.name = "Cisco"
        created_dt.model = "TestSwitch"
        mock_nb_api.dcim.device_types.create.return_value = created_dt

        device_types = [
            {
                "manufacturer": {"slug": "cisco"},
                "model": "TestSwitch",
                "slug": "testswitch",
                "src": "/tmp/device-types/cisco/testswitch.yaml",
            }
        ]
        # Use a tracking iterator to verify the progress wrapper is actually consumed.
        consumed = []

        def tracking_iter():
            for item in device_types:
                consumed.append(item)
                yield item

        nb.create_device_types(device_types, progress=tracking_iter())
        assert len(consumed) > 0, "Progress iterator was not consumed by create_device_types"

    def test_image_file_not_found_logs_error(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        """When glob finds no image file, handle.log is called with an error."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {}

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        created_dt = MagicMock()
        created_dt.id = 1
        created_dt.manufacturer.name = "Cisco"
        created_dt.model = "TestSwitch"
        mock_nb_api.dcim.device_types.create.return_value = created_dt
        mock_settings.handle.log.reset_mock()

        dev_dir = tmp_path / "device-types" / "cisco"
        dev_dir.mkdir(parents=True)

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "front_image": True,
            "src": str(dev_dir / "testswitch.yaml"),
        }
        # glob returns empty list → no image found → log error
        with patch("glob.glob", return_value=[]):
            nb.create_device_types([device_type])
        assert any("Error locating image file" in str(c) for c in mock_settings.handle.log.call_args_list)

    def test_module_bays_not_created_when_modules_false(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """module-bays are only created when self.modules is True."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.existing_device_types = {}
        dt.existing_device_types_by_slug = {}
        dt.create_module_bays = MagicMock()

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types = dt
        nb.modules = False  # explicitly disabled

        created_dt = MagicMock()
        created_dt.id = 1
        created_dt.manufacturer.name = "Cisco"
        created_dt.model = "TestSwitch"
        mock_nb_api.dcim.device_types.create.return_value = created_dt

        device_type = {
            "manufacturer": {"slug": "cisco"},
            "model": "TestSwitch",
            "slug": "testswitch",
            "module-bays": [{"name": "MB1"}],
            "src": "/tmp/device-types/cisco/testswitch.yaml",
        }
        nb.create_device_types([device_type])
        dt.create_module_bays.assert_not_called()


class TestCreateModuleTypesCornerCases:
    """Corner-case tests for create_module_types (cognitive complexity 16)."""

    def test_progress_iterator_used(self, mock_settings, mock_pynetbox):
        """When progress is provided, iteration goes through it."""
        mock_pynetbox.api.return_value.version = "3.5"
        nb = NetBox(mock_settings, mock_settings.handle)

        created_mt = MagicMock()
        created_mt.id = 1
        created_mt.manufacturer.name = "Cisco"
        created_mt.model = "LC"
        nb.netbox.dcim.module_types.create.return_value = created_mt

        module_types = [
            {
                "manufacturer": {"slug": "cisco"},
                "model": "LC",
                "src": "/repo/module-types/cisco/lc.yaml",
            }
        ]
        consumed = []

        def tracking_iter():
            for item in module_types:
                consumed.append(item)
                yield item

        nb.create_module_types(
            module_types,
            progress=tracking_iter(),
            all_module_types={},
            module_type_existing_images={},
        )
        nb.netbox.dcim.module_types.create.assert_called_once()
        assert len(consumed) > 0, "Progress iterator was not consumed by create_module_types"

    def test_all_module_types_fetched_when_none(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        """all_module_types is fetched when not supplied."""
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
        nb.netbox.dcim.module_types.create.return_value = MagicMock(
            id=1, manufacturer=MagicMock(name="Cisco"), model="LC"
        )

        with patch.object(nb, "get_existing_module_types", return_value={}) as mock_get:
            nb.create_module_types(
                [{"manufacturer": {"slug": "cisco"}, "model": "LC", "src": "/f.yaml"}],
                module_type_existing_images={},
            )
        mock_get.assert_called_once()

    def test_module_type_existing_images_fetched_when_none(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        """module_type_existing_images is fetched when not supplied."""
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
        nb.netbox.dcim.module_types.create.return_value = MagicMock(
            id=1, manufacturer=MagicMock(name="Cisco"), model="LC"
        )

        with patch.object(nb, "_fetch_module_type_existing_images", return_value={}) as mock_fetch:
            nb.create_module_types(
                [{"manufacturer": {"slug": "cisco"}, "model": "LC", "src": "/f.yaml"}],
                all_module_types={},
            )
        mock_fetch.assert_called_once()


class TestPreloadGlobalCornerCases:
    """Corner-case tests for _preload_global (cognitive complexity 26)."""

    def test_wait_fallback_when_no_progress_updates_queue(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """When progress_updates is None and futures are pending, concurrent.futures.wait is called."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        # future that is initially not done, then done on second call
        future = MagicMock()
        done_sequence = [False, True]
        future.done.side_effect = lambda: done_sequence.pop(0)
        future.result.return_value = []

        progress = MagicMock()
        progress.add_task.return_value = 1

        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": None,  # no queue → triggers wait() fallback
            "endpoint_totals": {},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": set(),
        }
        components = [("interface_templates", "Interface Templates")]
        with patch("concurrent.futures.wait") as mock_wait:
            dt._preload_global(components, preload_job=preload_job, progress=progress)
        # concurrent.futures.wait should have been called
        mock_wait.assert_called()

    def test_already_done_endpoint_has_task_stopped(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """Endpoint in finished_endpoints has its progress task stopped without double-processing."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        future.done.return_value = True
        future.result.return_value = []

        progress = MagicMock()
        progress.add_task.return_value = 1

        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": queue.Queue(),
            "endpoint_totals": {},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": {"interface_templates"},
        }
        components = [("interface_templates", "Interface Templates")]
        dt._preload_global(components, preload_job=preload_job, progress=progress)
        progress.stop_task.assert_called_with(1)

    def test_progress_update_dropped_for_finished_endpoint(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """Progress updates for already-finished endpoints are dropped when getting from queue."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        # First call: not done; second call: done
        done_seq = [False, True]
        future.done.side_effect = lambda: done_seq.pop(0)
        future.result.return_value = []

        q = queue.Queue()
        # Add an update for a DIFFERENT (already-finished) endpoint
        q.put(("other_endpoint", 5))

        progress = MagicMock()
        progress.add_task.return_value = 1

        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": q,
            "endpoint_totals": {},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": set(),
        }
        components = [("interface_templates", "Interface Templates")]
        dt._preload_global(components, preload_job=preload_job, progress=progress)
        # "other_endpoint" update should be dropped (not in pending)
        # The test mainly verifies no exception is raised


# ---------------------------------------------------------------------------
# Additional tests for remaining missing lines
# ---------------------------------------------------------------------------


class TestUpdateComponentsAdditionsNoEndpoint:
    """Tests for additions branch with missing endpoint in update_components."""

    def test_no_endpoint_for_addition_continues(self, mock_settings, mock_pynetbox, graphql_client, make_device_types):
        """Addition branch: endpoint returns None → continue (line 1550)."""
        from core.change_detector import ChangeType, ComponentChange

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        # Make dcim.interface_templates return None (falsy)
        dt.netbox.dcim.interface_templates = None

        changes = [ComponentChange("interfaces", "eth0", ChangeType.COMPONENT_ADDED)]
        yaml_data = {"interfaces": [{"name": "eth0"}]}
        # Should not raise
        dt.update_components(yaml_data, 1, changes, parent_type="device")


class TestPowerOutletWithoutPowerPortKey:
    """Test that power outlets without 'power_port' key use the continue path."""

    def test_outlet_without_power_port_key_skips_link(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Power outlet that has no 'power_port' key hits the continue at line 1723."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {
            "power_outlet_templates": {("device", 1): {}},
            "power_port_templates": {("device", 1): {}},
        }
        # Outlet without "power_port" key → continue at line 1723
        power_outlets = [{"name": "PO1"}]  # no power_port key
        dt.create_power_outlets(power_outlets, 1)
        call_args = mock_nb_api.dcim.power_outlet_templates.create.call_args[0][0]
        assert call_args[0]["name"] == "PO1"


class TestFrontPortWithoutRearPortKey:
    """Test that front ports without 'rear_port' key hit the continue at line 1808."""

    def test_front_port_without_rear_port_key_skips_link(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Front port without 'rear_port' key hits the continue at line 1808."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {
            "rear_port_templates": {("device", 1): {}},
            "front_port_templates": {("device", 1): {}},
        }
        # Front port without rear_port key → continue at line 1808
        front_ports = [{"name": "FP1", "type": "8p8c"}]  # no rear_port key
        dt.create_front_ports(front_ports, 1)
        call_args = mock_nb_api.dcim.front_port_templates.create.call_args[0][0]
        assert call_args[0]["name"] == "FP1"


class TestModulePowerOutletWithoutPowerPortKey:
    """Test module power outlets without 'power_port' key."""

    def test_module_outlet_without_power_port_key_skips_link(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """Module power outlet without 'power_port' key hits the continue at line 1925."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)
        dt.cached_components = {
            "power_outlet_templates": {("module", 1): {}},
            "power_port_templates": {("module", 1): {}},
        }
        power_outlets = [{"name": "PO1"}]  # no power_port key
        dt.create_module_power_outlets(power_outlets, 1)
        call_args = mock_nb_api.dcim.power_outlet_templates.create.call_args[0][0]
        assert call_args[0]["name"] == "PO1"


class TestUploadImageAttachmentExceptions:
    """Tests for exception paths in upload_image_attachment."""

    def test_request_exception_returns_false(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        """requests.RequestException during POST returns False (lines 2095-2097)."""
        import requests as _req3

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        img = tmp_path / "img.png"
        img.write_bytes(b"fake")

        with patch("core.netbox_api.requests") as mock_req:
            mock_req.RequestException = _req3.RequestException
            mock_req.post.side_effect = _req3.RequestException("conn error")
            result = dt.upload_image_attachment("http://nb", "token", str(img), "dcim.moduletype", 42)

        assert result is False
        assert mock_settings.handle.log.called


class TestPumpPreloadProgressFutureNotDone:
    """Tests for pump_preload_progress when futures are still running."""

    def test_pending_future_returns_false_when_no_updates(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types
    ):
        """When future is not done and no progress updates, returns False (line 1013)."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        future.done.return_value = False  # not done yet

        progress = MagicMock()
        preload_job = {
            "futures": {"interface_templates": future},
            "progress_updates": queue.Queue(),  # empty queue
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": set(),
        }
        result = dt.pump_preload_progress(preload_job, progress)
        # Future not done, no updates → no advancement
        assert result is False
        assert "interface_templates" not in preload_job["finished_endpoints"]


class TestPreloadGlobalMissingLines:
    """Targeted tests for remaining missing lines in _preload_global."""

    def test_already_done_endpoint_with_future_exception(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """already_done endpoint whose future raises → log + exception re-raised."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        future.done.return_value = True
        future.result.side_effect = RuntimeError("fetch failed")

        progress = MagicMock()
        progress.add_task.return_value = 1

        mock_settings.handle.log.reset_mock()
        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": queue.Queue(),
            "endpoint_totals": {},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": {"interface_templates"},  # already done
        }
        components = [("interface_templates", "Interface Templates")]
        with pytest.raises(RuntimeError, match="fetch failed"):
            dt._preload_global(components, preload_job=preload_job, progress=progress)
        mock_settings.handle.log.assert_any_call("Preload failed for interface_templates: fetch failed")

    def test_already_done_endpoint_progress_update_exception_swallowed(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """progress.stop_task raising for already_done endpoint is swallowed (1135-1136)."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        future.done.return_value = True
        future.result.return_value = []

        progress = MagicMock()
        progress.add_task.return_value = 1
        progress.stop_task.side_effect = RuntimeError("task gone")

        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": queue.Queue(),
            "endpoint_totals": {},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": {"interface_templates"},
        }
        components = [("interface_templates", "Interface Templates")]
        # Should not raise
        dt._preload_global(components, preload_job=preload_job, progress=progress)

    def test_pending_future_exception_logged(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """Future raising while pending logs error and re-raises."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        future = MagicMock()
        done_seq = [False, True]
        future.done.side_effect = lambda: done_seq.pop(0) if done_seq else True
        future.result.side_effect = RuntimeError("network error")

        progress = MagicMock()
        progress.add_task.return_value = 1

        mock_settings.handle.log.reset_mock()
        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": queue.Queue(),
            "endpoint_totals": {},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": set(),
        }
        components = [("interface_templates", "Interface Templates")]
        with pytest.raises(RuntimeError, match="network error"):
            dt._preload_global(components, preload_job=preload_job, progress=progress)
        mock_settings.handle.log.assert_any_call("Preload failed for interface_templates: network error")

    def test_progress_updates_get_with_timeout_advances_task(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """progress_updates.get(timeout=0.1) returns item and updates progress (1172-1177)."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        # First call: not done (triggers the timeout-get path); second: done
        done_seq = [False, True]
        future = MagicMock()
        future.done.side_effect = lambda: done_seq.pop(0) if done_seq else True
        future.result.return_value = []

        q = queue.Queue()
        # Pre-load with an update for the pending endpoint
        q.put(("interface_templates", 3))

        progress = MagicMock()
        progress.add_task.return_value = 1

        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": q,
            "endpoint_totals": {},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": set(),
        }
        components = [("interface_templates", "Interface Templates")]

        # Force _apply_progress_updates to return False so the item stays in queue
        # for progress_updates.get(timeout=0.1) to pick up
        with patch.object(DeviceTypes, "_apply_progress_updates", return_value=False):
            dt._preload_global(components, preload_job=preload_job, progress=progress)

        # progress.update should have been called for the queued advance (line 1177)
        progress.update.assert_called()

    def test_progress_updates_get_drops_finished_endpoint(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """progress_updates.get returns item for finished endpoint → dropped (line 1172-1174)."""
        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        # future not done first, then done
        done_seq = [False, True]
        future = MagicMock()
        future.done.side_effect = lambda: done_seq.pop(0) if done_seq else True
        future.result.return_value = []

        q = queue.Queue()
        # Update for a NON-pending endpoint → dropped at line 1172-1174
        q.put(("other_endpoint", 5))

        progress = MagicMock()
        progress.add_task.return_value = 1

        preload_job = {
            "executor": MagicMock(),
            "futures": {"interface_templates": future},
            "progress_updates": q,
            "endpoint_totals": {},
            "task_ids": {"interface_templates": 1},
            "finished_endpoints": set(),
        }
        components = [("interface_templates", "Interface Templates")]

        with patch.object(DeviceTypes, "_apply_progress_updates", return_value=False):
            dt._preload_global(components, preload_job=preload_job, progress=progress)
        # "other_endpoint" was dropped; no exception raised


class TestStartComponentPreloadProgressCallback:
    """Tests for the update_progress closure in start_component_preload (line 901)."""

    def test_update_progress_called_when_records_available(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """update_progress callback is triggered when _fetch_global_endpoint_records has records."""
        mock_nb_api = mock_pynetbox.api.return_value

        # Mock _fetch_global_endpoint_records to call its callback
        def fake_fetch(endpoint_name, progress_callback=None, expected_total=None):
            records = [MagicMock(name="fake")]
            if progress_callback is not None and records:
                progress_callback(endpoint_name, len(records))
            return records

        dt = make_device_types(nb_api=mock_nb_api)

        progress = MagicMock()
        progress.add_task.return_value = 1

        with patch.object(
            dt, "_get_endpoint_totals", return_value={ep: 0 for ep, _ in dt._component_preload_targets()}
        ):
            with patch.object(dt, "_fetch_global_endpoint_records", side_effect=fake_fetch):
                preload_job = dt.start_component_preload(progress=progress)
                # Let the futures complete
                dt.preload_all_components(preload_job=preload_job, progress=progress)

        # update_progress was called, which put items in progress_updates queue
        # pump_preload_progress or preload_all_components drained them
        progress.add_task.assert_called()
        # Assert the advance reached progress.update — guards against a regression
        # where the callback path silently stops publishing advances.
        update_calls = [c for c in progress.update.call_args_list if c.kwargs.get("advance")]
        total_advance = sum(c.kwargs["advance"] for c in update_calls)
        assert total_advance >= 1, "progress.update was never called with advance>=1"


class TestPreloadGlobalOwnExecutorProgressCallback:
    """Tests for _preload_global own-executor progress callback (line 1079)."""

    def test_update_progress_callback_triggered(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, graphql_client, make_device_types
    ):
        """The update_progress closure in _preload_global is called when records exist."""
        mock_nb_api = mock_pynetbox.api.return_value

        def fake_fetch(endpoint_name, progress_callback=None, expected_total=None):
            records = [MagicMock()]
            if progress_callback is not None and records:
                progress_callback(endpoint_name, len(records))
            return records

        dt = make_device_types(nb_api=mock_nb_api)

        progress = MagicMock()
        progress.add_task.return_value = 1

        components = [("interface_templates", "Interface Templates")]
        with patch.object(dt, "_get_endpoint_totals", return_value={"interface_templates": 0}):
            with patch.object(dt, "_fetch_global_endpoint_records", side_effect=fake_fetch):
                dt._preload_global(components, progress_wrapper=None, progress=progress)

        progress.add_task.assert_called()
        progress.stop_task.assert_called()
        # Assert the advance reached progress.update — guards against a regression
        # where the own-executor callback stops publishing advances.
        update_calls = [c for c in progress.update.call_args_list if c.kwargs.get("advance")]
        total_advance = sum(c.kwargs["advance"] for c in update_calls)
        assert total_advance >= 1, "progress.update was never called with advance>=1"


class TestUploadImagesRequestException:
    """Dedicated tests to ensure upload_images RequestException path is covered."""

    def test_upload_images_request_exception_lines_covered(
        self, mock_settings, mock_pynetbox, graphql_client, make_device_types, tmp_path
    ):
        """Verify lines 2039-2040 (RequestException catch in upload_images) are executed."""
        import requests as _req4

        mock_nb_api = mock_pynetbox.api.return_value
        dt = make_device_types(nb_api=mock_nb_api)

        img = tmp_path / "front2.jpg"
        img.write_bytes(b"data")
        mock_settings.handle.log.reset_mock()

        # Patch the whole requests namespace so except clause matches
        with patch("core.netbox_api.requests") as mock_req:
            mock_req.RequestException = _req4.RequestException
            mock_req.patch.side_effect = _req4.RequestException("network error")
            dt.upload_images("http://nb", "tok", {"front_image": str(img)}, 99)

        assert mock_settings.handle.log.called


# ---------------------------------------------------------------------------
# TestGetExistingRackTypes
# ---------------------------------------------------------------------------


class TestGetExistingRackTypes:
    """Tests for NetBox.get_existing_rack_types()."""

    def test_delegates_to_graphql(self, mock_settings, mock_pynetbox, graphql_client):
        """get_existing_rack_types() returns whatever graphql.get_rack_types() returns."""
        mock_pynetbox.api.return_value.version = "4.1"
        nb = NetBox(mock_settings, mock_settings.handle)
        nb.graphql = graphql_client
        expected = {"apc": {"AR1300": MagicMock()}}
        graphql_client.get_rack_types = MagicMock(return_value=expected)

        result = nb.get_existing_rack_types()

        graphql_client.get_rack_types.assert_called_once()
        assert result is expected


# ---------------------------------------------------------------------------
# TestCreateRackTypes
# ---------------------------------------------------------------------------


class TestCreateRackTypes:
    """Tests for NetBox.create_rack_types()."""

    def _make_nb(self, mock_settings, mock_pynetbox):
        mock_pynetbox.api.return_value.version = "4.1"
        return NetBox(mock_settings, mock_settings.handle)

    def test_empty_list_returns_immediately(self, mock_settings, mock_pynetbox):
        nb = self._make_nb(mock_settings, mock_pynetbox)
        nb.create_rack_types([])
        mock_pynetbox.api.return_value.dcim.rack_types.create.assert_not_called()

    def test_existing_rack_type_only_new_skips(self, mock_settings, mock_pynetbox):
        """only_new=True with an existing rack type: verbose_log called, no create/update."""
        from core.graphql_client import DotDict

        nb = self._make_nb(mock_settings, mock_pynetbox)
        existing = DotDict({"id": 1, "model": "AR1300", "slug": "apc-ar1300"})
        all_rack_types = {"apc": {"AR1300": existing}}

        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
        }
        nb.create_rack_types([rack_type], only_new=True, all_rack_types=all_rack_types)

        mock_settings.handle.verbose_log.assert_called()
        mock_pynetbox.api.return_value.dcim.rack_types.create.assert_not_called()
        mock_pynetbox.api.return_value.dcim.rack_types.update.assert_not_called()

    def test_existing_rack_type_fields_match_logs_unchanged(self, mock_settings, mock_pynetbox):
        """Existing rack type with identical fields logs 'Unchanged', no update called."""
        from core.graphql_client import DotDict

        nb = self._make_nb(mock_settings, mock_pynetbox)
        existing = DotDict({"id": 2, "model": "AR1300", "slug": "apc-ar1300", "u_height": 42})
        all_rack_types = {"apc": {"AR1300": existing}}

        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
            "u_height": 42,
        }
        nb.create_rack_types([rack_type], only_new=False, all_rack_types=all_rack_types)

        verbose_calls = [str(c) for c in mock_settings.handle.verbose_log.call_args_list]
        assert any("Unchanged" in c for c in verbose_calls)
        mock_pynetbox.api.return_value.dcim.rack_types.update.assert_not_called()

    def test_existing_rack_type_fields_differ_calls_update(self, mock_settings, mock_pynetbox):
        """Existing rack type with a changed field calls update and increments counter."""
        from core.graphql_client import DotDict

        nb = self._make_nb(mock_settings, mock_pynetbox)
        existing = DotDict({"id": 3, "model": "AR1300", "slug": "apc-ar1300", "u_height": 40})
        all_rack_types = {"apc": {"AR1300": existing}}

        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
            "u_height": 42,
        }
        nb.create_rack_types([rack_type], only_new=False, all_rack_types=all_rack_types)

        mock_pynetbox.api.return_value.dcim.rack_types.update.assert_called_once()
        assert nb.counter["rack_type_updated"] == 1

    def test_new_rack_type_calls_create(self, mock_settings, mock_pynetbox):
        """Non-existing rack type: create called, counter incremented, added to cache."""
        mock_pynetbox.api.return_value.version = "4.1"
        created_rt = MagicMock()
        created_rt.id = 99
        mock_pynetbox.api.return_value.dcim.rack_types.create.return_value = created_rt

        nb = self._make_nb(mock_settings, mock_pynetbox)
        all_rack_types = {}
        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
        }
        nb.create_rack_types([rack_type], only_new=False, all_rack_types=all_rack_types)

        mock_pynetbox.api.return_value.dcim.rack_types.create.assert_called_once()
        assert nb.counter["rack_type_added"] == 1
        assert all_rack_types["apc"]["AR1300"] is created_rt

    def test_request_error_on_create_logged_no_crash(self, mock_settings, mock_pynetbox):
        """RequestError during create is logged; processing continues."""
        import pynetbox

        mock_pynetbox.api.return_value.version = "4.1"
        err = pynetbox.RequestError(MagicMock(status_code=400, url="u", content=b'{"detail":"bad"}'))
        mock_pynetbox.api.return_value.dcim.rack_types.create.side_effect = err
        mock_pynetbox.RequestError = pynetbox.RequestError

        nb = self._make_nb(mock_settings, mock_pynetbox)
        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
            "src": "/some/file.yaml",
        }
        nb.create_rack_types([rack_type], all_rack_types={})  # should not raise

        mock_settings.handle.log.assert_called()

    def test_request_error_on_update_logged_no_crash(self, mock_settings, mock_pynetbox):
        """RequestError during update is logged; processing continues."""
        import pynetbox
        from core.graphql_client import DotDict

        mock_pynetbox.api.return_value.version = "4.1"
        err = pynetbox.RequestError(MagicMock(status_code=400, url="u", content=b'{"detail":"bad"}'))
        mock_pynetbox.api.return_value.dcim.rack_types.update.side_effect = err
        mock_pynetbox.RequestError = pynetbox.RequestError

        nb = self._make_nb(mock_settings, mock_pynetbox)
        existing = DotDict({"id": 5, "model": "AR1300", "u_height": 40})
        all_rack_types = {"apc": {"AR1300": existing}}
        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
            "u_height": 42,
        }
        nb.create_rack_types([rack_type], only_new=False, all_rack_types=all_rack_types)  # should not raise

        mock_settings.handle.log.assert_called()

    def test_all_rack_types_none_triggers_fetch(self, mock_settings, mock_pynetbox):
        """When all_rack_types=None, get_existing_rack_types() is called to populate the cache."""
        mock_pynetbox.api.return_value.version = "4.1"
        nb = self._make_nb(mock_settings, mock_pynetbox)
        nb.get_existing_rack_types = MagicMock(return_value={})
        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
        }
        nb.create_rack_types([rack_type], all_rack_types=None)

        nb.get_existing_rack_types.assert_called_once()

    def test_progress_iterator_used(self, mock_settings, mock_pynetbox):
        """When a progress wrapper is provided, it is used as the iterator."""
        mock_pynetbox.api.return_value.version = "4.1"
        created_rt = MagicMock()
        created_rt.id = 1
        mock_pynetbox.api.return_value.dcim.rack_types.create.return_value = created_rt

        nb = self._make_nb(mock_settings, mock_pynetbox)
        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
        }
        progress_items = [rack_type]
        nb.create_rack_types([rack_type], progress=iter(progress_items), all_rack_types={})

        mock_pynetbox.api.return_value.dcim.rack_types.create.assert_called_once()


# ============================================================
# NetBox version detection tests
# ============================================================


class TestVerifyCompatibility:
    """Tests for NetBox.verify_compatibility() version thresholds."""

    @pytest.mark.parametrize(
        "version_str, expected_modules, expected_new_filters, expected_rack_types, expected_m2m",
        [
            ("3.1", False, False, False, False),
            ("3.2", True, False, False, False),
            ("4.0", True, False, False, False),
            ("4.1", True, True, True, False),
            ("4.4", True, True, True, False),
            ("4.5", True, True, True, True),
            ("4.6", True, True, True, True),
            # Version strings with non-numeric suffixes
            ("4.5-beta", True, True, True, True),
            ("4.1.0", True, True, True, False),
        ],
    )
    def test_version_thresholds(
        self,
        version_str,
        expected_modules,
        expected_new_filters,
        expected_rack_types,
        expected_m2m,
        mock_settings,
        mock_pynetbox,
    ):
        mock_pynetbox.api.return_value.version = version_str
        nb = NetBox(mock_settings, mock_settings.handle)
        assert nb.modules == expected_modules, f"modules mismatch for {version_str}"
        assert nb.new_filters == expected_new_filters, f"new_filters mismatch for {version_str}"
        assert nb.rack_types == expected_rack_types, f"rack_types mismatch for {version_str}"
        assert nb.m2m_front_ports == expected_m2m, f"m2m_front_ports mismatch for {version_str}"

    def test_single_component_version_string(self, mock_settings, mock_pynetbox):
        """Version string with only major component (e.g. '4') does not crash."""
        mock_pynetbox.api.return_value.version = "4"
        nb = NetBox(mock_settings, mock_settings.handle)
        assert nb.new_filters is False  # 4.0 → no new filters

    def test_version_42_enables_new_filters_not_m2m(self, mock_settings, mock_pynetbox):
        mock_pynetbox.api.return_value.version = "4.2"
        nb = NetBox(mock_settings, mock_settings.handle)
        assert nb.new_filters is True
        assert nb.m2m_front_ports is False


# ============================================================
# Regression tests for bugs fixed during port-mappings work
# ============================================================


class TestRegressionPortMappings:
    """Regression tests for bugs found and fixed during the port-mappings PR."""

    def test_build_mappings_patch_returns_none_for_two_tuple(self, make_device_types, mock_pynetbox):
        """Regression: _build_mappings_patch must return None (not crash) for legacy 2-tuples.

        Bug: When ChangeDetector emitted 2-tuple (fp_pos, rp_pos) on legacy NetBox but
        _apply_mappings_change was called in M2M mode, the code crashed unpacking the tuple.
        Fix: _build_mappings_patch returns None when len(tup) != 3.

        Covers netbox_api.py line 1816.
        """
        dt = make_device_types()
        dt.m2m_front_ports = True
        dt.cached_components = {"rear_port_templates": {("device", 1): {"RP1": MagicMock(id=99)}}}

        # 2-tuple: legacy ChangeDetector format — should return None, not crash
        result = dt._build_mappings_patch("FP1", frozenset({(1, 2)}), 1, "device")
        assert result is None

    def test_legacy_empty_mappings_clears_rear_port(self, make_device_types, mock_pynetbox):
        """Regression: empty new_mappings frozenset must clear rear_port=None on legacy NetBox.

        Bug: The 'if new_mappings:' guard silently did nothing when mappings were removed.
        Fix: Added explicit 'if not new_mappings: rear_port=None; return' branch.
        """
        from core.change_detector import ChangeType, ComponentChange, PropertyChange

        dt = make_device_types()
        dt.m2m_front_ports = False

        existing_fp = MagicMock(id=10, name="FP1")
        dt.cached_components = {"front_port_templates": {("device", 1): {"FP1": existing_fp}}}

        changes = [
            ComponentChange(
                component_type="front-ports",
                component_name="FP1",
                change_type=ChangeType.COMPONENT_CHANGED,
                property_changes=[PropertyChange("_mappings", frozenset({("RP1", 1, 1)}), frozenset())],
            )
        ]
        endpoint = dt.netbox.dcim.front_port_templates
        dt.update_components({}, 1, changes, parent_type="device")

        endpoint.update.assert_called_once()
        payload = endpoint.update.call_args[0][0][0]
        assert payload["rear_port"] is None
        assert payload["rear_port_position"] is None

    def test_legacy_two_tuple_uses_yaml_fallback(self, make_device_types, mock_pynetbox):
        """Regression: 2-tuple _mappings on legacy NetBox must use YAML for rear port name.

        Bug: When ChangeDetector emitted 2-tuples (no rear port names), the code always
        warned and skipped — even when YAML data contained the rear port name.
        Fix: _apply_mappings_change falls back to yaml_mappings[0]["rear_port"] when len(first)!=3.
        """
        from core.change_detector import ChangeType, ComponentChange, PropertyChange

        dt = make_device_types()
        dt.m2m_front_ports = False

        existing_fp = MagicMock(id=10, name="FP1")
        mock_rp = MagicMock(id=99, name="RP1")
        dt.cached_components = {
            "front_port_templates": {("device", 1): {"FP1": existing_fp}},
            "rear_port_templates": {("device", 1): {"RP1": mock_rp}},
        }

        yaml_data = {
            "front-ports": [
                {"name": "FP1", "_mappings": [{"rear_port": "RP1", "front_port_position": 1, "rear_port_position": 2}]}
            ]
        }
        changes = [
            ComponentChange(
                component_type="front-ports",
                component_name="FP1",
                change_type=ChangeType.COMPONENT_CHANGED,
                property_changes=[PropertyChange("_mappings", frozenset({("RP1", 1, 1)}), frozenset({(1, 2)}))],
            )
        ]
        endpoint = dt.netbox.dcim.front_port_templates
        dt.update_components(yaml_data, 1, changes, parent_type="device")

        endpoint.update.assert_called_once()
        payload = endpoint.update.call_args[0][0][0]
        assert payload["rear_port"] == 99
        assert payload["rear_port_position"] == 2

    def test_legacy_two_tuple_without_yaml_warns_and_skips(self, make_device_types, mock_settings, mock_pynetbox):
        """Regression: 2-tuple _mappings without YAML fallback must warn+skip (not crash).

        Bug: Before len(first)!=3 guard, the code crashed with ValueError unpacking 2-tuples.
        Fix: Guard added. Without YAML fallback, still warn and skip gracefully.
        """
        from core.change_detector import ChangeType, ComponentChange, PropertyChange

        dt = make_device_types()
        dt.m2m_front_ports = False

        existing_fp = MagicMock(id=10, name="FP1")
        dt.cached_components = {"front_port_templates": {("device", 1): {"FP1": existing_fp}}}

        changes = [
            ComponentChange(
                component_type="front-ports",
                component_name="FP1",
                change_type=ChangeType.COMPONENT_CHANGED,
                property_changes=[PropertyChange("_mappings", frozenset(), frozenset({(1, 2)}))],
            )
        ]
        endpoint = dt.netbox.dcim.front_port_templates
        mock_settings.handle.log.reset_mock()
        dt.update_components({}, 1, changes, parent_type="device")

        endpoint.update.assert_not_called()
        assert any("NetBox < 4.5" in str(c) for c in mock_settings.handle.log.call_args_list)


# ============================================================
# _build_link_rear_ports edge cases (covering uncovered lines)
# ============================================================


class TestBuildLinkRearPortsEdgeCases:
    """Edge cases in _build_link_rear_ports not covered by existing tests."""

    def test_port_with_no_mappings_and_no_rear_port_is_skipped(self, make_device_types, mock_pynetbox):
        """Port with no _mappings key and no rear_port key is silently skipped.

        Covers netbox_api.py lines 2301-2302.
        """
        dt = make_device_types()
        mock_rp = MagicMock(id=99, name="RP1")
        dt.cached_components = {"rear_port_templates": {("device", 1): {"RP1": mock_rp}}}

        post_process = dt._build_link_rear_ports("device", "Front Port")
        # Port with neither _mappings nor rear_port key
        items = [{"name": "FP1", "type": "8p8c"}]
        post_process(items, 1)
        assert items == [{"name": "FP1", "type": "8p8c"}]  # unchanged

    def test_multiple_legacy_mappings_logs_warning_with_context(self, make_device_types, mock_settings, mock_pynetbox):
        """Multiple _mappings on legacy NetBox logs warning including context string.

        Covers netbox_api.py lines 2344-2345.
        """
        dt = make_device_types()
        dt.m2m_front_ports = False

        mock_rp1 = MagicMock(id=99)
        mock_rp2 = MagicMock(id=100)
        dt.cached_components = {
            "rear_port_templates": {("device", 1): {"RP1": mock_rp1, "RP2": mock_rp2}},
        }

        post_process = dt._build_link_rear_ports("device", "Front Port", context="MyDevice")
        items = [
            {
                "name": "FP1",
                "type": "8p8c",
                "_mappings": [
                    {"rear_port": "RP1", "front_port_position": 1, "rear_port_position": 1},
                    {"rear_port": "RP2", "front_port_position": 1, "rear_port_position": 1},
                ],
            }
        ]
        mock_settings.handle.log.reset_mock()
        post_process(items, 1)

        log_calls = [str(c) for c in mock_settings.handle.log.call_args_list]
        assert any("only first mapping applied" in c for c in log_calls)
        assert any("MyDevice" in c for c in log_calls)


# ---------------------------------------------------------------------------
# _module_type_has_missing_components (lines 770-782)
# ---------------------------------------------------------------------------


class TestModuleTypeHasMissingComponents:
    """Tests for NetBox._module_type_has_missing_components()."""

    def test_returns_true_when_component_missing(self, mock_settings, mock_pynetbox, make_device_types):
        """Returns True when a YAML-defined component name is absent from the cache."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        nb = NetBox(mock_settings, mock_settings.handle)
        # Pre-populate cache with an empty interface set for module 42.
        nb.device_types.cached_components["interface_templates"] = {("module", 42): {}}

        module_type = {"interfaces": [{"name": "xe-0/0/0"}]}
        existing_module = MagicMock()
        existing_module.id = 42

        result = nb._module_type_has_missing_components(module_type, existing_module, ["interfaces"])

        assert result is True

    def test_returns_false_when_all_components_present(self, mock_settings, mock_pynetbox, make_device_types):
        """Returns False when all YAML-defined components exist in the cache."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        nb = NetBox(mock_settings, mock_settings.handle)
        existing_iface = MagicMock()
        existing_iface.name = "xe-0/0/0"
        nb.device_types.cached_components["interface_templates"] = {("module", 42): {"xe-0/0/0": existing_iface}}

        module_type = {"interfaces": [{"name": "xe-0/0/0"}]}
        existing_module = MagicMock()
        existing_module.id = 42

        result = nb._module_type_has_missing_components(module_type, existing_module, ["interfaces"])

        assert result is False

    def test_returns_false_when_no_components_in_yaml(self, mock_settings, mock_pynetbox, make_device_types):
        """Returns False when the module type dict has no components under the key."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        nb = NetBox(mock_settings, mock_settings.handle)
        module_type = {}  # no "interfaces" key
        existing_module = MagicMock()
        existing_module.id = 99

        result = nb._module_type_has_missing_components(module_type, existing_module, ["interfaces"])

        assert result is False


# ---------------------------------------------------------------------------
# filter_actionable_module_types _MISSING skip (line 847)
# ---------------------------------------------------------------------------


class TestFilterActionableModuleTypesMissingAttr:
    """Tests for the _MISSING guard in filter_actionable_module_types."""

    def test_missing_netbox_field_is_not_treated_as_change(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        """When existing module lacks an attribute, it's skipped — no false positive change."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        mock_graphql_requests.side_effect = paginate_dispatch(
            {
                "manufacturer_list": [],
                "device_type_list": [],
                "module_type_list": [
                    {
                        "id": "10",
                        "model": "Linecard-A",
                        "manufacturer": {"id": "5", "name": "Arista", "slug": "arista"},
                    }
                ],
                "image_attachment_list": [],
            }
        )

        nb = NetBox(mock_settings, mock_settings.handle)
        nb.device_types._global_preload_done = True

        # existing_module is a spec=[] object so getattr(…, field, _MISSING) returns _MISSING
        existing_module = MagicMock(spec=[])
        existing_module.id = 10
        existing_module.manufacturer = MagicMock()
        existing_module.manufacturer.slug = "arista"
        existing_module.model = "Linecard-A"

        all_module_types = {"arista": {"Linecard-A": existing_module}}

        module_type = {
            "manufacturer": {"slug": "arista"},
            "model": "Linecard-A",
            "slug": "linecard-a",
            "part_number": "LC-123",
            "src": "/repo/module-types/arista/linecard-a.yaml",
        }

        with patch("glob.glob", return_value=[]):
            actionable, _, changed_property_log = nb.filter_actionable_module_types(
                [module_type],
                all_module_types,
                only_new=False,
            )

        # The _MISSING sentinel must prevent the module from being flagged for update.
        # A MagicMock(spec=[]) has no attributes, so every field access returns _MISSING
        # and the module should NOT appear in actionable or the change log.
        assert actionable == []
        assert changed_property_log == []


# ---------------------------------------------------------------------------
# log_module_type_changes non-empty log (lines 875-878)
# ---------------------------------------------------------------------------


class TestLogModuleTypeChanges:
    """Tests for NetBox.log_module_type_changes()."""

    def test_non_empty_log_emits_verbose_output(self, mock_settings, mock_pynetbox):
        """A non-empty changed_property_log triggers verbose logging."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        nb = NetBox(mock_settings, mock_settings.handle)
        mock_settings.handle.verbose_log.reset_mock()

        changed_property_log = [("cisco", "CM1", [("part_number", "old", "new")], [])]
        nb.log_module_type_changes(changed_property_log)

        mock_settings.handle.verbose_log.assert_called()

    def test_empty_log_emits_nothing(self, mock_settings, mock_pynetbox):
        """An empty changed_property_log does not trigger any logging calls."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        nb = NetBox(mock_settings, mock_settings.handle)
        mock_settings.handle.verbose_log.reset_mock()

        nb.log_module_type_changes([])

        mock_settings.handle.verbose_log.assert_not_called()


# ---------------------------------------------------------------------------
# _try_update_module_type error handlers (lines 918-925)
# ---------------------------------------------------------------------------


class TestTryUpdateModuleTypeErrors:
    """Tests for RequestError and retryable-exception handlers in _try_update_module_type."""

    def _make_nb(self, mock_settings, mock_pynetbox):
        mock_pynetbox.api.return_value.version = "3.5"
        return NetBox(mock_settings, mock_settings.handle)

    def _make_module_type_res(self):
        res = MagicMock()
        res.id = 1
        res.manufacturer.name = "Cisco"
        res.model = "CM1"
        return res

    def test_request_error_returns_false_and_logs(self, mock_settings, mock_pynetbox):
        """pynetbox.RequestError during update causes (False, False) return and log."""
        import pynetbox as real_pynb

        mock_pynetbox.api.return_value.version = "3.5"
        mock_pynetbox.RequestError = real_pynb.RequestError

        nb = self._make_nb(mock_settings, mock_pynetbox)
        mock_settings.handle.log.reset_mock()

        err = real_pynb.RequestError(MagicMock(status_code=400, content=b'{"detail":"bad"}'))
        nb.netbox.dcim.module_types.update.side_effect = err

        curr_mt = {"part_number": "NEW-123"}
        module_type_res = self._make_module_type_res()
        module_type_res.part_number = "OLD-123"

        ok, updated = nb._try_update_module_type(curr_mt, module_type_res, "test.yaml")

        assert ok is False
        assert updated is False
        mock_settings.handle.log.assert_called()

    def test_retryable_exception_returns_false_and_logs(self, mock_settings, mock_pynetbox):
        """A ConnectionError (retryable) after max retries causes (False, False) return."""
        import pynetbox as real_pynb
        import requests

        mock_pynetbox.RequestError = real_pynb.RequestError
        mock_pynetbox.api.return_value.version = "3.5"

        nb = self._make_nb(mock_settings, mock_pynetbox)
        mock_settings.handle.log.reset_mock()

        nb.netbox.dcim.module_types.update.side_effect = requests.exceptions.ConnectionError("dropped")

        curr_mt = {"part_number": "NEW-123"}
        module_type_res = self._make_module_type_res()
        module_type_res.part_number = "OLD-123"

        with patch("core.netbox_api.time.sleep") as mock_sleep:
            ok, updated = nb._try_update_module_type(curr_mt, module_type_res, "test.yaml")

        assert ok is False
        assert updated is False
        mock_settings.handle.log.assert_called()
        # Prove the retry loop actually ran the full budget with the correct backoff.
        from core.netbox_api import _MAX_RETRIES, _RETRY_BACKOFF

        assert nb.netbox.dcim.module_types.update.call_count == _MAX_RETRIES + 1
        assert mock_sleep.call_count == _MAX_RETRIES
        assert [call.args[0] for call in mock_sleep.call_args_list] == list(_RETRY_BACKOFF[:_MAX_RETRIES])


# ---------------------------------------------------------------------------
# _process_single_module_type: creation retryable exception (lines 979-983)
# ---------------------------------------------------------------------------


class TestProcessSingleModuleTypeCreateRetryable:
    """Tests for the retryable-exception handler when creating a module type."""

    def test_retryable_exception_on_create_returns_false(self, mock_settings, mock_pynetbox, mock_graphql_requests):
        """ConnectionError during module type creation causes the method to return False."""
        from unittest.mock import patch

        import pynetbox as real_pynb
        import requests

        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"
        mock_pynetbox.RequestError = real_pynb.RequestError

        nb = NetBox(mock_settings, mock_settings.handle)
        mock_settings.handle.log.reset_mock()

        mock_nb_api.dcim.module_types.create.side_effect = requests.exceptions.ConnectionError("network down")

        curr_mt = {
            "manufacturer": {"slug": "cisco"},
            "model": "CM-Retryable",
            "slug": "cm-retryable",
        }

        with patch("core.netbox_api.time.sleep") as mock_sleep:
            result = nb._process_single_module_type(
                curr_mt,
                "test.yaml",
                {},
                {},
                only_new=False,
            )

        assert result is False
        mock_settings.handle.log.assert_called()
        # Prove the retry loop actually ran the full budget with the correct backoff.
        from core.netbox_api import _MAX_RETRIES, _RETRY_BACKOFF

        assert mock_nb_api.dcim.module_types.create.call_count == _MAX_RETRIES + 1
        assert mock_sleep.call_count == _MAX_RETRIES
        assert [call.args[0] for call in mock_sleep.call_args_list] == list(_RETRY_BACKOFF[:_MAX_RETRIES])


# ---------------------------------------------------------------------------
# _process_single_module_type: remove_components call (line 1033)
# ---------------------------------------------------------------------------


class TestProcessSingleModuleTypeRemoveComponents:
    """Tests that remove_components=True calls device_types.remove_components."""

    def test_remove_components_is_called_when_flag_set(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, make_device_types
    ):
        """When remove_components=True and there are component changes, remove_components is called."""
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        nb = NetBox(mock_settings, mock_settings.handle)

        # Build a pre-existing module type so the "else" path (update) is taken.
        existing_module = MagicMock()
        existing_module.id = 55
        existing_module.manufacturer.name = "Cisco"
        existing_module.model = "CM-Remove"

        all_module_types = {"cisco": {"CM-Remove": existing_module}}

        # Populate cache so _compare_components returns a COMPONENT_REMOVED change.
        stale_iface = MagicMock()
        stale_iface.name = "xe-stale"
        nb.device_types.cached_components["interface_templates"] = {("module", 55): {"xe-stale": stale_iface}}
        nb.device_types._global_preload_done = True

        curr_mt = {
            "manufacturer": {"slug": "cisco"},
            "model": "CM-Remove",
            "slug": "cm-remove",
            "interfaces": [],  # empty → xe-stale should be detected as removed
        }

        nb.device_types.remove_components = MagicMock()
        nb.device_types.update_components = MagicMock()

        result = nb._process_single_module_type(
            curr_mt,
            "test.yaml",
            all_module_types,
            {},
            only_new=False,
            remove_components=True,
        )

        assert result is True
        nb.device_types.remove_components.assert_called_once()
        # Verify the payload: exactly one COMPONENT_REMOVED change for "xe-stale".
        from core.change_detector import ChangeType

        removal_changes = nb.device_types.remove_components.call_args.args[1]
        assert len(removal_changes) == 1
        assert removal_changes[0].change_type == ChangeType.COMPONENT_REMOVED
        assert removal_changes[0].component_name == "xe-stale"

    def test_component_reconciliation_continues_when_scalar_patch_fails(
        self, mock_settings, mock_pynetbox, mock_graphql_requests, make_device_types
    ):
        """A failed scalar PATCH must NOT skip subsequent component reconciliation.

        Regression: previously the early ``return False`` on a failed
        ``module_types.update`` left existing modules with property + component
        diffs in a partial-sync state because component reconciliation was
        skipped entirely.
        """
        mock_nb_api = mock_pynetbox.api.return_value
        mock_nb_api.version = "3.5"

        nb = NetBox(mock_settings, mock_settings.handle)

        existing_module = MagicMock()
        existing_module.id = 77
        existing_module.manufacturer.name = "Cisco"
        existing_module.model = "CM-Fail-Patch"
        # Make the scalar diff non-empty so update() will be invoked and fail.
        existing_module.part_number = "OLD_PN"

        all_module_types = {"cisco": {"CM-Fail-Patch": existing_module}}

        # Cache a stale interface so _compare_components yields a COMPONENT_REMOVED.
        stale_iface = MagicMock()
        stale_iface.name = "xe-stale"
        nb.device_types.cached_components["interface_templates"] = {("module", 77): {"xe-stale": stale_iface}}
        nb.device_types._global_preload_done = True

        curr_mt = {
            "manufacturer": {"slug": "cisco"},
            "model": "CM-Fail-Patch",
            "slug": "cm-fail-patch",
            "part_number": "NEW_PN",  # forces a scalar diff
            "interfaces": [],  # empty → xe-stale should be detected as removed
        }

        # Force the scalar PATCH to fail with a pynetbox RequestError.
        # pynetbox is mocked at module level, so we restore the real exception
        # class first (otherwise `except pynetbox.RequestError` raises TypeError).
        import pynetbox as _real_pynb

        mock_pynetbox.RequestError = _real_pynb.RequestError
        request_error = _real_pynb.RequestError(MagicMock(status_code=400, content=b'{"detail":"boom"}'))
        mock_nb_api.dcim.module_types.update = MagicMock(side_effect=request_error)

        nb.device_types.update_components = MagicMock()
        nb.device_types.remove_components = MagicMock()

        result = nb._process_single_module_type(
            curr_mt,
            "test.yaml",
            all_module_types,
            {},
            only_new=False,
            remove_components=True,
        )

        # The failed PATCH should NOT prevent component reconciliation.
        # Verify the failing PATCH was actually attempted (regression: scalar
        # diff detection silently skipping update() would still pass without
        # this assertion).
        mock_nb_api.dcim.module_types.update.assert_called_once()
        assert result is True
        nb.device_types.remove_components.assert_called_once()
        assert nb.counter["module_updated"] == 0
        assert nb.counter["module_update_failed"] == 1
        failures = nb.outcomes.failures()
        assert len(failures) == 1
        assert "CM-Fail-Patch" in failures[0].identity
