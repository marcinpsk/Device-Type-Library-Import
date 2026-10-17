"""Tests for retrying a NetBox write whose reply broke after the write committed.

A local HTTP server answers a real ``pynetbox`` client.  It commits each write, then drops,
cuts off or garbles the reply when a test asks it to, and it refuses a duplicate the way
NetBox does.  A retry that sends the write again therefore fails visibly.
"""

import pynetbox
import pytest
from helpers import FakeNetBox, recording_handle

from core.change_detector import ChangeType, ComponentChange
from core.component_registry import BY_YAML_KEY
from core.netbox_api import NetBox
from core.retry import create_with_retry

# The suite patches requests.Session by default, which would stop every request below.
pytestmark = pytest.mark.real_http

CISCO = {"id": 1, "name": "Cisco", "slug": "cisco"}
SWITCH = {"id": 5, "model": "C9300", "slug": "c9300", "manufacturer": {"id": 1, "name": "Cisco", "slug": "cisco"}}
REPLIES = ["lost", "truncated", "garbled"]


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    """Skip the wait between attempts."""
    monkeypatch.setattr("core.retry.time.sleep", lambda _seconds: None)


@pytest.fixture
def server():
    """Run a local NetBox-shaped server holding one manufacturer and one device type."""
    fake = FakeNetBox(manufacturers=[CISCO], device_types=[SWITCH])
    yield fake
    fake.close()


@pytest.fixture
def netbox(make_config, mock_pynetbox, server, tmp_path):
    """Build a real NetBox against the local server."""
    mock_pynetbox.RequestError = pynetbox.RequestError
    handle, console = recording_handle()
    nb = NetBox(make_config(netbox_url=server.url, repo_path=str(tmp_path)), handle)

    # connect_api ran against the patched pynetbox; every call under test uses a real client.
    api = server.api()
    nb.netbox = api
    nb.device_types.netbox = api
    nb.device_types.components.netbox = api
    nb.device_types.components.ensure_ready()
    return nb, console


def requests_to(server, verb, name):
    """Count the *verb* requests sent to collection *name*."""
    return sum(v == verb and n == name for v, n, _payload in server.requests)


def break_reads_after_now(server, count=3):
    """Drop the reply of the next *count* GETs, so each lookup before a retry fails too."""
    done = sum(verb == "GET" for verb, _name, _payload in server.requests)
    server.broken_replies.update({("GET", done + n): "lost" for n in range(1, count + 1)})


class TestCreate:
    """A create whose reply broke returns the object it committed, and creates no duplicate."""

    @pytest.mark.parametrize("reply", REPLIES)
    def test_a_device_type_create_is_not_repeated(self, netbox, server, reply):
        nb, _ = netbox
        server.broken_replies = {("POST", 1): reply}

        dt, skip = nb._create_new_device_type(
            {"manufacturer": {"slug": "cisco"}, "model": "C9500", "slug": "c9500"}, "c9500.yaml"
        )

        assert skip is False
        stored = [r for r in server.collection("device_types") if r["model"] == "C9500"]
        assert len(stored) == 1
        assert dt.id == stored[0]["id"]
        assert dt.manufacturer.name == "Cisco"
        assert requests_to(server, "POST", "device_types") == 1
        assert nb.counter["added"] == 1
        assert nb.outcomes.failures() == []

    @pytest.mark.parametrize("reply", REPLIES)
    def test_a_module_type_create_is_not_repeated(self, netbox, server, reply):
        nb, _ = netbox
        server.broken_replies = {("POST", 1): reply}
        all_module_types = {}

        ok = nb._process_single_module_type(
            {"manufacturer": {"slug": "cisco"}, "model": "C9300-NM-8X"}, "nm.yaml", all_module_types, {}, False
        )

        assert ok is True
        [stored] = server.collection("module_types")
        assert all_module_types["cisco"]["C9300-NM-8X"].id == stored["id"]
        assert requests_to(server, "POST", "module_types") == 1
        assert nb.counter["module_added"] == 1
        assert nb.outcomes.failures() == []

    @pytest.mark.parametrize("reply", REPLIES)
    def test_a_rack_type_create_is_not_repeated(self, netbox, server, reply):
        nb, _ = netbox
        server.broken_replies = {("POST", 1): reply}
        rack = {"manufacturer": {"slug": "cisco"}, "model": "R42", "slug": "r42", "form_factor": "4-post-cabinet"}

        nb.create_rack_types([{**rack, "src": "r42.yaml"}], all_rack_types={})

        assert len(server.collection("rack_types")) == 1
        assert requests_to(server, "POST", "rack_types") == 1
        assert nb.counter["rack_type_added"] == 1
        assert nb.outcomes.failures() == []

    @pytest.mark.parametrize("reply", REPLIES)
    def test_a_manufacturer_bulk_create_is_not_repeated(self, netbox, server, reply):
        nb, console = netbox
        server.broken_replies = {("POST", 1): reply}

        nb.create_manufacturers([{"name": "Juniper"}, {"name": "Nokia"}])

        assert sorted(r["slug"] for r in server.collection("manufacturers")) == ["cisco", "juniper", "nokia"]
        assert requests_to(server, "POST", "manufacturers") == 1
        assert nb.counter["manufacturer"] == 2
        assert not any("Error creating manufacturers" in line for line in console.lines)

    @pytest.mark.parametrize("reply", REPLIES)
    def test_a_component_bulk_create_is_not_repeated(self, netbox, server, reply):
        nb, _ = netbox
        server.broken_replies = {("POST", 1): reply}
        items = [{"name": f"Gi1/0/{n}", "type": "1000base-t"} for n in (1, 2, 3)]

        with nb.device_types.collect_component_errors() as errors:
            nb.device_types._create_generic(BY_YAML_KEY["interfaces"], items, SWITCH["id"])

        assert errors == []
        names = [r["name"] for r in server.collection("interface_templates")]
        assert names == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3"]
        assert requests_to(server, "POST", "interface_templates") == 1
        assert nb.counter["components_added"] == 3

    def test_a_large_bulk_create_is_looked_up_in_short_requests(self, netbox, server):
        """Hundreds of names in one lookup URL would pass a proxy's URL limit and fail with 414."""
        nb, _ = netbox
        server.max_url_length = 2000
        server.broken_replies = {("POST", 1): "lost"}
        items = [{"name": f"GigabitEthernet1/0/{n}", "type": "1000base-t"} for n in range(1, 201)]

        with nb.device_types.collect_component_errors() as errors:
            nb.device_types._create_generic(BY_YAML_KEY["interfaces"], items, SWITCH["id"])

        assert errors == []
        assert len(server.collection("interface_templates")) == 200
        assert requests_to(server, "POST", "interface_templates") == 1
        assert nb.counter["components_added"] == 200

    def test_a_partial_bulk_match_is_sent_again_not_taken_as_the_result(self, server):
        """Another writer holds one of the names: NetBox refuses the batch, and nothing is guessed."""
        server.collection("interface_templates").append({"id": 77, "name": "Gi1/0/1", "device_type": {"id": 5}})
        server.broken_replies = {("POST", 1): "lost"}
        items = [{"name": "Gi1/0/1", "device_type": 5}, {"name": "Gi1/0/2", "device_type": 5}]

        with pytest.raises(pynetbox.RequestError):
            create_with_retry(server.api().dcim.interface_templates, items, "name", device_type_id=5)

        assert [r["name"] for r in server.collection("interface_templates")] == ["Gi1/0/1"]
        assert requests_to(server, "POST", "interface_templates") == 2

    def test_retries_exhausted_fail_only_that_device_type(self, netbox, server):
        nb, _ = netbox
        server.broken_replies = {("POST", 1): "lost"}
        break_reads_after_now(server)

        dt, skip = nb._create_new_device_type(
            {"manufacturer": {"slug": "cisco"}, "model": "C9500", "slug": "c9500"}, "c9500.yaml"
        )
        nxt, _ = nb._create_new_device_type(
            {"manufacturer": {"slug": "cisco"}, "model": "C9600", "slug": "c9600"}, "c9600.yaml"
        )

        assert (dt, skip) == (None, True)
        [failure] = nb.outcomes.failures()
        assert "C9500" in failure.identity
        assert "after 3 retries" in failure.reason
        assert requests_to(server, "POST", "device_types") == 2  # one per device type; none is sent twice
        assert nxt.model == "C9600"


class TestDelete:
    """A delete whose reply broke counts as done; a delete NetBox refuses does not."""

    def test_a_delete_with_a_lost_reply_counts_as_removed(self, netbox, server):
        nb, _ = netbox
        server.collection("interface_templates").append({"id": 50, "name": "OLD", "device_type": {"id": 5}})
        server.broken_replies = {("DELETE", 1): "lost"}

        with nb.device_types.collect_component_errors() as errors:
            nb.device_types.remove_components(
                SWITCH["id"], [ComponentChange("interfaces", "OLD", ChangeType.COMPONENT_REMOVED)]
            )

        assert errors == []
        assert server.collection("interface_templates") == []
        assert requests_to(server, "DELETE", "interface_templates") == 1
        assert nb.counter["components_removed"] == 1

    def test_a_first_attempt_delete_of_a_missing_object_is_an_error(self, netbox, server):
        nb, _ = netbox
        stale = pynetbox.core.response.Record({"id": 88, "name": "OLD"}, server.api(), None)
        nb.device_types.components.record("interface_templates", "device", SWITCH["id"], {"OLD": stale})

        with nb.device_types.collect_component_errors() as errors:
            nb.device_types.remove_components(
                SWITCH["id"], [ComponentChange("interfaces", "OLD", ChangeType.COMPONENT_REMOVED)]
            )

        [error] = errors
        assert "Error removing interfaces (ID: 88)" in error
        assert requests_to(server, "DELETE", "interface_templates") == 1
        assert nb.counter["components_removed"] == 0


class TestTimeout:
    """A stalled reply times out, so the run does not hang on it."""

    def test_a_stalled_create_times_out_and_is_not_repeated(self, make_config, server, tmp_path, monkeypatch):
        monkeypatch.setattr("core.netbox_api._REST_TIMEOUT", (5, 0.5))
        # A real client from connect_api, so the session under test is the one the importer builds.
        nb = NetBox(make_config(netbox_url=server.url, repo_path=str(tmp_path)), recording_handle()[0])
        server.broken_replies = {("POST", 1): "stalled"}

        dt, skip = nb._create_new_device_type(
            {"manufacturer": {"slug": "cisco"}, "model": "C9500", "slug": "c9500"}, "c9500.yaml"
        )

        assert skip is False
        assert dt.model == "C9500"
        assert len([r for r in server.collection("device_types") if r["model"] == "C9500"]) == 1
        assert requests_to(server, "POST", "device_types") == 1
