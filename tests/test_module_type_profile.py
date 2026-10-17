"""Tests for keeping a module type's profile and attribute data in sync with NetBox.

The definitions are real YAML files parsed by the real parser.  A local HTTP server answers
a real ``pynetbox`` client and the real GraphQL client, so the payloads asserted on here are
the ones that would go over the wire.  The existing NetBox record is built the way the
GraphQL client builds it.
"""

import pynetbox
import pytest
from helpers import FakeNetBox, recording_handle

from core.graphql_client import _to_dotdict
from core.netbox_api import NetBox
from core.outcomes import EntityKind, Outcome
from core.repo import parse_single_file

# The suite patches requests.Session by default, which would stop every request below.
pytestmark = pytest.mark.real_http

CISCO = {"id": 1, "name": "Cisco", "slug": "cisco"}
PROFILES = [{"id": 3, "name": "Transceiver"}, {"id": 4, "name": "Fan"}]

SFP_YAML = """\
manufacturer: Cisco
model: SFP-10G-SR
part_number: 10-2415-03
profile: Transceiver
attribute_data:
  phy: 10GBASE-SR
  media: MMF
  reach: 400.0
  data_rate: 10G
  form_factor: SFP+
  connector_type: LC/UPC
"""

SFP_ATTRIBUTES = {
    "phy": "10GBASE-SR",
    "media": "MMF",
    "reach": 400.0,
    "data_rate": "10G",
    "form_factor": "SFP+",
    "connector_type": "LC/UPC",
}


@pytest.fixture
def server():
    """Run a local NetBox-shaped server holding the manufacturer and the profiles."""
    fake = FakeNetBox(manufacturers=[CISCO], module_type_profiles=PROFILES)
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


@pytest.fixture
def definition(tmp_path):
    """Parse a module type definition from a real YAML file."""

    def _parse(text=SFP_YAML):
        path = tmp_path / "module-types" / "Cisco" / "SFP-10G-SR.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        parsed = parse_single_file(str(path))
        parsed.pop("src")
        return parsed

    return _parse


def existing(server, profile=None, attribute_data=None):
    """Store the module type on the server and return it as the GraphQL client returns it."""
    record = {
        "id": 7,
        "model": "SFP-10G-SR",
        "part_number": "10-2415-03",
        "manufacturer": {"id": 1, "name": "Cisco", "slug": "cisco"},
        "profile": profile,
        "attribute_data": attribute_data,
    }
    server.collection("module_types").append(dict(record))
    return _to_dotdict(record)


class TestChangeDetection:
    """A profile or attribute that differs is reported like any other property."""

    def test_a_changed_profile_and_attribute_are_reported(self, netbox, server, definition):
        nb, console = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {**SFP_ATTRIBUTES, "reach": 300})

        actionable, _, log = nb.filter_actionable_module_types([definition()], {"cisco": {"SFP-10G-SR": record}})

        assert len(actionable) == 1
        assert log[0][2] == [("profile", "Fan", "Transceiver"), ("attribute_data.reach", 300, 400.0)]
        nb.handle.verbose = True
        nb.log_module_type_changes(log)
        assert any("profile" in line and "Fan" in line for line in console.lines)
        assert any("attribute_data.reach" in line and "400.0" in line for line in console.lines)

    def test_a_missing_profile_and_attributes_are_reported(self, netbox, server, definition):
        nb, _ = netbox
        record = existing(server)

        _, _, log = nb.filter_actionable_module_types([definition()], {"cisco": {"SFP-10G-SR": record}})

        fields = [field for field, _, _ in log[0][2]]
        assert fields == ["profile", *(f"attribute_data.{key}" for key in SFP_ATTRIBUTES)]

    def test_an_integer_and_an_equal_float_are_the_same_value(self, netbox, server, definition):
        nb, _ = netbox
        record = existing(server, {"id": 3, "name": "Transceiver"}, {**SFP_ATTRIBUTES, "reach": 400})

        actionable, _, log = nb.filter_actionable_module_types([definition()], {"cisco": {"SFP-10G-SR": record}})

        assert actionable == []
        assert log == []

    def test_an_omitted_profile_is_left_alone(self, netbox, server, definition):
        """A key absent from the YAML is not managed, as for every other property."""
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {"rpm": 3000})

        actionable, _, _ = nb.filter_actionable_module_types(
            [definition("manufacturer: Cisco\nmodel: SFP-10G-SR\npart_number: 10-2415-03\n")],
            {"cisco": {"SFP-10G-SR": record}},
        )

        assert actionable == []

    def test_stored_attributes_that_are_not_an_object_are_reported_not_raised(self, netbox, server, definition):
        nb, _ = netbox
        record = existing(server, {"id": 3, "name": "Transceiver"}, [3000])

        actionable, _, log = nb.filter_actionable_module_types([definition()], {"cisco": {"SFP-10G-SR": record}})

        assert len(actionable) == 1
        assert [field for field, _, _ in log[0][2]] == [f"attribute_data.{key}" for key in SFP_ATTRIBUTES]

    def test_a_boolean_and_a_number_are_different_values(self, netbox, server, definition):
        nb, _ = netbox
        record = existing(server, {"id": 3, "name": "Transceiver"}, {**SFP_ATTRIBUTES, "hot_swap": 1})

        _, _, log = nb.filter_actionable_module_types(
            [definition(SFP_YAML + "  hot_swap: true\n")], {"cisco": {"SFP-10G-SR": record}}
        )

        assert log[0][2] == [("attribute_data.hot_swap", 1, True)]

    @pytest.mark.parametrize("declared", ["{}", "null"])
    def test_explicit_empty_attributes_clear_the_stored_ones(self, netbox, server, definition, declared):
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {"rpm": 3000})
        curr_mt = definition(f"manufacturer: Cisco\nmodel: SFP-10G-SR\nattribute_data: {declared}\n")

        _, _, log = nb.filter_actionable_module_types([curr_mt], {"cisco": {"SFP-10G-SR": record}})
        assert log[0][2] == [("attribute_data", {"rpm": 3000}, {})]

        nb._try_update_module_type(curr_mt, record, "cisco/SFP-10G-SR.yaml")
        assert server.sent("PATCH", "module_types") == [{"id": 7, "attributes": {}}]


class TestUpdate:
    """The update path patches the profile and attributes under the names NetBox accepts."""

    def test_a_changed_profile_and_attribute_are_patched(self, netbox, server, definition):
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {**SFP_ATTRIBUTES, "reach": 300})

        assert nb._try_update_module_type(definition(), record, "cisco/SFP-10G-SR.yaml") == (True, True)

        assert server.sent("PATCH", "module_types") == [
            {"id": 7, "profile": {"name": "Transceiver"}, "attributes": SFP_ATTRIBUTES}
        ]

    @pytest.mark.parametrize("stored", [{"rpm": 3000}, {**SFP_ATTRIBUTES, "rpm": 3000}])
    def test_a_changed_profile_drops_the_old_profile_attributes(self, netbox, server, definition, stored):
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, stored)

        assert nb._try_update_module_type(definition(), record, "cisco/SFP-10G-SR.yaml") == (True, True)

        [stored_type] = server.collection("module_types")
        assert stored_type["profile"] == {"id": 3, "name": "Transceiver"}
        assert stored_type["attribute_data"] == SFP_ATTRIBUTES

    def test_a_rejected_profile_change_keeps_the_old_profile_and_attributes(self, netbox, server, definition):
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {"rpm": 3000})
        curr_mt = definition(SFP_YAML.replace("profile: Transceiver", "profile: No Such Profile"))

        assert nb._try_update_module_type(curr_mt, record, "cisco/SFP-10G-SR.yaml") == (False, False)

        [stored_type] = server.collection("module_types")
        assert stored_type["profile"] == {"id": 4, "name": "Fan"}
        assert stored_type["attribute_data"] == {"rpm": 3000}

    @pytest.mark.parametrize("reply", ["lost", "truncated", "garbled"])
    @pytest.mark.parametrize("broken", [{1, 2, 3, 4}, {2, 3, 4, 5}], ids=["clear", "write"])
    def test_a_profile_change_with_broken_replies_keeps_the_old_profile_and_attributes(
        self, netbox, server, definition, monkeypatch, broken, reply
    ):
        """Each PATCH commits but its reply breaks, so every retry is exhausted."""
        monkeypatch.setattr("core.netbox_api.time.sleep", lambda _seconds: None)
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {"rpm": 3000})
        server.broken_replies = {("PATCH", number): reply for number in broken}

        assert nb._try_update_module_type(definition(), record, "cisco/SFP-10G-SR.yaml") == (False, False)

        [stored_type] = server.collection("module_types")
        assert stored_type["profile"] == {"id": 4, "name": "Fan"}
        assert stored_type["attribute_data"] == {"rpm": 3000}

    @pytest.mark.parametrize("reply", ["lost", "truncated", "garbled"])
    @pytest.mark.parametrize("broken", [1, 2], ids=["clear", "write"])
    def test_a_profile_change_retries_a_broken_reply(self, netbox, server, definition, monkeypatch, broken, reply):
        monkeypatch.setattr("core.netbox_api.time.sleep", lambda _seconds: None)
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {"rpm": 3000})
        server.broken_replies = {("PATCH", broken): reply}

        assert nb._try_update_module_type(definition(), record, "cisco/SFP-10G-SR.yaml") == (True, True)

        [stored_type] = server.collection("module_types")
        assert stored_type["profile"] == {"id": 3, "name": "Transceiver"}
        assert stored_type["attribute_data"] == SFP_ATTRIBUTES
        assert len(server.sent("PATCH", "module_types")) == 3

    @pytest.mark.parametrize("reply", ["truncated", "garbled"])
    def test_an_update_retries_a_broken_reply(self, netbox, server, definition, monkeypatch, reply):
        monkeypatch.setattr("core.netbox_api.time.sleep", lambda _seconds: None)
        nb, _ = netbox
        record = existing(server, {"id": 3, "name": "Transceiver"}, {})
        server.broken_replies = {("PATCH", 1): reply}

        assert nb._try_update_module_type(definition(), record, "cisco/SFP-10G-SR.yaml") == (True, True)

        assert server.collection("module_types")[0]["attribute_data"] == SFP_ATTRIBUTES
        assert len(server.sent("PATCH", "module_types")) == 2

    @pytest.mark.parametrize("reply", ["truncated", "garbled"])
    def test_an_update_whose_replies_stay_broken_fails_only_that_module_type(
        self, netbox, server, definition, monkeypatch, reply
    ):
        monkeypatch.setattr("core.netbox_api.time.sleep", lambda _seconds: None)
        nb, console = netbox
        record = existing(server, {"id": 3, "name": "Transceiver"}, {})
        server.broken_replies = {("PATCH", number): reply for number in range(1, 5)}

        assert nb._try_update_module_type(definition(), record, "cisco/SFP-10G-SR.yaml") == (False, False)

        assert len(server.sent("PATCH", "module_types")) == 4
        assert any("after 3 retries" in line for line in console.lines)

    def test_a_failed_recovery_clear_still_restores_the_old_profile(self, netbox, server, definition):
        nb, console = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {"rpm": 3000})
        curr_mt = definition(SFP_YAML.replace("profile: Transceiver", "profile: No Such Profile"))
        server.broken_replies = {("PATCH", number): "garbled" for number in range(3, 7)}

        assert nb._try_update_module_type(curr_mt, record, "cisco/SFP-10G-SR.yaml") == (False, False)

        [stored_type] = server.collection("module_types")
        assert stored_type["profile"] == {"id": 4, "name": "Fan"}
        assert stored_type["attribute_data"] == {"rpm": 3000}
        assert any("Could not clear" in line for line in console.lines)

    def test_a_profile_change_keeps_explicit_empty_attributes(self, netbox, server, definition):
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {})
        curr_mt = definition(SFP_YAML.split("attribute_data")[0] + "attribute_data: {}\n")

        assert nb._try_update_module_type(curr_mt, record, "x.yaml") == (True, True)

        [stored_type] = server.collection("module_types")
        assert stored_type["profile"] == {"id": 3, "name": "Transceiver"}
        assert stored_type["attribute_data"] == {}

    def test_a_profile_only_change_drops_empty_old_attributes(self, netbox, server, definition):
        """A new profile can reject {} (required keys) but accepts no attributes, as on create."""
        nb, _ = netbox
        record = existing(server, {"id": 4, "name": "Fan"}, {})

        assert nb._try_update_module_type(definition(SFP_YAML.split("attribute_data")[0]), record, "x.yaml") == (
            True,
            True,
        )

        [stored_type] = server.collection("module_types")
        assert stored_type["profile"] == {"id": 3, "name": "Transceiver"}
        assert stored_type["attribute_data"] is None

    def test_an_unchanged_profile_keeps_attributes_the_yaml_omits(self, netbox, server, definition):
        nb, _ = netbox
        record = existing(server, {"id": 3, "name": "Transceiver"}, {**SFP_ATTRIBUTES, "reach": 300, "rpm": 3000})

        assert nb._try_update_module_type(definition(), record, "cisco/SFP-10G-SR.yaml") == (True, True)

        assert server.collection("module_types")[0]["attribute_data"] == {**SFP_ATTRIBUTES, "rpm": 3000}

    def test_an_unknown_profile_fails_the_module_type(self, netbox, server, definition):
        nb, console = netbox
        record = existing(server, {"id": 4, "name": "Fan"})
        curr_mt = definition(SFP_YAML.replace("profile: Transceiver", "profile: No Such Profile"))

        nb._process_single_module_type(
            curr_mt, "cisco/SFP-10G-SR.yaml", {"cisco": {"SFP-10G-SR": record}}, {}, only_new=False
        )

        failed = [r for r in nb.outcomes.records if r.outcome is Outcome.FAILED]
        assert [(r.kind, r.identity) for r in failed] == [(EntityKind.MODULE_TYPE, "Cisco/SFP-10G-SR")]
        assert any("No Such Profile" in line for line in console.lines)
        assert server.collection("module_types")[0]["profile"] == {"id": 4, "name": "Fan"}


class TestCreate:
    """A new module type carries its profile and attributes."""

    def test_attributes_are_sent_under_the_rest_field_name(self, netbox, server, definition):
        nb, _ = netbox

        nb._process_single_module_type(definition(), "cisco/SFP-10G-SR.yaml", {}, {}, only_new=False)

        [created] = server.sent("POST", "module_types")
        assert created["profile"] == {"name": "Transceiver"}
        assert created["attributes"] == SFP_ATTRIBUTES
        assert "attribute_data" not in created


class TestMalformedDefinition:
    """A profile or attribute_data of the wrong shape fails its own file at parse time, not the whole run."""

    BASE = "manufacturer: Cisco\nmodel: SFP-10G-SR\n"

    @pytest.mark.parametrize(
        "extra",
        [
            "profile: [Transceiver]\n",
            "profile:\n  id: 3\n",
            "profile:\n  name: [Transceiver]\n",
            "attribute_data: [phy]\n",
            "attribute_data: 10G\n",
            "attribute_data:\n  manufactured: 2026-10-16\n",
            "attribute_data:\n  rpm: .nan\n",
            "attribute_data:\n  rpm: .inf\n",
            "attribute_data:\n  1: fast\n",
            "attribute_data:\n  speeds:\n    1: fast\n",
            "profile:\n  name: Fan\n  id: 2026-10-16\n",
        ],
    )
    def test_the_file_is_rejected(self, tmp_path, extra):
        path = tmp_path / "bad.yaml"
        path.write_text(self.BASE + extra, encoding="utf-8")

        parsed = parse_single_file(str(path))

        assert isinstance(parsed, str)
        assert parsed.startswith("Error:")

    @pytest.mark.parametrize(
        ("extra", "profile"),
        [
            ("profile: null\nattribute_data: null\n", None),
            ("profile:\n  name: Transceiver\n", {"name": "Transceiver"}),
        ],
    )
    def test_null_and_a_named_mapping_are_accepted(self, netbox, server, tmp_path, extra, profile):
        nb, _ = netbox
        path = tmp_path / "ok.yaml"
        path.write_text(self.BASE + extra, encoding="utf-8")
        parsed = parse_single_file(str(path))

        assert parsed["profile"] == profile
        nb.filter_actionable_module_types([parsed], {"cisco": {"SFP-10G-SR": existing(server)}})
