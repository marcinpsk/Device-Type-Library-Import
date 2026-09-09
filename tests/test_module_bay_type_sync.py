"""Tests for keeping module bay type assignments in sync with NetBox.

Resolving a reference name to an id is :mod:`core.module_bay_types` and is tested there.
This file covers the wiring around it: the relation a module type carries itself, the
component update path, and the gate that keeps the field off a server that predates it.

Both sides are real.  The catalog is written to disk and read by a real
``ModuleBayTypeCatalog``; a local HTTP server answers a real ``pynetbox`` client and the
real GraphQL client, so the payloads asserted on here are the ones that would go over the
wire.  Only the version handshake is stood in for, to fix the server release under test.
"""

import pynetbox
import pytest

from core.change_detector import ChangeType, ComponentChange, PropertyChange
from core.component_registry import BY_YAML_KEY
from core.graphql_client import NetBoxGraphQLClient
from core.module_bay_types import ModuleBayTypeCatalog
from core.netbox_api import DeviceTypes, NetBox
from core.outcomes import EntityKind, Outcome
from helpers import FakeNetBox, recording_handle, write_module_bay_type

# The suite patches requests.Session by default, which would stop every request below.
pytestmark = pytest.mark.real_http

JUNIPER = {"id": 1, "name": "Juniper", "slug": "juniper"}


def stub(**attrs):
    """Return an object carrying exactly *attrs*, the way NetBox nests a related object."""
    return type("Stub", (), attrs)()


def created_id(server, slug):
    """Return the id the server gave the module bay type it created for *slug*."""
    return next(record["id"] for record in server.collection("module_bay_types") if record["slug"] == slug)


def related(name, slug=None, manufacturer_slug=None):
    """Return a module bay type as NetBox returns it nested inside a relation."""
    return stub(name=name, slug=slug, manufacturer=stub(slug=manufacturer_slug))


class NetBoxRecord:
    """An existing NetBox object as the importer holds it: an id, plus what was fetched.

    A field the query did not ask for is genuinely absent, which is the difference the
    comparison turns on, so this carries only what a test hands it.
    """

    def __init__(self, record_id, **fields):
        """Store the id and the fields this record is meant to have."""
        self.id = record_id
        for name, value in fields.items():
            setattr(self, name, value)


@pytest.fixture
def catalog_root(tmp_path):
    """Write the catalog these tests resolve against and return its root."""
    root = tmp_path / "library"
    write_module_bay_type(root, "Juniper", "mx304-re", "MX304-RE", "Juniper MX304 routing-engine slot")
    write_module_bay_type(root, "Juniper", "mx304-lmic", "MX304-LMIC", "Juniper MX304 LMIC slot")
    return root


@pytest.fixture
def server():
    """Run a local NetBox-shaped server seeded with the manufacturers the catalog needs."""
    fake = FakeNetBox(manufacturers=[JUNIPER])
    yield fake
    fake.close()


@pytest.fixture
def make_device_types(server, catalog_root):
    """Build a real DeviceTypes talking to the local server, with its cache already primed."""

    def _make(module_bay_types_supported=True):
        handle, console = recording_handle()
        device_types = DeviceTypes(
            server.api(),
            handle,
            {},
            False,
            graphql=NetBoxGraphQLClient(server.url, "test-token", supports_module_bay_types=True),
            repo_path=str(catalog_root),
            module_bay_types_supported=module_bay_types_supported,
        )
        device_types.components.ensure_ready()
        return device_types, console

    return _make


@pytest.fixture
def netbox(make_config, mock_pynetbox, server, catalog_root):
    """Build a real NetBox against the local server, reporting the release that has the feature."""
    mock_pynetbox.api.return_value.version = "4.7"
    mock_pynetbox.RequestError = pynetbox.RequestError
    handle, console = recording_handle()
    config = make_config(netbox_url=server.url, repo_path=str(catalog_root))
    nb = NetBox(config, handle)
    assert nb.module_bay_types, "a 4.7 server supports module bay types; the rest of this file assumes it"

    # connect_api ran against the patched pynetbox; every call under test uses a real client.
    api = server.api()
    nb.netbox = api
    nb.device_types.netbox = api
    nb.device_types.components.netbox = api
    nb.device_types.components.ensure_ready()
    return nb, console


class TestModuleTypeOwnRelation:
    """A module type says which classes it belongs to, and that has to stay in sync."""

    def test_a_missing_class_is_reported_as_a_change(self, netbox):
        nb, _ = netbox
        existing = NetBoxRecord(7, module_bay_types=[])
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        assert nb._type_relation_changes(module_type, existing) == [("module_bay_types", [], ["MX304-RE"])]

    def test_the_right_class_is_left_alone(self, netbox):
        nb, _ = netbox
        existing = NetBoxRecord(7, module_bay_types=[related("MX304-RE", "mx304-re", "juniper")])
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        assert nb._type_relation_changes(module_type, existing) == []

    def test_the_same_name_from_the_wrong_scope_is_corrected(self, netbox):
        """Juniper owns MX304-RE. A Generic object of that name is not the one referenced."""
        nb, _ = netbox
        existing = NetBoxRecord(7, module_bay_types=[related("MX304-RE", "mx304-re", "generic")])
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        assert nb._type_relation_changes(module_type, existing) == [("module_bay_types", ["MX304-RE"], ["MX304-RE"])]

    def test_names_are_compared_when_netbox_returned_no_identity(self, netbox):
        """A record carrying only a name cannot answer the scope question; names still can."""
        nb, _ = netbox
        existing = NetBoxRecord(7, module_bay_types=[related("MX304-LMIC")])
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        assert nb._type_relation_changes(module_type, existing) == [("module_bay_types", ["MX304-LMIC"], ["MX304-RE"])]

    def test_an_unresolvable_reference_is_reported_even_when_the_name_matches(self, netbox):
        """A name that happens to match must not make an unresolvable reference look applied.

        Comparison cannot say which object the name means, so the write path has to try,
        fail, and refuse. Reporting no change here skips that entirely.
        """
        nb, _ = netbox
        existing = NetBoxRecord(7, module_bay_types=[related("NO-SUCH-CLASS", "no-such", "juniper")])
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["NO-SUCH-CLASS"]}

        assert nb._type_relation_changes(module_type, existing) == [
            ("module_bay_types", ["NO-SUCH-CLASS"], ["NO-SUCH-CLASS"])
        ]

    def test_a_matching_but_unresolvable_name_does_not_read_as_updated(self, netbox, server):
        """The end of that path: the module type is refused, not patched with its scalars."""
        nb, _ = netbox
        server.collection("module_types").append({"id": 7, "model": "JNP304-RE"})
        existing = NetBoxRecord(
            7,
            model="JNP304-RE",
            manufacturer=stub(name="Juniper"),
            module_bay_types=[related("NO-SUCH-CLASS", "no-such", "juniper")],
            description="old",
        )
        module_type = {
            "model": "JNP304-RE",
            "manufacturer": {"slug": "juniper"},
            "description": "new",
            "module_bay_types": ["NO-SUCH-CLASS"],
        }

        assert nb._try_update_module_type(module_type, existing, "juniper/jnp304-re.yaml") == (False, False)
        assert not server.sent("PATCH", "module_types")

    def test_a_field_the_query_did_not_return_is_skipped(self, netbox):
        """Reading an absent field as empty would report a change on every run."""
        nb, _ = netbox
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        assert nb._type_relation_changes(module_type, NetBoxRecord(7)) == []

    def test_an_omitted_key_leaves_the_relation_unmanaged(self, netbox):
        nb, _ = netbox
        existing = NetBoxRecord(7, module_bay_types=[related("MX304-RE", "mx304-re", "juniper")])

        assert nb._type_relation_changes({"model": "JNP304-RE"}, existing) == []

    def test_a_malformed_reference_leaves_the_relation_unmanaged(self, netbox):
        """A bare key parses as None; clearing on it would drop a restriction nobody removed."""
        nb, _ = netbox
        existing = NetBoxRecord(7, module_bay_types=[related("MX304-RE", "mx304-re", "juniper")])
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": None}

        assert nb._type_relation_changes(module_type, existing) == []

    def test_names_are_compared_when_the_definition_names_no_manufacturer(self, netbox):
        """Without an owning manufacturer there is no scope, so the name comparison stands."""
        nb, _ = netbox
        existing = NetBoxRecord(7, module_bay_types=[related("MX304-LMIC", "mx304-lmic", "juniper")])
        module_type = {"model": "JNP304-RE", "module_bay_types": ["MX304-RE"]}

        assert nb._type_relation_changes(module_type, existing) == [("module_bay_types", ["MX304-LMIC"], ["MX304-RE"])]

    def test_an_older_server_reports_no_relation_changes(self, netbox):
        """Below 4.7 the relation does not exist, so there is nothing to compare."""
        nb, _ = netbox
        nb.module_bay_types = False
        existing = NetBoxRecord(7, module_bay_types=[])
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        assert nb._type_relation_changes(module_type, existing) == []


class TestModuleTypeCreatePayload:
    """What the create path sends for a module type's own relation."""

    def test_names_are_replaced_by_ids(self, netbox, server):
        nb, _ = netbox
        payload = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        resolved = nb._resolve_type_relations(payload)

        created = server.sent("POST", "module_bay_types")
        assert [p["slug"] for p in created] == ["mx304-re"]
        assert resolved["module_bay_types"] == [created_id(server, "mx304-re")]
        assert resolved["model"] == "JNP304-RE"

    def test_a_payload_without_the_relation_is_untouched(self, netbox, server):
        nb, _ = netbox
        payload = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}}

        assert nb._resolve_type_relations(payload) == payload
        assert not server.sent("POST", "module_bay_types")

    def test_an_older_server_never_sees_the_field(self, netbox, server):
        """Sending a field the server does not have would fail the whole create."""
        nb, _ = netbox
        nb.module_bay_types = False
        payload = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        assert nb._resolve_type_relations(payload) == {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}}
        assert not server.sent("POST", "module_bay_types")


class TestModuleTypeUpdate:
    """The update path patches the relation, and survives one it cannot resolve."""

    def test_a_changed_relation_is_patched_as_ids(self, netbox, server):
        nb, _ = netbox
        server.collection("module_types").append({"id": 7, "model": "JNP304-RE"})
        existing = NetBoxRecord(7, model="JNP304-RE", manufacturer=stub(name="Juniper"), module_bay_types=[])
        module_type = {"model": "JNP304-RE", "manufacturer": {"slug": "juniper"}, "module_bay_types": ["MX304-RE"]}

        ok, updated = nb._try_update_module_type(module_type, existing, "juniper/jnp304-re.yaml")

        assert (ok, updated) == (True, True)
        assert server.sent("PATCH", "module_types") == [{"id": 7, "module_bay_types": [created_id(server, "mx304-re")]}]

    def test_an_unresolvable_reference_is_logged_and_the_run_goes_on(self, netbox, server):
        """One bad module type must not end the run, and must not be written without it."""
        nb, console = netbox
        server.collection("module_types").append({"id": 7, "model": "JNP304-RE"})
        existing = NetBoxRecord(7, model="JNP304-RE", manufacturer=stub(name="Juniper"), module_bay_types=[])
        module_type = {
            "model": "JNP304-RE",
            "manufacturer": {"slug": "juniper"},
            "module_bay_types": ["NO-SUCH-CLASS"],
        }

        ok, updated = nb._try_update_module_type(module_type, existing, "juniper/jnp304-re.yaml")

        assert (ok, updated) == (False, False), "an unapplied relation must not read as success"
        assert not server.sent("PATCH", "module_types")
        assert any("NO-SUCH-CLASS" in line for line in console.lines)

    def test_a_scalar_change_is_held_back_when_the_relation_cannot_resolve(self, netbox, server):
        """Patching the description while dropping the restriction is a half-applied write."""
        nb, console = netbox
        server.collection("module_types").append({"id": 7, "model": "JNP304-RE"})
        existing = NetBoxRecord(
            7,
            model="JNP304-RE",
            manufacturer=stub(name="Juniper"),
            module_bay_types=[],
            description="old",
        )
        module_type = {
            "model": "JNP304-RE",
            "manufacturer": {"slug": "juniper"},
            "description": "new",
            "module_bay_types": ["NO-SUCH-CLASS"],
        }

        ok, updated = nb._try_update_module_type(module_type, existing, "juniper/jnp304-re.yaml")

        assert (ok, updated) == (False, False)
        assert not server.sent("PATCH", "module_types"), "the scalar PATCH must not go out alone"
        assert any("NO-SUCH-CLASS" in line for line in console.lines)


class TestModuleTypeCreateRefusal:
    """A module type whose relation cannot be resolved is reported, not written without it."""

    def test_an_unresolvable_reference_skips_the_module_type(self, netbox, server):
        nb, console = netbox
        curr_mt = {
            "model": "JNP304-RE",
            "manufacturer": {"slug": "juniper"},
            "module_bay_types": ["NO-SUCH-CLASS"],
        }

        created = nb._process_single_module_type(curr_mt, "juniper/jnp304-re.yaml", {}, {}, only_new=False)

        assert created is False
        assert not server.sent("POST", "module_types")
        assert any("NO-SUCH-CLASS" in line for line in console.lines)
        # The registry is the only tally of failures; a path that merely logs is absent
        # from the run summary and from the itemised report.
        failed = [r for r in nb.outcomes.records if r.outcome is Outcome.FAILED]
        assert [(r.kind, r.identity) for r in failed] == [(EntityKind.MODULE_TYPE, "juniper/JNP304-RE")]
        assert "NO-SUCH-CLASS" in failed[0].reason


class TestModuleTypeUpdateOutcome:
    """The run summary must show the module type whose relation could not be applied."""

    def test_an_unresolvable_relation_is_recorded_as_a_failure(self, netbox, server):
        """Driven through the parent operation, because that is where the outcome is recorded."""
        nb, console = netbox
        server.collection("module_types").append({"id": 7, "model": "JNP304-RE"})
        existing = NetBoxRecord(
            7, model="JNP304-RE", manufacturer=stub(name="Juniper"), module_bay_types=[], description="old"
        )
        curr_mt = {
            "model": "JNP304-RE",
            "manufacturer": {"slug": "juniper"},
            "description": "new",
            "module_bay_types": ["NO-SUCH-CLASS"],
        }

        nb._process_single_module_type(
            curr_mt, "juniper/jnp304-re.yaml", {"juniper": {"JNP304-RE": existing}}, {}, only_new=False
        )

        failed = [r for r in nb.outcomes.records if r.outcome is Outcome.FAILED]
        assert [r.kind for r in failed] == [EntityKind.MODULE_TYPE], "the failure must reach the run summary"
        assert not server.sent("PATCH", "module_types"), "nothing may be written for a type it could not apply"
        assert any("NO-SUCH-CLASS" in line for line in console.lines)


class TestComponentCreatePayload:
    """A module bay is created with the restriction its definition asked for, or not at all."""

    def test_names_are_replaced_by_ids(self, make_device_types, server):
        device_types, _ = make_device_types()
        component = BY_YAML_KEY["module-bays"]
        items = [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC"]}]

        resolved = device_types._resolve_relations(component, items, {"slug": "juniper"})

        assert resolved == [{"name": "FPC 0", "module_bay_types": [created_id(server, "mx304-lmic")]}]

    def test_an_item_without_the_field_passes_through(self, make_device_types, server):
        device_types, _ = make_device_types()
        component = BY_YAML_KEY["module-bays"]
        items = [{"name": "FPC 0"}]

        assert device_types._resolve_relations(component, items, {"slug": "juniper"}) == items
        assert not server.sent("POST", "module_bay_types")

    def test_an_unresolvable_restriction_drops_the_bay_rather_than_relaxing_it(self, make_device_types, server):
        """Creating the bay without its restriction would silently accept any module."""
        device_types, console = make_device_types()
        component = BY_YAML_KEY["module-bays"]
        items = [
            {"name": "FPC 0", "module_bay_types": ["NO-SUCH-CLASS"]},
            {"name": "FPC 1", "module_bay_types": ["MX304-LMIC"]},
        ]

        with device_types.collect_component_errors() as collected:
            resolved = device_types._resolve_relations(component, items, {"slug": "juniper"})

        assert [item["name"] for item in resolved] == ["FPC 1"]
        # Collected, not just printed: the parent's outcome reason is built from these.
        assert [e for e in collected if "FPC 0" in e and "NO-SUCH-CLASS" in e]
        assert any("FPC 0" in line for line in console.lines)

    def test_an_older_server_never_sees_the_field(self, make_device_types, server):
        device_types, _ = make_device_types(module_bay_types_supported=False)
        component = BY_YAML_KEY["module-bays"]
        items = [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC"]}]

        assert device_types._resolve_relations(component, items, {"slug": "juniper"}) == [{"name": "FPC 0"}]
        assert not server.sent("POST", "module_bay_types")

    def test_a_netbox_rejection_skips_the_bay_instead_of_ending_the_run(self, make_device_types, server):
        """A 403 while resolving must not escape the per-component recovery.

        The callers recover from ModuleBayTypeError only, so a raw RequestError ends the
        run with a traceback and leaves a partly created parent behind.
        """
        device_types, _ = make_device_types()
        server.errors["module_bay_types"] = 403
        items = [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC"]}]

        with device_types.collect_component_errors() as collected:
            assert device_types._resolve_relations(BY_YAML_KEY["module-bays"], items, {"slug": "juniper"}) == []
        assert [e for e in collected if "FPC 0" in e and "403" in e]

    def test_a_lost_connection_skips_the_bay_instead_of_ending_the_run(self, make_device_types, server):
        """A dropped connection is not a RequestError, so it escaped the same recovery."""
        device_types, _ = make_device_types()
        server.close()  # the port stops answering; resolution now hits a refused connection
        items = [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC"]}]

        with device_types.collect_component_errors() as collected:
            assert device_types._resolve_relations(BY_YAML_KEY["module-bays"], items, {"slug": "juniper"}) == []
        assert [e for e in collected if "FPC 0" in e]

    def test_a_component_kind_with_no_relations_is_untouched(self, make_device_types):
        device_types, _ = make_device_types()
        items = [{"name": "xe-0/0/0", "type": "100gbase-x-qsfp28"}]

        assert device_types._resolve_relations(BY_YAML_KEY["interfaces"], items, {"slug": "juniper"}) == items

    def test_an_unknown_manufacturer_drops_the_bay_rather_than_sending_names(self, make_device_types):
        """Without a scope the names cannot become ids, and NetBox rejects raw names."""
        device_types, console = make_device_types()
        items = [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC"]}]

        assert device_types._resolve_relations(BY_YAML_KEY["module-bays"], items, None) == []
        assert any("FPC 0" in line for line in console.lines)

    def test_an_unknown_manufacturer_still_passes_through_a_bay_with_no_restriction(self, make_device_types):
        device_types, _ = make_device_types()
        items = [{"name": "FPC 0"}]

        assert device_types._resolve_relations(BY_YAML_KEY["module-bays"], items, None) == items

    def test_an_older_server_strips_the_field_even_without_a_manufacturer(self, make_device_types):
        """The manufacturer question must not decide whether an unsupported field is sent."""
        device_types, _ = make_device_types(module_bay_types_supported=False)
        items = [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC"]}]

        assert device_types._resolve_relations(BY_YAML_KEY["module-bays"], items, None) == [{"name": "FPC 0"}]


class TestComponentCreateWiring:
    """Through create_components(), so the resolution is proved to be wired in, not just present."""

    def test_a_created_bay_carries_resolved_ids(self, make_device_types, server):
        device_types, _ = make_device_types()
        device_types.components.record("module_bay_templates", "device", 3, {})

        device_types.create_components(
            "module-bays",
            [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC"]}],
            3,
            manufacturer={"slug": "juniper"},
        )

        posted = server.sent("POST", "module_bay_templates")
        assert [p["name"] for p in posted] == ["FPC 0"]
        assert posted[0]["module_bay_types"] == [created_id(server, "mx304-lmic")]

    def test_an_older_server_creates_the_bay_without_the_field(self, make_device_types, server):
        device_types, _ = make_device_types(module_bay_types_supported=False)
        device_types.components.record("module_bay_templates", "device", 3, {})

        device_types.create_components(
            "module-bays",
            [{"name": "FPC 0", "module_bay_types": ["MX304-LMIC"]}],
            3,
            manufacturer={"slug": "juniper"},
        )

        posted = server.sent("POST", "module_bay_templates")
        assert posted and "module_bay_types" not in posted[0]

    def test_an_unresolvable_bay_is_never_posted(self, make_device_types, server):
        device_types, _ = make_device_types()
        device_types.components.record("module_bay_templates", "device", 3, {})

        with device_types.collect_component_errors() as collected:
            device_types.create_components(
                "module-bays",
                [{"name": "FPC 0", "module_bay_types": ["NO-SUCH-CLASS"]}],
                3,
                manufacturer={"slug": "juniper"},
            )

        assert not server.sent("POST", "module_bay_templates")
        assert [e for e in collected if "FPC 0" in e]


class TestComponentUpdatePayload:
    """An existing bay whose restriction changed is patched with ids, not names."""

    @staticmethod
    def _change(name, new_value):
        return ComponentChange(
            component_type="module-bays",
            component_name=name,
            change_type=ChangeType.COMPONENT_CHANGED,
            property_changes=[PropertyChange(property_name="module_bay_types", old_value=[], new_value=new_value)],
        )

    def test_a_changed_restriction_is_patched_as_ids(self, make_device_types, server):
        device_types, _ = make_device_types()
        server.collection("module_bay_templates").append({"id": 55, "name": "FPC 0"})
        device_types.components.record("module_bay_templates", "device", 3, {"FPC 0": NetBoxRecord(55)})

        device_types._apply_updates_for_type(
            "module-bays", [self._change("FPC 0", ["MX304-LMIC"])], {"manufacturer": {"slug": "juniper"}}, 3, "device"
        )

        assert server.sent("PATCH", "module_bay_templates") == [
            {"id": 55, "module_bay_types": [created_id(server, "mx304-lmic")]}
        ]

    def test_a_rejected_patch_is_collected_rather_than_raised(self, make_device_types, server):
        """The bay resolves; NetBox refuses the write. That must land in the entity's report."""
        device_types, _ = make_device_types()
        server.collection("module_bay_templates").append({"id": 55, "name": "FPC 0"})
        device_types.components.record("module_bay_templates", "device", 3, {"FPC 0": NetBoxRecord(55)})
        server.errors["module_bay_templates"] = 400

        with device_types.collect_component_errors() as collected:
            device_types._apply_updates_for_type(
                "module-bays",
                [self._change("FPC 0", ["MX304-LMIC"])],
                {"manufacturer": {"slug": "juniper"}},
                3,
                "device",
            )

        assert [e for e in collected if "55" in e]

    def test_an_unresolvable_restriction_is_logged_and_nothing_is_patched(self, make_device_types, server):
        device_types, _ = make_device_types()
        server.collection("module_bay_templates").append({"id": 55, "name": "FPC 0"})
        device_types.components.record("module_bay_templates", "device", 3, {"FPC 0": NetBoxRecord(55)})

        with device_types.collect_component_errors() as collected:
            device_types._apply_updates_for_type(
                "module-bays",
                [self._change("FPC 0", ["NO-SUCH-CLASS"])],
                {"manufacturer": {"slug": "juniper"}},
                3,
                "device",
            )

        assert not server.sent("PATCH", "module_bay_templates")
        assert [e for e in collected if "FPC 0" in e and "NO-SUCH-CLASS" in e]


class TestCatalogWiring:
    """The catalog is built once per run, from the library checkout the run is using."""

    def test_the_catalog_is_built_from_the_repo_path_and_reused(self, make_device_types, catalog_root):
        device_types, _ = make_device_types()

        catalog = device_types.module_bay_types

        assert isinstance(catalog, ModuleBayTypeCatalog)
        assert device_types.module_bay_types is catalog
        assert catalog.identities_for("juniper", ["MX304-RE"]) == frozenset({("juniper", "mx304-re")})
