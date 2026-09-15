"""Tests for module bay type reference resolution.

Driven through the public interface (``ids_for`` / ``identities_for``) against catalog files
the tests write themselves and a real ``pynetbox`` client talking HTTP to a local server.
Nothing here is mocked: the client serialises, filters and paginates for real, which is
where the semantics that matter actually live.
"""

import pytest
from helpers import FakeNetBox, write_module_bay_type

from core.module_bay_types import ModuleBayCatalogError, ModuleBayTypeCatalog, ModuleBayTypeError


class Handle:
    """Capture what the catalog logs."""

    def __init__(self):
        """Start with no recorded lines."""
        self.lines = []

    def log(self, message):
        """Record one line."""
        self.lines.append(message)

    def verbose_log(self, message):
        """Record one verbose line."""
        self.lines.append(message)


DEFAULT_MANUFACTURERS = (
    {"id": 1, "name": "Juniper", "slug": "juniper"},
    {"id": 2, "name": "Cisco", "slug": "cisco"},
    {"id": 3, "name": "Nokia", "slug": "nokia"},
)


@pytest.fixture
def library(tmp_path):
    """Write the catalog the resolution tests resolve against, and return its root.

    QSFP-DD is defined twice on purpose, by Juniper and by Generic, so the owner-scope
    rule has two candidates to choose between.
    """
    root = tmp_path / "library"
    write_module_bay_type(root, "Juniper", "mx304-re", "MX304-RE", "Juniper MX304 routing-engine slot compatibility")
    write_module_bay_type(root, "Juniper", "mx304-lmic", "MX304-LMIC", "Juniper MX304 LMIC slot compatibility")
    write_module_bay_type(root, "Juniper", "qsfp-dd", "QSFP-DD", "Juniper MX304 QSFP-DD cage")
    write_module_bay_type(root, "Generic", "qsfp-dd", "QSFP-DD", "QSFP-DD pluggable transceiver form factor")
    return root


@pytest.fixture
def catalog(library):
    """Build a catalog wired to a real pynetbox client and a local NetBox-shaped server."""
    servers = []

    def _make(module_bay_types=(), manufacturers=None, root=None):
        server = FakeNetBox(
            manufacturers=DEFAULT_MANUFACTURERS if manufacturers is None else manufacturers,
            module_bay_types=module_bay_types,
        )
        servers.append(server)
        return ModuleBayTypeCatalog(server.api(), str(root or library), Handle()), server

    yield _make
    for server in servers:
        server.close()


@pytest.mark.real_http
class TestResolution:
    """Names resolve to ids, in the owning manufacturer's scope and then in Generic."""

    def test_resolves_in_owner_manufacturer_scope(self, catalog):
        cat, server = catalog()
        ids = cat.ids_for("juniper", ["MX304-RE"])
        assert len(ids) == 1
        created = server.sent("POST", "module_bay_types")
        assert created == [
            {
                "name": "MX304-RE",
                "slug": "mx304-re",
                "manufacturer": 1,
                "description": "Juniper MX304 routing-engine slot compatibility",
            }
        ]

    def test_falls_back_to_generic_for_another_manufacturer(self, catalog):
        """A Cisco optic reaches the Generic form factor, and Generic is created on demand."""
        cat, server = catalog()
        assert len(cat.ids_for("cisco", ["QSFP-DD"])) == 1
        made = server.sent("POST", "manufacturers")
        assert made == [{"name": "Generic", "slug": "generic"}]

    def test_owner_scope_wins_over_generic(self, catalog):
        """Juniper and Generic both define QSFP-DD, and a Juniper reference means Juniper's."""
        cat, server = catalog()
        cat.ids_for("juniper", ["QSFP-DD"])
        created = server.sent("POST", "module_bay_types")
        assert [p["manufacturer"] for p in created] == [1]
        assert not server.sent("POST", "manufacturers")

    def test_existing_object_is_reused_not_recreated(self, catalog):
        cat, server = catalog(
            module_bay_types=[{"id": 77, "name": "MX304-RE", "slug": "mx304-re", "manufacturer": {"id": 1}}]
        )
        assert cat.ids_for("juniper", ["MX304-RE"]) == [77]
        assert not server.sent("POST", "module_bay_types")

    def test_repeated_resolution_is_cached(self, catalog):
        cat, server = catalog()
        first = cat.ids_for("juniper", ["MX304-RE"])
        before = len(server.requests)

        assert cat.ids_for("juniper", ["MX304-RE"]) == first
        assert len(first) == 1, "an empty result would make the request count meaningless"
        assert len(server.requests) == before

    def test_order_is_not_meaningful(self, catalog):
        cat, _ = catalog()
        a = cat.ids_for("juniper", ["MX304-RE", "MX304-LMIC"])
        b = cat.ids_for("juniper", ["MX304-LMIC", "MX304-RE"])
        assert len(a) == 2
        assert sorted(a) == sorted(b)


@pytest.mark.real_http
class TestRefusals:
    """An unresolved name and a conflicting identity are reported, never papered over."""

    def test_unresolved_name_raises_rather_than_dropping(self, catalog):
        cat, _ = catalog()
        with pytest.raises(ModuleBayTypeError) as exc:
            cat.ids_for("juniper", ["NO-SUCH-CLASS"])
        assert "NO-SUCH-CLASS" in str(exc.value)

    def test_same_name_different_slug_is_an_error_not_a_rename(self, catalog):
        """The catalog says mx304-re; NetBox holds mx304_re.  Never silently rename."""
        cat, server = catalog(
            module_bay_types=[{"id": 88, "name": "MX304-RE", "slug": "mx304_re", "manufacturer": {"id": 1}}]
        )
        with pytest.raises(ModuleBayTypeError) as exc:
            cat.ids_for("juniper", ["MX304-RE"])
        assert "mx304_re" in str(exc.value)
        assert "mx304-re" in str(exc.value)
        assert not server.sent("POST", "module_bay_types")


@pytest.mark.real_http
class TestCatalogReading:
    """The catalog is read from real files on disk, including the shapes that are rejected."""

    def test_entry_without_a_description_is_created_without_one(self, tmp_path, catalog):
        write_module_bay_type(tmp_path, "Generic", "sfp", "SFP")
        cat, server = catalog(root=tmp_path)
        cat.ids_for("generic", ["SFP"])
        created = server.sent("POST", "module_bay_types")
        generic = next(m for m in server.collection("manufacturers") if m["slug"] == "generic")
        assert created == [{"name": "SFP", "slug": "sfp", "manufacturer": generic["id"]}]

    def test_non_yaml_files_and_empty_documents_are_skipped(self, tmp_path, catalog):
        write_module_bay_type(tmp_path, "Generic", "sfp", "SFP")
        (tmp_path / "module-bay-types" / "Generic" / "README.md").write_text("not a catalog entry\n")
        (tmp_path / "module-bay-types" / "Generic" / "blank.yaml").write_text("# only a comment\n")
        cat, _ = catalog(root=tmp_path)
        assert len(cat.ids_for("generic", ["SFP"])) == 1

    def test_a_yaml_document_that_is_not_a_mapping_is_refused(self, tmp_path, catalog):
        """Silently skipping it shrinks the catalog, and a Generic entry then answers instead."""
        write_module_bay_type(tmp_path, "Generic", "sfp", "SFP")
        directory = tmp_path / "module-bay-types" / "Juniper"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "sfp.yaml").write_text("- name: SFP\n  slug: sfp\n", encoding="utf-8")
        cat, _ = catalog(root=tmp_path)

        with pytest.raises(ModuleBayCatalogError):
            cat.identities_for("Juniper", ["SFP"])

    def test_an_entry_missing_a_required_field_is_refused_at_load(self, tmp_path, catalog):
        """A half-written entry must fail as a catalog error, not as a KeyError mid-run."""
        directory = tmp_path / "module-bay-types" / "Generic"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "sfp.yaml").write_text("name: SFP\nmanufacturer: Generic\n", encoding="utf-8")
        cat, _ = catalog(root=tmp_path)

        with pytest.raises(ModuleBayCatalogError) as exc:
            cat.identities_for("generic", ["SFP"])
        assert "slug" in str(exc.value)
        assert "sfp.yaml" in str(exc.value)

    def test_unparseable_yaml_is_refused_as_a_catalog_error(self, tmp_path, catalog):
        """A parser error escaping the boundary ends the run before it reports anything."""
        directory = tmp_path / "module-bay-types" / "Generic"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "sfp.yaml").write_text("name: [\n", encoding="utf-8")
        cat, _ = catalog(root=tmp_path)

        with pytest.raises(ModuleBayCatalogError) as exc:
            cat.identities_for("generic", ["SFP"])
        assert "sfp.yaml" in str(exc.value)

    def test_a_broken_catalog_is_read_once_not_on_every_lookup(self, tmp_path, catalog, monkeypatch):
        """The load caches only on success, so a bad catalog re-walked the tree every time."""
        import core.module_bay_types as module

        write_module_bay_type(tmp_path, "Generic", "sfp", "SFP")
        write_module_bay_type(tmp_path, "Generic", "sfp-again", "SFP")
        cat, _ = catalog(root=tmp_path)

        walks = []
        real_walk = module.os.walk
        monkeypatch.setattr(module.os, "walk", lambda *a, **k: walks.append(1) or real_walk(*a, **k))

        for _ in range(3):
            with pytest.raises(ModuleBayCatalogError):
                cat.identities_for("generic", ["SFP"])
        assert len(walks) == 1

    def test_duplicate_scoped_entry_is_refused(self, tmp_path, catalog):
        """Two files claiming the same (manufacturer, name) would make a reference ambiguous."""
        write_module_bay_type(tmp_path, "Generic", "sfp", "SFP")
        write_module_bay_type(tmp_path, "Generic", "sfp-again", "SFP")
        cat, _ = catalog(root=tmp_path)
        with pytest.raises(ModuleBayCatalogError) as exc:
            cat.ids_for("generic", ["SFP"])
        assert "Duplicate" in str(exc.value)
        assert "SFP" in str(exc.value)


@pytest.mark.real_http
class TestMalformedReferences:
    """A reference list that is not a list of names is refused, never read as empty."""

    def test_a_bare_key_is_refused_rather_than_clearing(self, catalog):
        """`module_bay_types:` with no value parses as None; treating it as [] would clear."""
        cat, server = catalog()
        with pytest.raises(ModuleBayTypeError) as exc:
            cat.ids_for("juniper", None)
        assert "list of names" in str(exc.value)
        assert not server.sent("POST", "module_bay_types")
        assert not server.sent("POST", "manufacturers")

    def test_a_non_string_entry_is_refused(self, catalog):
        cat, _ = catalog()
        with pytest.raises(ModuleBayTypeError):
            cat.ids_for("juniper", [{"name": "MX304-RE"}])
        with pytest.raises(ModuleBayTypeError):
            cat.ids_for("juniper", ["MX304-RE", 7])
        with pytest.raises(ModuleBayTypeError):
            cat.ids_for("juniper", ["  "])

    def test_an_empty_list_is_allowed_and_holds_no_classes(self, catalog):
        """`module_bay_types: []` is an explicit instruction, not a malformed value."""
        cat, server = catalog()
        assert cat.ids_for("juniper", []) == []
        assert not server.sent("POST", "module_bay_types")
        assert not server.sent("POST", "manufacturers")

    def test_duplicate_names_collapse(self, catalog):
        """The relationship is a set, so a repeated name must not produce a repeated id."""
        cat, _ = catalog()
        once = cat.ids_for("juniper", ["MX304-RE"])

        assert len(once) == 1
        assert cat.ids_for("juniper", ["MX304-RE", "MX304-RE"]) == once


@pytest.mark.real_http
class TestACatalogFailureIsNotAPerComponentSkip:
    """A broken catalog is terminal for the run, but every caller recovers per component."""

    @staticmethod
    def _broken_catalog(tmp_path, catalog):
        root = tmp_path / "broken"
        write_module_bay_type(root, "Juniper", "mx304-re", "MX304-RE", "fine")
        # A half-written entry: the readers index on name and dereference slug.
        (root / "module-bay-types" / "Juniper" / "bad.yaml").write_text(
            "name: 123\nslug: bad\nmanufacturer: Juniper\n", encoding="utf-8"
        )
        return catalog(root=root)[0]

    def test_a_malformed_entry_is_not_reported_as_a_relation_change(self, tmp_path, catalog):
        """_relation_change recovers from ModuleBayTypeError, so a load failure must not be one."""
        from types import SimpleNamespace

        from core.change_detector import _relation_change
        from core.module_bay_types import ModuleBayCatalogError

        broken = self._broken_catalog(tmp_path, catalog)
        netbox_comp = SimpleNamespace(name="RE0", module_bay_types=[])

        with pytest.raises(ModuleBayCatalogError):
            _relation_change(
                "module_bay_types",
                {"name": "RE0", "module_bay_types": ["MX304-RE"]},
                netbox_comp,
                catalog=broken,
                manufacturer="Juniper",
            )

    def test_the_catalog_failure_is_not_a_module_bay_type_error(self, tmp_path, catalog):
        """Sibling, not subclass: an `except ModuleBayTypeError` must not swallow it."""
        from core.module_bay_types import ModuleBayCatalogError

        broken = self._broken_catalog(tmp_path, catalog)

        with pytest.raises(ModuleBayCatalogError) as caught:
            broken.identities_for("Juniper", ["MX304-RE"])

        assert not isinstance(caught.value, ModuleBayTypeError), "per-name catches would swallow it"

    def test_an_unresolved_name_is_still_a_recoverable_module_bay_type_error(self, catalog):
        """The split must not promote a per-name miss into a run-ending failure."""
        resolver, _server = catalog()

        with pytest.raises(ModuleBayTypeError):
            resolver.identities_for("Juniper", ["NOT-IN-CATALOG"])


@pytest.mark.real_http
class TestUnreadableCatalogDirectory:
    """os.walk swallows a directory it cannot read, which silently shrinks the catalog."""

    def test_an_unreadable_vendor_directory_is_not_silently_skipped(self, tmp_path, catalog):
        """The owner-scoped entry would vanish and the name would resolve to Generic instead."""
        import os

        if not hasattr(os, "geteuid"):
            pytest.skip("no POSIX ownership, so the permission bits mean nothing here")
        if os.geteuid() == 0:
            pytest.skip("root ignores the permission bits this test relies on")

        root = tmp_path / "library"
        write_module_bay_type(root, "Juniper", "qsfp-dd", "QSFP-DD", "the owner-scoped entry")
        write_module_bay_type(root, "Generic", "qsfp-dd", "QSFP-DD", "the fallback entry")
        vendor_dir = root / "module-bay-types" / "Juniper"
        os.chmod(vendor_dir, 0o000)
        try:
            resolver, _server = catalog(root=root)

            with pytest.raises(ModuleBayCatalogError):
                resolver.identities_for("Juniper", ["QSFP-DD"])
        finally:
            os.chmod(vendor_dir, 0o700)
