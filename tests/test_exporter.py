"""Tests for core/export.py — Exporter class."""

import pytest
from unittest.mock import MagicMock, patch
import yaml

from core.export import (
    ExportItem,
    Exporter,
    _canon_mfr_slug,
    _is_subset,
    _make_filename,
    _normalize_for_compare,
    _repo_supersedes,
    _sanitize_attachment_filename,
    _yaml_equal,
    _SKIP,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_settings(tmp_path):
    s = MagicMock()
    s.NETBOX_URL = "http://localhost:8000/"
    s.NETBOX_TOKEN = "test-token"
    s.IGNORE_SSL_ERRORS = False
    s.REPO_PATH = str(tmp_path / "repo")
    return s


def _make_handle():
    h = MagicMock()
    h.log = MagicMock()
    h.verbose = False
    return h


def _make_mfr(name="Nokia", slug="nokia"):
    m = MagicMock()
    m.name = name
    m.slug = slug
    return m


def _make_dt(
    id=1,
    model="7750-SR-7s",
    slug="nokia-7750-sr-7s",
    last_updated="2024-01-01T00:00:00Z",
    u_height=7,
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
):
    r = MagicMock()
    r.id = id
    r.model = model
    r.slug = slug
    r.last_updated = last_updated
    r.u_height = u_height
    r.is_full_depth = is_full_depth
    r.part_number = part_number
    r.airflow = airflow
    r.weight = weight
    r.weight_unit = weight_unit
    r.description = description
    r.comments = comments
    r.subdevice_role = subdevice_role
    r.front_image = front_image
    r.rear_image = rear_image
    r.manufacturer = _make_mfr()
    return r


def _make_mt(
    id=10,
    model="SFP-10G",
    last_updated="2024-01-01T00:00:00Z",
    part_number=None,
    airflow=None,
    weight=None,
    weight_unit=None,
    description="",
    comments="",
):
    r = MagicMock()
    r.id = id
    r.model = model
    r.last_updated = last_updated
    r.part_number = part_number
    r.airflow = airflow
    r.weight = weight
    r.weight_unit = weight_unit
    r.description = description
    r.comments = comments
    r.manufacturer = _make_mfr()
    return r


def _make_rt(
    id=20,
    model="Rack-42U",
    slug="rack-42u",
    last_updated="2024-01-01T00:00:00Z",
    form_factor="4-post-cabinet",
    description="",
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
):
    r = MagicMock()
    r.id = id
    r.model = model
    r.slug = slug
    r.last_updated = last_updated
    r.form_factor = form_factor
    r.description = description
    r.width = width
    r.u_height = u_height
    r.starting_unit = starting_unit
    r.outer_width = outer_width
    r.outer_height = outer_height
    r.outer_depth = outer_depth
    r.outer_unit = outer_unit
    r.mounting_depth = mounting_depth
    r.weight = weight
    r.max_weight = max_weight
    r.weight_unit = weight_unit
    r.desc_units = desc_units
    r.comments = comments
    r.manufacturer = _make_mfr()
    return r


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestMakeFilename:
    """Tests for _make_filename sanitizer."""

    def test_spaces_replaced_with_dashes(self):
        assert _make_filename("10622 G2") == "10622-G2"

    def test_forward_slash_replaced(self):
        assert _make_filename("PS-7220-IXR-D2/D3-AC-B2F") == "PS-7220-IXR-D2-D3-AC-B2F"

    def test_back_slash_replaced(self):
        assert _make_filename("model\\sub") == "model-sub"

    def test_consecutive_dashes_collapsed(self):
        assert _make_filename("A / B") == "A-B"

    def test_leading_trailing_dashes_stripped(self):
        assert _make_filename("/leading-slash") == "leading-slash"

    def test_no_change_for_clean_model(self):
        assert _make_filename("7750-SR-7s") == "7750-SR-7s"

    def test_case_preserved(self):
        assert _make_filename("7220 IXR-D2L 25/100GE") == "7220-IXR-D2L-25-100GE"


class TestNormalizeForCompare:
    """Tests for _normalize_for_compare function."""

    def test_float_int_coercion(self):
        result = _normalize_for_compare({"u_height": 1.0, "weight": 2.5})
        assert result["u_height"] == 1
        assert isinstance(result["u_height"], int)
        assert result["weight"] == 2.5

    def test_empty_string_becomes_none(self):
        result = _normalize_for_compare({"description": ""})
        assert result["description"] is None

    def test_nested_list_normalized(self):
        result = _normalize_for_compare({"interfaces": [{"positions": 1.0}]})
        assert result["interfaces"][0]["positions"] == 1
        assert isinstance(result["interfaces"][0]["positions"], int)

    def test_named_component_lists_sorted_for_comparison(self):
        """Components with 'name' field compare equal regardless of order."""
        a = {"interfaces": [{"name": "c1"}, {"name": "c2"}, {"name": "c10"}]}
        b = {"interfaces": [{"name": "c10"}, {"name": "c1"}, {"name": "c2"}]}
        assert _normalize_for_compare(a) == _normalize_for_compare(b)

    def test_lists_without_name_field_not_reordered(self):
        """Plain lists (e.g. of strings) keep their order."""
        a = _normalize_for_compare({"x": [3, 1, 2]})
        assert a["x"] == [3, 1, 2]


class TestYamlEqual:
    """Tests for _yaml_equal helper."""

    def test_yaml_equal_normalizes_component_order_and_numbers(self):
        left = {"interfaces": [{"name": "b", "positions": 1.0}, {"name": "a", "positions": 2.0}]}
        right = {"interfaces": [{"name": "a", "positions": 2}, {"name": "b", "positions": 1}]}
        assert _yaml_equal(left, right) is True


class TestRepoSupersedes:
    """Tests for _repo_supersedes / _is_subset (asymmetric containment)."""

    def test_equal_dicts(self):
        repo = {"manufacturer": "Nokia", "model": "X", "u_height": 1}
        nb = {"manufacturer": "Nokia", "model": "X", "u_height": 1}
        assert _repo_supersedes(repo, nb) is True

    def test_repo_has_extra_field(self):
        """Repo carries 'profile' that NB lacks → repo is superset → suppress."""
        repo = {"manufacturer": "Nokia", "model": "X", "profile": "psu"}
        nb = {"manufacturer": "Nokia", "model": "X"}
        assert _repo_supersedes(repo, nb) is True

    def test_nb_has_extra_field(self):
        """NB carries 'comments' that repo lacks → NOT a superset → export."""
        repo = {"manufacturer": "Nokia", "model": "X"}
        nb = {"manufacturer": "Nokia", "model": "X", "comments": "datasheet"}
        assert _repo_supersedes(repo, nb) is False

    def test_value_differs(self):
        repo = {"manufacturer": "Nokia", "model": "7750-SR-7s"}
        nb = {"manufacturer": "Nokia", "model": "7750 SR-7s"}
        assert _repo_supersedes(repo, nb) is False

    def test_named_component_match_by_name(self):
        """Each NB component must be in repo (by name) with equal fields."""
        repo = {
            "interfaces": [
                {"name": "eth0", "type": "1000base-t"},
                {"name": "eth1", "type": "1000base-t"},
            ]
        }
        nb = {"interfaces": [{"name": "eth0", "type": "1000base-t"}]}
        assert _repo_supersedes(repo, nb) is True

    def test_repo_component_has_extra_field(self):
        """Per-component extras in repo (e.g. 'label') don't trigger export."""
        repo = {"interfaces": [{"name": "eth0", "type": "1000base-t", "label": "WAN"}]}
        nb = {"interfaces": [{"name": "eth0", "type": "1000base-t"}]}
        assert _repo_supersedes(repo, nb) is True

    def test_nb_component_value_differs(self):
        repo = {"interfaces": [{"name": "eth0", "type": "1000base-t"}]}
        nb = {"interfaces": [{"name": "eth0", "type": "10gbase-t"}]}
        assert _repo_supersedes(repo, nb) is False

    def test_nb_has_extra_component(self):
        repo = {"interfaces": [{"name": "eth0", "type": "1000base-t"}]}
        nb = {
            "interfaces": [
                {"name": "eth0", "type": "1000base-t"},
                {"name": "eth1", "type": "1000base-t"},
            ]
        }
        assert _repo_supersedes(repo, nb) is False

    def test_is_subset_with_floats(self):
        """Numeric normalization applies (33 vs 33.0)."""
        assert _is_subset(_normalize_for_compare({"weight": 33}), _normalize_for_compare({"weight": 33.0})) is True

    def test_is_subset_returns_false_when_sub_list_sup_is_not_list(self):
        assert _is_subset([1, 2], {"not": "a-list"}) is False

    def test_is_subset_returns_false_when_sub_is_dict_sup_is_not_dict(self):
        """Branch: sub is dict but sup is a scalar or list."""
        assert _is_subset({"key": "val"}, "not-a-dict") is False
        assert _is_subset({"key": "val"}, [1, 2]) is False

    def test_is_subset_positional_lists_require_exact_equality(self):
        assert _is_subset([1, 2], [1, 2]) is True

    # ── manufacturer normalization ──────────────────────────────────────────

    def test_repo_dict_mfr_supersedes_nb_slug_string(self):
        """Repo with dict-form manufacturer must compare equal to NB plain slug.

        Before the fix, {name: Nokia, slug: nokia} vs "nokia" was never a
        subset because _is_subset(str, dict) falls through to str == dict.
        """
        repo = {"manufacturer": {"name": "Nokia", "slug": "nokia"}, "model": "X"}
        nb = {"manufacturer": "nokia", "model": "X"}
        assert _repo_supersedes(repo, nb) is True

    def test_repo_capitalised_slug_dict_normalised(self):
        """Capitalized slug value in repo YAML must still match NB string."""
        repo = {"manufacturer": {"slug": "Nokia"}, "model": "X"}
        nb = {"manufacturer": "nokia", "model": "X"}
        assert _repo_supersedes(repo, nb) is True

    def test_repo_name_only_dict_mfr_normalised(self):
        """Dict with only 'name' key is slugified and matches NB slug string."""
        repo = {"manufacturer": {"name": "Cisco Systems"}, "model": "X"}
        nb = {"manufacturer": "cisco-systems", "model": "X"}
        assert _repo_supersedes(repo, nb) is True


class TestCanonMfrSlug:
    """Unit tests for the _canon_mfr_slug helper."""

    def test_plain_string_lowercased(self):
        assert _canon_mfr_slug("Nokia") == "nokia"

    def test_slug_key_normalised(self):
        assert _canon_mfr_slug({"slug": "Nokia"}) == "nokia"

    def test_name_key_slugified(self):
        assert _canon_mfr_slug({"name": "Cisco Systems"}) == "cisco-systems"

    def test_slug_preferred_over_name(self):
        assert _canon_mfr_slug({"slug": "cisco", "name": "Cisco Systems"}) == "cisco"

    def test_unknown_type_returns_empty(self):
        assert _canon_mfr_slug(42) == ""
        assert _canon_mfr_slug(None) == ""

    def test_empty_dict_returns_empty(self):
        assert _canon_mfr_slug({}) == ""


class TestExporterDirWritable:
    """Tests for export directory writability checks."""

    def test_raises_when_dir_not_writable(self, tmp_path, mocker):
        settings = _make_settings(tmp_path)
        export_dir = tmp_path / "export"
        export_dir.mkdir()
        mocker.patch("os.access", return_value=False)
        exporter = Exporter(settings, _make_handle(), str(export_dir), False, None)
        with pytest.raises(PermissionError, match="not writable"):
            exporter._verify_export_dir_writable()

    def test_creates_dir_if_missing(self, tmp_path):
        settings = _make_settings(tmp_path)
        export_dir = tmp_path / "export" / "new"
        exporter = Exporter(settings, _make_handle(), str(export_dir), False, None)
        exporter._verify_export_dir_writable()
        assert export_dir.exists()


class TestDetermineExportSet:
    """Test the three export triggers."""

    def _setup_exporter(self, tmp_path):
        settings = _make_settings(tmp_path)
        (tmp_path / "repo").mkdir(parents=True)
        return Exporter(settings, _make_handle(), str(tmp_path / "extra"), False, None)

    def test_absent_from_repo_triggers_export(self, tmp_path):
        exporter = self._setup_exporter(tmp_path)
        dt = _make_dt()
        items = exporter._determine_export_set_for_device_types(
            nb_records=[dt],
            repo_dt_by_slug={},
            components_by_dt_id={},
        )
        assert len(items) == 1
        assert items[0].reason == "absent"

    def test_matching_yaml_not_exported(self, tmp_path):
        exporter = self._setup_exporter(tmp_path)
        dt = _make_dt()
        from core.nb_serializer import serialize_device_type

        repo_yaml = serialize_device_type(dt, {})
        items = exporter._determine_export_set_for_device_types(
            nb_records=[dt],
            repo_dt_by_slug={("nokia", dt.slug): repo_yaml},
            components_by_dt_id={},
        )
        assert len(items) == 0

    def test_differs_from_repo_triggers_export(self, tmp_path):
        exporter = self._setup_exporter(tmp_path)
        dt = _make_dt(u_height=7)
        repo_yaml = {
            "manufacturer": {"slug": "nokia"},
            "model": dt.model,
            "slug": dt.slug,
            "u_height": 9,
            "is_full_depth": True,
        }
        items = exporter._determine_export_set_for_device_types(
            nb_records=[dt],
            repo_dt_by_slug={("nokia", dt.slug): repo_yaml},
            components_by_dt_id={},
        )
        assert len(items) == 1
        assert items[0].reason == "differs"

    def test_images_missing_locally_triggers_export(self, tmp_path):
        exporter = self._setup_exporter(tmp_path)
        dt = _make_dt(front_image="/media/devicetype-images/nokia-7750-sr-7s.front.png")
        from core.nb_serializer import serialize_device_type

        repo_yaml = serialize_device_type(dt, {})
        # Do NOT create the image file — it's missing
        items = exporter._determine_export_set_for_device_types(
            nb_records=[dt],
            repo_dt_by_slug={("nokia", dt.slug): repo_yaml},
            components_by_dt_id={},
        )
        assert len(items) == 1
        assert items[0].reason == "images-missing"

    def test_images_present_not_exported(self, tmp_path):
        exporter = self._setup_exporter(tmp_path)
        dt = _make_dt(front_image="/media/devicetype-images/nokia-7750-sr-7s.front.png")
        from core.nb_serializer import serialize_device_type

        repo_yaml = serialize_device_type(dt, {})
        # Create the image file
        img_dir = tmp_path / "repo" / "elevation-images" / "Nokia"
        img_dir.mkdir(parents=True)
        (img_dir / "nokia-7750-sr-7s.front.png").write_bytes(b"PNG")
        items = exporter._determine_export_set_for_device_types(
            nb_records=[dt],
            repo_dt_by_slug={("nokia", dt.slug): repo_yaml},
            components_by_dt_id={},
        )
        assert len(items) == 0

    def test_slug_collision_across_manufacturers_resolved_correctly(self, tmp_path):
        """Two DTs with the same slug but different manufacturers must each match their own repo YAML."""
        exporter = self._setup_exporter(tmp_path)

        shared_slug = "shared-model-x1"

        dt_nokia = _make_dt(id=1, model="Model-X1", slug=shared_slug)
        dt_nokia.manufacturer = _make_mfr(name="Nokia", slug="nokia")

        dt_acme = _make_dt(id=2, model="Model-X1", slug=shared_slug)
        dt_acme.manufacturer = _make_mfr(name="Acme", slug="acme")

        from core.nb_serializer import serialize_device_type

        nokia_repo_yaml = serialize_device_type(dt_nokia, {})
        # Acme YAML differs (u_height 99) so it should trigger "differs"
        acme_repo_yaml = {
            "manufacturer": {"slug": "acme"},
            "model": dt_acme.model,
            "slug": dt_acme.slug,
            "u_height": 99,
            "is_full_depth": True,
        }

        repo_dt_by_slug = {
            ("nokia", shared_slug): nokia_repo_yaml,
            ("acme", shared_slug): acme_repo_yaml,
        }

        items = exporter._determine_export_set_for_device_types(
            nb_records=[dt_nokia, dt_acme],
            repo_dt_by_slug=repo_dt_by_slug,
            components_by_dt_id={},
        )

        # Nokia matches exactly → no export; Acme differs → export with reason "differs"
        assert len(items) == 1
        assert items[0].reason == "differs"
        assert items[0].nb_record.id == dt_acme.id


class TestWriteYaml:
    """Tests for YAML file writing with overwrite guards."""

    def test_writes_new_file(self, tmp_path):
        settings = _make_settings(tmp_path)
        exporter = Exporter(settings, _make_handle(), str(tmp_path / "extra"), False, None)
        dest = tmp_path / "extra" / "device-types" / "Nokia" / "test.yaml"
        exporter._write_yaml(dest, {"model": "Test", "u_height": 1})
        assert dest.exists()
        loaded = yaml.safe_load(dest.read_text())
        assert loaded["model"] == "Test"

    def test_overwrite_guard_blocks_changed_file(self, tmp_path):
        settings = _make_settings(tmp_path)
        exporter = Exporter(settings, _make_handle(), str(tmp_path / "extra"), force_overwrite=False, vendor_slugs=None)
        dest = tmp_path / "extra" / "device-types" / "Nokia" / "test.yaml"
        dest.parent.mkdir(parents=True)
        dest.write_text(yaml.dump({"model": "Old"}))
        result = exporter._write_yaml(dest, {"model": "New"})
        assert result is False  # blocked
        assert yaml.safe_load(dest.read_text())["model"] == "Old"

    def test_force_overwrite_allows_changed_file(self, tmp_path):
        settings = _make_settings(tmp_path)
        exporter = Exporter(settings, _make_handle(), str(tmp_path / "extra"), force_overwrite=True, vendor_slugs=None)
        dest = tmp_path / "extra" / "device-types" / "Nokia" / "test.yaml"
        dest.parent.mkdir(parents=True)
        dest.write_text(yaml.dump({"model": "Old"}))
        result = exporter._write_yaml(dest, {"model": "New"})
        assert result is True
        assert yaml.safe_load(dest.read_text())["model"] == "New"


class TestManifestConsistency:
    """Tests for manifest update consistency during image downloads."""

    def test_manifest_not_updated_when_image_download_fails(self, tmp_path):
        """When images fail to download, manifest entry should NOT be updated."""
        from core.export_manifest import load_manifest

        settings = _make_settings(tmp_path)
        (tmp_path / "repo").mkdir(parents=True)
        export_dir = tmp_path / "extra"
        exporter = Exporter(settings, _make_handle(), str(export_dir), False, None)
        # Patch _download_image to simulate failure (returns None)
        exporter._download_image = MagicMock(return_value=None)
        # Patch graphql to return a single device type
        dt = _make_dt(front_image="/media/img/nokia-7750-sr-7s.front.png")
        exporter.graphql.get_device_types = MagicMock(return_value=({("nokia", dt.model): dt}, {dt.slug: dt}))
        exporter.graphql.get_module_types = MagicMock(return_value={})
        exporter.graphql.get_rack_types = MagicMock(return_value={})
        exporter.graphql.get_component_templates = MagicMock(return_value=[])
        exporter.run()
        # Manifest should NOT have an entry for this item (images failed)
        manifest = load_manifest(export_dir / ".export-manifest.json")
        assert "Nokia/nokia-7750-sr-7s" not in manifest.get("device-types", {})

    def test_manifest_updated_when_first_image_skipped_second_succeeds(self, tmp_path):
        """First image returns _SKIP (already exists), second returns hash → ok=True → manifest updated."""
        from core.export_manifest import load_manifest

        settings = _make_settings(tmp_path)
        (tmp_path / "repo").mkdir(parents=True)
        export_dir = tmp_path / "extra"
        exporter = Exporter(settings, _make_handle(), str(export_dir), False, None)
        # First call: _SKIP (already exists); second call: hash string (success)
        exporter._download_image = MagicMock(side_effect=[_SKIP, "abc123hash"])
        dt = _make_dt(
            front_image="/media/img/nokia-7750-sr-7s.front.png",
            rear_image="/media/img/nokia-7750-sr-7s.rear.png",
        )
        exporter.graphql.get_device_types = MagicMock(return_value=({("nokia", dt.model): dt}, {dt.slug: dt}))
        exporter.graphql.get_module_types = MagicMock(return_value={})
        exporter.graphql.get_rack_types = MagicMock(return_value={})
        exporter.graphql.get_component_templates = MagicMock(return_value=[])
        exporter.run()
        manifest = load_manifest(export_dir / ".export-manifest.json")
        assert "Nokia/nokia-7750-sr-7s" in manifest.get("device-types", {})

    def test_manifest_not_updated_when_first_succeeds_second_fails(self, tmp_path):
        """First image returns hash (success), second returns None (failure) → ok=False → manifest NOT updated."""
        from core.export_manifest import load_manifest

        settings = _make_settings(tmp_path)
        (tmp_path / "repo").mkdir(parents=True)
        export_dir = tmp_path / "extra"
        exporter = Exporter(settings, _make_handle(), str(export_dir), False, None)
        # First call: hash (success); second call: None (failure)
        exporter._download_image = MagicMock(side_effect=["abc123hash", None])
        dt = _make_dt(
            front_image="/media/img/nokia-7750-sr-7s.front.png",
            rear_image="/media/img/nokia-7750-sr-7s.rear.png",
        )
        exporter.graphql.get_device_types = MagicMock(return_value=({("nokia", dt.model): dt}, {dt.slug: dt}))
        exporter.graphql.get_module_types = MagicMock(return_value={})
        exporter.graphql.get_rack_types = MagicMock(return_value={})
        exporter.graphql.get_component_templates = MagicMock(return_value=[])
        exporter.run()
        manifest = load_manifest(export_dir / ".export-manifest.json")
        assert "Nokia/nokia-7750-sr-7s" not in manifest.get("device-types", {})


class TestWriteYamlEdgeCases:
    """Edge cases for _write_yaml with corrupted or identical files."""

    def test_corrupted_existing_file_force_overwrites(self, tmp_path):
        settings = _make_settings(tmp_path)
        exporter = Exporter(settings, _make_handle(), str(tmp_path / "extra"), force_overwrite=True, vendor_slugs=None)
        dest = tmp_path / "extra" / "Nokia" / "test.yaml"
        dest.parent.mkdir(parents=True)
        dest.write_bytes(b"\xff\xfe invalid utf-8")  # corrupted file
        result = exporter._write_yaml(dest, {"model": "Test"})
        assert result is True
        assert yaml.safe_load(dest.read_text())["model"] == "Test"

    def test_corrupted_existing_file_no_force_blocks(self, tmp_path):
        settings = _make_settings(tmp_path)
        exporter = Exporter(settings, _make_handle(), str(tmp_path / "extra"), force_overwrite=False, vendor_slugs=None)
        dest = tmp_path / "extra" / "Nokia" / "test.yaml"
        dest.parent.mkdir(parents=True)
        dest.write_bytes(b"\xff\xfe invalid utf-8")  # corrupted file
        result = exporter._write_yaml(dest, {"model": "Test"})
        assert result is False  # blocked — treat corrupted file as different content


class TestModuleTypeExport:
    """Tests for module type export set determination."""

    def test_absent_module_type_triggers_export(self, tmp_path):
        settings = _make_settings(tmp_path)
        (tmp_path / "repo").mkdir(parents=True)
        exporter = Exporter(settings, _make_handle(), str(tmp_path / "extra"), False, None)
        mt = MagicMock()
        mt.id = 10
        mt.model = "SFP-10G"
        mt.last_updated = "2024-01-01T00:00:00Z"
        mt.part_number = None
        mt.airflow = None
        mt.weight = None
        mt.weight_unit = None
        mt.description = ""
        mt.comments = ""
        mt.manufacturer = _make_mfr()
        items = exporter._determine_export_set_for_module_types(
            nb_records=[mt],
            repo_mt_by_key={},
            components_by_mt_id={},
        )
        assert len(items) == 1
        assert items[0].reason == "absent"
        assert items[0].kind == "module-type"


class TestVendorDirSlugNormalization:
    """Tests for Exporter._vendor_dirs slug-based directory matching."""

    def _make_exporter(self, tmp_path, vendor_slugs):
        settings = _make_settings(tmp_path)
        return Exporter(settings, _make_handle(), str(tmp_path / "extra"), False, vendor_slugs)

    def test_single_word_dir_matches_slug(self, tmp_path):
        root = tmp_path / "device-types"
        (root / "Nokia").mkdir(parents=True)
        exporter = self._make_exporter(tmp_path, ["nokia"])
        dirs = list(exporter._vendor_dirs(root))
        assert len(dirs) == 1
        assert dirs[0].name == "Nokia"

    def test_multi_word_dir_matches_hyphenated_slug(self, tmp_path):
        """'Extreme Networks' dir must match slug 'extreme-networks'."""
        root = tmp_path / "device-types"
        (root / "Extreme Networks").mkdir(parents=True)
        exporter = self._make_exporter(tmp_path, ["extreme-networks"])
        dirs = list(exporter._vendor_dirs(root))
        assert len(dirs) == 1
        assert dirs[0].name == "Extreme Networks"

    def test_non_matching_vendor_excluded(self, tmp_path):
        root = tmp_path / "device-types"
        (root / "Nokia").mkdir(parents=True)
        (root / "Juniper").mkdir(parents=True)
        exporter = self._make_exporter(tmp_path, ["nokia"])
        dirs = list(exporter._vendor_dirs(root))
        assert len(dirs) == 1
        assert dirs[0].name == "Nokia"

    def test_no_filter_yields_all_dirs(self, tmp_path):
        root = tmp_path / "device-types"
        (root / "Nokia").mkdir(parents=True)
        (root / "Extreme Networks").mkdir(parents=True)
        exporter = self._make_exporter(tmp_path, None)
        names = {d.name for d in exporter._vendor_dirs(root)}
        assert names == {"Nokia", "Extreme Networks"}

    def test_nonexistent_root_yields_nothing(self, tmp_path):
        root = tmp_path / "does-not-exist"
        exporter = self._make_exporter(tmp_path, None)
        assert list(exporter._vendor_dirs(root)) == []


class TestExporterAdditionalCoverage:
    """Additional coverage tests for Exporter internals."""

    def _make_exporter(self, tmp_path, force_overwrite=False):
        settings = _make_settings(tmp_path)
        (tmp_path / "repo").mkdir(parents=True, exist_ok=True)
        return Exporter(settings, _make_handle(), str(tmp_path / "extra"), force_overwrite, None)

    def test_get_module_image_details_is_cached(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        exporter.graphql.get_module_type_image_details = MagicMock(return_value={1: {}})

        assert exporter._get_module_image_details() == {1: {}}
        assert exporter._get_module_image_details() == {1: {}}
        exporter.graphql.get_module_type_image_details.assert_called_once()

    def test_load_repo_device_types_skips_bad_yaml(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        vdir = tmp_path / "repo" / "device-types" / "Nokia"
        vdir.mkdir(parents=True)
        (vdir / "good.yaml").write_text("slug: good-slug\nmodel: Good\n", encoding="utf-8")
        (vdir / "bad.yaml").write_text("foo: [\n", encoding="utf-8")

        assert exporter._load_repo_device_types() == {("nokia", "good-slug"): {"slug": "good-slug", "model": "Good"}}

    def test_load_repo_module_types_accepts_dict_and_string_manufacturers(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        vdir = tmp_path / "repo" / "module-types" / "Nokia"
        vdir.mkdir(parents=True)
        (vdir / "named.yaml").write_text("manufacturer:\n  name: Nokia\nmodel: M1\n", encoding="utf-8")
        (vdir / "slugged.yaml").write_text("manufacturer:\n  slug: nokia\nmodel: M2\n", encoding="utf-8")
        (vdir / "string.yaml").write_text("manufacturer: Nokia\nmodel: M3\n", encoding="utf-8")
        (vdir / "bad.yaml").write_text("manufacturer: [\n", encoding="utf-8")

        result = exporter._load_repo_module_types()

        assert ("nokia", "M1") in result
        assert ("nokia", "M2") in result
        assert ("nokia", "M3") in result

    def test_load_repo_rack_types_accepts_dict_and_string_manufacturers(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        vdir = tmp_path / "repo" / "rack-types" / "Nokia"
        vdir.mkdir(parents=True)
        (vdir / "named.yaml").write_text("manufacturer:\n  name: Nokia\nmodel: R1\n", encoding="utf-8")
        (vdir / "slugged.yaml").write_text("manufacturer:\n  slug: nokia\nmodel: R2\n", encoding="utf-8")
        (vdir / "string.yaml").write_text("manufacturer: Nokia\nmodel: R3\n", encoding="utf-8")
        (vdir / "bad.yaml").write_text("manufacturer: [\n", encoding="utf-8")

        result = exporter._load_repo_rack_types()

        assert ("nokia", "R1") in result
        assert ("nokia", "R2") in result
        assert ("nokia", "R3") in result

    def test_fetch_vendor_components_groups_device_and_module_records(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        dt_rec = MagicMock()
        dt_rec.device_type = MagicMock(id=11)
        dt_rec.module_type = None
        mt_rec = MagicMock()
        mt_rec.device_type = None
        mt_rec.module_type = MagicMock(id=22)

        def _side_effect(endpoint_name, manufacturer_slug=None):
            return [dt_rec, mt_rec] if endpoint_name == "interface_templates" else []

        mock_client = MagicMock()
        mock_client.get_component_templates.side_effect = _side_effect
        with patch("core.export.NetBoxGraphQLClient", return_value=mock_client):
            dt_result, mt_result = exporter._fetch_vendor_components("nokia")

        assert dt_result[11]["interface_templates"] == [dt_rec]
        assert mt_result[22]["interface_templates"] == [mt_rec]

    def test_determine_export_set_for_module_types_differs_and_superseded(self, tmp_path):
        from core.nb_serializer import serialize_module_type

        exporter = self._make_exporter(tmp_path)
        mt = _make_mt(part_number="NEW")

        differs = exporter._determine_export_set_for_module_types(
            nb_records=[mt],
            repo_mt_by_key={("nokia", mt.model): {"manufacturer": "Nokia", "model": mt.model, "part_number": "OLD"}},
            components_by_mt_id={},
        )
        superseded = exporter._determine_export_set_for_module_types(
            nb_records=[mt],
            repo_mt_by_key={("nokia", mt.model): {**serialize_module_type(mt, {}), "profile": "extra"}},
            components_by_mt_id={},
        )

        assert differs[0].reason == "differs"
        assert superseded == []

    def test_module_type_slug_only_manufacturer_treated_as_present(self, tmp_path):
        """Regression: repo YAML with manufacturer: {slug: nokia} must not cause duplicate export.

        The loader stores keys as (mfr_slug, model); the lookup uses rec.manufacturer.slug.
        Prior to the fix the loader used mfr_name ("Nokia") for {name:} entries but the
        raw slug string ("nokia") for {slug:}-only entries, causing a mismatch.
        """
        from core.nb_serializer import serialize_module_type

        exporter = self._make_exporter(tmp_path)
        mt = _make_mt()
        repo_yaml = serialize_module_type(mt, {})

        items = exporter._determine_export_set_for_module_types(
            nb_records=[mt],
            repo_mt_by_key={("nokia", mt.model): repo_yaml},
            components_by_mt_id={},
        )

        assert items == [], "module type present in repo with slug-only key must not be re-exported"

    def test_determine_export_set_for_rack_types_all_paths(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        absent_rt = _make_rt(model="R-ABSENT", slug="r-absent")
        differs_rt = _make_rt(model="R-DIFF", slug="r-diff", u_height=42)
        same_rt = _make_rt(model="R-SAME", slug="r-same")

        result = exporter._determine_export_set_for_rack_types(
            nb_records=[absent_rt, differs_rt, same_rt],
            repo_rt_by_key={
                ("nokia", "R-DIFF"): {"manufacturer": "Nokia", "model": "R-DIFF", "u_height": 40},
                ("nokia", "R-SAME"): {
                    "manufacturer": "Nokia",
                    "model": "R-SAME",
                    "slug": "r-same",
                    "form_factor": "4-post-cabinet",
                    "width": 19,
                    "u_height": 42,
                    "starting_unit": 1,
                    "desc_units": False,
                    "comments": "",
                    "description": "",
                    "profile": "extra",
                },
            },
        )

        assert [item.reason for item in result] == ["absent", "differs"]
        assert [item.nb_record.model for item in result] == ["R-ABSENT", "R-DIFF"]

    def test_check_missing_images_handles_rear_only_and_none(self, tmp_path):
        exporter = self._make_exporter(tmp_path)

        assert exporter._check_missing_images(None, "/rear.png", "Nokia", "rack") == "images-missing"
        assert exporter._check_missing_images(None, None, "Nokia", "rack") is None

    def test_write_yaml_returns_true_for_same_content(self, tmp_path):
        exporter = self._make_exporter(tmp_path, force_overwrite=False)
        dest = tmp_path / "extra" / "device-types" / "Nokia" / "same.yaml"
        dest.parent.mkdir(parents=True)
        content = yaml.dump({"model": "Same"}, default_flow_style=False, allow_unicode=True, sort_keys=False)
        dest.write_text(content, encoding="utf-8")

        assert exporter._write_yaml(dest, {"model": "Same"}) is True
        assert dest.read_text(encoding="utf-8") == content

    def test_download_type_images_dispatches_module_and_rack(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        exporter._download_module_type_images = MagicMock(return_value=False)
        exporter._download_device_type_images = MagicMock(return_value=True)
        dt_item = ExportItem("device-type", _make_dt(), None, {}, "absent", "Nokia", "dt.yaml", "Nokia/dt")
        mt_item = ExportItem("module-type", _make_mt(), None, {}, "absent", "Nokia", "mt.yaml", "Nokia/mt")
        rt_item = ExportItem("rack-type", _make_rt(), None, {}, "absent", "Nokia", "rt.yaml", "Nokia/rt")

        assert exporter._download_type_images(dt_item) is True
        assert exporter._download_type_images(mt_item) is False
        assert exporter._download_type_images(rt_item) is True

    def test_download_module_type_images_handles_fetch_failure(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        item = ExportItem("module-type", _make_mt(id=77), None, {}, "absent", "Nokia", "mt.yaml", "Nokia/mt")
        exporter._get_module_image_details = MagicMock(side_effect=RuntimeError("boom"))

        assert exporter._download_module_type_images(item) is False
        assert any("Could not fetch module image details" in str(call) for call in exporter.handle.log.call_args_list)

    def test_download_module_type_images_downloads_available_attachments(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        item = ExportItem("module-type", _make_mt(id=55), None, {}, "absent", "Nokia", "mt.yaml", "Nokia/mt")
        exporter._get_module_image_details = MagicMock(
            return_value={
                55: {
                    "front.png": {"url": "/img/front.png"},
                    "rear.png": MagicMock(url="/img/rear.png"),
                    "skip.png": {"url": None},
                }
            }
        )
        exporter._download_image = MagicMock(side_effect=["hash", None])

        assert exporter._download_module_type_images(item) is False
        assert exporter._download_image.call_count == 2

    def test_download_module_type_images_rejects_path_traversal(self, tmp_path):
        """Attachment names with directory separators are sanitized (stripped to basename)."""
        exporter = self._make_exporter(tmp_path)
        item = ExportItem("module-type", _make_mt(id=99), None, {}, "absent", "Nokia", "mt.yaml", "Nokia/mt")
        exporter._get_module_image_details = MagicMock(
            return_value={
                99: {
                    "../evil.png": {"url": "/img/evil.png"},
                }
            }
        )
        calls = []

        def capture_download(url_path, dest, content_type_out=None):
            calls.append(dest)
            return "hash"

        exporter._download_image = capture_download

        result = exporter._download_module_type_images(item)
        assert result is True
        assert len(calls) == 1
        img_dir = exporter.export_dir / "module-images" / "Nokia"
        # The file must be written under img_dir, not the parent
        assert calls[0].parent == img_dir
        assert calls[0].name == "evil.png"

    def test_download_module_type_images_derives_extension_from_url(self, tmp_path):
        """When att_name has no extension, URL suffix is used to add one."""
        exporter = self._make_exporter(tmp_path)
        item = ExportItem("module-type", _make_mt(id=42), None, {}, "absent", "Nokia", "mt.yaml", "Nokia/mt")
        exporter._get_module_image_details = MagicMock(
            return_value={
                42: {
                    "front": {"url": "/media/front.jpg"},  # no extension in att_name
                }
            }
        )
        calls = []

        def capture_download(url_path, dest, content_type_out=None):
            calls.append((url_path, dest))
            return "abc123"

        exporter._download_image = capture_download

        result = exporter._download_module_type_images(item)
        assert result is True
        assert len(calls) == 1
        _, dest = calls[0]
        assert dest.suffix == ".jpg"

    def test_download_module_type_images_renames_from_content_type(self, tmp_path):
        """When neither att_name nor URL has a known extension, Content-Type renames the file."""
        exporter = self._make_exporter(tmp_path)
        item = ExportItem("module-type", _make_mt(id=11), None, {}, "absent", "Nokia", "mt.yaml", "Nokia/mt")
        exporter._get_module_image_details = MagicMock(
            return_value={
                11: {
                    "front": {"url": "/media/front"},  # no extension anywhere
                }
            }
        )
        img_dir = exporter.export_dir / "module-images" / "Nokia"
        img_dir.mkdir(parents=True, exist_ok=True)

        def capture_download(url_path, dest, content_type_out=None):
            # Write a dummy file and populate content_type_out
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"imgdata")
            if content_type_out is not None:
                content_type_out.append("image/webp")
            return "deadbeef"

        exporter._download_image = capture_download
        result = exporter._download_module_type_images(item)
        assert result is True
        # The file should have been renamed to include .webp extension
        assert (img_dir / "front.webp").exists()
        assert not (img_dir / "front.bin").exists()

    def test_download_module_type_images_rename_skips_overwrite_when_dest_exists(self, tmp_path):
        """Rename step must NOT overwrite an existing file when force_overwrite=False."""
        exporter = self._make_exporter(tmp_path, force_overwrite=False)
        item = ExportItem("module-type", _make_mt(id=22), None, {}, "absent", "Nokia", "mt.yaml", "Nokia/mt")
        exporter._get_module_image_details = MagicMock(
            return_value={
                22: {
                    "front": {"url": "/media/front"},  # no extension → provisional dest = front.bin
                }
            }
        )
        img_dir = exporter.export_dir / "module-images" / "Nokia"
        img_dir.mkdir(parents=True, exist_ok=True)
        # Pre-existing file at the final (renamed) destination
        existing = img_dir / "front.webp"
        existing.write_bytes(b"original")

        def capture_download(url_path, dest, content_type_out=None):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"new")
            if content_type_out is not None:
                content_type_out.append("image/webp")
            return "newhash"

        exporter._download_image = capture_download
        result = exporter._download_module_type_images(item)
        assert result is True
        # Existing file must not have been overwritten
        assert existing.read_bytes() == b"original"
        # The provisional .bin file should have been cleaned up
        assert not (img_dir / "front.bin").exists()

    def test_download_image_skip_existing_file(self, tmp_path):
        exporter = self._make_exporter(tmp_path, force_overwrite=False)
        dest = tmp_path / "extra" / "elevation-images" / "Nokia" / "existing.png"
        dest.parent.mkdir(parents=True)
        dest.write_bytes(b"old")

        assert exporter._download_image("/media/existing.png", dest) is _SKIP

    def test_download_image_handles_request_error(self, tmp_path):
        import requests

        exporter = self._make_exporter(tmp_path)
        dest = tmp_path / "extra" / "elevation-images" / "Nokia" / "error.png"
        with patch("core.export.requests.get", side_effect=requests.RequestException("nope")):
            assert exporter._download_image("/media/error.png", dest) is None

    def test_download_image_rejects_non_image_response(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        dest = tmp_path / "extra" / "elevation-images" / "Nokia" / "bad.png"
        resp = MagicMock(ok=False, status_code=404, headers={"Content-Type": "application/json"})

        with patch("core.export.requests.get", return_value=resp):
            assert exporter._download_image("/media/bad.png", dest) is None

    def test_download_image_writes_file_and_returns_hash(self, tmp_path):
        import hashlib

        exporter = self._make_exporter(tmp_path)
        dest = tmp_path / "extra" / "elevation-images" / "Nokia" / "ok.png"
        resp = MagicMock(ok=True, status_code=200, headers={"Content-Type": "image/png"}, content=b"image-bytes")

        with patch("core.export.requests.get", return_value=resp):
            result = exporter._download_image("/media/ok.png", dest)

        assert result == hashlib.sha256(b"image-bytes").hexdigest()
        assert dest.read_bytes() == b"image-bytes"

    def test_download_device_type_images_uses_url_extension(self, tmp_path):
        """Extension must be derived from the URL, not hardcoded to .png."""
        exporter = self._make_exporter(tmp_path)
        dt = _make_dt(front_image="/media/nokia-7750.front.jpg", slug="nokia-7750")
        item = ExportItem("device-type", dt, None, {}, "absent", "Nokia", "nokia-7750.yaml", "Nokia/nokia-7750")

        resp = MagicMock(ok=True, status_code=200, headers={"Content-Type": "image/jpeg"}, content=b"JPEG")
        with patch("core.export.requests.get", return_value=resp):
            result = exporter._download_device_type_images(item)

        assert result is True
        dest = tmp_path / "extra" / "elevation-images" / "Nokia" / "nokia-7750.front.jpg"
        assert dest.exists(), "JPEG image must be saved with .jpg extension from URL"

    def test_download_device_type_images_falls_back_to_png_for_unknown_ext(self, tmp_path):
        """Unknown URL extension falls back to .png."""
        exporter = self._make_exporter(tmp_path)
        dt = _make_dt(front_image="/media/nokia-7750.front", slug="nokia-7750")
        item = ExportItem("device-type", dt, None, {}, "absent", "Nokia", "nokia-7750.yaml", "Nokia/nokia-7750")

        resp = MagicMock(ok=True, status_code=200, headers={"Content-Type": "image/png"}, content=b"PNG")
        with patch("core.export.requests.get", return_value=resp):
            result = exporter._download_device_type_images(item)

        assert result is True
        # URL has no recognised ext → falls back to .png; content-type is also png so same name
        dest = tmp_path / "extra" / "elevation-images" / "Nokia" / "nokia-7750.front.png"
        assert dest.exists()

    def test_run_skips_fresh_records_and_exits_when_nothing_to_export(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        dt = _make_dt()
        mt = _make_mt()
        rt = _make_rt()
        exporter.graphql.get_device_types = MagicMock(return_value=({("nokia", dt.model): dt}, {dt.slug: dt}))
        exporter.graphql.get_module_types = MagicMock(return_value={"nokia": {mt.model: mt}})
        exporter.graphql.get_rack_types = MagicMock(return_value={"nokia": {rt.model: rt}})
        progress = MagicMock()
        progress.add_task.side_effect = [1, 2]

        with patch("core.export.is_entry_fresh", return_value=True):
            exporter.run(progress=progress)

        assert progress.advance.call_args_list == [((1,),), ((2,),)]
        skipped_calls = exporter.handle.verbose_log.call_args_list
        assert any("Skipped 3 record(s) unchanged" in call.args[0] for call in skipped_calls)
        nothing_calls = exporter.handle.log.call_args_list
        assert any("Nothing to export" in call.args[0] for call in nothing_calls)

    def test_run_advances_write_task_for_skips_and_writes(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        dt = _make_dt(last_updated="2024-01-02T00:00:00Z")
        mt = _make_mt(last_updated="2024-01-03T00:00:00Z")
        exporter.graphql.get_device_types = MagicMock(return_value=({("nokia", dt.model): dt}, {dt.slug: dt}))
        exporter.graphql.get_module_types = MagicMock(return_value={"nokia": {mt.model: mt}})
        exporter.graphql.get_rack_types = MagicMock(return_value={})
        exporter._fetch_vendor_components = MagicMock(return_value=({}, {}))
        exporter._determine_export_set_for_device_types = MagicMock(
            return_value=[
                ExportItem("device-type", dt, None, {"model": dt.model}, "absent", "Nokia", "dt.yaml", "Nokia/dt")
            ]
        )
        exporter._determine_export_set_for_module_types = MagicMock(
            return_value=[
                ExportItem("module-type", mt, None, {"model": mt.model}, "differs", "Nokia", "mt.yaml", "Nokia/mt")
            ]
        )
        exporter._write_yaml = MagicMock(side_effect=[False, True])
        exporter._download_type_images = MagicMock(return_value=True)
        progress = MagicMock()
        progress.add_task.side_effect = [1, 2]

        with patch("core.export.is_entry_fresh", return_value=False):
            exporter.run(progress=progress)

        assert progress.advance.call_args_list == [((1,),), ((2,),), ((2,),)]
        assert any("Skipped (overwrite guard)" in call.args[0] for call in exporter.handle.log.call_args_list)
        assert any("wrote 1 file(s), skipped 1" in call.args[0] for call in exporter.handle.log.call_args_list)

    def test_compare_vendors_to_items_skips_fresh_and_fetches_stale_vendor_once(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        nokia_dt = _make_dt(model="Nokia-DT")
        nokia_mt = _make_mt(model="Nokia-MT")
        acme_mfr = _make_mfr(name="Acme", slug="acme")
        acme_fresh_dt = _make_dt(model="Acme-Fresh-DT", slug="acme-fresh-dt")
        acme_fresh_dt.manufacturer = acme_mfr
        acme_stale_dt = _make_dt(model="Acme-Stale-DT", slug="acme-stale-dt")
        acme_stale_dt.manufacturer = acme_mfr
        acme_stale_mt = _make_mt(model="Acme-Stale-MT")
        acme_stale_mt.manufacturer = acme_mfr
        progress = MagicMock()
        progress.add_task.return_value = 41
        exporter._fetch_vendor_components = MagicMock(return_value=({"dt-components": 1}, {"mt-components": 1}))
        exporter._determine_export_set_for_device_types = MagicMock(return_value=["dt-export"])
        exporter._determine_export_set_for_module_types = MagicMock(return_value=["mt-export"])

        def _is_fresh(_manifest, kind, key, _last_updated):
            return key in {"Nokia/nokia-7750-sr-7s", "Nokia/Nokia-MT", "Acme/acme-fresh-dt"}

        with patch("core.export.is_entry_fresh", side_effect=_is_fresh):
            items, skipped_fresh = exporter._compare_vendors_to_items(
                all_vendor_slugs=["acme", "nokia"],
                dt_by_vendor={"acme": [acme_fresh_dt, acme_stale_dt], "nokia": [nokia_dt]},
                mt_by_vendor={"acme": [acme_stale_mt], "nokia": [nokia_mt]},
                manifest={},
                repo_dt_by_slug={"acme-stale-dt": {"slug": "acme-stale-dt"}},
                repo_mt_by_key={("Acme", "Acme-Stale-MT"): {"model": "Acme-Stale-MT"}},
                progress=progress,
            )

        assert items == ["dt-export", "mt-export"]
        assert skipped_fresh == 3
        progress.add_task.assert_called_once_with("Comparing vendors", total=2)
        assert progress.advance.call_args_list == [((41,),), ((41,),)]
        exporter._fetch_vendor_components.assert_called_once_with("acme")
        exporter._determine_export_set_for_device_types.assert_called_once_with(
            nb_records=[acme_stale_dt],
            repo_dt_by_slug={"acme-stale-dt": {"slug": "acme-stale-dt"}},
            components_by_dt_id={"dt-components": 1},
        )
        exporter._determine_export_set_for_module_types.assert_called_once_with(
            nb_records=[acme_stale_mt],
            repo_mt_by_key={("Acme", "Acme-Stale-MT"): {"model": "Acme-Stale-MT"}},
            components_by_mt_id={"mt-components": 1},
        )

    def test_compare_racks_to_items_skips_fresh_and_exports_stale(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        fresh_rt = _make_rt(model="Rack-Fresh")
        stale_rt = _make_rt(model="Rack-Stale")
        progress = MagicMock()
        progress.add_task.return_value = 42
        exporter._determine_export_set_for_rack_types = MagicMock(return_value=["rack-export"])

        with patch(
            "core.export.is_entry_fresh",
            side_effect=lambda _manifest, _kind, key, _last_updated: key == "Nokia/Rack-Fresh",
        ):
            items, skipped_fresh = exporter._compare_racks_to_items(
                all_rt={"nokia": {fresh_rt.model: fresh_rt, stale_rt.model: stale_rt}},
                manifest={},
                repo_rt_by_key={("Nokia", "Rack-Stale"): {"model": "Rack-Stale"}},
                progress=progress,
            )

        assert items == ["rack-export"]
        assert skipped_fresh == 1
        progress.add_task.assert_called_once_with("Comparing rack types", total=2)
        assert progress.advance.call_args_list == [((42,),), ((42,),)]
        exporter._determine_export_set_for_rack_types.assert_called_once_with(
            nb_records=[stale_rt],
            repo_rt_by_key={("Nokia", "Rack-Stale"): {"model": "Rack-Stale"}},
        )

    def test_write_export_items_logs_summary_updates_manifest_and_tracks_progress(self, tmp_path):
        exporter = self._make_exporter(tmp_path)
        manifest = {}
        manifest_path = tmp_path / "extra" / ".export-manifest.json"
        progress = MagicMock()
        progress.add_task.return_value = 43
        dt_item = ExportItem("device-type", _make_dt(), None, {"model": "dt"}, "absent", "Nokia", "dt.yaml", "Nokia/dt")
        mt_item = ExportItem(
            "module-type", _make_mt(), None, {"model": "mt"}, "differs", "Nokia", "mt.yaml", "Nokia/mt"
        )
        rt_item = ExportItem(
            "rack-type", _make_rt(), None, {"model": "rt"}, "images-missing", "Nokia", "rt.yaml", "Nokia/rt"
        )
        exporter._write_yaml = MagicMock(side_effect=[False, True, True])
        exporter._download_type_images = MagicMock(side_effect=[True, False])

        with (
            patch("core.export.update_entry") as mock_update_entry,
            patch("core.export.save_manifest") as mock_save_manifest,
        ):
            exporter._write_export_items([dt_item, mt_item, rt_item], manifest, manifest_path, progress)

        progress.add_task.assert_called_once_with("Writing exports", total=3)
        assert progress.advance.call_args_list == [((43,),), ((43,),), ((43,),)]
        assert (
            exporter._write_yaml.call_args_list[0].args[0] == tmp_path / "extra" / "device-types" / "Nokia" / "dt.yaml"
        )
        assert (
            exporter._write_yaml.call_args_list[1].args[0] == tmp_path / "extra" / "module-types" / "Nokia" / "mt.yaml"
        )
        assert exporter._write_yaml.call_args_list[2].args[0] == tmp_path / "extra" / "rack-types" / "Nokia" / "rt.yaml"
        mock_update_entry.assert_called_once_with(manifest, "module-types", "Nokia/mt", mt_item.nb_record.last_updated)
        mock_save_manifest.assert_called_once_with(manifest_path, manifest)
        assert any(
            "Will export 3 item(s) to" in call.args[0] and "1 absent, 1 differs, 1 images-missing" in call.args[0]
            for call in exporter.handle.log.call_args_list
        )
        assert any("Skipped (overwrite guard)" in call.args[0] for call in exporter.handle.log.call_args_list)
        assert any(
            "Export-diff complete: wrote 2 file(s), skipped 1" in call.args[0]
            for call in exporter.handle.log.call_args_list
        )

    def test_download_image_off_host_url_sends_no_auth(self, tmp_path):
        """Token must NOT be sent when the image URL resolves to a different host."""
        exporter = self._make_exporter(tmp_path)
        # base_url is http://localhost:8000 (from _make_settings)
        dest = tmp_path / "extra" / "images" / "off-host.png"
        captured_headers = {}

        def _fake_get(url, headers=None, verify=True, timeout=30):
            captured_headers.update(headers or {})
            resp = MagicMock(ok=True, status_code=200)
            resp.headers = {"Content-Type": "image/png"}
            resp.content = b"img"
            return resp

        with patch("core.export.requests.get", side_effect=_fake_get):
            exporter._download_image("https://s3.amazonaws.com/bucket/image.png", dest)

        assert "Authorization" not in captured_headers

    def test_download_image_same_host_url_sends_auth(self, tmp_path):
        """Token IS sent when the image URL is on the same host as base_url."""
        exporter = self._make_exporter(tmp_path)
        dest = tmp_path / "extra" / "images" / "same-host.png"
        captured_headers = {}

        def _fake_get(url, headers=None, verify=True, timeout=30):
            captured_headers.update(headers or {})
            resp = MagicMock(ok=True, status_code=200)
            resp.headers = {"Content-Type": "image/png"}
            resp.content = b"img"
            return resp

        with patch("core.export.requests.get", side_effect=_fake_get):
            exporter._download_image("/media/devicetype-images/image.png", dest)

        assert "Authorization" in captured_headers
        assert "Token" in captured_headers["Authorization"]

    def test_write_export_items_preserves_repo_only_fields_on_differs(self, tmp_path):
        """When reason='differs', repo-only top-level fields must survive the write."""
        exporter = self._make_exporter(tmp_path)
        nb_serialized = {"manufacturer": "Nokia", "model": "SR-1", "u_height": 1}
        repo_yaml = {
            "manufacturer": "Nokia",
            "model": "SR-1",
            "u_height": 2,  # differs → not merged (NB authoritative)
            "profile": "my-custom-profile",  # repo-only → must be preserved
            "comments": "Internal notes",  # repo-only → must be preserved
        }
        dt = MagicMock()
        dt.last_updated = "2024-01-01T00:00:00Z"
        item = ExportItem(
            kind="device-type",
            nb_record=dt,
            repo_yaml=repo_yaml,
            serialized=nb_serialized,
            reason="differs",
            mfr_name="Nokia",
            filename="SR-1.yaml",
            manifest_key="Nokia/SR-1",
        )

        written_data = {}

        def _capture_write(dest, data):
            written_data.update(data)
            return True

        exporter._write_yaml = _capture_write
        exporter._download_type_images = MagicMock(return_value=True)

        from unittest.mock import patch as _patch

        with _patch("core.export.update_entry"), _patch("core.export.save_manifest"):
            exporter._write_export_items(
                [item],
                {},
                tmp_path / "manifest.json",
                None,
            )

        assert written_data["profile"] == "my-custom-profile"
        assert written_data["comments"] == "Internal notes"
        # NB authoritative field is NOT overwritten by repo value
        assert written_data["u_height"] == 1

    def test_load_repo_device_types_logs_bad_yaml_at_verbose(self, tmp_path):
        """Malformed YAML must be logged at verbose level, not silently dropped."""
        exporter = self._make_exporter(tmp_path)
        vdir = tmp_path / "repo" / "device-types" / "Nokia"
        vdir.mkdir(parents=True)
        (vdir / "bad.yaml").write_text("foo: [\n", encoding="utf-8")

        exporter._load_repo_device_types()

        verbose_calls = " ".join(str(c) for c in exporter.handle.verbose_log.call_args_list)
        assert "Skipping malformed YAML" in verbose_calls or "malformed" in verbose_calls.lower()

    def test_load_repo_module_types_logs_bad_yaml_at_verbose(self, tmp_path):
        """Malformed module YAML must be logged at verbose level."""
        exporter = self._make_exporter(tmp_path)
        vdir = tmp_path / "repo" / "module-types" / "Nokia"
        vdir.mkdir(parents=True)
        (vdir / "bad.yaml").write_text("manufacturer: [\n", encoding="utf-8")

        exporter._load_repo_module_types()

        verbose_calls = " ".join(str(c) for c in exporter.handle.verbose_log.call_args_list)
        assert "Skipping malformed YAML" in verbose_calls or "malformed" in verbose_calls.lower()

    def test_load_repo_rack_types_logs_bad_yaml_at_verbose(self, tmp_path):
        """Malformed rack YAML must be logged at verbose level."""
        exporter = self._make_exporter(tmp_path)
        vdir = tmp_path / "repo" / "rack-types" / "Nokia"
        vdir.mkdir(parents=True)
        (vdir / "bad.yaml").write_text("manufacturer: [\n", encoding="utf-8")

        exporter._load_repo_rack_types()

        verbose_calls = " ".join(str(c) for c in exporter.handle.verbose_log.call_args_list)
        assert "Skipping malformed YAML" in verbose_calls or "malformed" in verbose_calls.lower()


class TestSanitizeAttachmentFilename:
    """Tests for _sanitize_attachment_filename."""

    def test_plain_name_with_known_extension_is_returned_unchanged(self):
        assert _sanitize_attachment_filename("front.png", "/media/front.png", "") == "front.png"

    def test_strips_directory_components(self):
        result = _sanitize_attachment_filename("../evil.png", "/media/evil.png", "")
        assert "/" not in result
        assert ".." not in result
        assert result == "evil.png"

    def test_strips_subdirectory_prefix(self):
        result = _sanitize_attachment_filename("subdir/img.jpg", "/media/img.jpg", "")
        assert result == "img.jpg"

    def test_derives_extension_from_url_when_name_has_none(self):
        result = _sanitize_attachment_filename("front", "/media/front.jpg", "")
        assert result == "front.jpg"

    def test_derives_extension_from_content_type_when_url_has_none(self):
        result = _sanitize_attachment_filename("front", "/media/front", "image/png")
        assert result == "front.png"

    def test_content_type_takes_priority_over_url(self):
        # content_type is non-empty → preferred over URL suffix
        result = _sanitize_attachment_filename("front", "/media/front.jpg", "image/png")
        assert result == "front.png"

    def test_falls_back_to_bin_when_nothing_known(self):
        result = _sanitize_attachment_filename("front", "/media/front", "")
        assert result == "front.bin"

    def test_empty_name_uses_attachment_prefix(self):
        result = _sanitize_attachment_filename("", "/media/front.png", "")
        assert result.endswith(".png")
        assert len(result) > 0

    def test_all_known_content_types_are_recognised(self):
        from core.export import _CONTENT_TYPE_EXT

        for ct, ext in _CONTENT_TYPE_EXT.items():
            result = _sanitize_attachment_filename("img", "/media/img", ct)
            assert result.endswith(ext), f"Expected {ext} for {ct}, got {result}"
