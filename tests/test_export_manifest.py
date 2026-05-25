"""Tests for core/export_manifest.py."""

import json
from core.export_manifest import load_manifest, save_manifest, is_entry_fresh, update_entry


class TestLoadManifest:
    """Tests for load_manifest function."""

    def test_returns_empty_manifest_when_file_missing(self, tmp_path):
        m = load_manifest(tmp_path / ".export-manifest.json")
        assert m == {"device-types": {}, "module-types": {}, "rack-types": {}}

    def test_returns_empty_manifest_when_corrupt(self, tmp_path):
        p = tmp_path / ".export-manifest.json"
        p.write_text("not-json{{{")
        m = load_manifest(p)
        assert m == {"device-types": {}, "module-types": {}, "rack-types": {}}

    def test_loads_existing_manifest(self, tmp_path):
        p = tmp_path / ".export-manifest.json"
        data = {
            "device-types": {"Nokia/acme-x": {"last_updated": "2024-01-01T00:00:00Z"}},
            "module-types": {},
            "rack-types": {},
        }
        p.write_text(json.dumps(data))
        m = load_manifest(p)
        assert m["device-types"]["Nokia/acme-x"]["last_updated"] == "2024-01-01T00:00:00Z"

    def test_returns_empty_when_json_is_list(self, tmp_path):
        """JSON array (not dict) must return the empty manifest, not raise AttributeError."""
        p = tmp_path / ".export-manifest.json"
        p.write_text(json.dumps([{"device-types": {}}]))
        m = load_manifest(p)
        assert m == {"device-types": {}, "module-types": {}, "rack-types": {}}

    def test_returns_empty_when_json_is_string(self, tmp_path):
        p = tmp_path / ".export-manifest.json"
        p.write_text('"just a string"')
        m = load_manifest(p)
        assert m == {"device-types": {}, "module-types": {}, "rack-types": {}}

    def test_returns_empty_when_section_is_not_dict(self, tmp_path):
        """A section that is not a dict (e.g. a list) must be reset to {}."""
        p = tmp_path / ".export-manifest.json"
        p.write_text(json.dumps({"device-types": ["bad"], "module-types": {}, "rack-types": {}}))
        m = load_manifest(p)
        assert m["device-types"] == {}
        assert m["module-types"] == {}

    def test_fills_missing_sections(self, tmp_path):
        """Manifest missing one section must get that section initialised to {}."""
        p = tmp_path / ".export-manifest.json"
        p.write_text(json.dumps({"device-types": {"Nokia/x": {"last_updated": "ts"}}}))
        m = load_manifest(p)
        assert m["module-types"] == {}
        assert m["rack-types"] == {}
        assert m["device-types"]["Nokia/x"]["last_updated"] == "ts"

    def test_non_utf8_file_returns_empty_manifest(self, tmp_path):
        """UnicodeDecodeError (non-UTF-8 file) must be caught and return empty manifest."""
        p = tmp_path / ".export-manifest.json"
        p.write_bytes(b"\xff\xfe{}")  # BOM + non-UTF-8 bytes
        m = load_manifest(p)
        assert m == {"device-types": {}, "module-types": {}, "rack-types": {}}


class TestSaveManifest:
    """Tests for save_manifest function."""

    def test_saves_atomically(self, tmp_path):
        p = tmp_path / ".export-manifest.json"
        data = {
            "device-types": {"Nokia/acme-x": {"last_updated": "2024-01-01T00:00:00Z"}},
            "module-types": {},
            "rack-types": {},
        }
        save_manifest(p, data)
        assert p.exists()
        loaded = json.loads(p.read_text())
        assert loaded == data

    def test_overwrites_existing(self, tmp_path):
        p = tmp_path / ".export-manifest.json"
        p.write_text(json.dumps({"device-types": {"old": {}}, "module-types": {}, "rack-types": {}}))
        new_data = {"device-types": {"new": {}}, "module-types": {}, "rack-types": {}}
        save_manifest(p, new_data)
        assert json.loads(p.read_text()) == new_data


class TestIsEntryFresh:
    """Tests for is_entry_fresh function."""

    def test_fresh_when_last_updated_matches(self):
        manifest = {
            "device-types": {"Nokia/acme-x": {"last_updated": "2024-01-01T00:00:00Z"}},
            "module-types": {},
            "rack-types": {},
        }
        assert is_entry_fresh(manifest, "device-types", "Nokia/acme-x", "2024-01-01T00:00:00Z") is True

    def test_stale_when_last_updated_differs(self):
        manifest = {
            "device-types": {"Nokia/acme-x": {"last_updated": "2024-01-01T00:00:00Z"}},
            "module-types": {},
            "rack-types": {},
        }
        assert is_entry_fresh(manifest, "device-types", "Nokia/acme-x", "2024-02-01T00:00:00Z") is False

    def test_stale_when_entry_missing(self):
        manifest = {"device-types": {}, "module-types": {}, "rack-types": {}}
        assert is_entry_fresh(manifest, "device-types", "Nokia/acme-x", "2024-01-01T00:00:00Z") is False


class TestUpdateEntry:
    """Tests for update_entry function."""

    def test_adds_new_entry(self):
        manifest = {"device-types": {}, "module-types": {}, "rack-types": {}}
        update_entry(manifest, "device-types", "Nokia/acme-x", "2024-01-01T00:00:00Z")
        assert manifest["device-types"]["Nokia/acme-x"]["last_updated"] == "2024-01-01T00:00:00Z"

    def test_updates_existing_entry(self):
        manifest = {"device-types": {"Nokia/acme-x": {"last_updated": "old"}}, "module-types": {}, "rack-types": {}}
        update_entry(manifest, "device-types", "Nokia/acme-x", "2024-02-01T00:00:00Z")
        assert manifest["device-types"]["Nokia/acme-x"]["last_updated"] == "2024-02-01T00:00:00Z"
