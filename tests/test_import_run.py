"""Tests for the import pipeline interface."""

from collections import Counter
from contextlib import contextmanager

import pytest

from core.errors import VendorSelectionError
from types import SimpleNamespace

from core.import_run import (
    ImportRun,
    RunSummary,
    VendorPlan,
    _log_run_summary,
    _process_device_types,
    _process_module_types,
    _process_rack_types,
)
from core.log_handler import LogHandler
from core.repo import DTLRepo


class _ComponentCache:
    """Record cache cleanup without providing import behavior."""

    def __init__(self):
        self.close_count = 0

    def close(self):
        """Record one cache close."""
        self.close_count += 1


class _DeviceTypes:
    """Provide the component cache used by pipeline cleanup."""

    def __init__(self):
        self.components = _ComponentCache()


class _Outcomes:
    """Provide an empty final failure report and an empty outcome aggregate."""

    @staticmethod
    def render_failure_report():
        """Return no failure lines."""
        return []

    @staticmethod
    def summary_by_kind():
        """Return no recorded outcomes."""
        return {}


class _NetBoxBoundary:
    """Expose run state and fail if planning starts an import."""

    def __init__(self):
        self.modules = True
        self.rack_types = True
        self.device_types = _DeviceTypes()
        self.outcomes = _Outcomes()
        self.counter = Counter(
            added=2,
            properties_updated=1,
            components_updated=3,
            components_added=4,
            components_removed=5,
            images=6,
            manufacturer=1,
            module_added=7,
            module_updated=8,
            module_update_failed=0,
            module_partial_update=0,
            rack_type_added=9,
            rack_type_updated=10,
            device_types_failed=0,
        )
        self.import_started = False

    def load_vendor(self, _vendor_slug):
        """Fail when a planning-only test starts the import."""
        self.import_started = True
        raise AssertionError("planning started the import")


class _RepositoryBoundary:
    """Return fixed source data for pipeline tests."""

    def __init__(self, root, *, vendors=None):
        self.devices_path = root / "device-types"
        self.modules_path = root / "module-types"
        self.racks_path = root / "rack-types"
        self.devices_path.mkdir()
        self.modules_path.mkdir()
        self.racks_path.mkdir()
        self.vendors = vendors if vendors is not None else [{"name": "Vendor One", "slug": "vendor-one"}]
        self.duplicate_definitions = []

    def get_devices_path(self):
        """Return the device-type source path."""
        return str(self.devices_path)

    def get_modules_path(self):
        """Return the module-type source path."""
        return str(self.modules_path)

    def get_racks_path(self):
        """Return the rack-type source path."""
        return str(self.racks_path)

    def discover_vendors(self, _devices_path, _modules_path, _racks_path):
        """Return the configured vendors."""
        return self.vendors

    @staticmethod
    def resolve_slug_files(_slugs):
        """Force the pipeline to use its full file scan."""
        return None

    @staticmethod
    def get_devices(path, vendors):
        """Return one source file for each type directory."""
        return ([f"{path}/{vendors[0]}.yaml"], [])

    @staticmethod
    def parse_files(files, slugs=None):
        """Return one parsed type identified by its source directory."""
        path = files[0]
        if "device-types" in path:
            return [{"manufacturer": {"slug": "vendor-one"}, "model": "Device One", "slug": "device-one"}]
        if "module-types" in path:
            return [{"manufacturer": {"slug": "vendor-one"}, "model": "Module One", "slug": "module-one"}]
        return [{"manufacturer": {"slug": "vendor-one"}, "model": "Rack One", "slug": "rack-one"}]


class _Progress:
    """Provide the progress shape used by an empty run."""

    def __init__(self):
        self.console = object()
        self.tasks = []


class _ProgressFactory:
    """Record entry and exit of the progress context."""

    def __init__(self):
        self.entered = False
        self.exited = False

    @contextmanager
    def __call__(self, _show_remaining_time):
        """Yield one progress object and record complete cleanup."""
        self.entered = True
        try:
            yield _Progress()
        finally:
            self.exited = True


class _FailingProgress(_Progress):
    """Fail while the run creates its vendor task."""

    @staticmethod
    def add_task(_description, total):
        """Raise a progress setup error."""
        raise RuntimeError(f"cannot track {total} vendor")


class _FailingProgressFactory(_ProgressFactory):
    """Yield a progress object that fails during setup."""

    @contextmanager
    def __call__(self, _show_remaining_time):
        """Yield failing progress and record context cleanup."""
        self.entered = True
        try:
            yield _FailingProgress()
        finally:
            self.exited = True


def test_plan_vendor_returns_inspectable_work_without_applying_it(make_config, tmp_path):
    """Planning returns parsed work and does not call the NetBox import API."""
    repo = _RepositoryBoundary(tmp_path)
    netbox = _NetBoxBoundary()
    run = ImportRun(make_config(), repo, netbox, LogHandler(False), _ProgressFactory())

    selection = run.discover()
    plan = run.plan_vendor(selection, selection.vendors[0])

    assert isinstance(plan, VendorPlan)
    assert plan.vendor == {"name": "Vendor One", "slug": "vendor-one"}
    assert [item["slug"] for item in plan.device_types] == ["device-one"]
    assert [item["slug"] for item in plan.module_types] == ["module-one"]
    assert [item["slug"] for item in plan.rack_types] == ["rack-one"]
    assert plan.prefetch_components is True
    assert netbox.import_started is False


def test_empty_device_types_return_before_cache_readiness(make_config):
    class DeviceTypes:
        @staticmethod
        def ensure_components_ready(manufacturer_slug=None):
            raise AssertionError(f"empty input populated the cache for {manufacturer_slug}")

    class NetBoxBoundary:
        device_types = DeviceTypes()

    handle = LogHandler(False)

    _process_device_types(
        make_config(only_new=False),
        NetBoxBoundary(),
        handle,
        None,
        [],
        vendor_slug="vendor-one",
    )


def test_discover_raises_a_typed_fatal_error_when_no_vendor_matches(make_config, tmp_path):
    repo = _RepositoryBoundary(tmp_path)
    run = ImportRun(
        make_config(vendors=("missing-vendor",)),
        repo,
        _NetBoxBoundary(),
        LogHandler(False),
        _ProgressFactory(),
    )

    with pytest.raises(VendorSelectionError, match="No vendors matched --vendors"):
        run.discover()


def test_discover_raises_a_typed_fatal_error_when_slug_selection_removes_the_vendor(make_config, tmp_path):
    class SlugResolvedRepository(_RepositoryBoundary):
        def resolve_slug_files(self, _slugs):
            return {
                "device_files": {"other-vendor": []},
                "module_vendors": set(),
                "rack_vendors": set(),
            }

    repo = SlugResolvedRepository(tmp_path)
    run = ImportRun(
        make_config(vendors=("vendor-one",), slugs=("missing-slug",)),
        repo,
        _NetBoxBoundary(),
        LogHandler(False),
        _ProgressFactory(),
    )

    with pytest.raises(VendorSelectionError, match="combination of --vendors and --slugs"):
        run.discover()


def test_execute_returns_snapshot_and_owns_console_lifecycle(make_config, tmp_path):
    """Execution returns a summary and releases the console and component cache."""
    repo = _RepositoryBoundary(tmp_path, vendors=[])
    netbox = _NetBoxBoundary()
    handle = LogHandler(False)
    progress_factory = _ProgressFactory()
    run = ImportRun(make_config(), repo, netbox, handle, progress_factory)

    summary = run.execute()

    assert isinstance(summary, RunSummary)
    assert summary.counter["added"] == 2
    assert summary.modules is True
    assert summary.rack_types is True
    assert progress_factory.entered is True
    assert progress_factory.exited is True
    assert handle.console is None
    assert netbox.device_types.components.close_count == 1
    netbox.counter["added"] = 99
    assert summary.counter["added"] == 2


def test_execute_releases_console_when_progress_setup_fails(make_config, tmp_path):
    """Progress setup errors do not leave the reporter attached to its console."""
    repo = _RepositoryBoundary(tmp_path)
    netbox = _NetBoxBoundary()
    handle = LogHandler(False)
    progress_factory = _FailingProgressFactory()
    run = ImportRun(make_config(), repo, netbox, handle, progress_factory)

    with pytest.raises(RuntimeError, match="cannot track 1 vendor"):
        run.execute()

    assert progress_factory.exited is True
    assert handle.console is None
    assert netbox.device_types.components.close_count == 1


class TestPartialLibraryLayouts:
    """A local checkout may hold one type root only, so planning must not read the absent ones."""

    TYPE_DIRS = ("device-types", "module-types", "rack-types")

    def _repo(self, tmp_path, present, make_config):
        """Build a real DTLRepo over a checkout holding *present* alone."""
        vendor = tmp_path / present / "TestVendor"
        vendor.mkdir(parents=True)
        (vendor / "thing.yaml").write_text("manufacturer: TestVendor\nmodel: Test\nslug: test\n")
        config = make_config(repo_url="local", repo_path=str(tmp_path))
        return DTLRepo(config, LogHandler(False)), config

    @pytest.mark.parametrize("present", TYPE_DIRS)
    def test_one_type_root_plans_without_reading_the_absent_ones(self, present, make_config, tmp_path):
        repo, config = self._repo(tmp_path, present, make_config)
        run = ImportRun(config, repo, _NetBoxBoundary(), LogHandler(False), _ProgressFactory())

        selection = run.discover()
        plan = run.plan_vendor(selection, {"name": "TestVendor", "slug": "testvendor"})

        parsed = {
            "device-types": len(plan.device_types),
            "module-types": len(plan.module_types),
            "rack-types": len(plan.rack_types),
        }
        assert parsed[present] == 1, parsed
        assert sum(parsed.values()) == 1, parsed


class _RecordingConsole:
    """Capture what the real LogHandler emits."""

    def __init__(self):
        self.lines = []

    def print(self, message, markup=False):
        """Record one emitted line."""
        self.lines.append(message)


def _recording_handle():
    """Return a real LogHandler writing into a recording console."""
    handle = LogHandler(False)
    console = _RecordingConsole()
    handle.set_console(console)
    return handle, console


class _ModuleNetBox:
    """Report one new module type so the banner is emitted."""

    modules = True
    device_types = _DeviceTypes()

    @staticmethod
    def get_existing_module_types():
        """Return no existing module types."""
        return {}

    @staticmethod
    def filter_actionable_module_types(module_types, _existing, only_new=False):
        """Treat every supplied module type as actionable."""
        return list(module_types), {}, []

    @staticmethod
    def filter_new_module_types(module_types, _existing):
        """Treat every supplied module type as new."""
        return list(module_types)

    @staticmethod
    def count_module_type_images(*_args, **_kwargs):
        """Report no images to upload."""
        return 0

    @staticmethod
    def create_module_types(*_args, **_kwargs):
        """Accept the import call without doing work."""

    @staticmethod
    def log_module_type_changes(_changes):
        """Accept the change log without doing work."""


class _RackNetBox:
    """Report one new rack type so the banner is emitted."""

    rack_types = True
    device_types = _DeviceTypes()

    @staticmethod
    def get_existing_rack_types():
        """Return no existing rack types."""
        return {}

    @staticmethod
    def create_rack_types(*_args, **_kwargs):
        """Accept the import call without doing work."""


def test_module_type_banner_names_the_vendor(make_config):
    """A multi-vendor run must say which vendor a module-type report belongs to."""
    handle, console = _recording_handle()

    _process_module_types(
        make_config(only_new=True),
        _ModuleNetBox(),
        handle,
        None,
        [{"manufacturer": {"slug": "vendor-one"}, "model": "Module One", "slug": "module-one"}],
        vendor_name="Vendor One",
    )

    banner = [line for line in console.lines if "MODULE TYPE CHANGE DETECTION" in line]
    assert len(banner) == 1
    assert "MODULE TYPE CHANGE DETECTION: Vendor One" in banner[0]


def test_rack_type_banner_names_the_vendor(make_config):
    """A multi-vendor run must say which vendor a rack-type report belongs to."""
    handle, console = _recording_handle()

    _process_rack_types(
        make_config(),
        _RackNetBox(),
        handle,
        None,
        [{"manufacturer": {"slug": "vendor-one"}, "model": "Rack One", "slug": "rack-one"}],
        vendor_name="Vendor One",
    )

    banner = [line for line in console.lines if "RACK TYPE CHANGE DETECTION" in line]
    assert len(banner) == 1
    assert "RACK TYPE CHANGE DETECTION: Vendor One" in banner[0]


def test_banners_omit_the_separator_when_no_vendor_is_given(make_config):
    """Without a vendor the banner keeps its plain title, with no trailing colon."""
    handle, console = _recording_handle()

    _process_rack_types(
        make_config(),
        _RackNetBox(),
        handle,
        None,
        [{"manufacturer": {"slug": "vendor-one"}, "model": "Rack One", "slug": "rack-one"}],
    )

    banner = [line for line in console.lines if "RACK TYPE CHANGE DETECTION" in line]
    assert len(banner) == 1
    assert banner[0].rstrip().endswith("RACK TYPE CHANGE DETECTION")


class _OutcomeNetBox:
    """Run-state stand-in carrying a real OutcomeRegistry."""

    def __init__(self, *, modules=True, rack_types=True, counter=None):
        from core.outcomes import OutcomeRegistry

        self.modules = modules
        self.rack_types = rack_types
        self.outcomes = OutcomeRegistry()
        base = dict(
            added=0,
            properties_updated=0,
            components_updated=0,
            components_added=0,
            components_removed=0,
            images=0,
            manufacturer=0,
            module_added=0,
            module_updated=0,
            rack_type_added=0,
            rack_type_updated=0,
        )
        base.update(counter or {})
        self.counter = Counter(base)


def _summary_lines(netbox):
    """Render a run summary through the real LogHandler and return its lines."""
    from datetime import datetime

    handle, console = _recording_handle()
    handle.verbose = True
    repo = SimpleNamespace(duplicate_definitions=[])
    summary = RunSummary.capture(netbox, repo, datetime.now())
    _log_run_summary(handle, summary)
    return console.lines


def test_failed_module_type_is_counted_in_the_summary():
    """A module type that failed must be counted, not only listed in the report."""
    from core.outcomes import EntityKind, Outcome

    nb = _OutcomeNetBox()
    nb.outcomes.record(EntityKind.MODULE_TYPE, "chicony/CPB09-031A", Outcome.FAILED, reason="boom")

    lines = _summary_lines(nb)

    assert any("1 modules failed" in line for line in lines), lines


def test_failed_rack_type_is_counted_in_the_summary():
    """A rack type that failed must appear in the headline counts."""
    from core.outcomes import EntityKind, Outcome

    nb = _OutcomeNetBox()
    nb.outcomes.record(EntityKind.RACK_TYPE, "lenovo/1410HPB", Outcome.FAILED, reason="boom")

    lines = _summary_lines(nb)

    assert any("1 rack types failed" in line for line in lines), lines


def test_partial_module_type_is_counted_in_the_summary():
    """A partially updated module must be counted from the registry."""
    from core.outcomes import EntityKind, Outcome

    nb = _OutcomeNetBox()
    nb.outcomes.record(EntityKind.MODULE_TYPE, "cisco/LC", Outcome.PARTIAL, reason="half applied")

    lines = _summary_lines(nb)

    assert any("1 modules partially updated" in line for line in lines), lines


def test_headline_counts_match_the_itemised_rows():
    """The invariant the two parallel tallies never enforced."""
    from core.outcomes import EntityKind, Outcome

    nb = _OutcomeNetBox()
    nb.outcomes.record(EntityKind.DEVICE_TYPE, "ribbon/SBC 5400", Outcome.FAILED, reason="a")
    nb.outcomes.record(EntityKind.DEVICE_TYPE, "acme/SW2", Outcome.FAILED, reason="b")
    nb.outcomes.record(EntityKind.MODULE_TYPE, "chicony/CPB09-031A", Outcome.FAILED, reason="c")
    nb.outcomes.record(EntityKind.RACK_TYPE, "lenovo/1410HPB", Outcome.FAILED, reason="d")

    lines = _summary_lines(nb)
    text = "\n".join(lines)

    assert "2 device types FAILED" in text
    assert "1 modules failed" in text
    assert "1 rack types failed" in text
    # The itemised report must agree with those headline numbers.
    assert "Failed entities: 4" in text
