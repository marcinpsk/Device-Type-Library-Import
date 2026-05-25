import importlib.util
import os
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _dt_sort_key(d):
    return (
        d.get("manufacturer", {}).get("slug", ""),
        d.get("model", ""),
        d.get("slug", ""),
    )


@pytest.fixture(scope="module")
def nb_dt_import():
    module_path = Path(__file__).resolve().parents[1] / "nb-dt-import.py"
    spec = importlib.util.spec_from_file_location("nb_dt_import", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["nb_dt_import"] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop("nb_dt_import", None)


def test_log_run_mode_reports_default_non_update_behavior(nb_dt_import):
    handle = MagicMock()
    args = SimpleNamespace(only_new=False, update=False, remove_components=False)

    nb_dt_import.log_run_mode(handle, args)

    messages = [call.args[0] for call in handle.log.call_args_list]
    assert any("--update not set" in message for message in messages)
    # remove-components guidance is only shown when --update is active
    assert not any("remove-components" in message for message in messages)


def test_log_run_mode_reports_update_and_remove_enabled(nb_dt_import):
    handle = MagicMock()
    args = SimpleNamespace(only_new=False, update=True, remove_components=True)

    nb_dt_import.log_run_mode(handle, args)

    messages = [call.args[0] for call in handle.log.call_args_list]
    assert any("--update enabled" in message for message in messages)
    assert any("--remove-components enabled" in message for message in messages)


def test_log_run_mode_reports_update_without_remove_components(nb_dt_import):
    handle = MagicMock()
    args = SimpleNamespace(only_new=False, update=True, remove_components=False)

    nb_dt_import.log_run_mode(handle, args)

    messages = [call.args[0] for call in handle.log.call_args_list]
    assert any("--update enabled" in message for message in messages)
    assert any("will not remove components" in message for message in messages)


def test_log_run_mode_reports_only_new_enabled(nb_dt_import):
    handle = MagicMock()
    args = SimpleNamespace(only_new=True, update=False, remove_components=False)

    nb_dt_import.log_run_mode(handle, args)

    messages = [call.args[0] for call in handle.log.call_args_list]
    assert any("--only-new enabled" in message for message in messages)


def test_should_only_create_new_modules_default_mode(nb_dt_import):
    args = SimpleNamespace(only_new=False, update=False)
    assert nb_dt_import.should_only_create_new_modules(args)


def test_should_only_create_new_modules_update_mode(nb_dt_import):
    args = SimpleNamespace(only_new=False, update=True)
    assert not nb_dt_import.should_only_create_new_modules(args)


def test_should_only_create_new_modules_only_new_flag(nb_dt_import):
    args = SimpleNamespace(only_new=True, update=True)
    assert nb_dt_import.should_only_create_new_modules(args)


def test_filter_new_device_types_by_model_and_slug(nb_dt_import):

    device_types = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "cisco"}, "model": "B", "slug": "b"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c-renamed"},
    ]
    existing_by_model = {("cisco", "A"): object()}
    existing_by_slug = {("juniper", "c-renamed"): object()}

    filtered = nb_dt_import.filter_new_device_types(device_types, existing_by_model, existing_by_slug)

    assert filtered == [{"manufacturer": {"slug": "cisco"}, "model": "B", "slug": "b"}]


def test_has_missing_device_images_detects_image_changes(nb_dt_import):

    image_change = SimpleNamespace(property_name="front_image")
    non_image_change = SimpleNamespace(property_name="part_number")
    report = SimpleNamespace(
        modified_device_types=[
            SimpleNamespace(property_changes=[non_image_change]),
            SimpleNamespace(property_changes=[image_change]),
        ]
    )

    assert nb_dt_import.has_missing_device_images(report)


def test_has_missing_device_images_detects_rear_image_changes(nb_dt_import):
    image_change = SimpleNamespace(property_name="rear_image")
    report = SimpleNamespace(
        modified_device_types=[
            SimpleNamespace(property_changes=[image_change]),
        ]
    )

    assert nb_dt_import.has_missing_device_images(report)


def test_has_missing_device_images_returns_false_for_none_report(nb_dt_import):
    assert not nb_dt_import.has_missing_device_images(None)


def test_has_missing_device_images_returns_false_when_no_image_changes(nb_dt_import):
    report = SimpleNamespace(
        modified_device_types=[
            SimpleNamespace(property_changes=[SimpleNamespace(property_name="part_number")]),
            SimpleNamespace(property_changes=[SimpleNamespace(property_name="u_height")]),
        ]
    )

    assert not nb_dt_import.has_missing_device_images(report)


def test_select_device_types_for_default_mode_scopes_to_new_and_missing_images(
    nb_dt_import,
):
    device_types = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "cisco"}, "model": "B", "slug": "b"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c"},
    ]
    change_report = SimpleNamespace(
        new_device_types=[
            SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a"),
        ],
        modified_device_types=[
            SimpleNamespace(
                manufacturer_slug="juniper",
                model="C",
                slug="c",
                property_changes=[SimpleNamespace(property_name="front_image")],
            ),
            SimpleNamespace(
                manufacturer_slug="cisco",
                model="B",
                slug="b",
                property_changes=[SimpleNamespace(property_name="part_number")],
            ),
        ],
    )

    selected = nb_dt_import.select_device_types_for_default_mode(device_types, change_report)

    expected = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c"},
    ]
    key = _dt_sort_key
    assert sorted(selected, key=key) == sorted(expected, key=key)


def test_select_device_types_for_update_mode_scopes_to_new_and_modified(nb_dt_import):
    device_types = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "cisco"}, "model": "B", "slug": "b"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c"},
    ]
    change_report = SimpleNamespace(
        new_device_types=[
            SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a"),
        ],
        modified_device_types=[
            SimpleNamespace(
                manufacturer_slug="juniper",
                model="C",
                slug="c",
                property_changes=[SimpleNamespace(property_name="part_number")],
            ),
        ],
    )

    selected = nb_dt_import.select_device_types_for_update_mode(device_types, change_report)

    expected = [
        {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"},
        {"manufacturer": {"slug": "juniper"}, "model": "C", "slug": "c"},
    ]
    key = _dt_sort_key
    assert sorted(selected, key=key) == sorted(expected, key=key)


def test_items_per_second_column_handles_empty_speed(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(SimpleNamespace(finished=False, speed=None))

    assert str(rendered) == "- it/s"


def test_items_per_second_column_renders_speed_value(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(SimpleNamespace(finished=False, speed=12.34))

    assert str(rendered) == "12.3 it/s"


def test_items_per_second_column_uses_elapsed_fallback(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(
        SimpleNamespace(
            finished=False,
            speed=None,
            completed=120,
            elapsed=10,
        )
    )

    assert str(rendered) == "12.0 it/s"


def test_items_per_second_column_uses_finished_speed_when_available(nb_dt_import):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(SimpleNamespace(finished=True, speed=None, finished_speed=5.0))

    assert str(rendered) == "5.0 it/s"


def test_items_per_second_column_uses_elapsed_fallback_when_finished_speed_missing(
    nb_dt_import,
):
    column = nb_dt_import.ItemsPerSecondColumn()

    rendered = column.render(
        SimpleNamespace(
            finished=True,
            speed=None,
            finished_speed=None,
            completed=200,
            elapsed=25,
        )
    )

    assert str(rendered) == "8.0 it/s"


# ---------------------------------------------------------------------------
# Helpers shared across TestMain and TestEntryPoint
# ---------------------------------------------------------------------------

_NB_DT_IMPORT_PATH = str(Path(__file__).resolve().parents[1] / "nb-dt-import.py")
_PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _make_mock_repo(device_types=None):
    """Return a pre-configured DTLRepo mock with no files by default."""
    mock_repo = MagicMock()
    mock_repo.get_devices.return_value = ([], [])
    mock_repo.get_devices_path.return_value = "/tmp/devices"
    mock_repo.get_modules_path.return_value = "/tmp/modules"
    mock_repo.get_racks_path.return_value = "/tmp/rack-types"
    mock_repo.discover_vendors.return_value = []
    mock_repo.parse_files.return_value = device_types if device_types is not None else []
    mock_repo.resolve_slug_files.return_value = None  # no pickle available by default
    return mock_repo


def _make_mock_netbox(modules=False, rack_types=False):
    """Return a pre-configured NetBox mock."""
    from collections import Counter

    mock_nb = MagicMock()
    mock_nb.modules = modules
    mock_nb.rack_types = rack_types
    mock_nb.device_types.existing_device_types = {}
    mock_nb.device_types.existing_device_types_by_slug = {}
    mock_nb.count_device_type_images.return_value = 0
    mock_nb.count_module_type_images.return_value = 0
    mock_nb.filter_actionable_module_types.return_value = ([], {}, [])
    mock_nb.get_existing_module_types.return_value = {}
    mock_nb.get_existing_rack_types.return_value = {}
    mock_nb.counter = Counter(
        added=0,
        components_added=0,
        manufacturer=0,
        module_added=3,
        module_updated=2,
        module_update_failed=0,
        rack_type_added=0,
        rack_type_updated=0,
        images=0,
        properties_updated=0,
        components_updated=0,
        components_removed=0,
        device_types_failed=0,
    )
    return mock_nb


def _empty_change_report():
    """Return a SimpleNamespace change report with no changes."""
    return SimpleNamespace(new_device_types=[], modified_device_types=[])


# ---------------------------------------------------------------------------
# MyProgress
# ---------------------------------------------------------------------------


class TestMyProgress:
    """Tests for the MyProgress Rich Progress subclass."""

    def test_get_renderables_yields_panel(self, nb_dt_import):
        """get_renderables yields exactly one Panel wrapping the tasks table."""
        from rich.panel import Panel

        progress = nb_dt_import.MyProgress()
        renderables = list(progress.get_renderables())

        assert len(renderables) == 1
        assert isinstance(renderables[0], Panel)


# ---------------------------------------------------------------------------
# get_progress_panel
# ---------------------------------------------------------------------------


class TestGetProgressPanel:
    """Tests for the get_progress_panel context manager."""

    def test_non_tty_yields_none(self, nb_dt_import):
        """Yields None when stdout is not a TTY (the default in CI/tests)."""
        with nb_dt_import.get_progress_panel() as progress:
            assert progress is None

    def test_tty_yields_my_progress_instance(self, nb_dt_import):
        """Yields a MyProgress instance when stdout is a TTY."""
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            with nb_dt_import.get_progress_panel() as progress:
                assert isinstance(progress, nb_dt_import.MyProgress)

    def test_tty_with_show_remaining_time_adds_column(self, nb_dt_import):
        """show_remaining_time=True appends a TimeRemainingColumn without error."""
        with patch("sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = True
            with nb_dt_import.get_progress_panel(show_remaining_time=True) as progress:
                assert progress is not None


# ---------------------------------------------------------------------------
# get_progress_wrapper
# ---------------------------------------------------------------------------


class TestGetProgressWrapper:
    """Tests for the get_progress_wrapper function."""

    def test_none_progress_returns_original_iterable(self, nb_dt_import):
        """Returns the iterable unchanged when progress is None."""
        items = [1, 2, 3]
        result = nb_dt_import.get_progress_wrapper(None, items)
        assert result is items

    def test_wraps_iterable_and_advances_task(self, nb_dt_import):
        """Consumes items, advances progress, and stops the task on finish."""
        mock_progress = MagicMock()
        mock_progress.add_task.return_value = 7

        result = list(nb_dt_import.get_progress_wrapper(mock_progress, [10, 20, 30], desc="Test"))

        assert result == [10, 20, 30]
        mock_progress.add_task.assert_called_once()
        assert mock_progress.advance.call_count == 3
        mock_progress.stop_task.assert_called_once_with(7)

    def test_on_step_called_per_item_and_in_finally(self, nb_dt_import):
        """on_step is called once per item and once more in the finally block."""
        mock_progress = MagicMock()
        mock_progress.add_task.return_value = 1
        on_step = MagicMock()

        list(nb_dt_import.get_progress_wrapper(mock_progress, [1, 2], on_step=on_step))

        # 2 items + 1 in finally = 3
        assert on_step.call_count == 3

    def test_generator_without_len_triggers_update_in_finally(self, nb_dt_import):
        """When iterable has no len(), total stays None and update() is called."""
        mock_progress = MagicMock()
        mock_progress.add_task.return_value = 1

        def gen():
            yield 1
            yield 2

        result = list(nb_dt_import.get_progress_wrapper(mock_progress, gen(), total=None))

        assert result == [1, 2]
        mock_progress.update.assert_called()

    def test_explicit_total_skips_update_in_finally(self, nb_dt_import):
        """When total is provided up front, update() is NOT called in finally."""
        mock_progress = MagicMock()
        mock_progress.add_task.return_value = 1

        list(nb_dt_import.get_progress_wrapper(mock_progress, [1, 2], total=2))

        mock_progress.update.assert_not_called()


# ---------------------------------------------------------------------------
# filter_device_types_by_change_keys – empty-keys branch
# ---------------------------------------------------------------------------


class TestFilterDeviceTypesByChangeKeys:
    """Tests for filter_device_types_by_change_keys edge cases."""

    def test_empty_change_keys_returns_empty_list(self, nb_dt_import):
        """Returns [] immediately when change_keys is an empty set."""
        device_types = [{"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"}]
        result = nb_dt_import.filter_device_types_by_change_keys(device_types, set())
        assert result == []


# ---------------------------------------------------------------------------
# select_device_types_* – None report branches
# ---------------------------------------------------------------------------


class TestSelectDeviceTypesNoneReport:
    """Tests for select_device_types_* functions with a None change report."""

    def test_select_default_mode_none_report_returns_empty(self, nb_dt_import):
        """Returns [] when change_report is None (default mode)."""
        result = nb_dt_import.select_device_types_for_default_mode([], None)
        assert result == []

    def test_select_update_mode_none_report_returns_empty(self, nb_dt_import):
        """Returns [] when change_report is None (update mode)."""
        result = nb_dt_import.select_device_types_for_update_mode([], None)
        assert result == []


# ---------------------------------------------------------------------------
# _image_progress_scope
# ---------------------------------------------------------------------------


class TestImageProgressScope:
    """Tests for the _image_progress_scope context manager."""

    def test_none_progress_resets_attribute_to_none(self, nb_dt_import):
        """Even with progress=None, _image_progress is reset to None on exit."""
        mock_dt = MagicMock()
        with nb_dt_import._image_progress_scope(None, mock_dt, total=5):
            pass
        assert mock_dt._image_progress is None

    def test_zero_total_does_not_create_task(self, nb_dt_import):
        """With total=0, no progress task is created."""
        mock_progress = MagicMock()
        mock_dt = MagicMock()

        with nb_dt_import._image_progress_scope(mock_progress, mock_dt, total=0):
            pass

        mock_progress.add_task.assert_not_called()
        assert mock_dt._image_progress is None

    def test_positive_total_creates_task_and_wires_callback(self, nb_dt_import):
        """Creates a task and sets _image_progress; clears it on exit."""
        mock_progress = MagicMock()
        mock_progress.add_task.return_value = 42
        mock_dt = MagicMock()

        with nb_dt_import._image_progress_scope(mock_progress, mock_dt, total=3):
            assert mock_dt._image_progress is not None
            mock_dt._image_progress(2)  # simulate uploading 2 images

        assert mock_dt._image_progress is None
        mock_progress.add_task.assert_called_once_with("Uploading Images", total=3)
        mock_progress.update.assert_called_with(42, advance=2)

    def test_cleanup_on_exception(self, nb_dt_import):
        """_image_progress is reset to None even when the body raises."""
        mock_progress = MagicMock()
        mock_progress.add_task.return_value = 1
        mock_dt = MagicMock()

        with pytest.raises(ValueError):
            with nb_dt_import._image_progress_scope(mock_progress, mock_dt, total=3):
                raise ValueError("boom")

        assert mock_dt._image_progress is None


# ---------------------------------------------------------------------------
# main() – comprehensive branch coverage
# ---------------------------------------------------------------------------


class TestMain:
    """Tests for the main() orchestration function covering all branches."""

    def test_only_new_no_device_types(self, nb_dt_import):
        """--only-new with no matching files logs 'No new device types'."""
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
        ):
            MockRepo.return_value = _make_mock_repo()
            MockNetBox.return_value = _make_mock_netbox()

            nb_dt_import.main()

    def test_only_new_creates_new_device_types(self, nb_dt_import):
        """--only-new calls create_device_types for genuinely new types."""
        dt = [{"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"}]
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
        ):
            mock_repo = _make_mock_repo(device_types=dt)
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            mock_repo.get_devices.return_value = (["file.yaml"], [])
            MockRepo.return_value = mock_repo
            MockNetBox.return_value = _make_mock_netbox()

            nb_dt_import.main()

            MockNetBox.return_value.create_device_types.assert_called_once()

    def test_default_mode_no_device_types(self, nb_dt_import):
        """Default mode with no discovered vendors completes without error."""
        with (
            patch.object(sys, "argv", ["nb-dt-import.py"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            MockRepo.return_value = _make_mock_repo()
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()

            nb_dt_import.main()

    def test_default_mode_with_new_device_types(self, nb_dt_import):
        """Default mode creates new device types when change report lists them."""
        dt = [{"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"}]
        change_entry = SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a")
        report = SimpleNamespace(new_device_types=[change_entry], modified_device_types=[])

        with (
            patch.object(sys, "argv", ["nb-dt-import.py"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_repo = _make_mock_repo(device_types=dt)
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            mock_repo.get_devices.return_value = (["file.yaml"], [])
            MockRepo.return_value = mock_repo
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = report

            nb_dt_import.main()

            MockNetBox.return_value.create_device_types.assert_called_once()

    def test_update_mode_no_changes(self, nb_dt_import):
        """--update with no changes logs 'No device type changes to process'."""
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--update"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            MockRepo.return_value = _make_mock_repo()
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()

            nb_dt_import.main()

    def test_update_mode_with_changes(self, nb_dt_import):
        """--update with changed types calls create_device_types with update=True."""
        dt = [{"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"}]
        change_entry = SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a")
        report = SimpleNamespace(new_device_types=[change_entry], modified_device_types=[])

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--update"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_repo = _make_mock_repo(device_types=dt)
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            mock_repo.get_devices.return_value = (["file.yaml"], [])
            MockRepo.return_value = mock_repo
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = report

            nb_dt_import.main()

            call_kwargs = MockNetBox.return_value.create_device_types.call_args[1]
            assert call_kwargs.get("update") is True

    def test_update_with_remove_components(self, nb_dt_import):
        """--update --remove-components passes remove_components=True to create_device_types."""
        dt = [{"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"}]
        change_entry = SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a")
        report = SimpleNamespace(new_device_types=[change_entry], modified_device_types=[])

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--update", "--remove-components"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_repo = _make_mock_repo(device_types=dt)
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            mock_repo.get_devices.return_value = (["file.yaml"], [])
            MockRepo.return_value = mock_repo
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = report

            nb_dt_import.main()

            call_kwargs = MockNetBox.return_value.create_device_types.call_args[1]
            assert call_kwargs.get("remove_components") is True

    def test_remove_components_without_update_exits_with_error(self, nb_dt_import):
        """--remove-components without --update triggers parser.error (SystemExit 2)."""
        with patch.object(sys, "argv", ["nb-dt-import.py", "--remove-components"]):
            with pytest.raises(SystemExit) as exc_info:
                nb_dt_import.main()
        assert exc_info.value.code == 2

    def test_remove_unmanaged_types_without_remove_components_exits_with_error(self, nb_dt_import):
        """--remove-unmanaged-types without --remove-components triggers parser.error (SystemExit 2)."""
        with patch.object(sys, "argv", ["nb-dt-import.py", "--update", "--remove-unmanaged-types"]):
            with pytest.raises(SystemExit) as exc_info:
                nb_dt_import.main()
        assert exc_info.value.code == 2

    def test_update_with_remove_unmanaged_types_sets_attribute_and_detector_kwarg(self, nb_dt_import):
        """--update --remove-components --remove-unmanaged-types propagates to NetBox and ChangeDetector."""
        dt = [{"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"}]
        change_entry = SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a")
        report = SimpleNamespace(new_device_types=[change_entry], modified_device_types=[])

        with (
            patch.object(
                sys,
                "argv",
                ["nb-dt-import.py", "--update", "--remove-components", "--remove-unmanaged-types"],
            ),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_repo = _make_mock_repo(device_types=dt)
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            mock_repo.get_devices.return_value = (["file.yaml"], [])
            MockRepo.return_value = mock_repo
            mock_nb = _make_mock_netbox()
            MockNetBox.return_value = mock_nb
            MockDetector.return_value.detect_changes.return_value = report

            nb_dt_import.main()

            assert mock_nb.remove_unmanaged_types is True
            # ChangeDetector instantiated with remove_unmanaged_types=True
            _, detector_kwargs = MockDetector.call_args
            assert detector_kwargs.get("remove_unmanaged_types") is True

    def test_force_resolve_conflicts_without_update_exits_with_error(self, nb_dt_import):
        """--force-resolve-conflicts without --update triggers parser.error (SystemExit 2)."""
        with patch.object(sys, "argv", ["nb-dt-import.py", "--force-resolve-conflicts"]):
            with pytest.raises(SystemExit) as exc_info:
                nb_dt_import.main()
        assert exc_info.value.code == 2

    def test_update_with_force_resolve_conflicts(self, nb_dt_import):
        """--update --force-resolve-conflicts sets netbox.force_resolve_conflicts=True."""
        dt = [{"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"}]
        change_entry = SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a")
        report = SimpleNamespace(new_device_types=[change_entry], modified_device_types=[])

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--update", "--force-resolve-conflicts"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_repo = _make_mock_repo(device_types=dt)
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            mock_repo.get_devices.return_value = (["file.yaml"], [])
            MockRepo.return_value = mock_repo
            mock_nb = _make_mock_netbox()
            MockNetBox.return_value = mock_nb
            MockDetector.return_value.detect_changes.return_value = report

            nb_dt_import.main()

            assert mock_nb.force_resolve_conflicts is True

    def test_verify_images_sets_attribute(self, nb_dt_import):
        """--verify-images propagates to netbox.verify_images = True."""
        dt = [{"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "a"}]
        change_entry = SimpleNamespace(manufacturer_slug="cisco", model="A", slug="a")
        report = SimpleNamespace(new_device_types=[change_entry], modified_device_types=[])

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--update", "--verify-images"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_repo = _make_mock_repo(device_types=dt)
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            mock_repo.get_devices.return_value = (["file.yaml"], [])
            MockRepo.return_value = mock_repo
            mock_nb = _make_mock_netbox()
            MockNetBox.return_value = mock_nb
            MockDetector.return_value.detect_changes.return_value = report

            nb_dt_import.main()

            assert mock_nb.verify_images is True

    def test_missing_env_var_triggers_system_exit(self, nb_dt_import):
        """A missing mandatory env var calls handle.exception which exits."""
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]),
            patch("nb_dt_import.DTLRepo"),
            patch("nb_dt_import.NetBox"),
            patch.dict(os.environ, {}, clear=True),
        ):
            with pytest.raises(SystemExit):
                nb_dt_import.main()

    def test_vendors_and_slugs_flags_log_lines(self, nb_dt_import):
        """--vendors and --slugs args cause their respective log lines to execute."""
        with (
            patch.object(
                sys,
                "argv",
                ["nb-dt-import.py", "--vendors", "cisco", "--slugs", "ws-c3750"],
            ),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_repo = _make_mock_repo()
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            MockRepo.return_value = mock_repo
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()

            nb_dt_import.main()  # should not raise

    def test_unknown_vendors_exits_nonzero(self, nb_dt_import):
        """--vendors with no matching slug exits with code 1 instead of silently doing nothing."""
        with (
            patch.object(
                sys,
                "argv",
                ["nb-dt-import.py", "--vendors", "nonexistent-vendor"],
            ),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox"),
        ):
            mock_repo = _make_mock_repo()
            mock_repo.discover_vendors.return_value = [{"name": "Nokia", "slug": "nokia"}]
            MockRepo.return_value = mock_repo
            with pytest.raises(SystemExit) as exc_info:
                nb_dt_import.main()
            assert exc_info.value.code == 1

    def test_modules_with_types_to_process(self, nb_dt_import):
        """modules=True + non-empty filter_actionable_module_types calls create_module_types."""
        module_type = {"manufacturer": {"slug": "cisco"}, "model": "CM1", "slug": "cm1"}

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--update"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_nb = _make_mock_netbox(modules=True)
            mock_nb.filter_actionable_module_types.return_value = ([module_type], {}, [])
            MockNetBox.return_value = mock_nb
            MockNetBox.filter_new_module_types.return_value = []

            mock_repo = _make_mock_repo()
            mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
            mock_repo.get_devices.return_value = ([], [])
            # parse_files returns the module type for any call
            mock_repo.parse_files.return_value = [module_type]
            MockRepo.return_value = mock_repo
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()

            nb_dt_import.main()

            mock_nb.create_module_types.assert_called_once()

    def test_modules_update_mode_logs_change_detection_section(self, nb_dt_import):
        """--update with modules=True logs the MODULE TYPE CHANGE DETECTION header."""
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--update"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_nb = _make_mock_netbox(modules=True)
            mock_nb.filter_actionable_module_types.return_value = ([], {}, [])
            MockNetBox.return_value = mock_nb
            MockNetBox.filter_new_module_types.return_value = []
            MockRepo.return_value = _make_mock_repo()
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()

            nb_dt_import.main()  # should not raise

    def test_settings_netbox_features_modules_logs_module_count(self, nb_dt_import):
        """When netbox.modules is True, module_added/updated counters are logged."""
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.LogHandler") as MockLogHandler,
        ):
            MockRepo.return_value = _make_mock_repo()
            mock_nb = _make_mock_netbox(modules=True)
            MockNetBox.return_value = mock_nb

            nb_dt_import.main()

        log_calls = [str(c) for c in MockLogHandler.return_value.log.call_args_list]
        logged = " ".join(log_calls)
        assert "3 modules created" in logged
        assert "2 modules updated" in logged

    def test_progress_panel_tty_sets_console_and_pumps_preload(self, nb_dt_import):
        """With a TTY progress, set_console is called and pump_preload wired up."""
        MockMyProgress = MagicMock()
        mock_prog = MagicMock()
        MockMyProgress.return_value.__enter__ = MagicMock(return_value=mock_prog)
        MockMyProgress.return_value.__exit__ = MagicMock(return_value=False)

        with (
            patch.object(sys, "argv", ["nb-dt-import.py"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
            patch("nb_dt_import.LogHandler") as MockLogHandler,
            patch("sys.stdout") as mock_stdout,
            patch("nb_dt_import.MyProgress", MockMyProgress),
        ):
            mock_stdout.isatty.return_value = True
            MockRepo.return_value = _make_mock_repo()
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()
            mock_handle = MockLogHandler.return_value

            nb_dt_import.main()

            # handle.set_console(progress.console) must have been called
            mock_handle.set_console.assert_any_call(mock_prog.console)


# ---------------------------------------------------------------------------
# _process_rack_types
# ---------------------------------------------------------------------------


class TestProcessRackTypes:
    """Tests for the _process_rack_types() helper function."""

    def _make_args(self, only_new=False):
        return SimpleNamespace(only_new=only_new)

    def test_rack_types_disabled_logs_warning_and_returns(self, nb_dt_import):
        """netbox.rack_types=False with actual rack types: warning logged, no further processing."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = False

        rack_type = {"manufacturer": {"slug": "apc"}, "model": "AR1300", "slug": "apc-ar1300"}
        nb_dt_import._process_rack_types(self._make_args(), netbox, handle, None, [rack_type])

        handle.log.assert_called_once()
        assert "4.1" in handle.log.call_args[0][0]
        netbox.get_existing_rack_types.assert_not_called()

    def test_empty_rack_types_returns_early(self, nb_dt_import):
        """rack_types=[]: returns immediately without any logging or API calls."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = True

        nb_dt_import._process_rack_types(self._make_args(), netbox, handle, None, [])

        handle.log.assert_not_called()
        handle.verbose_log.assert_not_called()
        netbox.get_existing_rack_types.assert_not_called()
        netbox.create_rack_types.assert_not_called()

    def test_full_flow_calls_create_rack_types(self, nb_dt_import):
        """Full flow: pre-parsed rack_types provided, create_rack_types called."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = True
        netbox.get_existing_rack_types.return_value = {}

        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
        }

        nb_dt_import._process_rack_types(self._make_args(), netbox, handle, None, [rack_type])

        netbox.create_rack_types.assert_called_once()

    def test_existing_rack_type_shows_as_existing(self, nb_dt_import):
        """A rack type already in NetBox is counted as existing, not new."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = True
        netbox.get_existing_rack_types.return_value = {"apc": {"AR1300": object()}}

        rack_type = {
            "manufacturer": {"slug": "apc"},
            "model": "AR1300",
            "slug": "apc-ar1300",
        }

        nb_dt_import._process_rack_types(self._make_args(), netbox, handle, None, [rack_type])

        log_calls = [call.args[0] for call in handle.verbose_log.call_args_list]
        assert any("No new rack types (1 unchanged)" in msg for msg in log_calls)


# ---------------------------------------------------------------------------
# if __name__ == "__main__" entry point
# ---------------------------------------------------------------------------


class TestEntryPoint:
    """Tests for the if __name__ == '__main__' entry point block."""

    def test_entry_point_calls_main_normally(self):
        """Running the script as __main__ with mocked deps completes without error."""
        with (
            patch("core.repo.DTLRepo") as MockDTLRepo,
            patch("core.netbox_api.NetBox") as MockNetBox,
        ):
            MockDTLRepo.return_value = _make_mock_repo()
            MockNetBox.return_value = _make_mock_netbox()

            with patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]):
                runpy.run_path(_NB_DT_IMPORT_PATH, run_name="__main__")

    def test_entry_point_keyboard_interrupt_exits_130(self):
        """KeyboardInterrupt raised inside main() becomes SystemExit(130)."""
        with patch("core.repo.DTLRepo") as MockDTLRepo, patch("core.netbox_api.NetBox"):
            MockDTLRepo.side_effect = KeyboardInterrupt()

            with patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]):
                with pytest.raises(SystemExit) as exc_info:
                    runpy.run_path(_NB_DT_IMPORT_PATH, run_name="__main__")

        assert exc_info.value.code == 130

    def test_entry_point_connection_error_exits_1(self):
        """requests.ConnectionError mid-run becomes SystemExit(1) with informative message."""
        import requests as _requests

        with patch("core.repo.DTLRepo") as MockDTLRepo, patch("core.netbox_api.NetBox"):
            MockDTLRepo.side_effect = _requests.exceptions.ConnectionError("Remote end closed connection")

            with patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]):
                with pytest.raises(SystemExit) as exc_info:
                    runpy.run_path(_NB_DT_IMPORT_PATH, run_name="__main__")

        assert exc_info.value.code == 1

    def test_entry_point_connection_error_message_references_netbox(self, capsys):
        """ConnectionError prints a human-friendly message (not a raw traceback)."""
        import requests as _requests

        with patch("core.repo.DTLRepo") as MockDTLRepo, patch("core.netbox_api.NetBox"):
            MockDTLRepo.side_effect = _requests.exceptions.ConnectionError("Remote end closed")

            with patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]):
                with pytest.raises(SystemExit):
                    runpy.run_path(_NB_DT_IMPORT_PATH, run_name="__main__")

        captured = capsys.readouterr()
        assert "connection" in captured.err.lower() or "netbox" in captured.err.lower()
        assert "Traceback" not in captured.err


# ---------------------------------------------------------------------------
# Per-vendor loop behaviour
# ---------------------------------------------------------------------------


class TestPerVendorLoop:
    """Tests for the per-vendor iteration logic in main()."""

    def _run_main(self, argv, mock_repo, mock_nb, nb_dt_import_module, mock_detector=None):
        with (
            patch.object(sys, "argv", argv),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            MockRepo.return_value = mock_repo
            MockNetBox.return_value = mock_nb
            if mock_detector is not None:
                MockDetector.return_value.detect_changes.return_value = mock_detector
            else:
                MockDetector.return_value.detect_changes.return_value = _empty_change_report()
            nb_dt_import_module.main()

    def test_vendor_flag_only_processes_matching_vendor(self, nb_dt_import):
        """--vendors cisco: load_vendor called only for cisco, not for juniper."""
        cisco_dt = {"manufacturer": {"slug": "cisco"}, "model": "C1", "slug": "cisco-c1"}
        juniper_dt = {"manufacturer": {"slug": "juniper"}, "model": "J1", "slug": "juniper-j1"}

        mock_nb = _make_mock_netbox()
        mock_repo = _make_mock_repo()
        mock_repo.discover_vendors.return_value = [
            {"name": "Cisco", "slug": "cisco"},
            {"name": "Juniper", "slug": "juniper"},
        ]

        def _get_devices_se(path, vendors):
            if vendors == ["cisco"]:
                return (["cisco.yaml"], [])
            if vendors == ["juniper"]:
                return (["juniper.yaml"], [])
            return ([], [])

        def _parse_files_se(files, slugs=None, progress=None):
            if "cisco.yaml" in files:
                return [cisco_dt]
            if "juniper.yaml" in files:
                return [juniper_dt]
            return []

        mock_repo.get_devices.side_effect = _get_devices_se
        mock_repo.parse_files.side_effect = _parse_files_se

        self._run_main(["nb-dt-import.py", "--vendors", "cisco"], mock_repo, mock_nb, nb_dt_import)

        slugs_loaded = [call.args[0] for call in mock_nb.load_vendor.call_args_list]
        assert "cisco" in slugs_loaded
        assert "juniper" not in slugs_loaded

    def test_no_vendor_flag_processes_all_vendors(self, nb_dt_import):
        """Without --vendors: load_vendor called for every discovered vendor."""
        cisco_dt = {"manufacturer": {"slug": "cisco"}, "model": "C1", "slug": "cisco-c1"}
        arista_dt = {"manufacturer": {"slug": "arista"}, "model": "A1", "slug": "arista-a1"}

        mock_nb = _make_mock_netbox()
        mock_repo = _make_mock_repo()
        mock_repo.discover_vendors.return_value = [
            {"name": "Cisco", "slug": "cisco"},
            {"name": "Arista", "slug": "arista"},
        ]

        def _get_devices_se(path, vendors):
            if vendors == ["cisco"]:
                return (["cisco.yaml"], [])
            if vendors == ["arista"]:
                return (["arista.yaml"], [])
            return ([], [])

        def _parse_files_se(files, slugs=None, progress=None):
            if "cisco.yaml" in files:
                return [cisco_dt]
            if "arista.yaml" in files:
                return [arista_dt]
            return []

        mock_repo.get_devices.side_effect = _get_devices_se
        mock_repo.parse_files.side_effect = _parse_files_se

        self._run_main(["nb-dt-import.py"], mock_repo, mock_nb, nb_dt_import)

        slugs_loaded = [call.args[0] for call in mock_nb.load_vendor.call_args_list]
        assert "cisco" in slugs_loaded
        assert "arista" in slugs_loaded

    def test_slug_filter_skips_vendor_with_no_matching_types(self, nb_dt_import):
        """--slug other-slug: vendor whose parsed files don't match the slug is skipped."""
        mock_nb = _make_mock_netbox()
        mock_repo = _make_mock_repo()
        mock_repo.discover_vendors.return_value = [{"name": "APC", "slug": "apc"}]
        mock_repo.get_devices.return_value = (["file.yaml"], [])
        # parse_files returns empty regardless (slug filter stripped all matches)
        mock_repo.parse_files.return_value = []

        self._run_main(["nb-dt-import.py", "--slugs", "other-slug"], mock_repo, mock_nb, nb_dt_import)

        mock_nb.load_vendor.assert_not_called()

    def test_vendor_with_matching_slug_is_processed(self, nb_dt_import):
        """Vendor whose slug matches parsed files does call load_vendor."""
        mock_nb = _make_mock_netbox()
        mock_repo = _make_mock_repo()
        mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
        dt = {"manufacturer": {"slug": "cisco"}, "model": "A", "slug": "cisco-a"}
        mock_repo.get_devices.return_value = (["file.yaml"], [])
        mock_repo.parse_files.return_value = [dt]

        self._run_main(["nb-dt-import.py"], mock_repo, mock_nb, nb_dt_import)

        mock_nb.load_vendor.assert_called_with("cisco")

    def test_module_type_only_vendor_uses_scoped_preload(self, nb_dt_import):
        """Vendor with only module types (no device types) must use scoped preload.

        Regression: the preload guard used to check ``parsed_device_types`` only,
        causing module-type-only vendors to fall back to the unscoped global preload.
        """
        mt = {"manufacturer": {"slug": "acbel"}, "model": "M1", "slug": "acbel-m1"}

        mock_nb = _make_mock_netbox(modules=True)
        mock_repo = _make_mock_repo()
        mock_repo.discover_vendors.return_value = [{"name": "Acbel", "slug": "acbel"}]

        def _get_devices_se(path, vendors):
            # Return module file only when querying the modules path
            if "module" in path:
                return (["module.yaml"], [])
            return ([], [])

        def _parse_files_se(files, slugs=None, progress=None):
            if "module.yaml" in files:
                return [mt]
            return []

        mock_repo.get_devices.side_effect = _get_devices_se
        mock_repo.parse_files.side_effect = _parse_files_se

        self._run_main(["nb-dt-import.py"], mock_repo, mock_nb, nb_dt_import)

        mock_nb.device_types.start_component_preload.assert_called_once()
        call_kwargs = mock_nb.device_types.start_component_preload.call_args
        assert call_kwargs.kwargs.get("manufacturer_slug") == "acbel"

        # The unscoped preload_all_components (no manufacturer_slug) must NOT be called
        for call in mock_nb.device_types.preload_all_components.call_args_list:
            assert call.kwargs.get("manufacturer_slug") is not None, (
                "preload_all_components called without manufacturer_slug (global fetch triggered)"
            )


# ---------------------------------------------------------------------------
# _process_module_types hints and counters (lines 554-559, 572, 574-575)
# ---------------------------------------------------------------------------


class TestProcessModuleTypesHints:
    """Tests for pending-removal counters and hint log lines in _process_module_types."""

    def _make_args(self, only_new=False, update=False, remove_components=False):
        return SimpleNamespace(
            only_new=only_new,
            update=update,
            remove_components=remove_components,
            vendors=None,
            slugs=None,
        )

    def test_pending_removal_counters_and_hints(self, nb_dt_import):
        """changed_property_log with COMPONENT_REMOVED entries increments pending counters.

        Emits both --update and --remove-components hints when flags are absent.
        """
        from core.change_detector import ChangeType

        comp_change = MagicMock()
        comp_change.change_type = ChangeType.COMPONENT_REMOVED
        changed_property_log = [("cisco", "CM1", [], [comp_change, comp_change])]

        handle = MagicMock()
        mock_nb = MagicMock()
        mock_nb.get_existing_module_types.return_value = {}
        module_to_process = {"manufacturer": {"slug": "cisco"}, "model": "CM1"}
        mock_nb.filter_actionable_module_types.return_value = (
            [module_to_process],
            {},
            changed_property_log,
        )
        mock_nb.count_module_type_images.return_value = 0

        mock_repo = MagicMock()
        mock_repo.get_devices.return_value = ([], [])

        nb_dt_import._process_module_types(
            self._make_args(only_new=False, update=False, remove_components=False),
            mock_nb,
            handle,
            None,
            [module_to_process],
        )

        logged = [call.args[0] for call in handle.log.call_args_list]
        # --update hint should appear (module_changed_count > 0, update=False)
        assert any("--update" in msg for msg in logged)
        # Removal guidance must include --update and --remove-components in the same hint.
        assert any("--update --remove-components" in msg for msg in logged)
        # The hint must report the actual counts: 2 components across 1 module type.
        assert any("2 stale component" in msg for msg in logged)
        assert any("1 module type" in msg for msg in logged)


# ---------------------------------------------------------------------------
# _log_run_summary rack_types and duplicate_definitions (lines 687-688, 697-700)
# ---------------------------------------------------------------------------


class TestLogRunSummary:
    """Tests for _log_run_summary rack_type and duplicate-definitions branches."""

    def test_rack_types_counters_are_logged(self, nb_dt_import):
        """When netbox.rack_types is True, rack_type_added/updated counters are logged."""
        from datetime import datetime

        handle = MagicMock()
        mock_nb = MagicMock()
        mock_nb.modules = False
        mock_nb.rack_types = True
        from collections import Counter

        mock_nb.counter = Counter(
            {
                "added": 0,
                "properties_updated": 0,
                "components_updated": 0,
                "components_added": 0,
                "components_removed": 0,
                "images": 0,
                "manufacturer": 0,
                "rack_type_added": 3,
                "rack_type_updated": 1,
            }
        )

        nb_dt_import._log_run_summary(handle, mock_nb, datetime.now())

        logged = [call.args[0] for call in handle.log.call_args_list]
        assert any("3 rack types created" in msg for msg in logged)
        assert any("1 rack types updated" in msg for msg in logged)

    def test_duplicate_definitions_are_logged(self, nb_dt_import):
        """When dtl_repo has duplicate_definitions, each entry is logged with kept/ignored."""
        from datetime import datetime

        handle = MagicMock()
        mock_nb = MagicMock()
        mock_nb.modules = False
        mock_nb.rack_types = False
        from collections import Counter

        mock_nb.counter = Counter(
            {
                "added": 0,
                "properties_updated": 0,
                "components_updated": 0,
                "components_added": 0,
                "components_removed": 0,
                "images": 0,
                "manufacturer": 0,
            }
        )

        mock_repo = MagicMock()
        mock_repo.duplicate_definitions = [
            {
                "manufacturer": "cisco",
                "model": "X",
                "kept": "a.yaml",
                "ignored": ["b.yaml"],
            }
        ]

        nb_dt_import._log_run_summary(handle, mock_nb, datetime.now(), dtl_repo=mock_repo)

        logged = [call.args[0] for call in handle.log.call_args_list]
        assert any("cisco" in msg for msg in logged)
        assert any("a.yaml" in msg for msg in logged)
        assert any("b.yaml" in msg for msg in logged)


# ---------------------------------------------------------------------------
# __main__ entry point: GraphQLError and NetBoxRequestError handlers (lines 876-890)
# ---------------------------------------------------------------------------


class TestEntryPointErrorHandlers:
    """Tests for GraphQLError and NetBoxRequestError handlers in the __main__ block."""

    def test_graphql_error_prints_message_and_exits_1(self, capsys):
        """GraphQLError raised from main() becomes SystemExit(1) with stderr output."""
        from core.graphql_client import GraphQLError

        with (
            patch("core.repo.DTLRepo") as MockDTLRepo,
            patch("core.netbox_api.NetBox"),
        ):
            MockDTLRepo.side_effect = GraphQLError("graphql failed")

            with patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]):
                with pytest.raises(SystemExit) as exc_info:
                    runpy.run_path(_NB_DT_IMPORT_PATH, run_name="__main__")

        assert exc_info.value.code == 1
        assert "graphql failed" in capsys.readouterr().err

    def test_netbox_request_error_prints_message_and_exits_1(self, capsys):
        """NetBoxRequestError raised from main() becomes SystemExit(1) with stderr output."""
        from unittest.mock import MagicMock

        import pynetbox.core.query

        mock_req = MagicMock()
        mock_req.status_code = 400
        mock_req.url = "http://netbox/api/"
        netbox_err = pynetbox.core.query.RequestError(mock_req)

        with (
            patch("core.repo.DTLRepo") as MockDTLRepo,
            patch("core.netbox_api.NetBox"),
        ):
            MockDTLRepo.side_effect = netbox_err

            with patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]):
                with pytest.raises(SystemExit) as exc_info:
                    runpy.run_path(_NB_DT_IMPORT_PATH, run_name="__main__")

        assert exc_info.value.code == 1
        assert "NetBox REST API request failed" in capsys.readouterr().err


class TestExportDiffFlags:
    """Test --export-diff CLI flag parsing and mutual exclusion."""

    def test_export_diff_flag_in_help(self):
        import subprocess

        result = subprocess.run(
            ["uv", "run", "--native-tls", "nb-dt-import.py", "--help"],
            capture_output=True,
            text=True,
            cwd=_PROJECT_ROOT,
        )
        assert "--export-diff" in result.stdout
        assert "--export-diff-dir" in result.stdout
        assert "--force-export-overwrite" in result.stdout

    def test_export_diff_mutually_exclusive_with_update(self):
        import subprocess

        result = subprocess.run(
            ["uv", "run", "--native-tls", "nb-dt-import.py", "--export-diff", "--update"],
            capture_output=True,
            text=True,
            cwd=_PROJECT_ROOT,
        )
        assert result.returncode == 2
        assert "--export-diff" in result.stderr

    def test_export_diff_mutually_exclusive_with_only_new(self):
        import subprocess

        result = subprocess.run(
            ["uv", "run", "--native-tls", "nb-dt-import.py", "--export-diff", "--only-new"],
            capture_output=True,
            text=True,
            cwd=_PROJECT_ROOT,
        )
        assert result.returncode == 2
        assert "--export-diff" in result.stderr

    def test_export_diff_mutually_exclusive_with_remove_components(self):
        import subprocess

        result = subprocess.run(
            ["uv", "run", "--native-tls", "nb-dt-import.py", "--export-diff", "--remove-components"],
            capture_output=True,
            text=True,
            cwd=_PROJECT_ROOT,
        )
        assert result.returncode == 2
        assert "--export-diff" in result.stderr


class TestDirectHelpers:
    """Tests for direct helper functions and custom progress columns."""

    def test_no_pulse_bar_column_uses_static_empty_bar_for_unknown_total(self, nb_dt_import):
        column = nb_dt_import.NoPulseBarColumn()
        bar = column.render(SimpleNamespace(total=None, completed=5, get_time=lambda: 0))

        assert bar.total == 1.0
        assert bar.completed == 0.0

    def test_parse_vendor_racks_calls_repo_when_directory_exists(self, nb_dt_import):
        repo = MagicMock()
        repo.get_devices.return_value = (["rack.yaml"], [])
        repo.parse_files.return_value = [{"model": "Rack"}]

        with patch("nb_dt_import.os.path.isdir", return_value=True):
            result = nb_dt_import._parse_vendor_racks(repo, "/racks", "nokia", ["rack"])

        assert result == [{"model": "Rack"}]
        repo.get_devices.assert_called_once_with("/racks", ["nokia"])
        repo.parse_files.assert_called_once_with(["rack.yaml"], slugs=["rack"])

    def test_finalize_task_registry_updates_unknown_totals_and_skips_missing_tasks(self, nb_dt_import):
        progress = MagicMock()
        progress.tasks = [SimpleNamespace(id=1, total=None, completed=3)]

        nb_dt_import._finalize_task_registry(progress, {"seen": 1, "missing": 2})

        progress.update.assert_called_once_with(1, total=3)
        progress.stop_task.assert_called_once_with(1)

    def test_validate_argument_combinations_blocks_force_resolve_without_update(self, nb_dt_import):
        parser = MagicMock()
        args = SimpleNamespace(
            export_diff=False,
            update=False,
            only_new=False,
            remove_components=False,
            remove_unmanaged_types=False,
            force_resolve_conflicts=True,
        )

        nb_dt_import._validate_argument_combinations(parser, args)

        parser.error.assert_called_once_with("--force-resolve-conflicts requires --update")

    def test_validate_argument_combinations_blocks_remove_unmanaged_without_remove_components(self, nb_dt_import):
        parser = MagicMock()
        args = SimpleNamespace(
            export_diff=False,
            update=True,
            only_new=False,
            remove_components=False,
            remove_unmanaged_types=True,
            force_resolve_conflicts=False,
        )

        nb_dt_import._validate_argument_combinations(parser, args)

        parser.error.assert_called_once_with("--remove-unmanaged-types requires --remove-components")

    def test_validate_argument_combinations_blocks_remove_unmanaged_with_export_diff(self, nb_dt_import):
        parser = MagicMock()
        parser.error.side_effect = SystemExit(2)
        args = SimpleNamespace(
            export_diff=True,
            update=False,
            only_new=False,
            remove_components=False,
            remove_unmanaged_types=True,
            force_resolve_conflicts=False,
        )

        with pytest.raises(SystemExit):
            nb_dt_import._validate_argument_combinations(parser, args)

        parser.error.assert_called_once_with(
            "--remove-unmanaged-types is an import-only flag and cannot be used with --export-diff"
        )

    def test_validate_argument_combinations_blocks_slugs_with_export_diff(self, nb_dt_import):
        parser = MagicMock()
        parser.error.side_effect = SystemExit(2)
        args = SimpleNamespace(
            export_diff=True,
            update=False,
            only_new=False,
            remove_components=False,
            remove_unmanaged_types=False,
            force_resolve_conflicts=False,
            slugs=["nokia-7750"],
            verify_images=False,
        )
        with pytest.raises(SystemExit):
            nb_dt_import._validate_argument_combinations(parser, args)
        parser.error.assert_called_once_with("--slugs is an import-only flag and cannot be used with --export-diff")

    def test_validate_argument_combinations_blocks_verify_images_with_export_diff(self, nb_dt_import):
        parser = MagicMock()
        parser.error.side_effect = SystemExit(2)
        args = SimpleNamespace(
            export_diff=True,
            update=False,
            only_new=False,
            remove_components=False,
            remove_unmanaged_types=False,
            force_resolve_conflicts=False,
            slugs=[],
            verify_images=True,
        )
        with pytest.raises(SystemExit):
            nb_dt_import._validate_argument_combinations(parser, args)
        parser.error.assert_called_once_with(
            "--verify-images is an import-only flag and cannot be used with --export-diff"
        )

    def test_validate_argument_combinations_blocks_force_resolve_with_export_diff(self, nb_dt_import):
        parser = MagicMock()
        parser.error.side_effect = SystemExit(2)
        args = SimpleNamespace(
            export_diff=True,
            update=False,
            only_new=False,
            remove_components=False,
            remove_unmanaged_types=False,
            force_resolve_conflicts=True,
            slugs=[],
            verify_images=False,
        )
        with pytest.raises(SystemExit):
            nb_dt_import._validate_argument_combinations(parser, args)
        parser.error.assert_called_once_with(
            "--force-resolve-conflicts is an import-only flag and cannot be used with --export-diff"
        )

        """_run_export_diff wires up Exporter with progress panel and console."""
        handle = MagicMock()
        progress = MagicMock()
        progress.console = object()
        args = SimpleNamespace(
            export_diff_dir="extra",
            force_export_overwrite=True,
            vendors=["nokia"],
            show_remaining_time=True,
        )

        class _Ctx:
            def __enter__(self):
                return progress

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch("nb_dt_import.get_progress_panel", return_value=_Ctx()),
            patch("core.export.Exporter") as MockExporter,
        ):
            nb_dt_import._run_export_diff(nb_dt_import.settings, handle, args)

        MockExporter.assert_called_once()
        handle.set_console.assert_called_once_with(progress.console)
        MockExporter.return_value.run.assert_called_once_with(progress=progress)


class TestMainAdditionalCoverage:
    """Additional main() coverage for export-diff and preload-job teardown."""

    def test_main_returns_early_for_export_diff(self, nb_dt_import):
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--export-diff"]),
            patch("nb_dt_import._run_export_diff") as mock_run_export,
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
        ):
            nb_dt_import.main()

        mock_run_export.assert_called_once()
        MockRepo.assert_not_called()
        MockNetBox.assert_not_called()

    def test_main_uses_slug_fast_path_device_files(self, nb_dt_import):
        mock_repo = _make_mock_repo()
        mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
        mock_repo.resolve_slug_files.return_value = {
            "device_files": {"cisco": ["resolved.yaml"]},
            "module_vendors": set(),
            "rack_vendors": set(),
        }
        mock_repo.parse_files.side_effect = lambda files, slugs=None, progress=None: (
            [{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x"}] if files == ["resolved.yaml"] else []
        )
        mock_nb = _make_mock_netbox()

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--slugs", "x"]),
            patch("nb_dt_import.DTLRepo", return_value=mock_repo),
            patch("nb_dt_import.NetBox", return_value=mock_nb),
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()
            nb_dt_import.main()

        assert any(call.args[0] == ["resolved.yaml"] for call in mock_repo.parse_files.call_args_list)

    def test_main_pumps_and_stops_preload_job(self, nb_dt_import):
        mock_repo = _make_mock_repo()
        mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]

        def _parse_files(files, slugs=None, progress=None):
            if files == ["device.yaml"]:
                return [{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x"}]
            return []

        mock_repo.get_devices.side_effect = lambda path, vendors=None: (
            (["device.yaml"], []) if path == "/tmp/devices" else ([], [])
        )
        mock_repo.parse_files.side_effect = _parse_files
        mock_nb = _make_mock_netbox()
        mock_nb.device_types.start_component_preload.return_value = "job-1"
        progress = MagicMock()
        progress.console = object()

        class _Ctx:
            def __enter__(self):
                return progress

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch.object(sys, "argv", ["nb-dt-import.py"]),
            patch("nb_dt_import.DTLRepo", return_value=mock_repo),
            patch("nb_dt_import.NetBox", return_value=mock_nb),
            patch("nb_dt_import.ChangeDetector") as MockDetector,
            patch("nb_dt_import._process_device_types", return_value="job-1"),
            patch("sys.stdout") as mock_stdout,
            patch("nb_dt_import.get_progress_panel", return_value=_Ctx()),
        ):
            mock_stdout.isatty.return_value = True
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()
            nb_dt_import.main()

        mock_nb.device_types.pump_preload_progress.assert_called()
        mock_nb.device_types.stop_component_preload.assert_called_with("job-1", progress=progress)

    def test_main_stops_preload_job_in_finally_on_error(self, nb_dt_import):
        mock_repo = _make_mock_repo()
        mock_repo.discover_vendors.return_value = [{"name": "Cisco", "slug": "cisco"}]
        mock_repo.get_devices.side_effect = lambda path, vendors=None: (
            (["device.yaml"], []) if path == "/tmp/devices" else ([], [])
        )
        mock_repo.parse_files.side_effect = lambda files, slugs=None, progress=None: (
            [{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x"}] if files == ["device.yaml"] else []
        )
        mock_nb = _make_mock_netbox()
        mock_nb.device_types.start_component_preload.return_value = "job-2"
        progress = MagicMock()
        progress.console = object()

        class _Ctx:
            def __enter__(self):
                return progress

            def __exit__(self, exc_type, exc, tb):
                return False

        with (
            patch.object(sys, "argv", ["nb-dt-import.py"]),
            patch("nb_dt_import.DTLRepo", return_value=mock_repo),
            patch("nb_dt_import.NetBox", return_value=mock_nb),
            patch("nb_dt_import._process_device_types", side_effect=RuntimeError("boom")),
            patch("nb_dt_import.get_progress_panel", return_value=_Ctx()),
        ):
            with pytest.raises(RuntimeError, match="boom"):
                nb_dt_import.main()

        mock_nb.device_types.stop_component_preload.assert_called_with("job-2", progress=progress)

    def test_build_argument_parser_sets_expected_defaults_and_flags(self, nb_dt_import):
        parser = nb_dt_import._build_argument_parser()

        defaults = parser.parse_args([])
        parsed = parser.parse_args(
            [
                "--vendors",
                "cisco",
                "juniper",
                "--url",
                "https://example.com/repo.git",
                "--slugs",
                "x",
                "y",
                "--branch",
                "feature/test",
                "--verbose",
                "--show-remaining-time",
                "--update",
                "--remove-components",
                "--remove-unmanaged-types",
                "--force-resolve-conflicts",
                "--verify-images",
                "--export-diff",
                "--export-diff-dir",
                "exports/",
                "--force-export-overwrite",
            ]
        )

        assert parser.description == "Import Netbox Device Types"
        assert parser.allow_abbrev is False
        assert defaults.export_diff_dir == "extra/"
        assert defaults.force_export_overwrite is False
        assert parsed.vendors == ["cisco", "juniper"]
        assert parsed.url == "https://example.com/repo.git"
        assert parsed.slugs == ["x", "y"]
        assert parsed.branch == "feature/test"
        assert parsed.verbose is True
        assert parsed.show_remaining_time is True
        assert parsed.update is True
        assert parsed.remove_components is True
        assert parsed.remove_unmanaged_types is True
        assert parsed.force_resolve_conflicts is True
        assert parsed.verify_images is True
        assert parsed.export_diff is True
        assert parsed.export_diff_dir == "exports/"
        assert parsed.force_export_overwrite is True

    def test_run_vendor_loop_processes_slug_fast_path_and_skips_empty_vendor(self, nb_dt_import):
        args = SimpleNamespace(only_new=False, slugs=["x"])
        handle = MagicMock()
        progress = MagicMock()
        dtl_repo = _make_mock_repo()
        dtl_repo.get_devices.side_effect = lambda path, vendors=None: (
            ([f"{vendors[0]}-{path.split('/')[-1]}.yaml"], [])
            if vendors and vendors[0] == "cisco" and path in {"/tmp/modules", "/tmp/rack-types"}
            else ([], [])
        )
        dtl_repo.parse_files.side_effect = lambda files, slugs=None, progress=None: (
            [{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x"}]
            if files == ["resolved.yaml"]
            else [{"manufacturer": {"slug": "cisco"}, "model": "M", "slug": "m"}]
            if files == ["cisco-modules.yaml"]
            else []
        )
        netbox = _make_mock_netbox(modules=True)
        netbox.device_types.start_component_preload.return_value = "job-1"
        slug_resolved = {
            "device_files": {"empty": [], "cisco": ["resolved.yaml"]},
            "module_vendors": {"cisco"},
            "rack_vendors": set(),
        }

        with (
            patch(
                "nb_dt_import._parse_vendor_racks",
                side_effect=[[], [{"manufacturer": {"slug": "cisco"}, "model": "R", "slug": "r"}]],
            ),
            patch("nb_dt_import._process_device_types", return_value="job-1") as mock_process_device_types,
            patch("nb_dt_import._process_module_types") as mock_process_module_types,
            patch("nb_dt_import._process_rack_types") as mock_process_rack_types,
            patch("nb_dt_import._finalize_task_registry") as mock_finalize,
        ):
            nb_dt_import._run_vendor_loop(
                dtl_repo=dtl_repo,
                netbox=netbox,
                args=args,
                handle=handle,
                vendors_to_process=[{"slug": "empty", "name": "Empty"}, {"slug": "cisco", "name": "Cisco"}],
                devices_path="/tmp/devices",
                modules_path="/tmp/modules",
                racks_path="/tmp/rack-types",
                slug_resolved=slug_resolved,
                progress=progress,
                task_registry={},
                vendor_task_id=7,
            )

        netbox.load_vendor.assert_called_once_with("cisco")
        netbox.device_types.start_component_preload.assert_called_once_with(
            manufacturer_slug="cisco",
            progress=progress,
            task_registry={},
        )
        # pump is now called after preload start, after create_manufacturers,
        # and after each of the three process_*_types steps → 5 calls total
        assert netbox.device_types.pump_preload_progress.call_count == 5
        netbox.device_types.pump_preload_progress.assert_called_with("job-1", progress)
        netbox.device_types.stop_component_preload.assert_called_once_with("job-1", progress=progress)
        netbox.create_manufacturers.assert_called_once_with([{"slug": "cisco", "name": "Cisco"}])
        mock_process_device_types.assert_called_once()
        mock_process_module_types.assert_called_once()
        mock_process_rack_types.assert_called_once()
        assert progress.advance.call_args_list == [((7,),), ((7,),)]
        mock_finalize.assert_called_once_with(progress, {})
        assert any(call.args[0] == ["resolved.yaml"] for call in dtl_repo.parse_files.call_args_list)

    def test_run_vendor_loop_stops_preload_in_finally_on_error(self, nb_dt_import):
        args = SimpleNamespace(only_new=False, slugs=[])
        handle = MagicMock()
        progress = MagicMock()
        dtl_repo = _make_mock_repo()
        dtl_repo.get_devices.side_effect = lambda path, vendors=None: (
            (["device.yaml"], []) if path == "/tmp/devices" else ([], [])
        )
        dtl_repo.parse_files.side_effect = lambda files, slugs=None, progress=None: (
            [{"manufacturer": {"slug": "cisco"}, "model": "X", "slug": "x"}] if files == ["device.yaml"] else []
        )
        netbox = _make_mock_netbox()
        netbox.device_types.start_component_preload.return_value = "job-2"

        with (
            patch("nb_dt_import._parse_vendor_racks", return_value=[]),
            patch("nb_dt_import._process_device_types", side_effect=RuntimeError("boom")),
            patch("nb_dt_import._finalize_task_registry") as mock_finalize,
        ):
            with pytest.raises(RuntimeError, match="boom"):
                nb_dt_import._run_vendor_loop(
                    dtl_repo=dtl_repo,
                    netbox=netbox,
                    args=args,
                    handle=handle,
                    vendors_to_process=[{"slug": "cisco", "name": "Cisco"}],
                    devices_path="/tmp/devices",
                    modules_path="/tmp/modules",
                    racks_path="/tmp/rack-types",
                    slug_resolved=None,
                    progress=progress,
                    task_registry={},
                    vendor_task_id=8,
                )

        netbox.device_types.stop_component_preload.assert_called_once_with("job-2", progress=progress)
        mock_finalize.assert_called_once_with(progress, {})
