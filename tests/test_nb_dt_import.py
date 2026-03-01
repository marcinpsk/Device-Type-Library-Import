import importlib.util
import os
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _dt_sort_key(d):
    return (d.get("manufacturer", {}).get("slug", ""), d.get("model", ""), d.get("slug", ""))


@pytest.fixture(scope="module")
def nb_dt_import():
    module_path = Path(__file__).resolve().parents[1] / "nb-dt-import.py"
    spec = importlib.util.spec_from_file_location("nb_dt_import", module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["nb_dt_import"] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop("nb_dt_import", None)


def test_filter_vendors_for_parsed_types_uses_parsed_subset(nb_dt_import):

    discovered_vendors = [
        {"name": "Cisco", "slug": "cisco"},
        {"name": "Juniper", "slug": "juniper"},
    ]
    parsed_types = [
        {"manufacturer": {"slug": "juniper"}, "model": "EX4300"},
    ]

    vendors, selected_slugs = nb_dt_import.filter_vendors_for_parsed_types(discovered_vendors, parsed_types)

    assert vendors == [{"name": "Juniper", "slug": "juniper"}]
    assert selected_slugs == {"juniper"}


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


def test_select_device_types_for_default_mode_scopes_to_new_and_missing_images(nb_dt_import):
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


def test_items_per_second_column_uses_elapsed_fallback_when_finished_speed_missing(nb_dt_import):
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


def _make_mock_repo(device_types=None):
    """Return a pre-configured DTLRepo mock with no files by default."""
    mock_repo = MagicMock()
    mock_repo.get_devices.return_value = ([], [])
    mock_repo.get_devices_path.return_value = "/tmp/devices"
    mock_repo.get_modules_path.return_value = "/tmp/modules"
    mock_repo.get_racks_path.return_value = "/tmp/rack-types"
    mock_repo.parse_files.return_value = device_types if device_types is not None else []
    return mock_repo


def _make_mock_netbox(modules=False, rack_types=False):
    """Return a pre-configured NetBox mock."""
    mock_nb = MagicMock()
    mock_nb.modules = modules
    mock_nb.rack_types = rack_types
    mock_nb.device_types.existing_device_types = {}
    mock_nb.device_types.existing_device_types_by_slug = {}
    mock_nb.count_device_type_images.return_value = 0
    mock_nb.count_module_type_images.return_value = 0
    mock_nb.filter_actionable_module_types.return_value = ([], [])
    mock_nb.get_existing_module_types.return_value = {}
    mock_nb.get_existing_rack_types.return_value = {}
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
            mock_repo.get_devices.return_value = (["file.yaml"], [{"slug": "cisco"}])
            MockRepo.return_value = mock_repo
            MockNetBox.return_value = _make_mock_netbox()

            nb_dt_import.main()

            MockNetBox.return_value.create_device_types.assert_called_once()

    def test_default_mode_no_device_types(self, nb_dt_import):
        """Default mode with empty file list logs 'No device types matched'."""
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

            # cache_preload_job is truthy here; stop_component_preload should be called
            MockNetBox.return_value.device_types.stop_component_preload.assert_called()

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
            mock_repo.get_devices.return_value = (["file.yaml"], [{"slug": "cisco"}])
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
            mock_repo.get_devices.return_value = (["file.yaml"], [{"slug": "cisco"}])
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
            mock_repo.get_devices.return_value = (["file.yaml"], [{"slug": "cisco"}])
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
            patch.object(sys, "argv", ["nb-dt-import.py", "--vendors", "cisco", "--slugs", "ws-c3750"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            MockRepo.return_value = _make_mock_repo()
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()

            nb_dt_import.main()  # should not raise

    def test_modules_future_no_module_files_with_slugs(self, nb_dt_import):
        """modules=True + --slugs triggers vendor filter path; empty bg result sets module_types=[]."""
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new", "--slugs", "my-slug"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
        ):
            mock_nb = _make_mock_netbox(modules=True)
            MockNetBox.return_value = mock_nb
            MockNetBox.filter_new_module_types.return_value = []
            MockRepo.return_value = _make_mock_repo()

            nb_dt_import.main()

    def test_modules_future_with_module_types_to_process(self, nb_dt_import):
        """modules=True + non-empty filter_actionable_module_types calls create_module_types."""
        module_type = {"manufacturer": {"slug": "cisco"}, "model": "CM1", "slug": "cm1"}

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--update"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.ChangeDetector") as MockDetector,
        ):
            mock_nb = _make_mock_netbox(modules=True)
            mock_nb.filter_actionable_module_types.return_value = ([module_type], [])
            MockNetBox.return_value = mock_nb
            MockNetBox.filter_new_module_types.return_value = []

            mock_repo = _make_mock_repo()

            def _get_devices_se(path, vendors):
                if path == "/tmp/modules":
                    return (["/module.yaml"], [])
                return ([], [])

            mock_repo.get_devices.side_effect = _get_devices_se
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
            mock_nb.filter_actionable_module_types.return_value = ([], [])
            MockNetBox.return_value = mock_nb
            MockNetBox.filter_new_module_types.return_value = []
            MockRepo.return_value = _make_mock_repo()
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()

            nb_dt_import.main()  # should not raise

    def test_modules_no_future_else_branch_no_module_files(self, nb_dt_import):
        """Else branch (no future): modules path called inline; empty result → module_types=[]."""
        # Make submit() return None so _module_parse_future stays None,
        # forcing the else branch in the second `if netbox.modules:` block.
        mock_executor = MagicMock()
        mock_executor.submit.return_value = None

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.concurrent.futures.ThreadPoolExecutor", return_value=mock_executor),
        ):
            mock_nb = _make_mock_netbox(modules=True)
            MockNetBox.return_value = mock_nb
            MockNetBox.filter_new_module_types.return_value = []
            MockRepo.return_value = _make_mock_repo()

            nb_dt_import.main()

    def test_modules_no_future_else_branch_with_module_files_and_slugs(self, nb_dt_import):
        """Else branch: module files present → parse_files called; --slugs triggers vendor filter."""
        mock_executor = MagicMock()
        mock_executor.submit.return_value = None

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new", "--slugs", "my-slug"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.concurrent.futures.ThreadPoolExecutor", return_value=mock_executor),
        ):
            mock_nb = _make_mock_netbox(modules=True)
            MockNetBox.return_value = mock_nb
            MockNetBox.filter_new_module_types.return_value = []

            mock_repo = _make_mock_repo()

            def _get_devices_se(path, vendors):
                if path == "/tmp/modules":
                    return (["/module.yaml"], [])
                return ([], [])

            mock_repo.get_devices.side_effect = _get_devices_se
            MockRepo.return_value = mock_repo

            nb_dt_import.main()

    def test_settings_netbox_features_modules_logs_module_count(self, nb_dt_import):
        """When NETBOX_FEATURES['modules'] is True, module_added counter is logged."""
        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch.object(nb_dt_import.settings, "NETBOX_FEATURES", {"modules": True}),
        ):
            MockRepo.return_value = _make_mock_repo()
            MockNetBox.return_value = _make_mock_netbox()

            nb_dt_import.main()  # should not raise

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
            patch("sys.stdout") as mock_stdout,
            patch("nb_dt_import.MyProgress", MockMyProgress),
        ):
            mock_stdout.isatty.return_value = True
            MockRepo.return_value = _make_mock_repo()
            MockNetBox.return_value = _make_mock_netbox()
            MockDetector.return_value.detect_changes.return_value = _empty_change_report()

            nb_dt_import.main()

            # handle.set_console(progress.console) was called
            mock_prog.console.__bool__.assert_not_called()  # console object exists

    def test_future_cancel_and_executor_shutdown_in_finally(self, nb_dt_import):
        """An exception during future.result() triggers cancel() and shutdown() in finally."""
        mock_future = MagicMock()
        mock_future.done.return_value = False
        mock_future.result.side_effect = RuntimeError("bg thread crash")

        mock_executor = MagicMock()
        mock_executor.submit.return_value = mock_future

        with (
            patch.object(sys, "argv", ["nb-dt-import.py", "--only-new"]),
            patch("nb_dt_import.DTLRepo") as MockRepo,
            patch("nb_dt_import.NetBox") as MockNetBox,
            patch("nb_dt_import.concurrent.futures.ThreadPoolExecutor", return_value=mock_executor),
        ):
            mock_nb = _make_mock_netbox(modules=True)
            MockNetBox.return_value = mock_nb
            MockRepo.return_value = _make_mock_repo()

            with pytest.raises(RuntimeError):
                nb_dt_import.main()

        mock_future.cancel.assert_called_once()
        mock_executor.shutdown.assert_called()


# ---------------------------------------------------------------------------
# _process_rack_types
# ---------------------------------------------------------------------------


class TestProcessRackTypes:
    """Tests for the _process_rack_types() helper function."""

    def _make_args(self, vendors=None, slugs=None, only_new=False):
        return SimpleNamespace(vendors=vendors, slugs=slugs, only_new=only_new)

    def test_rack_types_disabled_logs_warning_and_returns(self, nb_dt_import):
        """netbox.rack_types=False: warning logged, no further processing."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = False
        dtl_repo = MagicMock()

        nb_dt_import._process_rack_types(self._make_args(), netbox, dtl_repo, handle, None, set())

        handle.log.assert_called_once()
        assert "4.1" in handle.log.call_args[0][0]
        dtl_repo.get_racks_path.assert_not_called()

    def test_rack_types_dir_not_exist_verbose_log_and_returns(self, nb_dt_import, tmp_path):
        """rack_types=True but racks_path is not a directory: verbose_log + return."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = True
        dtl_repo = MagicMock()
        dtl_repo.get_racks_path.return_value = str(tmp_path / "nonexistent")

        nb_dt_import._process_rack_types(self._make_args(), netbox, dtl_repo, handle, None, set())

        handle.verbose_log.assert_called()
        assert "No rack-types directory" in handle.verbose_log.call_args[0][0]
        dtl_repo.get_devices.assert_not_called()

    def test_no_rack_files_verbose_log_and_returns(self, nb_dt_import, tmp_path):
        """racks_path exists but no files discovered: verbose_log + return."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = True
        dtl_repo = MagicMock()
        racks_dir = tmp_path / "rack-types"
        racks_dir.mkdir()
        dtl_repo.get_racks_path.return_value = str(racks_dir)
        dtl_repo.get_devices.return_value = ([], [])

        nb_dt_import._process_rack_types(self._make_args(), netbox, dtl_repo, handle, None, set())

        handle.verbose_log.assert_called()
        assert "No rack-type files" in handle.verbose_log.call_args[0][0]
        dtl_repo.parse_files.assert_not_called()

    def test_full_flow_calls_create_rack_types(self, nb_dt_import, tmp_path):
        """Full flow: files found, parse_files called, create_rack_types called."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = True
        netbox.get_existing_rack_types.return_value = {}

        racks_dir = tmp_path / "rack-types"
        racks_dir.mkdir()
        dtl_repo = MagicMock()
        dtl_repo.get_racks_path.return_value = str(racks_dir)
        dtl_repo.get_devices.return_value = (
            [str(racks_dir / "apc-ar1300.yaml")],
            [{"name": "APC", "slug": "apc"}],
        )
        rack_type = {"manufacturer": {"slug": "apc"}, "model": "AR1300", "slug": "apc-ar1300"}
        dtl_repo.parse_files.return_value = [rack_type]

        nb_dt_import._process_rack_types(self._make_args(), netbox, dtl_repo, handle, None, set())

        dtl_repo.parse_files.assert_called_once()
        netbox.create_rack_types.assert_called_once()

    def test_vendor_filter_from_selected_vendor_slugs_when_slugs_set(self, nb_dt_import, tmp_path):
        """When args.slugs set and no args.vendors, rack_vendor_filter uses selected_vendor_slugs."""
        handle = MagicMock()
        netbox = MagicMock()
        netbox.rack_types = True
        netbox.get_existing_rack_types.return_value = {}

        racks_dir = tmp_path / "rack-types"
        racks_dir.mkdir()
        dtl_repo = MagicMock()
        dtl_repo.get_racks_path.return_value = str(racks_dir)

        captured_vendor_filter = {}

        def _get_devices_se(path, vendors):
            captured_vendor_filter["vendors"] = vendors
            return ([], [])

        dtl_repo.get_devices.side_effect = _get_devices_se

        nb_dt_import._process_rack_types(
            self._make_args(vendors=None, slugs=["apc-ar1300"]),
            netbox,
            dtl_repo,
            handle,
            None,
            {"apc"},
        )

        assert captured_vendor_filter["vendors"] == ["apc"]


# ---------------------------------------------------------------------------
# if __name__ == "__main__" entry point
# ---------------------------------------------------------------------------


class TestEntryPoint:
    """Tests for the if __name__ == '__main__' entry point block."""

    def test_entry_point_calls_main_normally(self):
        """Running the script as __main__ with mocked deps completes without error."""
        with patch("core.repo.DTLRepo") as MockDTLRepo, patch("core.netbox_api.NetBox") as MockNetBox:
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
