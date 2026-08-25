"""Import pipeline planning and execution."""

from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
import os

from core.change_detector import ChangeDetector, ChangeType, IMAGE_PROPERTIES
from core.component_cache import NullTaskDisplay, RichTaskDisplay
from core.config import RunConfig
from core.errors import VendorSelectionError


_PROGRESS_DESC_WIDTH = 28


@dataclass(frozen=True)
class RunSelection:
    """Selected vendors and source paths for one import run."""

    vendors: tuple
    devices_path: str
    modules_path: str
    racks_path: str
    slug_resolved: dict | None


@dataclass(frozen=True)
class VendorPlan:
    """Parsed work for one vendor, before any NetBox write occurs."""

    vendor: dict
    device_types: list
    module_types: list
    rack_types: list
    prefetch_components: bool

    @property
    def has_types(self):
        """Return True when the plan contains at least one type."""
        return bool(self.device_types or self.module_types or self.rack_types)


@dataclass(frozen=True)
class RunSummary:
    """Snapshot of the result of one completed import run."""

    counter: Counter
    modules: bool
    rack_types: bool
    failure_lines: tuple
    duplicate_definitions: tuple
    elapsed: timedelta

    @classmethod
    def capture(cls, netbox, repo, started_at):
        """Capture mutable run state as a summary value."""
        return cls(
            counter=Counter(netbox.counter),
            modules=netbox.modules,
            rack_types=netbox.rack_types,
            failure_lines=tuple(netbox.outcomes.render_failure_report()),
            duplicate_definitions=tuple(repo.duplicate_definitions),
            elapsed=datetime.now() - started_at,
        )


def get_progress_wrapper(progress, iterable, desc=None, total=None, on_step=None, task_registry=None):
    """Wrap an iterable with a Rich progress task when progress is available."""
    if progress is None:
        return iterable

    description = (desc or "").ljust(_PROGRESS_DESC_WIDTH)
    if total is None:
        try:
            total = len(iterable)
        except TypeError:
            total = None

    if task_registry is not None:
        if description not in task_registry:
            task_registry[description] = progress.add_task(description, total=None)
        task_id = task_registry[description]
    else:
        task_id = progress.add_task(description, total=total)

    def iterator():
        """Yield items and advance the progress task."""
        count = 0
        try:
            for item in iterable:
                yield item
                count += 1
                progress.advance(task_id)
                if on_step:
                    on_step()
        finally:
            if task_registry is None:
                if total is None:
                    progress.update(task_id, total=max(count, 1), completed=count)
                progress.stop_task(task_id)
                progress.remove_task(task_id)
            if on_step:
                on_step()

    return iterator()


def filter_new_device_types(device_types, existing_by_model, existing_by_slug):
    """Return device types that do not exist in either lookup."""
    new_device_types = []
    for device_type in device_types:
        manufacturer_slug = device_type["manufacturer"]["slug"]
        model = device_type["model"]
        slug = device_type.get("slug", "")

        existing = existing_by_model.get((manufacturer_slug, model))
        if existing is None and slug:
            existing = existing_by_slug.get((manufacturer_slug, slug))

        if existing is None:
            new_device_types.append(device_type)

    return new_device_types


def _device_type_change_key(manufacturer_slug, model, slug):
    """Build a change-detection key."""
    return manufacturer_slug, model, slug or ""


def device_type_key(device_type):
    """Extract a change-detection key from a parsed device type."""
    return _device_type_change_key(
        device_type["manufacturer"]["slug"],
        device_type["model"],
        device_type.get("slug", ""),
    )


def change_entry_key(change_entry):
    """Extract a change-detection key from a change entry."""
    return _device_type_change_key(
        change_entry.manufacturer_slug,
        change_entry.model,
        change_entry.slug,
    )


def filter_device_types_by_change_keys(device_types, change_keys):
    """Return device types whose keys occur in the selected change keys."""
    if not change_keys:
        return []
    return [device_type for device_type in device_types if device_type_key(device_type) in change_keys]


def _device_types_with_images_keys(device_types):
    """Return keys for device types that declare images."""
    return {
        device_type_key(device_type)
        for device_type in device_types
        if device_type.get("front_image") or device_type.get("rear_image")
    }


def select_device_types_for_default_mode(device_types, change_report, verify_images=False):
    """Select new device types and device types with missing images."""
    if not change_report:
        return []

    new_keys = {change_entry_key(change) for change in change_report.new_device_types}
    image_change_keys = {
        change_entry_key(change)
        for change in change_report.modified_device_types
        if any(property_change.property_name in IMAGE_PROPERTIES for property_change in change.property_changes)
    }
    all_keys = new_keys | image_change_keys
    if verify_images:
        all_keys |= _device_types_with_images_keys(device_types)
    return filter_device_types_by_change_keys(device_types, all_keys)


def select_device_types_for_update_mode(device_types, change_report, verify_images=False):
    """Select all new and modified device types."""
    if not change_report:
        return []

    actionable_keys = {change_entry_key(change) for change in change_report.new_device_types}
    actionable_keys.update(change_entry_key(change) for change in change_report.modified_device_types)
    if verify_images:
        actionable_keys |= _device_types_with_images_keys(device_types)
    return filter_device_types_by_change_keys(device_types, actionable_keys)


def has_missing_device_images(change_report):
    """Return True when a device type has an image change."""
    if not change_report:
        return False
    for device_change in change_report.modified_device_types:
        if any(change.property_name in IMAGE_PROPERTIES for change in device_change.property_changes):
            return True
    return False


def log_run_mode(handle, config):
    """Log the active import mode."""
    if config.only_new:
        handle.log("Mode: --only-new enabled; existing device types and components will not be modified.")
    elif config.update:
        handle.log("Mode: --update enabled; changed properties and components on existing models will be updated.")
        if config.remove_components:
            handle.log("Mode: --remove-components enabled; missing components will be removed from existing models.")
            if config.remove_unmanaged_types:
                handle.log(
                    "Mode: --remove-unmanaged-types enabled; components whose entire YAML section is missing "
                    "will also be removed from existing models."
                )
        else:
            handle.log(
                "Mode: will not remove components from existing models; use --remove-components with "
                "--update to change this."
            )
        if config.force_resolve_conflicts:
            handle.log(
                "Mode: --force-resolve-conflicts enabled; constraint failures will trigger destructive "
                "remediation when no live device references the affected type."
            )
    else:
        handle.log("Mode: --update not set; changed properties/components will not be applied (use --update).")
    if config.verify_images:
        handle.log(
            "Mode: --verify-images enabled; images already recorded in NetBox will be verified via HTTP "
            "and re-uploaded if missing or content has changed."
        )


def should_only_create_new_modules(config):
    """Return True when module processing must skip updates."""
    return config.only_new or not config.update


def _cache_display(progress, task_registry):
    """Return the cache progress sink."""
    if progress is None:
        return NullTaskDisplay()
    return RichTaskDisplay(progress, registry=task_registry)


@contextmanager
def _image_progress_scope(progress, device_types, total=0):
    """Set and clear image upload progress state."""
    image_task = None
    if progress is not None and total > 0:
        image_task = progress.add_task("Uploading Images", total=total)

        def advance_images(count=1):
            """Advance the image upload task."""
            progress.update(image_task, advance=count)

        device_types._image_progress = advance_images
    try:
        yield
    finally:
        device_types._image_progress = None
        if progress is not None and image_task is not None:
            progress.stop_task(image_task)
            progress.remove_task(image_task)


def _process_device_types(config, netbox, handle, progress, device_types, vendor_slug=None, task_registry=None):
    """Process device types for one vendor."""
    if config.only_new:
        new_device_types = filter_new_device_types(
            device_types,
            netbox.device_types.existing_device_types,
            netbox.device_types.existing_device_types_by_slug,
        )
        if new_device_types:
            image_total = netbox.count_device_type_images(new_device_types)
            with _image_progress_scope(progress, netbox.device_types, total=image_total):
                netbox.create_device_types(
                    new_device_types,
                    progress=get_progress_wrapper(
                        progress,
                        new_device_types,
                        desc="Creating Device Types",
                        task_registry=task_registry,
                    ),
                    only_new=True,
                )
        else:
            handle.verbose_log("No new device types to create.")
        return

    if not device_types:
        handle.verbose_log("No device types matched filters.")
        return

    handle.verbose_log("Caching NetBox data for comparison (concurrent API requests started after parsing)...")
    netbox.device_types.ensure_components_ready(manufacturer_slug=vendor_slug)

    detector = ChangeDetector(
        netbox.device_types,
        handle,
        remove_unmanaged_types=config.remove_unmanaged_types,
        verbose=config.verbose,
    )
    change_report = detector.detect_changes(
        device_types,
        progress=get_progress_wrapper(progress, device_types, desc="Detecting Changes", task_registry=task_registry),
    )
    detector.log_change_report(change_report)

    if config.update:
        device_types_to_process = select_device_types_for_update_mode(
            device_types, change_report, verify_images=config.verify_images
        )
        if device_types_to_process:
            image_total = netbox.count_device_type_images(device_types_to_process)
            with _image_progress_scope(progress, netbox.device_types, total=image_total):
                netbox.create_device_types(
                    device_types_to_process,
                    progress=get_progress_wrapper(
                        progress,
                        device_types_to_process,
                        desc="Processing Device Types",
                        task_registry=task_registry,
                    ),
                    only_new=False,
                    update=True,
                    change_report=change_report,
                    remove_components=config.remove_components,
                )
        else:
            handle.verbose_log("No device type changes to process.")
    else:
        device_types_to_process = select_device_types_for_default_mode(
            device_types, change_report, verify_images=config.verify_images
        )
        if device_types_to_process:
            image_total = netbox.count_device_type_images(device_types_to_process)
            with _image_progress_scope(progress, netbox.device_types, total=image_total):
                netbox.create_device_types(
                    device_types_to_process,
                    progress=get_progress_wrapper(
                        progress,
                        device_types_to_process,
                        desc="Creating Device Types",
                        task_registry=task_registry,
                    ),
                    only_new=True,
                )
        else:
            handle.verbose_log("No new device types or missing images to process.")


def _process_module_types(config, netbox, handle, progress, module_types, task_registry=None):
    """Process module types for one vendor."""
    if not module_types:
        return

    handle.verbose_log(f"{len(module_types)} Module-Types Found")

    module_only_new = should_only_create_new_modules(config)
    existing_module_types = netbox.get_existing_module_types()
    module_types_to_process, module_type_existing_images, changed_property_log = netbox.filter_actionable_module_types(
        module_types,
        existing_module_types,
        only_new=config.only_new,
    )

    new_module_count = len(netbox.filter_new_module_types(module_types, existing_module_types))
    pending_removal_modules = 0
    pending_removal_components = 0
    for _slug, _model, _fields_info, component_changes in changed_property_log:
        removed_in_group = [
            change
            for change in (component_changes or [])
            if getattr(change, "change_type", None) == ChangeType.COMPONENT_REMOVED
        ]
        if removed_in_group:
            pending_removal_modules += 1
            pending_removal_components += len(removed_in_group)

    module_changed_count = len(changed_property_log)
    module_unchanged_count = len(module_types) - len(module_types_to_process) if not config.only_new else 0

    has_module_changes = new_module_count > 0 or module_changed_count > 0 or pending_removal_modules > 0
    if has_module_changes:
        handle.log("============================================================")
        handle.log("MODULE TYPE CHANGE DETECTION")
        handle.log("============================================================")
        if config.only_new:
            handle.log(f"New module types: {new_module_count}")
        else:
            image_only_count = max(0, len(module_types_to_process) - new_module_count - module_changed_count)
            handle.log(f"New module types:       {new_module_count}")
            handle.log(f"Unchanged module types: {module_unchanged_count}")
            handle.log(f"Modified module types:  {module_changed_count}")
            if image_only_count:
                handle.log(f"Image-only updates:     {image_only_count}")
            if module_changed_count and not config.update:
                handle.log("  (Run with --update to apply changes to existing module types)")
            if pending_removal_modules and not config.remove_components:
                remove_hint = "--remove-components" if config.update else "--update --remove-components"
                handle.log(
                    f"  (Run with {remove_hint} to remove {pending_removal_components} stale "
                    f"component(s) across {pending_removal_modules} module type(s))"
                )
        handle.log("------------------------------------------------------------")
        netbox.log_module_type_changes(changed_property_log)
    elif module_unchanged_count:
        handle.verbose_log(f"No module type changes ({module_unchanged_count} unchanged).")

    if module_types_to_process:
        module_image_total = netbox.count_module_type_images(
            module_types_to_process, existing_module_types, module_type_existing_images
        )
        with _image_progress_scope(progress, netbox.device_types, total=module_image_total):
            netbox.create_module_types(
                module_types_to_process,
                progress=get_progress_wrapper(
                    progress,
                    module_types_to_process,
                    desc="Processing Module Types",
                    task_registry=task_registry,
                ),
                only_new=module_only_new,
                all_module_types=existing_module_types,
                module_type_existing_images=module_type_existing_images,
                remove_components=config.remove_components,
            )
    else:
        handle.verbose_log("No module type changes to process.")


def _process_rack_types(config, netbox, handle, progress, rack_types, task_registry=None):
    """Process rack types for one vendor."""
    if not rack_types:
        return

    if not netbox.rack_types:
        handle.log("Rack types require NetBox >= 4.1. Skipping rack type import.")
        return

    handle.verbose_log(f"{len(rack_types)} Rack-Types Found")

    all_rack_types = netbox.get_existing_rack_types()
    new_count = sum(
        1
        for rack_type in rack_types
        if all_rack_types.get(rack_type.get("manufacturer", {}).get("slug", ""), {}).get(rack_type.get("model")) is None
    )
    existing_count = len(rack_types) - new_count

    if new_count == 0:
        handle.verbose_log(f"No new rack types ({existing_count} unchanged).")
    else:
        handle.log("============================================================")
        handle.log(f"New rack types:       {new_count}")
        handle.log(f"Existing rack types:  {existing_count}")
        handle.log("============================================================")

    netbox.create_rack_types(
        rack_types,
        progress=get_progress_wrapper(
            progress,
            rack_types,
            desc="Processing Rack Types",
            task_registry=task_registry,
        ),
        only_new=config.only_new,
        all_rack_types=all_rack_types,
    )


def _log_import_filters(handle, config):
    """Log active vendor and slug filters."""
    if config.vendors:
        handle.log(f"Importing vendors: {', '.join(config.vendors)}")
    if config.slugs:
        handle.log(f"Filtering by slugs: {', '.join(config.slugs)}")


def _log_run_summary(handle, summary):
    """Log a completed run summary."""
    counter = summary.counter
    handle.log("---")
    handle.verbose_log(f"Script took {summary.elapsed} to run")
    handle.log(f"{counter['added']} device types created")
    handle.log(f"{counter['properties_updated']} device types updated")
    component_updates = counter.get("device_types_component_updates", 0)
    if component_updates:
        handle.log(f"{component_updates} device types had component-only updates")
    failed = counter.get("device_types_failed", 0)
    if failed:
        handle.log(f"{failed} device types FAILED to update (see error log above)")
    handle.log(f"{counter['components_updated']} components updated")
    handle.log(f"{counter['components_added']} components added")
    handle.log(f"{counter['components_removed']} components removed")
    handle.verbose_log(f"{counter['images']} images uploaded")
    handle.log(f"{counter['manufacturer']} manufacturers created")
    if summary.modules:
        handle.log(f"{counter['module_added']} modules created")
        handle.log(f"{counter['module_updated']} modules updated")
        if counter["module_update_failed"]:
            handle.log(f"{counter['module_update_failed']} modules failed to update")
        if counter["module_partial_update"]:
            handle.log(f"{counter['module_partial_update']} modules partially updated")
    if summary.rack_types:
        handle.log(f"{counter['rack_type_added']} rack types created")
        handle.log(f"{counter['rack_type_updated']} rack types updated")

    for line in summary.failure_lines:
        handle.log(line)

    if summary.duplicate_definitions:
        handle.log("---")
        handle.log(
            f"WARNING: {len(summary.duplicate_definitions)} duplicate "
            "(manufacturer, model) definition(s) detected in the source repository:"
        )
        for duplicate in summary.duplicate_definitions:
            handle.log(f"  {duplicate['manufacturer']}/{duplicate['model']}")
            handle.log(f"    kept:    {duplicate['kept']}")
            for ignored in duplicate["ignored"]:
                handle.log(f"    ignored: {ignored}")
        handle.log("These duplicates would otherwise oscillate on every run. Please report/fix them upstream.")


def _parse_vendor_files(repo, base_path, vendor_name, slugs):
    """Parse one vendor's types under *base_path*, treating an absent type root as empty.

    A local library may ship only some of the three type roots, which is a layout, not a fault.
    """
    if not os.path.isdir(base_path):
        return []
    files, _ = repo.get_devices(base_path, [vendor_name.casefold()])
    return repo.parse_files(files, slugs=slugs)


def _finalize_task_registry(progress, task_registry):
    """Resolve unknown totals and stop cumulative progress tasks."""
    if not progress or not task_registry:
        return
    for task_id in task_registry.values():
        task = next((task for task in progress.tasks if task.id == task_id), None)
        if task is None:
            continue
        if task.total is None:
            progress.update(task_id, total=max(task.completed, 0))
        progress.stop_task(task_id)


class ImportRun:
    """Discover, plan, apply, and report one device library import."""

    def __init__(self, config, repo, netbox, reporter, progress_factory, *, started_at=None):
        """Store the resolved run dependencies.

        Args:
            config (RunConfig): Resolved run configuration.
            repo (DTLRepo): Checked out device library repository.
            netbox (NetBox): Connected NetBox interface.
            reporter (LogHandler): Run message sink.
            progress_factory: Context manager factory for the Rich progress display.
            started_at (datetime | None): Start time used for elapsed-time reporting.
        """
        if not isinstance(config, RunConfig):
            raise TypeError("config must be a RunConfig")
        self.config = config
        self.repo = repo
        self.netbox = netbox
        self.reporter = reporter
        self.progress_factory = progress_factory
        self.started_at = started_at or datetime.now()
        self.progress = None
        self.task_registry = None
        self.vendor_task_id = None

    def discover(self):
        """Discover source paths and select vendors for this run."""
        devices_path = self.repo.get_devices_path()
        modules_path = self.repo.get_modules_path()
        racks_path = self.repo.get_racks_path()
        all_vendors = self.repo.discover_vendors(devices_path, modules_path, racks_path)

        if self.config.vendors:
            vendor_slug_filter = {vendor.lower() for vendor in self.config.vendors}
            vendors = [vendor for vendor in all_vendors if vendor["slug"] in vendor_slug_filter]
            if not vendors:
                raise VendorSelectionError(
                    f"No vendors matched --vendors: {', '.join(self.config.vendors)}. "
                    f"Available: {', '.join(vendor['slug'] for vendor in all_vendors[:10])}"
                    f"{'...' if len(all_vendors) > 10 else ''}"
                )
        else:
            vendors = all_vendors

        vendors, slug_resolved = self._narrow_by_slug(vendors)
        if self.config.vendors and not vendors:
            raise VendorSelectionError(
                f"No vendors matched the combination of --vendors and --slugs: {', '.join(self.config.vendors)}"
            )

        return RunSelection(
            vendors=tuple(vendors),
            devices_path=devices_path,
            modules_path=modules_path,
            racks_path=racks_path,
            slug_resolved=slug_resolved,
        )

    def _narrow_by_slug(self, vendors):
        """Narrow vendors with the repository slug index when available."""
        if not self.config.slugs:
            return vendors, None

        slug_resolved = self.repo.resolve_slug_files(self.config.slugs)
        if slug_resolved is None:
            self.reporter.verbose_log("Slug index unavailable; falling back to full file scan.")
            return vendors, None

        matched_vendor_slugs = (
            set(slug_resolved["device_files"])
            | (slug_resolved["module_vendors"] or set())
            | (slug_resolved["rack_vendors"] or set())
        )
        if not matched_vendor_slugs:
            self.reporter.verbose_log("Slug index returned no matches; falling back to full file scan.")
            return vendors, None
        narrowed = [vendor for vendor in vendors if vendor["slug"] in matched_vendor_slugs]
        self.reporter.verbose_log(
            f"Slug index resolved {sum(len(files) for files in slug_resolved['device_files'].values())} "
            f"device file(s) across {len(matched_vendor_slugs)} vendor(s)."
        )
        return narrowed, slug_resolved

    def plan_vendor(self, selection, vendor):
        """Parse source files and return an inspectable vendor plan."""
        slug_resolved = selection.slug_resolved
        if slug_resolved is not None:
            device_files = slug_resolved["device_files"].get(vendor["slug"], [])
            device_types = self.repo.parse_files(device_files) if device_files else []
        else:
            device_types = _parse_vendor_files(
                self.repo, selection.devices_path, vendor["name"], self.config.slugs or []
            )

        if self.netbox.modules:
            module_hint = slug_resolved["module_vendors"] if slug_resolved is not None else None
            if module_hint is not None and vendor["slug"] not in module_hint:
                module_types = []
            else:
                module_types = _parse_vendor_files(
                    self.repo, selection.modules_path, vendor["name"], self.config.slugs or []
                )
        else:
            module_types = []

        if self.netbox.rack_types:
            rack_hint = slug_resolved["rack_vendors"] if slug_resolved is not None else None
            if rack_hint is not None and vendor["slug"] not in rack_hint:
                rack_types = []
            else:
                rack_types = _parse_vendor_files(
                    self.repo,
                    selection.racks_path,
                    vendor["name"],
                    self.config.slugs or [],
                )
        else:
            rack_types = []

        return VendorPlan(
            vendor=vendor,
            device_types=device_types,
            module_types=module_types,
            rack_types=rack_types,
            prefetch_components=bool(device_types or module_types) and not self.config.only_new,
        )

    def apply(self, plan):
        """Apply one vendor plan to NetBox."""
        if not plan.has_types:
            self._advance_vendor()
            return

        cache = self.netbox.device_types.components
        self.netbox.load_vendor(plan.vendor["slug"])

        if plan.prefetch_components:
            cache.begin_prefetch(
                manufacturer_slug=plan.vendor["slug"],
                display=_cache_display(self.progress, self.task_registry),
            )

        self.reporter.verbose_log(f"{len(plan.device_types)} Device-Types Found")
        cache.pump()
        self.netbox.create_manufacturers([plan.vendor])
        cache.pump()

        _process_device_types(
            self.config,
            self.netbox,
            self.reporter,
            self.progress,
            plan.device_types,
            vendor_slug=plan.vendor["slug"],
            task_registry=self.task_registry,
        )
        cache.pump()

        if self.netbox.modules:
            _process_module_types(
                self.config,
                self.netbox,
                self.reporter,
                self.progress,
                plan.module_types,
                task_registry=self.task_registry,
            )
            cache.pump()

        _process_rack_types(
            self.config,
            self.netbox,
            self.reporter,
            self.progress,
            plan.rack_types,
            task_registry=self.task_registry,
        )
        cache.pump()
        cache.close()
        self._advance_vendor()

    def _advance_vendor(self):
        """Advance the vendor progress task when it exists."""
        if self.vendor_task_id is not None:
            self.progress.advance(self.vendor_task_id)

    def _start_progress(self, vendors):
        """Initialize progress state for the selected vendors."""
        self.task_registry = {} if self.progress is not None else None
        self.vendor_task_id = None
        if self.progress is not None and vendors:
            description = "Vendors".ljust(_PROGRESS_DESC_WIDTH)
            self.vendor_task_id = self.progress.add_task(description, total=len(vendors))

    def _clear_progress(self):
        """Close preloads and release all progress state."""
        try:
            self.netbox.device_types.components.close()
        finally:
            try:
                _finalize_task_registry(self.progress, self.task_registry)
            finally:
                self.reporter.set_console(None)
                self.progress = None
                self.task_registry = None
                self.vendor_task_id = None

    def execute(self):
        """Execute the import sequence and return its summary."""
        log_run_mode(self.reporter, self.config)
        _log_import_filters(self.reporter, self.config)
        selection = self.discover()

        with self.progress_factory(self.config.show_remaining_time) as progress:
            self.progress = progress
            if progress is not None:
                self.reporter.set_console(progress.console)
            try:
                self._start_progress(selection.vendors)
                for vendor in selection.vendors:
                    self.apply(self.plan_vendor(selection, vendor))
            finally:
                self._clear_progress()

        summary = RunSummary.capture(self.netbox, self.repo, self.started_at)
        _log_run_summary(self.reporter, summary)
        return summary
