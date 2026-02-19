from collections import Counter
import concurrent.futures
import queue
import time
import pynetbox
import requests
import os
import glob
from pathlib import Path

from change_detector import COMPONENT_ALIASES, ChangeType

# Supported image file extensions for module-type image uploads
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".svg"}

# from pynetbox import RequestError as APIRequestError


class NetBox:
    """Singleton-style interface to the NetBox API for importing device and module types."""

    def __new__(cls, *args, **kwargs):
        """Allocate a new NetBox instance using the default object allocator."""
        return super().__new__(cls)

    def __init__(self, settings, handle):
        """Initialize NetBox API connection, verify version compatibility, and load manufacturers/device types.

        Args:
            settings: Settings module with NETBOX_URL, NETBOX_TOKEN, IGNORE_SSL_ERRORS, and NETBOX_FEATURES.
            handle (LogHandler): Logging handler for progress and error messages.
        """
        self.counter = Counter(
            added=0,
            components_added=0,
            manufacturer=0,
            module_added=0,
            images=0,
            properties_updated=0,
            components_updated=0,
            components_removed=0,
        )
        self.url = settings.NETBOX_URL
        self.token = settings.NETBOX_TOKEN
        self.handle = handle
        self.netbox = None
        self.ignore_ssl = settings.IGNORE_SSL_ERRORS
        self.modules = False
        self.new_filters = False
        self.connect_api()
        self.verify_compatibility()
        self.existing_manufacturers = self.get_manufacturers()
        self.device_types = DeviceTypes(self.netbox, self.handle, self.counter, self.ignore_ssl, self.new_filters)

    def connect_api(self):
        """Connect to the NetBox API using the stored URL and token credentials."""
        try:
            self.netbox = pynetbox.api(self.url, token=self.token, threading=True)
            if self.ignore_ssl:
                self.handle.verbose_log("IGNORE_SSL_ERRORS is True, catching exception and disabling SSL verification.")
                # requests.packages.urllib3.disable_warnings()
                self.netbox.http_session.verify = False
        except Exception as e:
            self.handle.exception("Exception", "NetBox API Error", e)

    def get_api(self):
        """Return the underlying pynetbox API instance."""
        return self.netbox

    def get_counter(self):
        """Return the shared operation counter."""
        return self.counter

    def verify_compatibility(self):
        """Check the connected NetBox version and configure feature flags accordingly.

        Sets ``self.modules = True`` for NetBox >= 3.2 and ``self.new_filters = True``
        for >= 4.1. Logs the detected version when the new-filter flag is enabled.
        """
        # nb.version should be the version in the form '3.2'
        version_split = [int(x) for x in self.netbox.version.split(".")]

        # Later than 3.2
        # Might want to check for the module-types entry as well?
        if version_split[0] > 3 or (version_split[0] == 3 and version_split[1] >= 2):
            self.modules = True

        # check if version >= 4.1 in order to use new filter names (https://github.com/netbox-community/netbox/issues/15410)
        if version_split[0] > 4 or (version_split[0] == 4 and version_split[1] >= 1):
            self.new_filters = True
            self.handle.log(f"Netbox version {self.netbox.version} found. Using new filters.")

    def get_manufacturers(self):
        """Fetch all manufacturers from NetBox and return them indexed by name."""
        return {str(item): item for item in self.netbox.dcim.manufacturers.all()}

    def create_manufacturers(self, vendors):
        """Create any vendors not already present in NetBox as manufacturers.

        Skips vendors whose name or slug already exists. Logs creation attempts and any
        API errors. Updates the shared counter for each manufacturer created.

        Args:
            vendors (list[dict]): Vendor dicts with at least a "name" key; "slug" is added if absent.
        """
        # Get existing manufacturers (name + slug)
        self.existing_manufacturers = self.get_manufacturers()
        existing_slugs = {item.slug for item in self.existing_manufacturers.values()}
        existing_names = {item.name for item in self.existing_manufacturers.values()}

        to_create = []

        for vendor in vendors:
            # Ensure slug is set
            vendor.setdefault("slug", vendor["name"].lower().replace(" ", "-"))

            # Check existence by name or slug
            if vendor["name"] in existing_names or vendor["slug"] in existing_slugs:
                self.handle.verbose_log(f"Manufacturer Exists: {vendor['name']} (slug: {vendor['slug']})")
            else:
                to_create.append(vendor)
                self.handle.verbose_log(f"Manufacturer queued for addition: {vendor['name']} (slug: {vendor['slug']})")

        # Only if there are manufacturers to create → API call
        if to_create:
            self.handle.log(f"Creating {len(to_create)} new manufacturers...")
            try:
                created_manufacturers = self.netbox.dcim.manufacturers.create(to_create)
                for manufacturer in created_manufacturers:
                    self.handle.verbose_log(f"Manufacturer Created: {manufacturer.name} - {manufacturer.id}")
                    self.counter.update({"manufacturer": 1})
            except pynetbox.RequestError as request_error:
                # Log error with detailed API error message
                self.handle.log(f"Error creating manufacturers: {request_error.error}")
        else:
            self.handle.verbose_log("No new manufacturers to create.")

    def create_device_types(
        self,
        device_types_to_add,
        progress=None,
        only_new=False,
        update=False,
        change_report=None,
        remove_components=False,
    ):
        """Create or update device types and their component templates in NetBox.

        For each device type:

        - Images are uploaded to existing types if the file exists locally and is not yet in NetBox.
        - If the type already exists and ``only_new`` is True, it is skipped (after image handling).
        - If ``update`` is True and a matching change entry exists, property changes are applied
          and component additions/removals are performed.
        - If the type does not exist, it is created along with all component templates.

        Args:
            device_types_to_add (list[dict]): Parsed YAML device-type dicts to process.
            progress: Optional progress iterator wrapping ``device_types_to_add``.
            only_new (bool): If True, skip update logic for existing device types.
            update (bool): If True, apply property/component changes to existing types.
            change_report (ChangeReport | None): Pre-computed change report; required when ``update`` is True.
            remove_components (bool): If True (with ``update``), remove components absent from YAML.
        """
        # Note: Caching is now done externally before this method via preload_all_components()

        iterator = progress if progress is not None else device_types_to_add
        for device_type in iterator:
            # Remove file base path
            src_file = device_type["src"]
            del device_type["src"]

            # Pre-process front/rear_image flag, remove it if present
            saved_images = {}
            image_base = os.path.dirname(src_file).replace("device-types", "elevation-images")
            for i in ["front_image", "rear_image"]:
                if i in device_type:
                    if device_type[i]:
                        image_glob = f"{image_base}/{device_type['slug']}.{i.split('_')[0]}.*"
                        images = glob.glob(image_glob, recursive=False)
                        if images:
                            saved_images[i] = images[0]
                        else:
                            self.handle.log(f"Error locating image file using '{image_glob}'")
                    del device_type[i]

            try:
                # Look up by (manufacturer_slug, model), with fallback to (manufacturer_slug, slug)
                # The fallback handles cases where device exists in NetBox with a different model name
                manufacturer_slug = device_type["manufacturer"]["slug"]
                device_slug = device_type.get("slug", "")

                # Try primary lookup by model
                dt = self.device_types.existing_device_types.get((manufacturer_slug, device_type["model"]))

                # Fallback to lookup by slug if model lookup failed
                if dt is None and device_slug:
                    dt = self.device_types.existing_device_types_by_slug.get((manufacturer_slug, device_slug))
                    if dt is not None:
                        self.handle.verbose_log(
                            f"Device Type found by slug (model mismatch): NetBox has '{dt.model}', "
                            f"YAML has '{device_type['model']}'"
                        )

                if dt is None:
                    raise KeyError("Device type not found")

                # Upload images for existing device types (if missing) — always, regardless of mode
                if saved_images:
                    if "front_image" in saved_images and getattr(dt, "front_image", None):
                        self.handle.verbose_log(f"Front image already exists for {dt.model}, skipping upload.")
                        del saved_images["front_image"]

                    if "rear_image" in saved_images and getattr(dt, "rear_image", None):
                        self.handle.verbose_log(f"Rear image already exists for {dt.model}, skipping upload.")
                        del saved_images["rear_image"]

                    if saved_images:
                        self.device_types.upload_images(self.url, self.token, saved_images, dt.id)

                if only_new:
                    self.handle.verbose_log(
                        f"Device Type Cached: {dt.manufacturer.name} - {dt.model} - {dt.id}. Skipping updates (images already handled)."
                    )
                    continue

                # If update mode is enabled, update device type properties and components
                if update and change_report:
                    # Find the matching change entry once
                    dt_change = None
                    for change in change_report.modified_device_types:
                        if change.manufacturer_slug == manufacturer_slug and change.model == device_type["model"]:
                            dt_change = change
                            break

                    if dt_change:
                        # Apply property changes (exclude image properties — uploads are handled separately)
                        if dt_change.property_changes:
                            updates = {
                                pc.property_name: pc.new_value
                                for pc in dt_change.property_changes
                                if pc.property_name not in ("front_image", "rear_image")
                            }
                            if updates:
                                try:
                                    dt.update(updates)
                                    self.counter.update({"properties_updated": 1})
                                    self.handle.verbose_log(
                                        f"Updated device type {dt.model} properties: {list(updates.keys())}"
                                    )
                                except pynetbox.RequestError as e:
                                    self.handle.log(f"Error updating device type {dt.model}: {e.error}")

                        # Apply component changes
                        if dt_change.component_changes:
                            self.device_types.update_components(
                                device_type, dt.id, dt_change.component_changes, parent_type="device"
                            )
                            if remove_components:
                                self.device_types.remove_components(
                                    dt.id, dt_change.component_changes, parent_type="device"
                                )

                self.handle.verbose_log(f"Device Type Cached: {dt.manufacturer.name} - " + f"{dt.model} - {dt.id}")

                # Device type already exists - skip component creation
                continue

            except KeyError:
                # Device type doesn't exist - create it
                try:
                    dt = self.netbox.dcim.device_types.create(device_type)
                    self.counter.update({"added": 1})
                    self.handle.verbose_log(f"Device Type Created: {dt.manufacturer.name} - " + f"{dt.model} - {dt.id}")
                except pynetbox.RequestError as e:
                    self.handle.log(
                        f"Error {e.error} creating device type:"
                        f" {device_type['manufacturer']['slug']} {device_type['model']}"
                    )
                    continue

            # Create components for newly created device type
            if "interfaces" in device_type:
                self.device_types.create_interfaces(device_type["interfaces"], dt.id)
            if "power-ports" in device_type:
                self.device_types.create_power_ports(device_type["power-ports"], dt.id)
            if "power-port" in device_type:
                self.device_types.create_power_ports(device_type["power-port"], dt.id)
            if "console-ports" in device_type:
                self.device_types.create_console_ports(device_type["console-ports"], dt.id)
            if "power-outlets" in device_type:
                self.device_types.create_power_outlets(device_type["power-outlets"], dt.id)
            if "console-server-ports" in device_type:
                self.device_types.create_console_server_ports(device_type["console-server-ports"], dt.id)
            if "rear-ports" in device_type:
                self.device_types.create_rear_ports(device_type["rear-ports"], dt.id)
            if "front-ports" in device_type:
                self.device_types.create_front_ports(device_type["front-ports"], dt.id, context=src_file)
            if "device-bays" in device_type:
                self.device_types.create_device_bays(device_type["device-bays"], dt.id)
            if self.modules and "module-bays" in device_type:
                self.device_types.create_module_bays(device_type["module-bays"], dt.id)

            # Upload images for newly created device types
            if saved_images:
                self.device_types.upload_images(self.url, self.token, saved_images, dt.id)

    def get_existing_module_types(self):
        """Fetch all module types from NetBox and return them indexed by manufacturer slug and model.

        Returns:
            dict: ``{manufacturer_slug: {model: pynetbox_record}}``
        """
        all_module_types = {}
        for curr_nb_mt in self.netbox.dcim.module_types.all():
            if curr_nb_mt.manufacturer.slug not in all_module_types:
                all_module_types[curr_nb_mt.manufacturer.slug] = {}

            all_module_types[curr_nb_mt.manufacturer.slug][curr_nb_mt.model] = curr_nb_mt
        return all_module_types

    @staticmethod
    def _find_existing_module_type(module_type, all_module_types):
        """Look up a module type in *all_module_types* by model name, with slug fallback.

        Args:
            module_type (dict): Parsed YAML module-type dict with "manufacturer" and "model" keys.
            all_module_types (dict): Nested mapping ``{manufacturer_slug: {model: record}}``.

        Returns:
            pynetbox Record | None: Matching record, or None if not found.
        """
        manufacturer_slug = module_type["manufacturer"]["slug"]
        existing_for_vendor = all_module_types.get(manufacturer_slug, {})

        existing = existing_for_vendor.get(module_type["model"])
        if existing is not None:
            return existing

        slug = module_type.get("slug")
        if not slug:
            return None

        for existing_module in existing_for_vendor.values():
            if getattr(existing_module, "slug", None) == slug:
                return existing_module

        return None

    @staticmethod
    def filter_new_module_types(module_types, all_module_types):
        """Return module types that do not yet exist in NetBox.

        Args:
            module_types (list[dict]): Parsed YAML module-type dicts to filter.
            all_module_types (dict): Existing module types indexed by manufacturer slug and model.

        Returns:
            list[dict]: Module types not found in *all_module_types*.
        """
        new_module_types = []
        for module_type in module_types:
            if NetBox._find_existing_module_type(module_type, all_module_types) is None:
                new_module_types.append(module_type)
        return new_module_types

    def filter_actionable_module_types(self, module_types, all_module_types, only_new=False):
        """Determine which module types need to be created or updated in NetBox.

        For ``only_new=True``, returns only module types absent from NetBox. Otherwise,
        bulk-preloads component caches for all existing module types and includes any
        whose images or components differ from NetBox.

        Args:
            module_types (list[dict]): Parsed YAML module-type dicts.
            all_module_types (dict): Existing module types from :meth:`get_existing_module_types`.
            only_new (bool): If True, skip change detection and return only truly new entries.

        Returns:
            tuple[list[dict], dict]: Actionable module types and existing-image mapping
                ``{module_type_id: set_of_image_names}``.
        """
        if not module_types:
            return [], {}

        if only_new:
            return self.filter_new_module_types(module_types, all_module_types), {}

        module_type_existing_images = self._fetch_module_type_existing_images()

        actionable_module_types = []
        component_keys = (
            "interfaces",
            "power-ports",
            "console-ports",
            "power-outlets",
            "console-server-ports",
            "rear-ports",
            "front-ports",
        )

        # Bulk-preload components for all existing module types so the per-module
        # loop below hits the cache instead of issuing individual API calls.
        existing_module_map = {}
        existing_module_ids = set()
        for module_type in module_types:
            existing_module = self._find_existing_module_type(module_type, all_module_types)
            existing_module_map[id(module_type)] = existing_module
            if existing_module is not None:
                existing_module_ids.add(existing_module.id)
        if existing_module_ids:
            self.device_types.preload_module_type_components(existing_module_ids, component_keys)

        for module_type in module_types:
            existing_module = existing_module_map[id(module_type)]
            if existing_module is None:
                actionable_module_types.append(module_type)
                continue

            existing_images = module_type_existing_images.get(existing_module.id, set())
            image_files = self._discover_module_image_files(module_type.get("src", ""))
            if any(os.path.splitext(os.path.basename(path))[0] not in existing_images for path in image_files):
                actionable_module_types.append(module_type)
                continue

            has_missing_components = False
            for component_key in component_keys:
                components = module_type.get(component_key)
                if not components:
                    continue

                endpoint_attr, cache_name = ENDPOINT_CACHE_MAP[component_key]
                endpoint = getattr(self.netbox.dcim, endpoint_attr)
                existing_components = self.device_types._get_cached_or_fetch(
                    cache_name, existing_module.id, "module", endpoint
                )
                requested_names = {component.get("name") for component in components if component.get("name")}
                if any(name not in existing_components for name in requested_names):
                    has_missing_components = True
                    break

            if has_missing_components:
                actionable_module_types.append(module_type)

        return actionable_module_types, module_type_existing_images

    def _fetch_module_type_existing_images(self):
        """Query NetBox for all image attachments on module types and return a mapping.

        Returns:
            dict: ``{module_type_id: set_of_attachment_names}``
        """
        module_type_existing_images = {}
        for att in self.netbox.extras.image_attachments.filter(object_type="dcim.moduletype"):
            names = module_type_existing_images.setdefault(att.object_id, set())
            if att.name:
                names.add(att.name)
        self.handle.verbose_log(
            f"Found {len(module_type_existing_images)} module type(s) with existing image attachments."
        )
        return module_type_existing_images

    def create_module_types(
        self, module_types, progress=None, only_new=False, all_module_types=None, module_type_existing_images=None
    ):
        """Create or update module types and their component templates in NetBox.

        For each module type: fetches or creates the record, uploads any new images,
        and creates missing component templates (interfaces, power ports, console ports,
        power outlets, console server ports, rear ports, and front ports).

        Args:
            module_types (list[dict]): Parsed YAML module-type dicts to process.
            progress: Optional progress iterator wrapping ``module_types``.
            only_new (bool): If True, skip component updates for existing module types.
            all_module_types (dict | None): Existing module types cache; fetched if None.
            module_type_existing_images (dict | None): Existing image map; fetched if None.
        """
        if not module_types:
            return

        if all_module_types is None:
            all_module_types = self.get_existing_module_types()

        if module_type_existing_images is None:
            module_type_existing_images = self._fetch_module_type_existing_images()

        iterator = progress if progress is not None else module_types
        for curr_mt in iterator:
            src_file = curr_mt.get("src", "Unknown")
            if "src" in curr_mt:
                del curr_mt["src"]

            is_new = False
            module_type_res = self._find_existing_module_type(curr_mt, all_module_types)
            if module_type_res is not None:
                self.handle.verbose_log(
                    f"Module Type Cached: {module_type_res.manufacturer.name} - "
                    + f"{module_type_res.model} - {module_type_res.id}"
                )
            else:
                try:
                    module_type_res = self.netbox.dcim.module_types.create(curr_mt)
                    self.counter["module_added"] += 1
                    is_new = True
                    manufacturer_slug = curr_mt["manufacturer"]["slug"]
                    all_module_types.setdefault(manufacturer_slug, {})[curr_mt["model"]] = module_type_res
                    self.handle.verbose_log(
                        f"Module Type Created: {module_type_res.manufacturer.name} - "
                        + f"{module_type_res.model} - {module_type_res.id}"
                    )
                except pynetbox.RequestError as excep:
                    self.handle.log(f"Error creating Module Type: {excep} (Context: {src_file})")
                    continue

            # Upload images for both cached and newly created module types
            self._upload_module_type_images(module_type_res, src_file, module_type_existing_images)

            if only_new and not is_new:
                continue

            # Module component keys often use hyphens in YAML
            if "interfaces" in curr_mt:
                self.device_types.create_module_interfaces(curr_mt["interfaces"], module_type_res.id, context=src_file)
            if "power-ports" in curr_mt:
                self.device_types.create_module_power_ports(
                    curr_mt["power-ports"], module_type_res.id, context=src_file
                )
            if "console-ports" in curr_mt:
                self.device_types.create_module_console_ports(
                    curr_mt["console-ports"], module_type_res.id, context=src_file
                )
            if "power-outlets" in curr_mt:
                self.device_types.create_module_power_outlets(
                    curr_mt["power-outlets"], module_type_res.id, context=src_file
                )
            if "console-server-ports" in curr_mt:
                self.device_types.create_module_console_server_ports(
                    curr_mt["console-server-ports"], module_type_res.id, context=src_file
                )
            if "rear-ports" in curr_mt:
                self.device_types.create_module_rear_ports(curr_mt["rear-ports"], module_type_res.id, context=src_file)
            if "front-ports" in curr_mt:
                self.device_types.create_module_front_ports(
                    curr_mt["front-ports"], module_type_res.id, context=src_file
                )

    @staticmethod
    def _discover_module_image_files(src_file):
        """Locate image files associated with a module-type YAML source file.

        Derives the image directory by replacing the ``module-types`` component in the source
        path with ``module-images`` and appending the file stem as a subdirectory, then
        returns all files with recognised image extensions.

        Args:
            src_file (str): Path to the module-type YAML file.

        Returns:
            list[str]: Absolute paths of discovered image files; empty if the directory cannot
                be derived or contains no recognised images.
        """
        if not src_file or src_file == "Unknown":
            return []

        src_path = Path(src_file)
        parts = list(src_path.parent.parts)
        try:
            # Replace the last occurrence — handles edge cases where
            # "module-types" could appear earlier in the path as well.
            idx = len(parts) - 1 - parts[::-1].index("module-types")
        except ValueError:
            return []

        parts[idx] = "module-images"
        image_dir = Path(*parts) / src_path.stem
        image_files = glob.glob(str(image_dir / "*"))
        return [f for f in image_files if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS]

    def _upload_module_type_images(self, module_type_res, src_file, module_type_existing_images):
        """Discover and upload images for a module type, skipping duplicates.

        Derives an image directory by replacing the 'module-types' path component
        with 'module-images' and appending the module filename (without extension).
        Only uploads images whose name (basename without extension) is not already
        present in module_type_existing_images for this module type.

        Parameters:
            module_type_res: pynetbox Record for the module type.
            src_file (str): Source YAML file path used to derive the image directory.
            module_type_existing_images (dict): module_type_id -> set of attachment names.
        """
        image_files = self._discover_module_image_files(src_file)
        if not image_files:
            return

        existing = module_type_existing_images.setdefault(module_type_res.id, set())
        for img_path in image_files:
            img_name = os.path.splitext(os.path.basename(img_path))[0]
            if img_name in existing:
                self.handle.verbose_log(
                    f"Image '{os.path.basename(img_path)}' already exists for {module_type_res.model}, skipping."
                )
                continue
            if self.device_types.upload_image_attachment(
                self.url, self.token, img_path, "dcim.moduletype", module_type_res.id
            ):
                existing.add(img_name)


# Component type -> (dcim endpoint attribute name, cache key name).
# The two tuple elements are intentionally identical today (endpoint attribute == cache name)
# but are kept separate to allow them to diverge independently in the future.
ENDPOINT_CACHE_MAP = {
    "interfaces": ("interface_templates", "interface_templates"),
    "power-ports": ("power_port_templates", "power_port_templates"),
    "power-port": ("power_port_templates", "power_port_templates"),
    "console-ports": ("console_port_templates", "console_port_templates"),
    "power-outlets": ("power_outlet_templates", "power_outlet_templates"),
    "console-server-ports": ("console_server_port_templates", "console_server_port_templates"),
    "rear-ports": ("rear_port_templates", "rear_port_templates"),
    "front-ports": ("front_port_templates", "front_port_templates"),
    "device-bays": ("device_bay_templates", "device_bay_templates"),
    "module-bays": ("module_bay_templates", "module_bay_templates"),
}


class DeviceTypes:
    """Manages caching and creation of device-type component templates in NetBox."""

    def __new__(cls, *args, **kwargs):
        """Allocate a new DeviceTypes instance using the default object allocator."""
        return super().__new__(cls)

    def __init__(self, netbox, exception_handler, counter, ignore_ssl, new_filters):
        """Initialize the DeviceTypes cache and load all existing device types from NetBox.

        Args:
            netbox: Connected pynetbox API instance.
            exception_handler (LogHandler): Handler for logging and error reporting.
            counter (Counter): Shared operation counter updated during creation.
            ignore_ssl (bool): Whether SSL certificate verification is disabled.
            new_filters (bool): Whether to use updated filter parameter names (NetBox >= 4.1).
        """
        self.netbox = netbox
        self.handle = exception_handler
        self.counter = counter
        self.ignore_ssl = ignore_ssl
        self.new_filters = new_filters
        self.cached_components = {}
        self.existing_device_types, self.existing_device_types_by_slug = self.get_device_types()

    def get_device_types(self):
        """Fetch all device types from NetBox and build two lookup indexes.

        Returns:
            tuple[dict, dict]:
                - ``by_model``: ``{(manufacturer_slug, model): record}``
                - ``by_slug``: ``{(manufacturer_slug, slug): record}``
        """
        # Build two indexes for lookup:
        # 1. By (manufacturer_slug, model) - primary lookup
        # 2. By (manufacturer_slug, slug) - fallback for renamed devices
        by_model = {}
        by_slug = {}
        for item in self.netbox.dcim.device_types.all():
            by_model[(item.manufacturer.slug, item.model)] = item
            by_slug[(item.manufacturer.slug, item.slug)] = item
        return by_model, by_slug

    def resolve_existing_device_type_ids(self, device_types):
        """Return NetBox device-type IDs matching parsed YAML device types."""
        ids = set()
        for device_type in device_types:
            manufacturer_slug = device_type["manufacturer"]["slug"]
            model = device_type["model"]
            slug = device_type.get("slug", "")

            existing = self.existing_device_types.get((manufacturer_slug, model))
            if existing is None and slug:
                existing = self.existing_device_types_by_slug.get((manufacturer_slug, slug))

            if existing is not None:
                ids.add(existing.id)

        return ids

    @staticmethod
    def _component_preload_targets():
        """Return the list of ``(endpoint_attr, display_label)`` pairs used for component preloading."""
        return [
            ("interface_templates", "Interfaces"),
            ("power_port_templates", "Power Ports"),
            ("console_port_templates", "Console Ports"),
            ("console_server_port_templates", "Console Server Ports"),
            ("power_outlet_templates", "Power Outlets"),
            ("rear_port_templates", "Rear Ports"),
            ("front_port_templates", "Front Ports"),
            ("device_bay_templates", "Device Bays"),
            ("module_bay_templates", "Module Bays"),
        ]

    def _get_endpoint_totals(self, components):
        """Fetch total record counts for all given component endpoints in parallel.

        Args:
            components: Iterable of ``(endpoint_name, label)`` tuples.

        Returns:
            dict: ``{endpoint_name: int}`` mapping each endpoint to its record count.
        """
        max_workers = max(1, min(len(components), 8))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as total_executor:
            total_futures = {
                endpoint_name: total_executor.submit(self._get_endpoint_total, endpoint_name)
                for endpoint_name, _label in components
            }
            return {endpoint_name: total_futures[endpoint_name].result() for endpoint_name, _label in components}

    def start_component_preload(self, vendor_slugs=None, progress=None):
        """Start concurrent component prefetch and return a preload job handle."""
        components = self._component_preload_targets()
        max_workers = max(1, min(len(components), 8))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)

        if vendor_slugs:
            vendor_scope = set(vendor_slugs)
            dt_ids = sorted(
                {dt.id for (mfr_slug, _model), dt in self.existing_device_types.items() if mfr_slug in vendor_scope}
            )
            futures = {
                endpoint_name: executor.submit(self._fetch_scoped_endpoint_records, endpoint_name, dt_ids)
                for endpoint_name, _label in components
            }
            return {
                "mode": "scoped",
                "components": components,
                "dt_ids": dt_ids,
                "futures": futures,
                "finished_endpoints": set(),
                "executor": executor,
            }

        endpoint_totals = self._get_endpoint_totals(components)
        progress_updates = queue.Queue()
        task_ids = None

        if progress is not None:
            task_ids = {
                endpoint_name: progress.add_task(
                    f"Caching {label}",
                    total=max(endpoint_totals.get(endpoint_name, 0), 1),
                )
                for endpoint_name, label in components
            }

        def update_progress(endpoint_name, advance):
            progress_updates.put((endpoint_name, advance))

        futures = {
            endpoint_name: executor.submit(
                self._fetch_global_endpoint_records,
                endpoint_name,
                update_progress,
                endpoint_totals.get(endpoint_name, 0),
            )
            for endpoint_name, _label in components
        }
        return {
            "mode": "global",
            "components": components,
            "futures": futures,
            "progress_updates": progress_updates,
            "endpoint_totals": endpoint_totals,
            "task_ids": task_ids,
            "finished_endpoints": set(),
            "executor": executor,
        }

    @staticmethod
    def stop_component_preload(preload_job):
        """Cancel any pending futures in *preload_job* and shut down its executor.

        Args:
            preload_job (dict | None): Preload job returned by :meth:`start_component_preload`; no-op if None.
        """
        if not preload_job:
            return

        futures = preload_job.get("futures", {})
        for future in futures.values():
            if not future.done():
                future.cancel()

        executor = preload_job.get("executor")
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)
            preload_job["executor"] = None

    @staticmethod
    def _apply_progress_updates(progress_updates, progress, task_ids, allowed_endpoints=None):
        """Drain the progress queue and advance the corresponding Rich progress tasks.

        Args:
            progress_updates (queue.Queue | None): Queue of ``(endpoint_name, advance)`` tuples.
            progress: Rich Progress instance, or None to skip.
            task_ids (dict | None): Mapping of endpoint name to Rich task ID.
            allowed_endpoints (set | None): If provided, only updates for these endpoints are applied.

        Returns:
            bool: True if at least one task was advanced; False otherwise.
        """
        if progress_updates is None or progress is None or not task_ids:
            return False

        advanced = False
        updates = {}
        while True:
            try:
                endpoint_name, advance = progress_updates.get_nowait()
                if allowed_endpoints is not None and endpoint_name not in allowed_endpoints:
                    continue
                updates[endpoint_name] = updates.get(endpoint_name, 0) + advance
            except queue.Empty:
                break

        for endpoint_name, advance in updates.items():
            task_id = task_ids.get(endpoint_name)
            if task_id is not None:
                progress.update(task_id, advance=advance)
                advanced = True

        return advanced

    def pump_preload_progress(self, preload_job, progress):
        """Drain pending progress updates and mark completed endpoints for *preload_job*.

        Intended to be called periodically while parsing is in progress so that the
        progress bar advances before :meth:`preload_all_components` is called.

        Args:
            preload_job (dict | None): Preload job returned by :meth:`start_component_preload`.
            progress: Rich Progress instance.

        Returns:
            bool: True if any progress updates were applied or endpoints were marked done.
        """
        if not preload_job:
            return False
        futures = preload_job.get("futures", {})
        finished_endpoints = preload_job.setdefault("finished_endpoints", set())
        pending_endpoints = {endpoint_name for endpoint_name in futures if endpoint_name not in finished_endpoints}

        advanced = self._apply_progress_updates(
            preload_job.get("progress_updates"),
            progress,
            preload_job.get("task_ids"),
            allowed_endpoints=pending_endpoints if pending_endpoints else None,
        )

        task_ids = preload_job.get("task_ids") or {}
        endpoint_totals = preload_job.get("endpoint_totals", {})
        for endpoint_name in pending_endpoints:
            future = futures.get(endpoint_name)
            if future is None or not future.done():
                continue
            if progress is not None and endpoint_name in task_ids:
                total = max(endpoint_totals.get(endpoint_name, 0), 1)
                progress.update(task_ids[endpoint_name], total=total, completed=total)
                progress.stop_task(task_ids[endpoint_name])
            finished_endpoints.add(endpoint_name)
            advanced = True

        return advanced

    def preload_all_components(
        self,
        progress_wrapper=None,
        vendor_slugs=None,
        preload_job=None,
        progress=None,
        device_type_ids=None,
    ):
        """Pre-fetch component templates to avoid N+1 queries during updates.

        Args:
            progress_wrapper: Optional callable to wrap iterables with progress bars
            vendor_slugs: Optional list of vendor slugs to scope the preload.
                When provided, only caches components for device types belonging
                to these vendors (per-device-type API calls).
                When None, fetches all components globally (bulk .all()).
            device_type_ids: Optional explicit set/list of device-type IDs to scope preload.
                When provided, takes precedence over vendor_slugs.
            preload_job: Optional preload job from start_component_preload().
            progress: Optional shared Rich Progress instance used to render
                all caching tasks inside a single progress panel.
        """
        components = self._component_preload_targets()

        if preload_job:
            mode = preload_job.get("mode")
            if mode == "scoped":
                self._preload_scoped(
                    preload_job.get("components", components),
                    preload_job.get("dt_ids", []),
                    progress_wrapper,
                    preload_job=preload_job,
                    progress=progress,
                )
            else:
                self._preload_global(
                    preload_job.get("components", components),
                    progress_wrapper,
                    preload_job=preload_job,
                    progress=progress,
                )
            return

        if device_type_ids is not None:
            self._preload_scoped(components, set(device_type_ids), progress_wrapper, progress=progress)
            return

        if vendor_slugs:
            # Collect device type IDs for the specified vendors
            dt_ids = {
                dt.id for (mfr_slug, _model), dt in self.existing_device_types.items() if mfr_slug in vendor_slugs
            }
            self._preload_scoped(components, dt_ids, progress_wrapper, progress=progress)
        else:
            self._preload_global(components, progress_wrapper, progress=progress)

    def _preload_global(self, components, progress_wrapper=None, preload_job=None, progress=None):
        """Fetch all component templates globally (no vendor/device filter)."""
        own_executor = preload_job is None
        if preload_job:
            executor = preload_job.get("executor")
            futures = preload_job.get("futures", {})
            progress_updates = preload_job.get("progress_updates")
            endpoint_totals = preload_job.get("endpoint_totals", {})
        else:
            max_workers = max(1, min(len(components), 8))
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
            endpoint_totals = self._get_endpoint_totals(components)
            if progress is not None:
                progress_updates = queue.Queue()

                def update_progress(endpoint_name, advance):
                    progress_updates.put((endpoint_name, advance))

                futures = {
                    endpoint: executor.submit(
                        self._fetch_global_endpoint_records,
                        endpoint,
                        update_progress,
                        endpoint_totals.get(endpoint, 0),
                    )
                    for endpoint, _label in components
                }
            else:
                futures = {
                    endpoint: executor.submit(
                        self._fetch_global_endpoint_records,
                        endpoint,
                        None,
                        endpoint_totals.get(endpoint, 0),
                    )
                    for endpoint, _label in components
                }
                progress_updates = None

        try:
            records_by_endpoint = {}
            if progress is not None:
                task_ids = preload_job.get("task_ids") if preload_job else None
                if not task_ids:
                    task_ids = {
                        endpoint: progress.add_task(
                            f"Caching {label}",
                            total=max(endpoint_totals.get(endpoint, 0), 1),
                        )
                        for endpoint, label in components
                    }
                future_map = {endpoint: futures[endpoint] for endpoint, _label in components if endpoint in futures}
                pending = set(future_map.keys())

                while pending:
                    had_updates = self._apply_progress_updates(
                        progress_updates,
                        progress,
                        task_ids,
                        allowed_endpoints=pending,
                    )

                    done_now = [endpoint_name for endpoint_name in pending if future_map[endpoint_name].done()]
                    for endpoint_name in done_now:
                        pending.remove(endpoint_name)
                        try:
                            records_by_endpoint[endpoint_name] = future_map[endpoint_name].result()
                        except (pynetbox.RequestError, concurrent.futures.CancelledError, Exception) as exc:
                            self.handle.log(f"Preload failed for {endpoint_name}: {exc}")
                            records_by_endpoint[endpoint_name] = []
                        final_total = max(
                            endpoint_totals.get(endpoint_name, 0),
                            len(records_by_endpoint[endpoint_name]),
                            1,
                        )
                        progress.update(
                            task_ids[endpoint_name],
                            total=final_total,
                            completed=final_total,
                        )
                        progress.stop_task(task_ids[endpoint_name])

                    if pending and not had_updates:
                        if progress_updates is not None:
                            try:
                                endpoint_name, advance = progress_updates.get(timeout=0.1)
                                if endpoint_name not in pending:
                                    progress_updates.put((endpoint_name, advance))
                                    continue
                                task_id = task_ids.get(endpoint_name)
                                if task_id is not None:
                                    progress.update(task_id, advance=advance)
                            except queue.Empty:
                                pass
                        else:
                            concurrent.futures.wait(
                                [future_map[endpoint_name] for endpoint_name in pending],
                                timeout=0.1,
                                return_when=concurrent.futures.FIRST_COMPLETED,
                            )
            else:
                for endpoint, label in components:
                    self.handle.verbose_log(f"Pre-fetching {label}...")
                    try:
                        records_by_endpoint[endpoint] = futures[endpoint].result()
                    except (pynetbox.RequestError, concurrent.futures.CancelledError, Exception) as exc:
                        self.handle.log(f"Preload failed for {label}: {exc}")
                        records_by_endpoint[endpoint] = []

            for endpoint, label in components:
                all_items = records_by_endpoint.get(endpoint, [])
                cache, count = self._build_component_cache(all_items)
                self.cached_components[endpoint] = cache
                self.handle.verbose_log(f"Cached {count} {label}.")
        finally:
            if executor:
                if own_executor:
                    executor.shutdown(wait=True)
                elif preload_job and preload_job.get("executor") is executor:
                    executor.shutdown(wait=True)
                    preload_job["executor"] = None

    def _preload_scoped(self, components, device_type_ids, progress_wrapper=None, preload_job=None, progress=None):
        """Fetch component templates for the given device type IDs via per-device-type API calls."""
        dt_ids = sorted(set(device_type_ids))
        self.handle.verbose_log(f"Scoped preload for {len(dt_ids)} device type(s)...")

        own_executor = preload_job is None
        if preload_job:
            executor = preload_job.get("executor")
            futures = preload_job.get("futures", {})
            progress_updates = None
        else:
            max_workers = max(1, min(len(components), 8))
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
            if progress is not None:
                progress_updates = queue.Queue()

                def update_progress(endpoint_name, advance):
                    progress_updates.put((endpoint_name, advance))

                futures = {
                    endpoint_name: executor.submit(
                        self._fetch_scoped_endpoint_records, endpoint_name, dt_ids, update_progress
                    )
                    for endpoint_name, _label in components
                }
            else:
                futures = {
                    endpoint_name: executor.submit(self._fetch_scoped_endpoint_records, endpoint_name, dt_ids)
                    for endpoint_name, _label in components
                }
                progress_updates = None

        try:
            records_by_endpoint = {}
            if progress is not None:
                if preload_job:
                    # Preloaded scoped jobs don't report per-device updates, so track completion per endpoint.
                    task_ids = {
                        endpoint_name: progress.add_task(f"Caching {label}", total=1)
                        for endpoint_name, label in components
                    }
                    future_map = {
                        futures[endpoint_name]: (endpoint_name, label)
                        for endpoint_name, label in components
                        if endpoint_name in futures
                    }
                    for future in concurrent.futures.as_completed(future_map):
                        endpoint_name, _label = future_map[future]
                        try:
                            records_by_endpoint[endpoint_name] = future.result()
                        except (pynetbox.RequestError, concurrent.futures.CancelledError, Exception) as exc:
                            self.handle.log(f"Preload failed for {endpoint_name}: {exc}")
                            records_by_endpoint[endpoint_name] = {}
                        progress.update(task_ids[endpoint_name], completed=1)
                        progress.stop_task(task_ids[endpoint_name])
                else:
                    total_per_endpoint = max(len(dt_ids), 1)
                    task_ids = {
                        endpoint_name: progress.add_task(
                            f"Caching {label}",
                            total=total_per_endpoint,
                        )
                        for endpoint_name, label in components
                    }
                    future_map = {
                        endpoint_name: futures[endpoint_name]
                        for endpoint_name, _label in components
                        if endpoint_name in futures
                    }
                    pending = set(future_map.keys())

                    while pending:
                        updates = {}
                        while True:
                            try:
                                endpoint_name, advance = progress_updates.get_nowait()
                                if endpoint_name not in pending:
                                    continue
                                updates[endpoint_name] = updates.get(endpoint_name, 0) + advance
                            except queue.Empty:
                                break

                        for endpoint_name, advance in updates.items():
                            progress.update(task_ids[endpoint_name], advance=advance)

                        done_now = [endpoint_name for endpoint_name in pending if future_map[endpoint_name].done()]
                        for endpoint_name in done_now:
                            pending.remove(endpoint_name)
                            try:
                                records_by_endpoint[endpoint_name] = future_map[endpoint_name].result()
                            except (pynetbox.RequestError, concurrent.futures.CancelledError, Exception) as exc:
                                self.handle.log(f"Preload failed for {endpoint_name}: {exc}")
                                records_by_endpoint[endpoint_name] = {}
                            progress.update(task_ids[endpoint_name], completed=total_per_endpoint)
                            progress.stop_task(task_ids[endpoint_name])

                        if pending and not updates:
                            try:
                                endpoint_name, advance = progress_updates.get(timeout=0.1)
                                if endpoint_name not in pending:
                                    progress_updates.put((endpoint_name, advance))
                                    continue
                                progress.update(task_ids[endpoint_name], advance=advance)
                            except queue.Empty:
                                pass
            else:
                for endpoint_name, label in components:
                    self.handle.verbose_log(f"Pre-fetching {label}...")
                    try:
                        records_by_endpoint[endpoint_name] = futures[endpoint_name].result()
                    except (pynetbox.RequestError, concurrent.futures.CancelledError, Exception) as exc:
                        self.handle.log(f"Preload failed for {label}: {exc}")
                        records_by_endpoint[endpoint_name] = {}

            for endpoint_name, label in components:
                records_by_dt = records_by_endpoint.get(endpoint_name, {})
                cache = {}
                count = 0
                for dt_id in dt_ids:
                    key = ("device", dt_id)
                    cache[key] = {}
                    for item in records_by_dt.get(dt_id, []):
                        cache[key][item.name] = item
                        count += 1

                self.cached_components[endpoint_name] = cache
                self.handle.verbose_log(f"Cached {count} {label}.")
        finally:
            if executor:
                if own_executor:
                    executor.shutdown(wait=True)
                elif preload_job and preload_job.get("executor") is executor:
                    executor.shutdown(wait=True)
                    preload_job["executor"] = None

    def _fetch_global_endpoint_records(self, endpoint_name, progress_callback=None, expected_total=None):
        """Fetch all records for *endpoint_name* from NetBox, emitting batched progress updates.

        Args:
            endpoint_name (str): Attribute name on ``self.netbox.dcim`` (e.g. ``"interface_templates"``).
            progress_callback (callable | None): Called with ``(endpoint_name, advance)`` periodically.
            expected_total (int | None): Expected record count; reserved for callers, unused here.

        Returns:
            list: All pynetbox records returned by ``endpoint.all()``.
        """
        endpoint = getattr(self.netbox.dcim, endpoint_name)
        records = []
        last_emit_time = time.monotonic()
        pending_advance = 0

        def flush_progress(force=False):
            nonlocal pending_advance, last_emit_time
            if progress_callback is None or pending_advance <= 0:
                return
            now = time.monotonic()
            if force or now - last_emit_time >= 1.0:
                progress_callback(endpoint_name, pending_advance)
                pending_advance = 0
                last_emit_time = now

        for item in endpoint.all():
            records.append(item)
            pending_advance += 1
            flush_progress()
        flush_progress(force=True)
        return records

    def _fetch_scoped_endpoint_records(self, endpoint_name, dt_ids, progress_callback=None):
        """Fetch component records for the given device-type IDs from a single endpoint.

        Issues one ``filter()`` API call per device-type ID and returns results grouped by ID.

        Args:
            endpoint_name (str): Attribute name on ``self.netbox.dcim``.
            dt_ids (list[int]): Device-type IDs to fetch components for.
            progress_callback (callable | None): Called with ``(endpoint_name, 1)`` after each ID.

        Returns:
            dict: ``{device_type_id: list[record]}``
        """
        endpoint = getattr(self.netbox.dcim, endpoint_name)
        records_by_dt = {}
        for dt_id in dt_ids:
            filter_kwargs = self._get_filter_kwargs(dt_id, "device")
            records_by_dt[dt_id] = list(endpoint.filter(**filter_kwargs))
            if progress_callback is not None:
                progress_callback(endpoint_name, 1)
        return records_by_dt

    def _get_endpoint_total(self, endpoint_name):
        """Return the total number of records for *endpoint_name*, or 0 on error.

        Args:
            endpoint_name (str): Attribute name on ``self.netbox.dcim``.

        Returns:
            int: Record count, or 0 if the count cannot be retrieved.
        """
        endpoint = getattr(self.netbox.dcim, endpoint_name)
        try:
            total = endpoint.count()
            if total is None:
                return 0
            return int(total)
        except (AttributeError, TypeError, ValueError, pynetbox.RequestError):
            return 0

    @staticmethod
    def _build_component_cache(items):
        """Organise a flat list of component records into a nested cache structure.

        Args:
            items (list): pynetbox records; each must have a ``device_type`` or ``module_type`` attribute.

        Returns:
            tuple[dict, int]: Cache ``{(parent_type, parent_id): {name: record}}`` and the total
                number of items successfully indexed.
        """
        cache = {}
        count = 0
        for item in items:
            parent_id = None
            parent_type = None

            if getattr(item, "device_type", None):
                parent_id = item.device_type.id
                parent_type = "device"
            elif getattr(item, "module_type", None):
                parent_id = item.module_type.id
                parent_type = "module"

            if not parent_id:
                continue

            key = (parent_type, parent_id)
            if key not in cache:
                cache[key] = {}
            cache[key][item.name] = item
            count += 1

        return cache, count

    def _get_filter_kwargs(self, parent_id, parent_type="device"):
        """Build endpoint filter keyword arguments for the given parent type and ID.

        Selects the correct parameter name based on the NetBox version (``self.new_filters``).

        Args:
            parent_id (int): ID of the device type or module type.
            parent_type (str): ``"device"`` or ``"module"``.

        Returns:
            dict: Filter kwargs to pass to a pynetbox endpoint's ``filter()`` method.
        """
        if parent_type == "device":
            key = "device_type_id" if self.new_filters else "devicetype_id"
            return {key: parent_id}
        else:
            # Module types: module_type_id (new) vs moduletype_id (old)
            key = "module_type_id" if self.new_filters else "moduletype_id"
            return {key: parent_id}

    def _get_cached_or_fetch(self, cache_name, parent_id, parent_type, endpoint):
        """Return cached components or fall back to fetching from the API.

        Args:
            cache_name: Key in self.cached_components (e.g. "rear_port_templates")
            parent_id: Device type or module type ID
            parent_type: "device" or "module"
            endpoint: pynetbox endpoint proxy to filter against on cache miss

        Returns:
            Dict mapping component name -> pynetbox Record
        """
        cache_key = (parent_type, parent_id)
        if cache_name in self.cached_components:
            if cache_key in self.cached_components[cache_name]:
                return self.cached_components[cache_name][cache_key]

        filter_kwargs = self._get_filter_kwargs(parent_id, parent_type)
        result = {item.name: item for item in endpoint.filter(**filter_kwargs)}
        self.cached_components.setdefault(cache_name, {})[cache_key] = result
        return result

    def preload_module_type_components(self, module_type_ids, component_keys):
        """Bulk-fetch components for module types and populate the cache.

        For each component endpoint referenced by *component_keys*, issues one
        ``filter()`` call per endpoint (filtering by module_type_id=[...]) and
        distributes the returned items into per-module-type cache entries so
        that subsequent ``_get_cached_or_fetch`` calls hit the cache.
        """
        if not module_type_ids:
            return

        seen_endpoints = set()
        targets = []
        for component_key in component_keys:
            endpoint_attr, cache_name = ENDPOINT_CACHE_MAP[component_key]
            if endpoint_attr in seen_endpoints:
                continue
            seen_endpoints.add(endpoint_attr)
            targets.append((endpoint_attr, cache_name))

        filter_key = "module_type_id" if self.new_filters else "moduletype_id"
        id_list = sorted(module_type_ids)

        for endpoint_attr, cache_name in targets:
            endpoint = getattr(self.netbox.dcim, endpoint_attr)
            cache = self.cached_components.setdefault(cache_name, {})
            # Pre-populate empty entries so cache hits return {} for IDs with no components
            for mid in id_list:
                cache.setdefault(("module", mid), {})
            for item in endpoint.filter(**{filter_key: id_list}):
                mid = item.module_type.id
                cache.setdefault(("module", mid), {})[item.name] = item

    def _create_generic(
        self,
        items,
        parent_id,
        endpoint,
        component_name,
        parent_type="device",
        post_process=None,
        context=None,
        cache_name=None,
    ):
        """Create component templates in NetBox, skipping those that already exist.

        Fetches existing components (via cache or API), filters *items* to only new entries,
        optionally runs *post_process* to mutate items before creation (e.g. resolving port IDs),
        then calls ``endpoint.create()`` and updates counters. On error, logs each failed item.

        Args:
            items (list[dict]): Component definitions to create; each must have a "name" key.
            parent_id (int): ID of the parent device or module type.
            endpoint: pynetbox endpoint proxy for create/filter calls.
            component_name (str): Human-readable component type for log messages.
            parent_type (str): ``"device"`` or ``"module"``; determines parent key and counter key.
            post_process (callable | None): Optional ``(items, parent_id)`` callback run before creation.
            context (str | None): Optional context string appended to error log messages.
            cache_name (str | None): Key in ``self.cached_components``; entry is invalidated after creation.
        """
        # Look up existing components via cache or API fallback
        existing = self._get_cached_or_fetch(cache_name, parent_id, parent_type, endpoint)

        to_create = [x for x in items if x["name"] not in existing]
        parent_key = "device_type" if parent_type == "device" else "module_type"

        for item in to_create:
            item[parent_key] = parent_id

        if post_process:
            post_process(to_create, parent_id)

        if to_create:
            try:
                created = endpoint.create(to_create)
                if parent_type == "device":
                    count = self.handle.log_device_ports_created(created, component_name)
                    self.counter.update({"components_added": count})
                else:
                    count = self.handle.log_module_ports_created(created, component_name)
                    self.counter.update({"components_added": count})

                # Invalidate cache so subsequent lookups re-fetch with new records
                if cache_name and cache_name in self.cached_components:
                    cache_key = (parent_type, parent_id)
                    self.cached_components[cache_name].pop(cache_key, None)
            except pynetbox.RequestError as excep:
                context_str = f" (Context: {context})" if context else ""
                if isinstance(excep.error, list):
                    for i, error in enumerate(excep.error):
                        if error:
                            item_name = to_create[i].get("name", "Unknown")
                            self.handle.log(f"Failed to create {component_name} '{item_name}': {error}{context_str}")
                else:
                    failed_items = [x["name"] for x in to_create]
                    self.handle.log(
                        f"Error '{excep.error}' creating {component_name}. Items: {failed_items}{context_str}"
                    )

    def update_components(self, yaml_data, device_type_id, component_changes, parent_type="device"):
        """
        Update existing components and add new components based on detected changes.

        Args:
            yaml_data: YAML device type data containing component definitions
            device_type_id: ID of the device type in NetBox
            component_changes: List of ComponentChange objects with detected changes
            parent_type: "device" or "module"
        """
        # Group changes by component type and change type
        changes_to_update = {}
        changes_to_add = {}
        for change in component_changes:
            if change.change_type == ChangeType.COMPONENT_CHANGED:
                if change.component_type not in changes_to_update:
                    changes_to_update[change.component_type] = []
                changes_to_update[change.component_type].append(change)
            elif change.change_type == ChangeType.COMPONENT_ADDED:
                if change.component_type not in changes_to_add:
                    changes_to_add[change.component_type] = []
                changes_to_add[change.component_type].append(change)

        # Handle component updates
        for comp_type, changes in changes_to_update.items():
            mapping = ENDPOINT_CACHE_MAP.get(comp_type)
            if not mapping:
                continue
            endpoint_attr, cache_name = mapping
            endpoint = getattr(self.netbox.dcim, endpoint_attr, None)
            if not endpoint:
                continue

            existing = self._get_cached_or_fetch(cache_name, device_type_id, parent_type, endpoint)

            updates = []
            for change in changes:
                if change.component_name in existing:
                    comp = existing[change.component_name]
                    update_data = {"id": comp.id}
                    for pc in change.property_changes:
                        update_data[pc.property_name] = pc.new_value
                    updates.append(update_data)

            success_count = 0
            for update_data in updates:
                try:
                    endpoint.update([update_data])
                    success_count += 1
                    self.handle.verbose_log(f"Updated {comp_type} (ID: {update_data['id']})")
                except pynetbox.RequestError as e:
                    self.handle.log(f"Error updating {comp_type} (ID: {update_data['id']}): {e.error}")

            if success_count:
                self.counter.update({"components_updated": success_count})
                self.handle.verbose_log(f"Updated {success_count} {comp_type}")

                # Invalidate cache so subsequent lookups re-fetch with updated records
                if cache_name in self.cached_components:
                    cache_key = (parent_type, device_type_id)
                    self.cached_components[cache_name].pop(cache_key, None)

        # Handle component additions
        for comp_type, changes in changes_to_add.items():
            # Resolve YAML key: check canonical key first, then aliases
            yaml_key = None
            if comp_type in yaml_data:
                yaml_key = comp_type
            else:
                for alias, canonical in COMPONENT_ALIASES.items():
                    if canonical == comp_type and alias in yaml_data:
                        yaml_key = alias
                        break
            if yaml_key is None:
                continue

            mapping = ENDPOINT_CACHE_MAP.get(comp_type)
            if not mapping:
                continue
            endpoint_attr, cache_name = mapping
            endpoint = getattr(self.netbox.dcim, endpoint_attr, None)
            if not endpoint:
                continue

            # Find the new components in the YAML data
            yaml_components = yaml_data.get(yaml_key) or []
            new_component_names = {change.component_name for change in changes}
            components_to_add = [c for c in yaml_components if c.get("name") in new_component_names]

            if not components_to_add:
                continue

            # Format component name for logging (e.g. "power_port_templates" -> "Power Port")
            component_name = endpoint_attr.replace("_templates", "").replace("_", " ").title()

            self._create_generic(
                components_to_add,
                device_type_id,
                endpoint,
                component_name,
                parent_type=parent_type,
                cache_name=cache_name,
            )

    def remove_components(self, device_type_id, component_changes, parent_type="device"):
        """
        Remove components that exist in NetBox but not in YAML.

        Args:
            device_type_id: ID of the device type in NetBox
            component_changes: List of ComponentChange objects with detected changes
            parent_type: "device" or "module"
        """
        # Filter for removal changes only
        removals = [c for c in component_changes if c.change_type == ChangeType.COMPONENT_REMOVED]

        # Group removals by component type
        removals_by_type = {}
        for removal in removals:
            if removal.component_type not in removals_by_type:
                removals_by_type[removal.component_type] = []
            removals_by_type[removal.component_type].append(removal)

        # Process removals for each component type
        for comp_type, changes in removals_by_type.items():
            mapping = ENDPOINT_CACHE_MAP.get(comp_type)
            if not mapping:
                continue
            endpoint_attr, cache_name = mapping
            endpoint = getattr(self.netbox.dcim, endpoint_attr, None)
            if not endpoint:
                continue

            existing = self._get_cached_or_fetch(cache_name, device_type_id, parent_type, endpoint)

            ids_to_delete = []
            for change in changes:
                if change.component_name in existing:
                    comp = existing[change.component_name]
                    ids_to_delete.append(comp.id)
                    self.handle.verbose_log(f"Removing {comp_type}: {change.component_name} (ID: {comp.id})")

            # Delete components one at a time so a single failure doesn't skip the rest
            success_count = 0
            for comp_id in ids_to_delete:
                try:
                    endpoint.delete([comp_id])
                    success_count += 1
                except pynetbox.RequestError as e:
                    self.handle.log(f"Error removing {comp_type} (ID: {comp_id}): {e.error}")

            if success_count:
                self.counter.update({"components_removed": success_count})
                self.handle.log(f"Removed {success_count} {comp_type}")

                # Invalidate cache so subsequent lookups re-fetch without deleted records
                if cache_name in self.cached_components:
                    cache_key = (parent_type, device_type_id)
                    self.cached_components[cache_name].pop(cache_key, None)

    def create_interfaces(self, interfaces, device_type, context=None):
        """Create interface templates for a device type, handling bridge references.

        Strips ``bridge`` entries before creation and re-applies them after by resolving
        bridge interface names to their NetBox IDs.

        Args:
            interfaces (list[dict]): Interface template definitions; may include a "bridge" key.
            device_type (int): ID of the parent device type.
            context (str | None): Optional context string for log messages.
        """
        bridged_interfaces = {}
        # Pre-process to separate bridge config
        for x in interfaces:
            if "bridge" in x:
                bridged_interfaces[x["name"]] = x["bridge"]
                del x["bridge"]

        self._create_generic(
            interfaces,
            device_type,
            self.netbox.dcim.interface_templates,
            "Interface",
            context=context,
            cache_name="interface_templates",
        )

        if bridged_interfaces:
            all_interfaces = self._get_cached_or_fetch(
                "interface_templates", device_type, "device", self.netbox.dcim.interface_templates
            )

            to_update = []
            for name, bridge_name in bridged_interfaces.items():
                if name in all_interfaces and bridge_name in all_interfaces:
                    iface = all_interfaces[name]
                    bridge = all_interfaces[bridge_name]
                    to_update.append({"id": iface.id, "bridge": bridge.id})
                else:
                    self.handle.log(f"Error bridging {name} to {bridge_name}: Interface not found (Context: {context})")

            if to_update:
                try:
                    self.netbox.dcim.interface_templates.update(to_update)
                    self.handle.verbose_log(f"Bridged {len(to_update)} interfaces.")
                except pynetbox.RequestError as e:
                    self.handle.log(f"Error bridging interfaces: {e} (Context: {context})")

    def create_power_ports(self, power_ports, device_type, context=None):
        """Create power port templates for a device type."""
        self._create_generic(
            power_ports,
            device_type,
            self.netbox.dcim.power_port_templates,
            "Power Port",
            context=context,
            cache_name="power_port_templates",
        )

    def create_console_ports(self, console_ports, device_type, context=None):
        """Create console port templates for a device type."""
        self._create_generic(
            console_ports,
            device_type,
            self.netbox.dcim.console_port_templates,
            "Console Port",
            context=context,
            cache_name="console_port_templates",
        )

    def create_power_outlets(self, power_outlets, device_type, context=None):
        """Create power outlet templates for a device type, resolving power-port name references.

        Args:
            power_outlets (list[dict]): Power-outlet template definitions; may include a "power_port" name key.
            device_type (int): ID of the parent device type.
            context (str | None): Optional context string for log messages.
        """

        def link_ports(items, pid):
            existing_pp = self._get_cached_or_fetch(
                "power_port_templates", pid, "device", self.netbox.dcim.power_port_templates
            )

            outlets_to_remove = []
            for outlet in items:
                if "power_port" not in outlet:
                    continue
                try:
                    power_port = existing_pp[outlet["power_port"]]
                    outlet["power_port"] = power_port.id
                except KeyError:
                    available = list(existing_pp.keys()) if existing_pp else []
                    ctx = f" (Context: {context})" if context else ""
                    self.handle.log(
                        f'Could not find Power Port "{outlet["power_port"]}" for Power Outlet "{outlet.get("name", "Unknown")}". '
                        f"Available: {available}{ctx}"
                    )
                    outlets_to_remove.append(outlet)

            # Remove outlets with invalid power port references
            for outlet in outlets_to_remove:
                items.remove(outlet)

            if outlets_to_remove:
                skipped_names = [o["name"] for o in outlets_to_remove]
                ctx = f" (Context: {context})" if context else ""
                self.handle.log(
                    f"Skipped {len(outlets_to_remove)} power outlet(s) with invalid power port refs: {skipped_names}{ctx}"
                )

        self._create_generic(
            power_outlets,
            device_type,
            self.netbox.dcim.power_outlet_templates,
            "Power Outlet",
            post_process=link_ports,
            context=context,
            cache_name="power_outlet_templates",
        )

    def create_console_server_ports(self, console_server_ports, device_type, context=None):
        """Create console server port templates for a device type."""
        self._create_generic(
            console_server_ports,
            device_type,
            self.netbox.dcim.console_server_port_templates,
            "Console Server Port",
            context=context,
            cache_name="console_server_port_templates",
        )

    def create_rear_ports(self, rear_ports, device_type, context=None):
        """Create rear port templates for a device type."""
        self._create_generic(
            rear_ports,
            device_type,
            self.netbox.dcim.rear_port_templates,
            "Rear Port",
            context=context,
            cache_name="rear_port_templates",
        )

    def create_front_ports(self, front_ports, device_type, context=None):
        """
        Create front port templates for a device type, resolving rear-port references before creation.

        For each front-port entry, attempts to resolve its `rear_port` name to the corresponding rear-port ID; front ports whose `rear_port` cannot be resolved are removed and a log entry is emitted (including the optional context). After resolving and pruning entries, the function creates the remaining front-port templates in NetBox and records created items via the shared counters/handlers.

        Parameters:
            front_ports (list[dict]): List of front-port template definitions. Each item is expected to include a "name" and a "rear_port" (the rear-port name to resolve).
            device_type (int): ID of the device type (device_type) to which the front ports belong.
            context (str | None): Optional context string appended to log messages for disambiguation.
        """

        def link_rear_ports(items, pid):
            existing_rp = self._get_cached_or_fetch(
                "rear_port_templates", pid, "device", self.netbox.dcim.rear_port_templates
            )

            ports_to_remove = []
            for port in items:
                try:
                    rear_port = existing_rp[port["rear_port"]]
                    port["rear_port"] = rear_port.id
                except KeyError:
                    available = list(existing_rp.keys()) if existing_rp else []
                    ctx = f" (Context: {context})" if context else ""
                    self.handle.log(
                        f'Could not find Rear Port "{port["rear_port"]}" for Front Port "{port["name"]}". '
                        f"Available: {available}{ctx}"
                    )
                    ports_to_remove.append(port)

            # Remove front ports with invalid rear port references
            for port in ports_to_remove:
                items.remove(port)

            if ports_to_remove:
                skipped_names = [p["name"] for p in ports_to_remove]
                ctx = f" (Context: {context})" if context else ""
                self.handle.log(
                    f"Skipped {len(ports_to_remove)} front port(s) with invalid rear port refs: {skipped_names}{ctx}"
                )

        self._create_generic(
            front_ports,
            device_type,
            self.netbox.dcim.front_port_templates,
            "Front Port",
            post_process=link_rear_ports,
            context=context,
            cache_name="front_port_templates",
        )

    def create_device_bays(self, device_bays, device_type, context=None):
        """Create device bay templates for a device type."""
        self._create_generic(
            device_bays,
            device_type,
            self.netbox.dcim.device_bay_templates,
            "Device Bay",
            context=context,
            cache_name="device_bay_templates",
        )

    def create_module_bays(self, module_bays, device_type, context=None):
        """Create module bay templates for a device type."""
        self._create_generic(
            module_bays,
            device_type,
            self.netbox.dcim.module_bay_templates,
            "Module Bay",
            context=context,
            cache_name="module_bay_templates",
        )

    # Module methods
    def create_module_interfaces(self, interfaces, module_type, context=None):
        """Create interface templates for a module type."""
        self._create_generic(
            interfaces,
            module_type,
            self.netbox.dcim.interface_templates,
            "Module Interface",
            parent_type="module",
            context=context,
            cache_name="interface_templates",
        )

    def create_module_power_ports(self, power_ports, module_type, context=None):
        """Create power port templates for a module type."""
        self._create_generic(
            power_ports,
            module_type,
            self.netbox.dcim.power_port_templates,
            "Module Power Port",
            parent_type="module",
            context=context,
            cache_name="power_port_templates",
        )

    def create_module_console_ports(self, console_ports, module_type, context=None):
        """Create console port templates for a module type."""
        self._create_generic(
            console_ports,
            module_type,
            self.netbox.dcim.console_port_templates,
            "Module Console Port",
            parent_type="module",
            context=context,
            cache_name="console_port_templates",
        )

    def create_module_power_outlets(self, power_outlets, module_type, context=None):
        """Create power outlet templates for a module type, resolving power-port name references."""

        def link_ports(items, pid):
            existing_pp = self._get_cached_or_fetch(
                "power_port_templates", pid, "module", self.netbox.dcim.power_port_templates
            )

            for outlet in items:
                try:
                    power_port = existing_pp[outlet["power_port"]]
                    outlet["power_port"] = power_port.id
                except KeyError:
                    pass

        self._create_generic(
            power_outlets,
            module_type,
            self.netbox.dcim.power_outlet_templates,
            "Module Power Outlet",
            parent_type="module",
            post_process=link_ports,
            context=context,
            cache_name="power_outlet_templates",
        )

    def create_module_console_server_ports(self, console_server_ports, module_type, context=None):
        """Create console server port templates for a module type."""
        self._create_generic(
            console_server_ports,
            module_type,
            self.netbox.dcim.console_server_port_templates,
            "Module Console Server Port",
            parent_type="module",
            context=context,
            cache_name="console_server_port_templates",
        )

    def create_module_rear_ports(self, rear_ports, module_type, context=None):
        """
        Create rear-port templates for a module type in NetBox.

        Adds any rear port templates from `rear_ports` that do not already exist for the specified `module_type`.
        Parameters:
            rear_ports (list[dict]): List of rear-port template definitions to create; each item must include a `name` and any other template fields required by NetBox.
            module_type (int|object): The module type identifier or object used to associate created templates with the parent module type.
            context (str, optional): Optional context string used for logging to identify the source of these templates.
        """
        self._create_generic(
            rear_ports,
            module_type,
            self.netbox.dcim.rear_port_templates,
            "Module Rear Port",
            parent_type="module",
            context=context,
            cache_name="rear_port_templates",
        )

    def create_module_front_ports(self, front_ports, module_type, context=None):
        """
        Create front-port templates for a module-type and link them to their rear ports.

        Creates any missing module front-port templates under the given module_type. If a front port references a rear port by name, the rear port name is resolved to the rear-port ID; front ports with unresolved rear-port names are removed from creation and a log message is emitted (includes `context` if provided).

        Parameters:
            front_ports (list[dict]): List of front-port template definitions. Each dict must include at least "name"; items may reference a rear port by the "rear_port" key (name).
            module_type (int | object): Module type identifier or object to associate the created front ports with.
            context (str | None): Optional context string appended to log messages for easier debugging.
        """

        def link_rear_ports(items, pid):
            """Resolve each front-port's rear_port name to the corresponding rear-port ID for a module."""
            existing_rp = self._get_cached_or_fetch(
                "rear_port_templates", pid, "module", self.netbox.dcim.rear_port_templates
            )

            ports_to_remove = []
            for port in items:
                try:
                    rear_port = existing_rp[port["rear_port"]]
                    port["rear_port"] = rear_port.id
                except KeyError:
                    available = list(existing_rp.keys()) if existing_rp else []
                    ctx = f" (Context: {context})" if context else ""
                    self.handle.log(
                        f'Could not find Rear Port "{port["rear_port"]}" for Front Port "{port["name"]}". '
                        f"Available: {available}{ctx}"
                    )
                    ports_to_remove.append(port)

            # Remove front ports with invalid rear port references
            for port in ports_to_remove:
                items.remove(port)

            if ports_to_remove:
                skipped_names = [p["name"] for p in ports_to_remove]
                ctx = f" (Context: {context})" if context else ""
                self.handle.log(
                    f"Skipped {len(ports_to_remove)} module front port(s) with invalid rear port refs: {skipped_names}{ctx}"
                )

        self._create_generic(
            front_ports,
            module_type,
            self.netbox.dcim.front_port_templates,
            "Module Front Port",
            parent_type="module",
            post_process=link_rear_ports,
            context=context,
            cache_name="front_port_templates",
        )

    def upload_images(self, baseurl, token, images, device_type):
        """
        Upload front and/or rear image files to the specified NetBox device type.

        Sends a PATCH request to the device-type endpoint attaching the provided image files, increments self.counter["images"] by the number of files sent, and ensures all opened file handles are closed. Respects self.ignore_ssl to determine SSL verification behavior.

        Parameters:
            baseurl (str): Base URL of the NetBox instance (e.g. "https://netbox.example.com").
            token (str): API token used for the Authorization header.
            images (dict): Mapping of form field name to local file path (e.g. {"front_image": "/path/front.jpg", "rear_image": "/path/rear.jpg"}).
            device_type (int | str): Identifier of the device type to update in NetBox (used in the endpoint URL).
        """
        url = f"{baseurl}/api/dcim/device-types/{device_type}/"
        headers = {"Authorization": f"Token {token}"}

        # Open files with proper cleanup to avoid resource leaks
        file_handles = {}
        try:
            for field, path in images.items():
                file_handles[field] = (os.path.basename(path), open(path, "rb"))
            response = requests.patch(
                url, headers=headers, files=file_handles, verify=(not self.ignore_ssl), timeout=60
            )
            response.raise_for_status()
            self.handle.verbose_log(f"Images {images} updated at {url}: {response.status_code}")
            self.counter["images"] += len(images)
        except OSError as e:
            self.handle.log(f"Error reading image file for device type {device_type}: {e}")
        except requests.RequestException as e:
            self.handle.log(f"Error uploading images for device type {device_type}: {e}")
        finally:
            for _, (_, fh) in file_handles.items():
                try:
                    fh.close()
                except Exception:
                    pass

    def upload_image_attachment(self, baseurl, token, image_path, object_type, object_id):
        """Upload an image as an Image Attachment to a NetBox object.

        Uses POST /api/extras/image-attachments/ to attach an image to any
        NetBox object type (e.g. module types which lack built-in image fields).

        Parameters:
            baseurl (str): Base URL of the NetBox instance.
            token (str): API token for authorization.
            image_path (str): Local file path of the image to upload.
            object_type (str): NetBox content type string (e.g. "dcim.moduletype").
            object_id (int | str): ID of the object to attach the image to.

        Returns:
            bool: True if the upload succeeded, False on any error.
        """
        url = f"{baseurl}/api/extras/image-attachments/"
        headers = {"Authorization": f"Token {token}"}
        data = {
            "object_type": object_type,
            "object_id": str(object_id),
            "name": os.path.splitext(os.path.basename(image_path))[0],
        }

        try:
            with open(image_path, "rb") as f:
                files = {"image": (os.path.basename(image_path), f)}
                response = requests.post(
                    url,
                    headers=headers,
                    data=data,
                    files=files,
                    verify=(not self.ignore_ssl),
                    timeout=60,
                )
                response.raise_for_status()
                self.handle.verbose_log(
                    f"Image attachment '{os.path.basename(image_path)}' uploaded"
                    f" for {object_type} {object_id}: {response.status_code}"
                )
                self.counter["images"] += 1
                return True
        except OSError as e:
            self.handle.log(f"Error reading image file {image_path}: {e}")
            return False
        except requests.RequestException as e:
            self.handle.log(f"Error uploading image attachment for {object_type} {object_id}: {e}")
            return False
