from collections import Counter
import pynetbox
import requests
import os
import glob

# from pynetbox import RequestError as APIRequestError


class NetBox:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, settings, handle):
        self.counter = Counter(
            added=0,
            updated=0,
            manufacturer=0,
            module_added=0,
            module_port_added=0,
            images=0,
            properties_updated=0,
            components_updated=0,
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
        try:
            self.netbox = pynetbox.api(self.url, token=self.token)
            if self.ignore_ssl:
                self.handle.verbose_log("IGNORE_SSL_ERRORS is True, catching exception and disabling SSL verification.")
                # requests.packages.urllib3.disable_warnings()
                self.netbox.http_session.verify = False
        except Exception as e:
            self.handle.exception("Exception", "NetBox API Error", e)

    def get_api(self):
        return self.netbox

    def get_counter(self):
        return self.counter

    def verify_compatibility(self):
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
        return {str(item): item for item in self.netbox.dcim.manufacturers.all()}

    def create_manufacturers(self, vendors):
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
                self.handle.verbose_log(f'Manufacturer Exists: {vendor["name"]} (slug: {vendor["slug"]})')
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
            self.handle.log("No new manufacturers to create.")

    def create_device_types(self, device_types_to_add, progress=None, only_new=False, update=False, change_report=None):
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

                if only_new:
                    self.handle.verbose_log(
                        f"Device Type Exists: {dt.manufacturer.name} - {dt.model} - {dt.id}. Skipping updates."
                    )
                    continue

                # If update mode is enabled, update device type properties and components
                if update and change_report:
                    self._update_device_type_if_changed(dt, device_type, change_report)
                    # Also update changed components
                    manufacturer_slug = device_type["manufacturer"]["slug"]
                    for dt_change in change_report.modified_device_types:
                        if dt_change.manufacturer_slug == manufacturer_slug and dt_change.model == device_type["model"]:
                            if dt_change.component_changes:
                                self.device_types.update_components(
                                    device_type, dt.id, dt_change.component_changes, parent_type="device"
                                )
                            break

                self.handle.verbose_log(f"Device Type Exists: {dt.manufacturer.name} - " + f"{dt.model} - {dt.id}")
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
                        f' {device_type["manufacturer"]["slug"]} {device_type["model"]}'
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

            # Finally, update images if any
            if saved_images:
                # Check if images are already present on the device type object
                # dt is the object returned by pynetbox or created

                # Use dot notation or getattr because pynetbox objects mimic attributes
                # We want to remove from saved_images if dt.front_image or dt.rear_image exists

                if "front_image" in saved_images and getattr(dt, "front_image", None):
                    self.handle.verbose_log(f"Front image already exists for {dt.model}, skipping upload.")
                    del saved_images["front_image"]

                if "rear_image" in saved_images and getattr(dt, "rear_image", None):
                    self.handle.verbose_log(f"Rear image already exists for {dt.model}, skipping upload.")
                    del saved_images["rear_image"]

                if saved_images:
                    self.device_types.upload_images(self.url, self.token, saved_images, dt.id)

    def _update_device_type_if_changed(self, netbox_dt, yaml_data, change_report):
        """
        Update device type properties if changes were detected.

        Args:
            netbox_dt: The existing NetBox device type object
            yaml_data: The YAML data for this device type
            change_report: ChangeReport object with detected changes
        """
        manufacturer_slug = yaml_data["manufacturer"]["slug"]
        model = yaml_data["model"]

        # Find the change entry for this device type
        dt_change = None
        for change in change_report.modified_device_types:
            if change.manufacturer_slug == manufacturer_slug and change.model == model:
                dt_change = change
                break

        if not dt_change or not dt_change.property_changes:
            return

        # Build update payload from property changes
        updates = {}
        for pc in dt_change.property_changes:
            updates[pc.property_name] = pc.new_value

        if updates:
            try:
                netbox_dt.update(updates)
                self.counter.update({"properties_updated": 1})
                self.handle.verbose_log(f"Updated device type {netbox_dt.model} properties: {list(updates.keys())}")
            except pynetbox.RequestError as e:
                self.handle.log(f"Error updating device type {netbox_dt.model}: {e.error}")

    def create_module_types(self, module_types, progress=None, only_new=False):
        all_module_types = {}
        for curr_nb_mt in self.netbox.dcim.module_types.all():
            if curr_nb_mt.manufacturer.slug not in all_module_types:
                all_module_types[curr_nb_mt.manufacturer.slug] = {}

            all_module_types[curr_nb_mt.manufacturer.slug][curr_nb_mt.model] = curr_nb_mt

        iterator = progress if progress is not None else module_types
        for curr_mt in iterator:
            src_file = curr_mt.get("src", "Unknown")
            if "src" in curr_mt:
                del curr_mt["src"]

            try:
                module_type_res = all_module_types[curr_mt["manufacturer"]["slug"]][curr_mt["model"]]
                if only_new:
                    self.handle.verbose_log(
                        f"Module Type Exists: {module_type_res.manufacturer.name} - "
                        + f"{module_type_res.model} - {module_type_res.id}. Skipping updates."
                    )
                    continue
                self.handle.verbose_log(
                    f"Module Type Exists: {module_type_res.manufacturer.name} - "
                    + f"{module_type_res.model} - {module_type_res.id}"
                )
            except KeyError:
                try:
                    module_type_res = self.netbox.dcim.module_types.create(curr_mt)
                    self.counter["created"] += 1
                    self.handle.verbose_log(
                        f"Module Type Created: {module_type_res.manufacturer.name} - "
                        + f"{module_type_res.model} - {module_type_res.id}"
                    )
                except pynetbox.RequestError as excep:
                    self.handle.log(f"Error creating Module Type: {excep} (Context: {src_file})")
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


class DeviceTypes:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self, netbox, exception_handler, counter, ignore_ssl, new_filters):
        self.netbox = netbox
        self.handle = exception_handler
        self.counter = counter
        self.ignore_ssl = ignore_ssl
        self.new_filters = new_filters
        self.cached_components = {}
        self.existing_device_types, self.existing_device_types_by_slug = self.get_device_types()

    def get_device_types(self):
        # Build two indexes for lookup:
        # 1. By (manufacturer_slug, model) - primary lookup
        # 2. By (manufacturer_slug, slug) - fallback for renamed devices
        by_model = {}
        by_slug = {}
        for item in self.netbox.dcim.device_types.all():
            by_model[(item.manufacturer.slug, item.model)] = item
            by_slug[(item.manufacturer.slug, item.slug)] = item
        return by_model, by_slug

    def preload_all_components(self, progress_wrapper=None):
        """Pre-fetch all component templates to avoid N+1 queries during updates."""
        components = [
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

        for endpoint, label in components:
            # Only print log message if not using progress wrapper (tqdm shows its own description)
            if not progress_wrapper:
                self.handle.log(f"Pre-fetching {label}...")
            # We need to map parent_id -> {component_name: component_obj}
            # parent can be device_type or module_type.
            # Ideally we split by type, but the API endpoints are distinct for devicetype components vs module components?
            # NetBox < 3.2: shared. NetBox >= 3.2: still shared endpoints usually, but filtered by device_type_id or module_type_id.
            # Actually, in pynetbox: dcim.interface_templates handles both.
            # Objects have 'device_type' OR 'module_type' attribute.

            cache = {}
            # Count to provide feedback
            count = 0

            # Fetch all items from endpoint - this returns a generator/iterator
            all_items = getattr(self.netbox.dcim, endpoint).all()

            # Wrap with progress bar if available
            if progress_wrapper:
                # Get total count for progress bar (triggers an extra API call per endpoint)
                total = len(all_items)
                items_iter = progress_wrapper(all_items, desc=f"Caching {label}", total=total)
            else:
                items_iter = all_items

            for item in items_iter:
                parent_id = None
                parent_type = None

                if getattr(item, "device_type", None):
                    parent_id = item.device_type.id
                    parent_type = "device"
                elif getattr(item, "module_type", None):
                    parent_id = item.module_type.id
                    parent_type = "module"

                if parent_id:
                    key = (parent_type, parent_id)
                    if key not in cache:
                        cache[key] = {}

                    # Store by name for easy lookup
                    cache[key][item.name] = item
                    count += 1

            self.cached_components[endpoint] = cache
            self.handle.verbose_log(f"Cached {count} {label}.")

    def _get_filter_kwargs(self, parent_id, parent_type="device"):
        if parent_type == "device":
            key = "device_type_id" if self.new_filters else "devicetype_id"
            return {key: parent_id}
        else:
            # Module types: module_type_id (new) vs moduletype_id (old)
            key = "module_type_id" if self.new_filters else "moduletype_id"
            return {key: parent_id}

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
        # cache_name represents the endpoint name, e.g., 'interface_templates'
        existing = {}
        if cache_name and cache_name in self.cached_components:
            # Use cache
            key = (parent_type, parent_id)
            existing = self.cached_components[cache_name].get(key, {})
            # existing is already in format {name: item} from preload
        else:
            # Fallback to API filter
            filter_kwargs = self._get_filter_kwargs(parent_id, parent_type)
            existing = {str(item): item for item in endpoint.filter(**filter_kwargs)}

        to_create = [x for x in items if x["name"] not in existing]
        parent_key = "device_type" if parent_type == "device" else "module_type"

        for item in to_create:
            item[parent_key] = parent_id

        if post_process:
            post_process(to_create, parent_id)

        if to_create:
            try:
                created = endpoint.create(to_create)
                # Log logic is slightly different for device/module in original code just by name
                # "Interface" vs "Module Interface"
                # We can reuse log_device_ports_created for both if we pass the right strings
                # Actually log_module_ports_created looks for port.module_type.id, log_device_ports_created for port.device_type.id
                # Use appropriate logger
                if parent_type == "device":
                    count = self.handle.log_device_ports_created(created, component_name)
                    self.counter.update({"updated": count})
                else:
                    count = self.handle.log_module_ports_created(created, component_name)
                    self.counter.update({"updated": count})
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
        from change_detector import ChangeType

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

        # Map component types to endpoints
        endpoint_map = {
            "interfaces": self.netbox.dcim.interface_templates,
            "power-ports": self.netbox.dcim.power_port_templates,
            "power-port": self.netbox.dcim.power_port_templates,
            "console-ports": self.netbox.dcim.console_port_templates,
            "power-outlets": self.netbox.dcim.power_outlet_templates,
            "console-server-ports": self.netbox.dcim.console_server_port_templates,
            "rear-ports": self.netbox.dcim.rear_port_templates,
            "front-ports": self.netbox.dcim.front_port_templates,
            "device-bays": self.netbox.dcim.device_bay_templates,
            "module-bays": self.netbox.dcim.module_bay_templates,
        }

        cache_map = {
            "interfaces": "interface_templates",
            "power-ports": "power_port_templates",
            "power-port": "power_port_templates",
            "console-ports": "console_port_templates",
            "power-outlets": "power_outlet_templates",
            "console-server-ports": "console_server_port_templates",
            "rear-ports": "rear_port_templates",
            "front-ports": "front_port_templates",
            "device-bays": "device_bay_templates",
            "module-bays": "module_bay_templates",
        }

        # Handle component updates
        for comp_type, changes in changes_to_update.items():
            endpoint = endpoint_map.get(comp_type)
            cache_name = cache_map.get(comp_type)
            if not endpoint or not cache_name:
                continue

            # Get existing components from cache
            cache_key = (parent_type, device_type_id)
            existing = self.cached_components.get(cache_name, {}).get(cache_key, {})

            updates = []
            for change in changes:
                if change.component_name in existing:
                    comp = existing[change.component_name]
                    update_data = {"id": comp.id}
                    for pc in change.property_changes:
                        update_data[pc.property_name] = pc.new_value
                    updates.append(update_data)

            if updates:
                try:
                    endpoint.update(updates)
                    self.counter.update({"components_updated": len(updates)})
                    self.handle.verbose_log(f"Updated {len(updates)} {comp_type}")
                except pynetbox.RequestError as e:
                    self.handle.log(f"Error updating {comp_type}: {e.error}")

        # Handle component additions
        for comp_type, changes in changes_to_add.items():
            if comp_type not in yaml_data:
                continue

            # Find the new components in the YAML data
            yaml_components = yaml_data[comp_type]
            new_component_names = {change.component_name for change in changes}
            components_to_add = [c for c in yaml_components if c.get("name") in new_component_names]

            if not components_to_add:
                continue

            # Use the existing create methods for each component type
            if comp_type == "interfaces":
                self.create_interfaces(components_to_add, device_type_id)
            elif comp_type in ("power-ports", "power-port"):
                self.create_power_ports(components_to_add, device_type_id)
            elif comp_type == "console-ports":
                self.create_console_ports(components_to_add, device_type_id)
            elif comp_type == "power-outlets":
                self.create_power_outlets(components_to_add, device_type_id)
            elif comp_type == "console-server-ports":
                self.create_console_server_ports(components_to_add, device_type_id)
            elif comp_type == "rear-ports":
                self.create_rear_ports(components_to_add, device_type_id)
            elif comp_type == "front-ports":
                self.create_front_ports(components_to_add, device_type_id)
            elif comp_type == "device-bays":
                self.create_device_bays(components_to_add, device_type_id)
            elif comp_type == "module-bays":
                self.create_module_bays(components_to_add, device_type_id)

    def create_interfaces(self, interfaces, device_type, context=None):
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
            # Use cached interfaces if available, otherwise fetch from API
            cache_key = ("device", device_type)
            if "interface_templates" in self.cached_components:
                all_interfaces = self.cached_components["interface_templates"].get(cache_key, {})
                # If cache exists but is empty for this device type, fetch from API (e.g., newly created device type)
                if not all_interfaces:
                    filter_kwargs = self._get_filter_kwargs(device_type, "device")
                    all_interfaces = {
                        str(item): item for item in self.netbox.dcim.interface_templates.filter(**filter_kwargs)
                    }
            else:
                filter_kwargs = self._get_filter_kwargs(device_type, "device")
                all_interfaces = {
                    str(item): item for item in self.netbox.dcim.interface_templates.filter(**filter_kwargs)
                }

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
        self._create_generic(
            power_ports,
            device_type,
            self.netbox.dcim.power_port_templates,
            "Power Port",
            context=context,
            cache_name="power_port_templates",
        )

    def create_console_ports(self, console_ports, device_type, context=None):
        self._create_generic(
            console_ports,
            device_type,
            self.netbox.dcim.console_port_templates,
            "Console Port",
            context=context,
            cache_name="console_port_templates",
        )

    def create_power_outlets(self, power_outlets, device_type, context=None):
        def link_ports(items, pid):
            # Use cached power ports if available, otherwise fetch from API
            cache_key = ("device", pid)
            if "power_port_templates" in self.cached_components:
                existing_pp = self.cached_components["power_port_templates"].get(cache_key, {})
                # If cache exists but is empty for this device type, fetch from API (e.g., newly created device type)
                if not existing_pp:
                    pp_endpoint = self.netbox.dcim.power_port_templates
                    pp_kwargs = self._get_filter_kwargs(pid, "device")
                    existing_pp = {str(item): item for item in pp_endpoint.filter(**pp_kwargs)}
            else:
                pp_endpoint = self.netbox.dcim.power_port_templates
                pp_kwargs = self._get_filter_kwargs(pid, "device")
                existing_pp = {str(item): item for item in pp_endpoint.filter(**pp_kwargs)}

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
        self._create_generic(
            console_server_ports,
            device_type,
            self.netbox.dcim.console_server_port_templates,
            "Console Server Port",
            context=context,
            cache_name="console_server_port_templates",
        )

    def create_rear_ports(self, rear_ports, device_type, context=None):
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
            # Use cached rear ports if available, otherwise fetch from API
            cache_key = ("device", pid)
            if "rear_port_templates" in self.cached_components:
                existing_rp = self.cached_components["rear_port_templates"].get(cache_key, {})
                # If cache exists but is empty for this device type, fetch from API (e.g., newly created device type)
                if not existing_rp:
                    rp_endpoint = self.netbox.dcim.rear_port_templates
                    rp_kwargs = self._get_filter_kwargs(pid, "device")
                    existing_rp = {str(item): item for item in rp_endpoint.filter(**rp_kwargs)}
            else:
                rp_endpoint = self.netbox.dcim.rear_port_templates
                rp_kwargs = self._get_filter_kwargs(pid, "device")
                existing_rp = {str(item): item for item in rp_endpoint.filter(**rp_kwargs)}

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
        self._create_generic(
            device_bays,
            device_type,
            self.netbox.dcim.device_bay_templates,
            "Device Bay",
            context=context,
            cache_name="device_bay_templates",
        )

    def create_module_bays(self, module_bays, device_type, context=None):
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
        def link_ports(items, pid):
            # Use cached power ports if available, otherwise fetch from API
            cache_key = ("module", pid)
            if "power_port_templates" in self.cached_components:
                existing_pp = self.cached_components["power_port_templates"].get(cache_key, {})
                # If cache exists but is empty for this module type, fetch from API (e.g., newly created module type)
                if not existing_pp:
                    pp_endpoint = self.netbox.dcim.power_port_templates
                    pp_kwargs = self._get_filter_kwargs(pid, "module")
                    existing_pp = {str(item): item for item in pp_endpoint.filter(**pp_kwargs)}
            else:
                pp_endpoint = self.netbox.dcim.power_port_templates
                pp_kwargs = self._get_filter_kwargs(pid, "module")
                existing_pp = {str(item): item for item in pp_endpoint.filter(**pp_kwargs)}

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
            # Use cached rear ports if available, otherwise fetch from API
            """
            Resolve each front-port's `rear_port` name to the corresponding rear-port ID for a module and remove any front-ports whose `rear_port` cannot be resolved.

            This function mutates `items` in place: for each port dict it replaces the string `rear_port` value with the matching rear-port `.id` when found, logs a message for each missing rear-port (including the available rear-port names), and removes ports with unresolved `rear_port` references. After processing it logs a summary of how many module front ports were skipped. The logs may include the outer-scope `context` value if present.

            Parameters:
                items (list[dict]): List of front-port dictionaries; each must contain at least `"name"` and `"rear_port"` (the latter initially a name string).
                pid (int): The module type ID used to scope the rear-port lookup.
            """
            cache_key = ("module", pid)
            if "rear_port_templates" in self.cached_components:
                existing_rp = self.cached_components["rear_port_templates"].get(cache_key, {})
                # If cache exists but is empty for this module type, fetch from API (e.g., newly created module type)
                if not existing_rp:
                    rp_endpoint = self.netbox.dcim.rear_port_templates
                    rp_kwargs = self._get_filter_kwargs(pid, "module")
                    existing_rp = {str(item): item for item in rp_endpoint.filter(**rp_kwargs)}
            else:
                rp_endpoint = self.netbox.dcim.rear_port_templates
                rp_kwargs = self._get_filter_kwargs(pid, "module")
                existing_rp = {str(item): item for item in rp_endpoint.filter(**rp_kwargs)}

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
            self.handle.log(f"Images {images} updated at {url}: {response.status_code}")
            self.counter["images"] += len(images)
        finally:
            for _, (_, fh) in file_handles.items():
                try:
                    fh.close()
                except Exception:
                    pass
