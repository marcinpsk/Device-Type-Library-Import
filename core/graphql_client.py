"""NetBox GraphQL client for querying device types, manufacturers, and related data.

Provides a thin wrapper around NetBox's ``/graphql/`` endpoint with automatic
pagination, authentication, and convenience methods that return data structures
compatible with the existing REST-based code in ``netbox_api.py``.
"""

import threading

import requests


class GraphQLError(Exception):
    """Raised when a GraphQL query fails (HTTP error or GraphQL-level errors)."""


class DotDict(dict):
    """Dict subclass that supports attribute access, matching pynetbox Record patterns.

    Nested dicts are automatically wrapped so ``d.manufacturer.slug`` works.
    ``str(d)`` returns the ``name`` value if present (like pynetbox Records).
    """

    def __getattr__(self, key):
        """Return the value for *key* using attribute-style access."""
        try:
            value = self[key]
        except KeyError:
            raise AttributeError(f"'DotDict' has no attribute '{key}'")
        if isinstance(value, dict) and not isinstance(value, DotDict):
            value = DotDict(value)
            self[key] = value
        return value

    def __setattr__(self, key, value):
        """Store *value* under *key* in the underlying dict."""
        self[key] = value

    def __str__(self):
        """Return the ``name`` value if present, otherwise the repr of the dict."""
        name = self.get("name")
        if isinstance(name, str) and name:
            return name
        return repr(self)


def _to_dotdict(obj):
    """Recursively convert dicts (and lists of dicts) to DotDict instances.

    Coerces ``id`` fields from strings to integers since GraphQL serializes
    IDs as strings but the rest of the codebase expects integer IDs.
    """
    if isinstance(obj, dict):
        converted = {}
        for k, v in obj.items():
            if k == "id" and isinstance(v, str):
                try:
                    converted[k] = int(v)
                except ValueError:
                    converted[k] = v
            else:
                converted[k] = _to_dotdict(v)
        return DotDict(converted)
    if isinstance(obj, list):
        return [_to_dotdict(item) for item in obj]
    return obj


# Deterministic mapping from endpoint name to its GraphQL list key.
# Using rstrip("s") would strip multiple trailing 's' chars from hypothetical
# future names; this mapping is explicit and safe.
ENDPOINT_TO_LIST_KEY = {
    "interface_templates": "interface_template_list",
    "power_port_templates": "power_port_template_list",
    "console_port_templates": "console_port_template_list",
    "console_server_port_templates": "console_server_port_template_list",
    "power_outlet_templates": "power_outlet_template_list",
    "rear_port_templates": "rear_port_template_list",
    "front_port_templates": "front_port_template_list",
    "device_bay_templates": "device_bay_template_list",
    "module_bay_templates": "module_bay_template_list",
}

# Mapping of endpoint names (as used in DeviceTypes) to their GraphQL fields.
# Every entry also includes ``device_type { id }`` and ``module_type { id }`` automatically.
COMPONENT_TEMPLATE_FIELDS = {
    "interface_templates": ["id", "name", "type", "mgmt_only", "label", "enabled", "poe_mode", "poe_type"],
    "power_port_templates": ["id", "name", "type", "maximum_draw", "allocated_draw", "label"],
    "console_port_templates": ["id", "name", "type", "label"],
    "console_server_port_templates": ["id", "name", "type", "label"],
    "power_outlet_templates": ["id", "name", "type", "feed_leg", "label"],
    "rear_port_templates": ["id", "name", "type", "positions", "label"],
    "front_port_templates": ["id", "name", "type", "label", "rear_port_position"],
    "device_bay_templates": ["id", "name", "label"],
    "module_bay_templates": ["id", "name", "position", "label"],
}

# Endpoints whose GraphQL schema has no ``module_type`` parent field.
_NO_MODULE_TYPE = {"device_bay_templates", "module_bay_templates"}


class NetBoxGraphQLClient:
    """Client for querying NetBox via its GraphQL API.

    Args:
        url: Base URL of the NetBox instance (e.g. ``"http://netbox.local"``).
        token: API authentication token.
        ignore_ssl: If True, skip SSL certificate verification.

    Notes:
        :attr:`DEFAULT_PAGE_SIZE` is a client-side default (5 000).  Most NetBox
        instances cap ``MAX_PAGE_SIZE`` at 1 000 by default, in which case
        :meth:`query_all` detects the clamping and emits a one-time warning.
        If a server is configured to *reject* oversized ``limit`` values with a
        GraphQL validation error instead of silently clamping them, callers
        should lower ``page_size`` by passing it explicitly to :meth:`query_all`,
        or raise the server's ``MAX_PAGE_SIZE`` setting to match.
    """

    def __init__(self, url, token, ignore_ssl=False, log_handler=None, page_size=5000):
        """Store connection parameters for later use in :meth:`query`.

        Args:
            url: Base URL of the NetBox instance.
            token: API authentication token.
            ignore_ssl: If True, skip SSL certificate verification.
            log_handler: Optional :class:`~log_handler.LogHandler` used to emit
                warnings (e.g. server-side page-size clamping).  Falls back to
                ``print`` when not provided.
            page_size: Default number of items per GraphQL page
                (default: 5 000).
        """
        self.DEFAULT_PAGE_SIZE = page_size
        self.url = url.rstrip("/")
        self.graphql_url = f"{self.url}/graphql/"
        self.token = token
        self.ignore_ssl = ignore_ssl
        self._log_handler = log_handler
        self._page_size_clamping_warned = False
        self._page_size_clamping_lock = threading.Lock()

        self._session = requests.Session()
        # v2 tokens start with "nbt_" prefix (format: nbt_<key>.<secret>);
        # v1 tokens are plain 40-char hex strings using legacy Token auth.
        auth_scheme = "Bearer" if self.token.startswith("nbt_") else "Token"
        self._session.headers.update(
            {
                "Authorization": f"{auth_scheme} {self.token}",
                "Content-Type": "application/json",
            }
        )
        self._session.verify = not self.ignore_ssl

    def close(self):
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    # ── Low-level ──────────────────────────────────────────────────────────

    def query(self, graphql_query, variables=None):
        """Execute a single GraphQL query and return the ``data`` portion.

        Raises:
            GraphQLError: On HTTP errors or if the response contains GraphQL errors.
        """
        payload = {"query": graphql_query}
        if variables is not None:
            payload["variables"] = variables

        try:
            response = self._session.post(
                self.graphql_url,
                json=payload,
                timeout=60,
            )
            response.raise_for_status()
            body = response.json()
        except requests.RequestException as exc:
            raise GraphQLError(str(exc)) from exc
        except ValueError as exc:
            raise GraphQLError(f"Invalid JSON response from NetBox GraphQL endpoint: {exc}") from exc

        if "errors" in body:
            messages = "; ".join(e.get("message", str(e)) for e in body["errors"])
            raise GraphQLError(messages)

        return body.get("data", {})

    def query_all(self, graphql_query, list_key, page_size=None, variables=None, on_page=None):
        """Auto-paginate a GraphQL list query using offset/limit.

        The *graphql_query* **must** accept a ``$pagination: OffsetPaginationInput``
        variable and pass it to the list field.

        Detects server-side page size clamping (``MAX_PAGE_SIZE``): if the server
        returns fewer items than requested on the first page but more items exist
        on subsequent pages, a warning is emitted once per client instance so the
        operator knows performance will be reduced.

        Args:
            graphql_query: GraphQL query string with ``$pagination`` variable.
            list_key: Key in the response ``data`` dict that holds the list.
            page_size: Number of items per page (default: :data:`DEFAULT_PAGE_SIZE`).
            variables: Additional variables to merge into each request.
            on_page: Optional callable invoked after each page with the page item
                count as its single argument.  Useful for streaming progress
                updates to callers without buffering the full result first.

        Returns:
            list: All collected items across pages.
        """
        if page_size is None:
            page_size = self.DEFAULT_PAGE_SIZE

        all_items = []
        offset = 0
        effective_page_size = None  # actual cap imposed by the server

        while True:
            merged = dict(variables or {})
            merged["pagination"] = {"offset": offset, "limit": page_size}

            data = self.query(graphql_query, variables=merged)
            page = data.get(list_key, [])
            n = len(page)

            if n == 0:
                break

            all_items.extend(page)
            offset += n

            if on_page is not None:
                on_page(n)

            if effective_page_size is None:
                # First non-empty page: establish the effective cap.
                effective_page_size = n
                if n < page_size:
                    # The server may have clamped the page size.  We continue
                    # and warn once we confirm on the next page.
                    pass
            elif n > 0 and effective_page_size < page_size:
                # Second page arrived and the first page was smaller than
                # requested — clamping confirmed.
                with self._page_size_clamping_lock:
                    if not self._page_size_clamping_warned:
                        self._page_size_clamping_warned = True
                        msg = (
                            f"WARNING: NetBox capped the GraphQL page size at "
                            f"{effective_page_size} (requested {page_size}). "
                            f"Fetching all records will require more round-trips and "
                            f"will be slower than expected. Consider raising "
                            f"MAX_PAGE_SIZE on your NetBox server."
                        )
                        if self._log_handler is not None:
                            self._log_handler.log(msg)
                        else:
                            print(msg)

            # Stop when we received a partial page (end of data).
            if n < effective_page_size:
                break

        return all_items

    # ── Convenience query methods ──────────────────────────────────────────

    def get_manufacturers(self):
        """Fetch all manufacturers and return them indexed by name.

        Returns:
            dict: ``{name_str: {"id": ..., "name": ..., "slug": ...}}``
        """
        query = """
        query($pagination: OffsetPaginationInput) {
          manufacturer_list(pagination: $pagination) {
            id
            name
            slug
          }
        }
        """
        items = self.query_all(query, list_key="manufacturer_list")
        return {item["name"]: _to_dotdict(item) for item in items}

    def get_device_types(self):
        """Fetch all device types and return two lookup indexes.

        Returns:
            tuple[dict, dict]:
                - ``by_model``: ``{(manufacturer_slug, model): record}``
                - ``by_slug``: ``{(manufacturer_slug, slug): record}``
        """
        query = """
        query($pagination: OffsetPaginationInput) {
          device_type_list(pagination: $pagination) {
            id
            model
            slug
            u_height
            part_number
            is_full_depth
            subdevice_role
            airflow
            weight
            weight_unit
            comments
            front_image { url }
            rear_image { url }
            manufacturer {
              id
              name
              slug
            }
          }
        }
        """
        items = self.query_all(query, list_key="device_type_list")

        by_model = {}
        by_slug = {}
        for item in items:
            # Flatten image objects to URL strings (matching pynetbox behavior)
            for img_field in ("front_image", "rear_image"):
                img = item.get(img_field)
                if isinstance(img, dict):
                    item[img_field] = img.get("url") or None
            record = _to_dotdict(item)
            mfr_slug = record.manufacturer.slug
            by_model[(mfr_slug, record.model)] = record
            by_slug[(mfr_slug, record.slug)] = record

        return by_model, by_slug

    def get_module_types(self):
        """Fetch all module types and return them indexed by manufacturer slug and model.

        Returns:
            dict: ``{manufacturer_slug: {model: record}}``
        """
        query = """
        query($pagination: OffsetPaginationInput) {
          module_type_list(pagination: $pagination) {
            id
            model
            manufacturer {
              id
              name
              slug
            }
          }
        }
        """
        items = self.query_all(query, list_key="module_type_list")

        result = {}
        for item in items:
            record = _to_dotdict(item)
            mfr_slug = record.manufacturer.slug
            result.setdefault(mfr_slug, {})[record.model] = record

        return result

    def get_rack_types(self):
        """Fetch all rack types and return them indexed by manufacturer slug and model.

        Returns:
            dict: ``{manufacturer_slug: {model: record}}``
        """
        query = """
        query($pagination: OffsetPaginationInput) {
          rack_type_list(pagination: $pagination) {
            id
            model
            slug
            form_factor
            width
            u_height
            starting_unit
            outer_width
            outer_height
            outer_depth
            outer_unit
            mounting_depth
            weight
            max_weight
            weight_unit
            desc_units
            comments
            description
            manufacturer {
              id
              name
              slug
            }
          }
        }
        """
        items = self.query_all(query, list_key="rack_type_list")
        result = {}
        for item in items:
            record = _to_dotdict(item)
            mfr_slug = record.manufacturer.slug
            result.setdefault(mfr_slug, {})[record.model] = record
        return result

    def get_module_type_images(self):
        """Fetch image attachments for module types and return a mapping.

        Uses a ``ContentTypeFilter`` to restrict results to ``dcim.moduletype``
        attachments.  Falls back to fetching all image attachments and filtering
        in Python when the server returns a schema error (e.g. older NetBox
        versions with different filter syntax).

        Returns:
            dict: ``{module_type_id: set_of_attachment_names}``
        """
        # ContentTypeFilter syntax (NetBox ≥ 4.x strawberry-django GraphQL)
        query = """
        query($pagination: OffsetPaginationInput) {
          image_attachment_list(
            pagination: $pagination,
            filters: {object_type: {app_label: {exact: "dcim"}, model: {exact: "moduletype"}}}
          ) {
            id
            name
            object_id
          }
        }
        """
        try:
            items = self.query_all(query, list_key="image_attachment_list")
        except GraphQLError:
            # Fallback: fetch all attachments and filter in Python
            fallback_query = """
            query($pagination: OffsetPaginationInput) {
              image_attachment_list(pagination: $pagination) {
                id
                name
                object_id
                object_type { app_label model }
              }
            }
            """
            all_items = self.query_all(fallback_query, list_key="image_attachment_list")
            items = [
                i
                for i in all_items
                if (i.get("object_type") or {}).get("app_label") == "dcim"
                and (i.get("object_type") or {}).get("model") == "moduletype"
            ]

        result = {}
        for item in items:
            name = item.get("name")
            if not name:
                continue
            obj_id = item["object_id"]
            if isinstance(obj_id, str):
                try:
                    obj_id = int(obj_id)
                except ValueError:
                    continue
            result.setdefault(obj_id, set()).add(name)

        return result

    def get_component_templates(self, endpoint_name, on_page=None):
        """Fetch component template records for the given endpoint.

        Args:
            endpoint_name: Endpoint name as used by DeviceTypes (e.g. ``"interface_templates"``).
            on_page: Optional callable passed to :meth:`query_all` to receive the item
                count after each page is fetched.

        Returns:
            list[DotDict]: All matching component template records.

        Raises:
            ValueError: If *endpoint_name* is not a recognized component template endpoint.
        """
        if endpoint_name not in COMPONENT_TEMPLATE_FIELDS or endpoint_name not in ENDPOINT_TO_LIST_KEY:
            raise ValueError(f"Unknown component endpoint: {endpoint_name}")

        fields = COMPONENT_TEMPLATE_FIELDS[endpoint_name]
        list_key = ENDPOINT_TO_LIST_KEY[endpoint_name]
        field_block = "\n            ".join(fields)

        parent_fields = "device_type { id }"
        if endpoint_name not in _NO_MODULE_TYPE:
            parent_fields += "\n            module_type { id }"

        query = f"""
        query($pagination: OffsetPaginationInput) {{
          {list_key}(pagination: $pagination) {{
            {field_block}
            {parent_fields}
          }}
        }}
        """

        try:
            items = self.query_all(query, list_key=list_key, on_page=on_page)
        except GraphQLError as original_exc:
            if endpoint_name == "front_port_templates" and "rear_port_position" in fields:
                # rear_port_position was removed in NetBox >= 4.5 (replaced by M2M rear_ports).
                # Retry without it so the query works on both schema versions.
                fallback_fields = [f for f in fields if f != "rear_port_position"]
                field_block = "\n            ".join(fallback_fields)
                fallback_query = f"""
        query($pagination: OffsetPaginationInput) {{
          {list_key}(pagination: $pagination) {{
            {field_block}
            {parent_fields}
          }}
        }}
        """
                try:
                    items = self.query_all(fallback_query, list_key=list_key, on_page=on_page)
                except GraphQLError as fallback_exc:
                    raise fallback_exc from original_exc
            else:
                raise
        return [_to_dotdict(item) for item in items]
