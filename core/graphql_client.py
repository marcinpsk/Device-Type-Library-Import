"""NetBox GraphQL client for querying device types, manufacturers, and related data.

Provides a thin wrapper around NetBox's ``/graphql/`` endpoint with automatic
pagination, authentication, and convenience methods that return data structures
compatible with the existing REST-based code in ``netbox_api.py``.
"""

import threading
import time

import requests

# Module-level dedup: tracks (url, requested_page_size) pairs that have already
# emitted the page-size clamping warning so the message appears at most once
# even when multiple client instances share the same server.
_CLAMPING_WARNED: set = set()
_CLAMPING_WARNED_LOCK = threading.Lock()


class GraphQLError(Exception):
    """Raised when a GraphQL query fails (HTTP error or GraphQL-level errors)."""


class GraphQLCountMismatchError(GraphQLError):
    """Raised when a GraphQL-cached component count differs from the REST API count.

    Indicates that GraphQL silently truncated results, which would lead to
    incomplete data being imported.  The import should be aborted and retried.
    """


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
    "interface_templates": [
        "id",
        "name",
        "type",
        "mgmt_only",
        "label",
        "enabled",
        "poe_mode",
        "poe_type",
        "description",
        "rf_role",
    ],
    "power_port_templates": [
        "id",
        "name",
        "type",
        "maximum_draw",
        "allocated_draw",
        "label",
        "description",
    ],
    "console_port_templates": ["id", "name", "type", "label", "description"],
    "console_server_port_templates": ["id", "name", "type", "label", "description"],
    "power_outlet_templates": ["id", "name", "type", "feed_leg", "label", "description"],
    "rear_port_templates": ["id", "name", "type", "positions", "label", "description", "color"],
    "front_port_templates": [
        "id",
        "name",
        "type",
        "label",
        "description",
        "color",
        "mappings { id front_port_position rear_port_position rear_port { id name } }",
    ],
    "device_bay_templates": ["id", "name", "label", "description"],
    "module_bay_templates": ["id", "name", "position", "label", "description"],
}

# Endpoints whose GraphQL schema has no ``module_type`` parent field.
# Note: module_bay_templates is intentionally excluded from this set — NetBox's
# module_bay_template_list DOES support module_type { id }, so we must include it
# in the query to correctly cache module bays owned by module types.
_NO_MODULE_TYPE = {"device_bay_templates"}


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
        if self.ignore_ssl:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def close(self):
        """Close the underlying HTTP session."""
        self._session.close()

    def __enter__(self):
        """Return *self* to support use as a context manager."""
        return self

    def __exit__(self, exc_type, exc, tb):
        """Close the session on context-manager exit."""
        self.close()

    # ── Low-level ──────────────────────────────────────────────────────────

    def query(self, graphql_query, variables=None, _retries=3):
        """Execute a single GraphQL query and return the ``data`` portion.

        Retries up to *_retries* times (with exponential back-off) on transient
        connection errors so that a single dropped connection during a long
        paginated fetch does not silently empty a component cache.

        Raises:
            GraphQLError: On HTTP errors or if the response contains GraphQL errors.
        """
        payload = {"query": graphql_query}
        if variables is not None:
            payload["variables"] = variables

        for attempt in range(1 + _retries):
            try:
                response = self._session.post(
                    self.graphql_url,
                    json=payload,
                    timeout=60,
                )
                response.raise_for_status()
                body = response.json()
            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 403:
                    raise GraphQLError(
                        f"403 Forbidden from {self.graphql_url}\n"
                        "Hint: Verify that your API token has the required permissions "
                        "and that GraphQL is enabled in the NetBox configuration."
                    ) from exc
                if status in {429, 502, 503, 504} and attempt < _retries:
                    backoff = 2**attempt
                    time.sleep(backoff)
                    continue
                # Non-transient HTTP errors are not retried.
                raise GraphQLError(str(exc)) from exc
            except requests.RequestException as exc:
                if attempt < _retries:
                    backoff = 2**attempt
                    time.sleep(backoff)
                    continue
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
                _key = (self.url, page_size)
                with _CLAMPING_WARNED_LOCK:
                    if _key not in _CLAMPING_WARNED:
                        _CLAMPING_WARNED.add(_key)
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

    def _build_manufacturer_filter(self, slugs):
        """Return ``(var_decl, filter_fragment, extra_variables)`` for manufacturer filtering.

        ``var_decl`` is appended to the query's variable list (e.g.
        ``', $manufacturer_slug: String!'``).  ``filter_fragment`` is placed
        before the ``pagination`` argument in the list field call.
        ``extra_variables`` is the dict to pass as ``variables`` to
        :meth:`query_all`.

        Args:
            slugs: ``None`` or a non-empty list of manufacturer slug strings.

        Returns:
            tuple[str, str, dict]
        """
        if not slugs:
            return "", "", {}
        if not isinstance(slugs, list) or any(not isinstance(s, str) or not s.strip() for s in slugs):
            raise ValueError("manufacturer_slugs must be None or a non-empty list of non-empty strings")
        slugs = [s.strip() for s in slugs]
        if len(slugs) == 1:
            return (
                ", $manufacturer_slug: String!",
                "filters: {manufacturer: {slug: {exact: $manufacturer_slug}}}, ",
                {"manufacturer_slug": slugs[0]},
            )
        return (
            ", $manufacturer_slugs: [String!]!",
            "filters: {manufacturer: {slug: {in_list: $manufacturer_slugs}}}, ",
            {"manufacturer_slugs": slugs},
        )

    def get_device_types(self, manufacturer_slugs=None):
        """Fetch all device types and return two lookup indexes.

        Args:
            manufacturer_slugs: Optional list of manufacturer slugs to filter by.
                When provided, only device types from the specified manufacturers are returned.

        Returns:
            tuple[dict, dict]:
                - ``by_model``: ``{(manufacturer_slug, model): record}``
                - ``by_slug``: ``{(manufacturer_slug, slug): record}``

        Raises:
            ValueError: If *manufacturer_slugs* is an empty list.
        """
        if manufacturer_slugs is not None and len(manufacturer_slugs) == 0:
            raise ValueError("manufacturer_slugs must be None or a non-empty list")

        var_decl, filter_fragment, extra_vars = self._build_manufacturer_filter(manufacturer_slugs)

        query = f"""
        query($pagination: OffsetPaginationInput{var_decl}) {{
          device_type_list({filter_fragment}pagination: $pagination) {{
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
            description
            comments
            last_updated
            front_image {{ url }}
            rear_image {{ url }}
            manufacturer {{
              id
              name
              slug
            }}
          }}
        }}
        """
        items = self.query_all(query, list_key="device_type_list", variables=extra_vars or None)

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

    def get_module_types(self, manufacturer_slugs=None):
        """Fetch all module types and return them indexed by manufacturer slug and model.

        Args:
            manufacturer_slugs: Optional list of manufacturer slugs to filter by.
                When provided, only module types from the specified manufacturers are returned.

        Returns:
            dict: ``{manufacturer_slug: {model: record}}``

        Raises:
            ValueError: If *manufacturer_slugs* is an empty list.
        """
        if manufacturer_slugs is not None and len(manufacturer_slugs) == 0:
            raise ValueError("manufacturer_slugs must be None or a non-empty list")

        var_decl, filter_fragment, extra_vars = self._build_manufacturer_filter(manufacturer_slugs)

        query = f"""
        query($pagination: OffsetPaginationInput{var_decl}) {{
          module_type_list({filter_fragment}pagination: $pagination) {{
            id
            model
            part_number
            airflow
            description
            comments
            weight
            weight_unit
            last_updated
            manufacturer {{
              id
              name
              slug
            }}
          }}
        }}
        """
        items = self.query_all(query, list_key="module_type_list", variables=extra_vars or None)

        result = {}
        for item in items:
            record = _to_dotdict(item)
            mfr_slug = record.manufacturer.slug
            result.setdefault(mfr_slug, {})[record.model] = record

        return result

    def get_rack_types(self, manufacturer_slugs=None):
        """Fetch all rack types and return them indexed by manufacturer slug and model.

        Args:
            manufacturer_slugs: Optional list of manufacturer slugs to filter by.
                When provided, only rack types from the specified manufacturers are returned.

        Returns:
            dict: ``{manufacturer_slug: {model: record}}``

        Raises:
            ValueError: If *manufacturer_slugs* is an empty list.
        """
        if manufacturer_slugs is not None and len(manufacturer_slugs) == 0:
            raise ValueError("manufacturer_slugs must be None or a non-empty list")

        var_decl, filter_fragment, extra_vars = self._build_manufacturer_filter(manufacturer_slugs)

        query = f"""
        query($pagination: OffsetPaginationInput{var_decl}) {{
          rack_type_list({filter_fragment}pagination: $pagination) {{
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
            last_updated
            manufacturer {{
              id
              name
              slug
            }}
          }}
        }}
        """
        items = self.query_all(query, list_key="rack_type_list", variables=extra_vars or None)
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
        except GraphQLError as e:
            if isinstance(e, GraphQLCountMismatchError):
                raise
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

    def get_module_type_image_details(self):
        """Fetch image attachments for module types including attachment IDs and URLs.

        Used by the ``--verify-images`` code path to obtain the information needed to
        check physical presence, compare content hashes, and delete stale attachments.

        Returns:
            dict: ``{module_type_id: {attachment_name: {"att_id": id, "url": url}}}``
        """
        query = """
        query($pagination: OffsetPaginationInput) {
          image_attachment_list(
            pagination: $pagination,
            filters: {object_type: {app_label: {exact: "dcim"}, model: {exact: "moduletype"}}}
          ) {
            id
            name
            object_id
            image { url }
          }
        }
        """
        try:
            items = self.query_all(query, list_key="image_attachment_list")
        except GraphQLError as e:
            if isinstance(e, GraphQLCountMismatchError):
                raise
            fallback_query = """
            query($pagination: OffsetPaginationInput) {
              image_attachment_list(pagination: $pagination) {
                id
                name
                object_id
                image { url }
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
            att_id = item.get("id")
            if isinstance(att_id, str):
                try:
                    att_id = int(att_id)
                except ValueError:
                    att_id = None
            image_field = item.get("image") or {}
            url = image_field.get("url", "") if isinstance(image_field, dict) else str(image_field or "")
            result.setdefault(obj_id, {})[name] = {"att_id": att_id, "url": url}

        return result

    @staticmethod
    def _front_port_field_variants(fields):
        """Yield successive field-list tiers for the front_port_templates fallback.

        Tier 1: mappings block (NetBox 4.5+)
        Tier 2: rear_port_position scalar (<4.5)
        Tier 3: neither (field removed entirely)
        """
        yield fields
        fallback = []
        for f in fields:
            if "mappings" in f:
                fallback.extend(["rear_port_position", "rear_port { id name }"])
            else:
                fallback.append(f)
        yield fallback
        stripped = [f for f in fallback if f != "rear_port_position" and "rear_port" not in f]
        if len(stripped) < len(fallback):
            yield stripped

    def _query_component_endpoint(
        self, list_key, filter_clause, endpoint_name, fields, parent_fields, on_page, var_decl="", extra_variables=None
    ):
        """Query a component template endpoint with fallback logic for front_port_templates.

        Args:
            list_key: GraphQL list key (e.g., "interface_template_list").
            filter_clause: GraphQL filter clause string (empty or with trailing comma/space).
            endpoint_name: Endpoint name for fallback handling.
            fields: List of field strings.
            parent_fields: String with device_type/module_type fields.
            on_page: Optional callable for progress reporting.
            var_decl: Optional variable declaration string appended to the query signature.
            extra_variables: Optional dict of extra variables to pass to query_all.

        Returns:
            list: Raw items (not DotDict-wrapped).
        """

        def _build_query(field_list):
            field_block = "\n            ".join(field_list)
            return f"""
        query($pagination: OffsetPaginationInput{var_decl}) {{
          {list_key}({filter_clause}pagination: $pagination) {{
            {field_block}
            {parent_fields}
          }}
        }}
        """

        is_front_port_with_mappings = endpoint_name == "front_port_templates" and any("mappings" in f for f in fields)
        field_variants = list(self._front_port_field_variants(fields)) if is_front_port_with_mappings else [fields]

        # Three-tier fallback for front_port_templates:
        #   Tier 1: mappings { ... }       (NetBox 4.5+)
        #   Tier 2: rear_port_position     (<4.5 direct scalar field)
        #   Tier 3: neither                (future: field removed entirely)
        original_exc = last_exc = None
        for variant in field_variants:
            try:
                return self.query_all(
                    _build_query(variant), list_key=list_key, on_page=on_page, variables=extra_variables
                )
            except GraphQLError as exc:
                if isinstance(exc, GraphQLCountMismatchError):
                    raise
                last_exc = exc
                if original_exc is None:
                    original_exc = exc

        if original_exc is last_exc:
            raise last_exc
        raise last_exc from original_exc

    def get_component_templates(self, endpoint_name, manufacturer_slug=None, on_page=None):
        """Fetch component template records for the given endpoint.

        Args:
            endpoint_name: Endpoint name as used by DeviceTypes (e.g. ``"interface_templates"``).
            manufacturer_slug: Optional manufacturer slug to filter by. When provided,
                fetches templates for both device types and module types from that manufacturer.
                This is intentionally a single slug (not a list) because component preloading
                operates one vendor at a time, unlike :meth:`get_device_types` /
                :meth:`get_module_types` which accept a ``manufacturer_slugs`` list.
            on_page: Optional callable passed to :meth:`query_all` to receive the item
                count after each page is fetched.

        Returns:
            list[DotDict]: All matching component template records.

        Raises:
            ValueError: If *endpoint_name* is not a recognized component template endpoint.
            ValueError: If *manufacturer_slug* is an empty string.
        """
        if endpoint_name not in COMPONENT_TEMPLATE_FIELDS or endpoint_name not in ENDPOINT_TO_LIST_KEY:
            raise ValueError(f"Unknown component endpoint: {endpoint_name}")

        if manufacturer_slug is not None and len(manufacturer_slug) == 0:
            raise ValueError("manufacturer_slug must be None or a non-empty string")

        fields = COMPONENT_TEMPLATE_FIELDS[endpoint_name]
        list_key = ENDPOINT_TO_LIST_KEY[endpoint_name]

        parent_fields = "device_type { id }"
        if endpoint_name not in _NO_MODULE_TYPE:
            parent_fields += "\n            module_type { id }"

        if manufacturer_slug is None:
            # Unfiltered query (original behavior)
            items = self._query_component_endpoint(
                list_key=list_key,
                filter_clause="",
                endpoint_name=endpoint_name,
                fields=fields,
                parent_fields=parent_fields,
                on_page=on_page,
            )
        else:
            var_decl = ", $manufacturer_slug: String!"
            extra_vars = {"manufacturer_slug": manufacturer_slug}
            # Vendor-scoped: query device-type-filtered templates
            device_filter = "filters: {device_type: {manufacturer: {slug: {exact: $manufacturer_slug}}}}, "
            device_items = self._query_component_endpoint(
                list_key=list_key,
                filter_clause=device_filter,
                endpoint_name=endpoint_name,
                fields=fields,
                parent_fields=parent_fields,
                on_page=on_page,
                var_decl=var_decl,
                extra_variables=extra_vars,
            )

            # If endpoint supports module_type, also query module-type-filtered templates
            if endpoint_name not in _NO_MODULE_TYPE:
                module_filter = "filters: {module_type: {manufacturer: {slug: {exact: $manufacturer_slug}}}}, "
                module_items = self._query_component_endpoint(
                    list_key=list_key,
                    filter_clause=module_filter,
                    endpoint_name=endpoint_name,
                    fields=fields,
                    parent_fields=parent_fields,
                    on_page=on_page,
                    var_decl=var_decl,
                    extra_variables=extra_vars,
                )
                items = device_items + module_items
            else:
                items = device_items

        return [_to_dotdict(item) for item in items]
