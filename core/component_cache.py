"""The component-template cache: one owner for prefetch, lookup and readiness.

NetBox stores component templates (interfaces, power ports, ...) per device type and
per module type.  Comparing a whole vendor one template at a time is an N+1 query, so
this module fetches every endpoint once, concurrently, and answers lookups from memory.

The interface is deliberately small: ``begin_prefetch``, ``pump``, ``ensure_ready``,
``get``, ``entries``, ``invalidate``.  Futures, the progress queue, per-endpoint task
state and the readiness flag stay inside.  Callers used to sequence those by hand.
"""

import concurrent.futures
import queue

from core.compat import (
    device_type_filter_key,
    device_type_filter_kwargs,
    module_type_filter_key,
    module_type_filter_kwargs,
)
from core.graphql_client import (
    GraphQLCountMismatchError,
    GraphQLSchemaError,
    _NO_MODULE_TYPE as NO_MODULE_TYPE_ENDPOINTS,
)

# Component endpoints fetched up front, with the label shown in the progress display.
PRELOAD_TARGETS = (
    ("interface_templates", "Interfaces"),
    ("power_port_templates", "Power Ports"),
    ("console_port_templates", "Console Ports"),
    ("console_server_port_templates", "Console Server Ports"),
    ("power_outlet_templates", "Power Outlets"),
    ("rear_port_templates", "Rear Ports"),
    ("front_port_templates", "Front Ports"),
    ("device_bay_templates", "Device Bays"),
    ("module_bay_templates", "Module Bays"),
)

# YAML component key -> (pynetbox endpoint attribute, cache name).
ENDPOINT_CACHE_MAP = {
    "interfaces": ("interface_templates", "interface_templates"),
    "power-ports": ("power_port_templates", "power_port_templates"),
    "console-ports": ("console_port_templates", "console_port_templates"),
    "power-outlets": ("power_outlet_templates", "power_outlet_templates"),
    "console-server-ports": (
        "console_server_port_templates",
        "console_server_port_templates",
    ),
    "rear-ports": ("rear_port_templates", "rear_port_templates"),
    "front-ports": ("front_port_templates", "front_port_templates"),
    "device-bays": ("device_bay_templates", "device_bay_templates"),
    "module-bays": ("module_bay_templates", "module_bay_templates"),
}

# Endpoints whose GraphQL schema is missing fields required for accurate change
# detection, and where REST provides them.  Add an endpoint here if a NetBox
# version drops a field from GraphQL but keeps it in REST.
REST_ONLY_ENDPOINTS: frozenset = frozenset()


def _chunked(items, size):
    """Yield successive *size*-length chunks of *items*."""
    for start in range(0, len(items), size):
        yield items[start : start + size]


class NullTaskDisplay:
    """Progress sink that reports nothing, so the cache never branches on a missing display."""

    def add(self, key, label):
        """Register a task for *key*."""

    def advance(self, key, amount):
        """Advance *key* by *amount*, which is negative when a retry rewinds it."""

    def finish(self, key, total):
        """Mark *key* complete at *total*."""

    def discard(self, key):
        """Drop *key* without completing it."""


class RichTaskDisplay:
    """Progress sink backed by a Rich Progress instance.

    A *registry* makes the tasks cumulative: they are created once, shared between
    vendors, and left on screen for the caller to finalize.  Without one, this display
    owns its tasks and removes them as each endpoint completes.
    """

    def __init__(self, progress, registry=None):
        """Wrap *progress*, reusing tasks from *registry* when one is given."""
        self.progress = progress
        self.registry = registry
        self.task_ids = {}

    @property
    def _owns_tasks(self):
        """Whether this display may stop and remove its tasks, rather than a shared owner."""
        return self.registry is None

    def add(self, key, label):
        """Create, or borrow from the registry, the task that tracks *key*."""
        description = f"Caching {label}"
        if self.registry is None:
            self.task_ids[key] = self.progress.add_task(description, total=None)
            return
        if description not in self.registry:
            self.registry[description] = self.progress.add_task(description, total=None)
        self.task_ids[key] = self.registry[description]

    def advance(self, key, amount):
        """Advance *key*, clamping a rewind at zero so a retry cannot show a negative bar."""
        task_id = self.task_ids.get(key)
        if task_id is None or not amount:
            return
        if amount > 0:
            self.progress.update(task_id, advance=amount)
            return
        task = next((t for t in self.progress.tasks if t.id == task_id), None)
        if task is not None:
            self.progress.update(task_id, completed=max(0, task.completed + amount))

    def finish(self, key, total):
        """Complete *key* at *total*, and clear it when this display owns the task."""
        task_id = self.task_ids.pop(key, None)
        if task_id is None or not self._owns_tasks:
            return
        self.progress.update(task_id, total=total, completed=total)
        self._clear(task_id)

    def discard(self, key):
        """Drop *key*, and clear it when this display owns the task."""
        task_id = self.task_ids.pop(key, None)
        if task_id is not None and self._owns_tasks:
            self._clear(task_id)

    def _clear(self, task_id):
        """Stop and remove *task_id*, tolerating a display that already dropped it."""
        try:
            self.progress.stop_task(task_id)
            self.progress.remove_task(task_id)
        except KeyError:
            pass


class ComponentCache:
    """Component templates for one vendor, fetched once and answered from memory.

    Lookups are keyed ``{endpoint: {(parent_type, parent_id): {name: record}}}`` where
    *parent_type* is ``"device"`` or ``"module"``.  A miss falls back to a targeted REST
    filter, which happens for types created during this run and after an invalidation.
    """

    def __init__(self, netbox, graphql, handle, new_filters, max_threads, wrap_record=None):
        """Build a cache over the *netbox* REST client and the *graphql* client.

        Args:
            netbox: pynetbox API object, used for REST fallbacks and count checks.
            graphql: GraphQL client used for the bulk fetch.
            handle: Log handler.
            new_filters (bool): Whether this NetBox takes the newer filter parameter names.
            max_threads (int): Upper bound on concurrent endpoint fetches.
            wrap_record (callable | None): Applied to every front-port record, so change
                detection sees one mappings shape across NetBox versions.
        """
        self.netbox = netbox
        self.graphql = graphql
        self.handle = handle
        self.new_filters = new_filters
        self.max_threads = max_threads
        self._wrap_record = wrap_record or (lambda record: record)

        self._entries = {}
        self._ready = False
        self._job = None

    # ── State ────────────────────────────────────────────────────────────────

    @property
    def ready(self):
        """Whether the bulk prefetch has completed for the current vendor."""
        return self._ready

    def reset(self):
        """Drop every entry and cancel any prefetch, so a new vendor starts clean."""
        self.close()
        self._entries = {}
        self._ready = False

    # ── Prefetch lifecycle ───────────────────────────────────────────────────

    def begin_prefetch(self, manufacturer_slug=None, display=None):
        """Start fetching every endpoint in the background.

        Returns immediately.  Call :meth:`pump` while doing other work to advance the
        display, then :meth:`ensure_ready` to collect the results.  A second call while
        a prefetch is already in flight is a no-op.
        """
        if self._job is not None or self._ready:
            return

        display = display or NullTaskDisplay()
        for endpoint_name, label in PRELOAD_TARGETS:
            display.add(endpoint_name, label)

        updates = queue.Queue()
        max_workers = max(1, min(len(PRELOAD_TARGETS), self.max_threads))
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        try:
            futures = {
                endpoint_name: executor.submit(
                    self._fetch_endpoint,
                    endpoint_name,
                    lambda name, advance: updates.put((name, advance)),
                    manufacturer_slug,
                )
                for endpoint_name, _label in PRELOAD_TARGETS
            }
        except Exception:
            executor.shutdown(wait=False, cancel_futures=True)
            for endpoint_name, _label in PRELOAD_TARGETS:
                display.discard(endpoint_name)
            raise

        self._job = {
            "executor": executor,
            "futures": futures,
            "updates": updates,
            "display": display,
            "done": set(),
            "manufacturer_slug": manufacturer_slug,
        }

    def pump(self):
        """Advance the display for a prefetch in flight, without blocking.

        Returns:
            bool: True when something advanced, so a caller can tell idle from busy.
        """
        if self._job is None:
            return False
        advanced = self._drain_updates()
        for endpoint_name in self._pending():
            future = self._job["futures"][endpoint_name]
            if not future.done():
                continue
            self._finish_endpoint(endpoint_name, future)
            advanced = True
        return advanced

    def ensure_ready(self, manufacturer_slug=None, device_type_ids=None):
        """Populate the cache, starting the prefetch first when nothing is in flight.

        Idempotent: the second and later calls return at once.  Callers that need cached
        data call this instead of tracking whether an earlier stage already ran.

        Args:
            manufacturer_slug (str | None): When given, the vendor-scoped integrity and
                count checks run once the fetch completes.
            device_type_ids (set | None): Device-type IDs for this vendor, used by those
                checks.  Ignored when *manufacturer_slug* is None.
        """
        if self._ready:
            return
        if self._job is None:
            self.begin_prefetch(manufacturer_slug=manufacturer_slug)
        elif (
            manufacturer_slug is not None
            and self._job["manufacturer_slug"] is not None
            and manufacturer_slug != self._job["manufacturer_slug"]
        ):
            raise ValueError(
                f"Prefetch for manufacturer {self._job['manufacturer_slug']!r} "
                f"cannot be collected for {manufacturer_slug!r}."
            )

        records = self._collect()
        for endpoint_name, label in PRELOAD_TARGETS:
            count = self.populate(endpoint_name, records.get(endpoint_name, []))
            self.handle.verbose_log(f"Cached {count} {label}.")

        if manufacturer_slug is not None:
            self._verify_vendor_scope(manufacturer_slug, device_type_ids or set())
        self._ready = True

    def close(self):
        """Cancel a prefetch in flight and release its executor."""
        job, self._job = self._job, None
        if job is None:
            return
        for future in job["futures"].values():
            if not future.done():
                future.cancel()
        job["executor"].shutdown(wait=False, cancel_futures=True)
        for endpoint_name in job["futures"]:
            if endpoint_name not in job["done"]:
                job["display"].discard(endpoint_name)

    def __enter__(self):
        """Return the cache, so a run can scope the prefetch to a ``with`` block."""
        return self

    def __exit__(self, *exc_info):
        """Cancel any prefetch left in flight."""
        self.close()
        return False

    # ── Lookup ───────────────────────────────────────────────────────────────

    def entries(self, endpoint_name, parent_type, parent_id):
        """Return the cached ``{name: record}`` for one parent, or ``{}`` on a miss.

        A pure read: unlike :meth:`get` it never reaches NetBox, so change detection
        cannot turn a cold cache into a burst of REST calls.
        """
        return self._entries.get(endpoint_name, {}).get((parent_type, parent_id), {})

    def get(self, endpoint_name, parent_type, parent_id, endpoint):
        """Return cached components for one parent, falling back to a targeted REST filter.

        A miss means the parent was created during this run or its entry was invalidated
        after a mutation.  Both are narrow, so one filtered call is cheap.
        """
        key = (parent_type, parent_id)
        cached = self._entries.get(endpoint_name, {})
        if key in cached:
            return cached[key]

        if parent_type == "device":
            filter_kwargs = device_type_filter_kwargs(parent_id, new_filters=self.new_filters)
        else:
            filter_kwargs = module_type_filter_kwargs(parent_id, new_filters=self.new_filters)
        result = {item.name: item for item in endpoint.filter(**filter_kwargs)}
        self.record(endpoint_name, parent_type, parent_id, result)
        return result

    def record(self, endpoint_name, parent_type, parent_id, components):
        """Store the known ``{name: record}`` set for one parent.

        The write half of :meth:`entries`.  An empty mapping is meaningful: it says the
        parent has no components, which is a hit rather than a reason to re-read NetBox.
        """
        self._entries.setdefault(endpoint_name, {})[(parent_type, parent_id)] = components

    def invalidate(self, endpoint_name, parent_type, parent_id):
        """Drop one parent's entry, so the next lookup re-reads it after a mutation."""
        self._entries.get(endpoint_name, {}).pop((parent_type, parent_id), None)

    def populate(self, endpoint_name, records):
        """Index *records* under *endpoint_name*, merging with what is already cached.

        Returns:
            int: How many records carried a parent and were indexed.
        """
        indexed = self._entries.setdefault(endpoint_name, {})
        count = 0
        for item in records:
            if getattr(item, "device_type", None):
                key = ("device", item.device_type.id)
            elif getattr(item, "module_type", None):
                key = ("module", item.module_type.id)
            else:
                continue
            indexed.setdefault(key, {})[item.name] = item
            count += 1
        return count

    # ── Fetching ─────────────────────────────────────────────────────────────

    def _fetch_endpoint(self, endpoint_name, on_advance, manufacturer_slug):
        """Return every record for *endpoint_name*, reporting each page through *on_advance*."""
        if endpoint_name in REST_ONLY_ENDPOINTS:
            records = list(getattr(self.netbox.dcim, endpoint_name).all())
            if records:
                on_advance(endpoint_name, len(records))
            return records

        records = self.graphql.get_component_templates(
            endpoint_name,
            manufacturer_slug=manufacturer_slug,
            on_page=lambda n: n and on_advance(endpoint_name, n),
        )
        if endpoint_name == "front_port_templates":
            records = [self._wrap_record(record) for record in records]
        return records

    def _pending(self):
        """Return the endpoints whose future has not been collected yet."""
        return [name for name in self._job["futures"] if name not in self._job["done"]]

    def _drain_updates(self):
        """Apply every queued page count to the display, coalescing per endpoint."""
        totals = {}
        while True:
            try:
                endpoint_name, advance = self._job["updates"].get_nowait()
            except queue.Empty:
                break
            totals[endpoint_name] = totals.get(endpoint_name, 0) + advance

        for endpoint_name, advance in totals.items():
            self._job["display"].advance(endpoint_name, advance)
        return any(totals.values())

    def _finish_endpoint(self, endpoint_name, future):
        """Mark *endpoint_name* complete on the display, sizing the bar to the result."""
        try:
            total = max(len(future.result()), 1)
        except Exception:
            total = 1
        self._job["display"].finish(endpoint_name, total)
        self._job["done"].add(endpoint_name)

    def _collect(self):
        """Wait for every endpoint future and return ``{endpoint: [records]}``."""
        job = self._job
        try:
            while self._pending():
                self._drain_updates()
                progressed = False
                for endpoint_name in self._pending():
                    if job["futures"][endpoint_name].done():
                        self._finish_endpoint(endpoint_name, job["futures"][endpoint_name])
                        progressed = True
                if self._pending() and not progressed:
                    concurrent.futures.wait(
                        [job["futures"][name] for name in self._pending()],
                        timeout=0.1,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )

            records = {}
            for endpoint_name, future in job["futures"].items():
                try:
                    records[endpoint_name] = future.result()
                except Exception as exc:
                    self.handle.log(f"Preload failed for {endpoint_name}: {exc}")
                    raise
            return records
        finally:
            job["executor"].shutdown(wait=True)
            self._job = None

    # ── Vendor-scoped checks ─────────────────────────────────────────────────

    def _verify_vendor_scope(self, manufacturer_slug, device_type_ids):
        """Run the cross-vendor and truncation checks for the vendor just fetched."""
        try:
            module_types = self.graphql.get_module_types(manufacturer_slugs=[manufacturer_slug])
        except GraphQLSchemaError as exc:
            # Only a rejected query shape may skip the guard; a failed request must not.
            self.handle.log(f"WARNING: Component cache integrity check skipped: {exc}")
            return
        module_type_ids = {record.id for models in module_types.values() for record in models.values()}

        vendor_scope_valid = self._drop_foreign_entries(device_type_ids, module_type_ids)
        # A count mismatch means the prefetch failed an integrity check, so let it propagate.
        self._check_counts_against_rest(device_type_ids, module_type_ids, vendor_scope_valid)

    def _belongs_to_vendor(self, key, device_type_ids, module_type_ids):
        """Whether the cache *key* names a device or module type of the current vendor."""
        parent_type, parent_id = key
        if parent_type == "device":
            return parent_id in device_type_ids
        return parent_id in module_type_ids

    def _drop_foreign_entries(self, device_type_ids, module_type_ids):
        """Clear any endpoint holding no record for this vendor, which means stale data.

        Returns:
            bool: True when every non-empty endpoint held at least one matching record.
        """
        all_ok = True
        for endpoint_name, indexed in list(self._entries.items()):
            if not indexed:
                continue
            if any(self._belongs_to_vendor(key, device_type_ids, module_type_ids) for key in indexed):
                continue
            self.handle.log(
                f"ERROR: Cached {endpoint_name} contains no records matching the current vendor — "
                "clearing to prevent cross-vendor contamination."
            )
            self._entries[endpoint_name] = {}
            all_ok = False
        return all_ok

    def _rest_count(self, rest_endpoint, filter_key, ids):
        """Return the REST count for *ids*, chunked to stay inside the URL length limit."""
        total = 0
        for chunk in _chunked(ids, 100):
            total += rest_endpoint.count(**{filter_key: chunk})
        return total

    def _check_counts_against_rest(self, device_type_ids, module_type_ids, vendor_scope_valid):
        """Compare each endpoint's cached count with REST, which GraphQL cannot truncate.

        Raises:
            GraphQLCountMismatchError: When an endpoint holds fewer records than REST reports.
        """
        dt_filter_key = device_type_filter_key(self.new_filters)
        mt_filter_key = module_type_filter_key(self.new_filters)
        dt_ids = list(device_type_ids)
        mt_ids = list(module_type_ids)

        for endpoint_name, _label in PRELOAD_TARGETS:
            if endpoint_name in REST_ONLY_ENDPOINTS:
                # Already fetched over REST, so comparing REST to REST proves nothing.
                continue

            cached_count = sum(
                len(records)
                for key, records in self._entries.get(endpoint_name, {}).items()
                if self._belongs_to_vendor(key, device_type_ids, module_type_ids)
            )

            rest_endpoint = getattr(self.netbox.dcim, endpoint_name)
            rest_count = 0
            if dt_ids:
                rest_count += self._rest_count(rest_endpoint, dt_filter_key, dt_ids)
            if mt_ids and endpoint_name not in NO_MODULE_TYPE_ENDPOINTS:
                rest_count += self._rest_count(rest_endpoint, mt_filter_key, mt_ids)

            if cached_count != rest_count:
                if vendor_scope_valid:
                    reason = "GraphQL may have silently truncated the result set."
                else:
                    reason = "The cache failed vendor validation after cross-vendor contamination was cleared."
                raise GraphQLCountMismatchError(
                    f"{endpoint_name}: GraphQL returned {cached_count} records but REST reports {rest_count}. {reason}"
                )
