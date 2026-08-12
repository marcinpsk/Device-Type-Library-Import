"""Tests for core/component_cache.py — the component-template cache.

The fakes here stand in for NetBox and Rich, not for the cache: every test drives a
real ComponentCache, so the prefetch, the index and the fallbacks are the code under
test rather than a mock's idea of them.
"""

import time

import pytest

from core.component_cache import (
    ComponentCache,
    NO_MODULE_TYPE_ENDPOINTS,
    NullTaskDisplay,
    PRELOAD_TARGETS,
    RichTaskDisplay,
    _chunked,
)
from core.graphql_client import GraphQLCountMismatchError, GraphQLSchemaError, _NO_MODULE_TYPE


# ── Fakes ─────────────────────────────────────────────────────────────────────


class Record:
    """A component-template record, as GraphQL and pynetbox both present one."""

    def __init__(self, name, device_type=None, module_type=None):
        """Build a record owned by a device type or a module type."""
        self.name = name
        self.device_type = _Parent(device_type) if device_type else None
        self.module_type = _Parent(module_type) if module_type else None


class _Parent:
    """The nested ``{"id": n}`` shape both APIs return for a parent."""

    def __init__(self, id):
        """Hold the parent *id*."""
        self.id = id


class FakeEndpoint:
    """A pynetbox endpoint proxy that answers from a fixed record list."""

    def __init__(self, records=(), count=0):
        """Answer filters with *records* and counts with *count*."""
        self.records = list(records)
        self._count = count
        self.filter_calls = []
        self.count_calls = []

    def filter(self, **kwargs):
        self.filter_calls.append(kwargs)
        return list(self.records)

    def all(self):
        return list(self.records)

    def count(self, **kwargs):
        self.count_calls.append(kwargs)
        return self._count


class FakeDcim:
    """The ``api.dcim`` namespace, creating an empty endpoint on first access."""

    def __init__(self, endpoints):
        """Serve endpoints out of the *endpoints* mapping."""
        self._endpoints = endpoints

    def __getattr__(self, name):
        return self._endpoints.setdefault(name, FakeEndpoint())


class FakeNetBox:
    """A pynetbox API object holding only the dcim endpoints these tests use."""

    def __init__(self, endpoints=None):
        """Expose *endpoints* under ``dcim``."""
        self.endpoints = endpoints if endpoints is not None else {}
        self.dcim = FakeDcim(self.endpoints)


class FakeGraphQL:
    """GraphQL client returning canned component templates and module types."""

    def __init__(self, records=None, module_types=None, module_types_error=None):
        """Return *records* per endpoint, and *module_types* or *module_types_error* for the guard."""
        self.records = records or {}
        self.module_types = module_types or {}
        self.module_types_error = module_types_error
        self.endpoints_seen = []
        self.slugs_seen = []

    def get_component_templates(self, endpoint_name, manufacturer_slug=None, on_page=None):
        self.endpoints_seen.append(endpoint_name)
        self.slugs_seen.append(manufacturer_slug)
        records = self.records.get(endpoint_name, [])
        if on_page is not None and records:
            on_page(len(records))
        return records

    def get_module_types(self, manufacturer_slugs=None):
        if self.module_types_error is not None:
            raise self.module_types_error
        return self.module_types


class FakeHandle:
    """A log handler that keeps what it was told."""

    def __init__(self):
        """Start with no messages."""
        self.logged = []
        self.verbose = []

    def log(self, message):
        self.logged.append(message)

    def verbose_log(self, message):
        self.verbose.append(message)


class FakeTask:
    """One row of the progress display."""

    def __init__(self, task_id, description, total):
        """Create the task with its *description* and starting *total*."""
        self.id = task_id
        self.description = description
        self.total = total
        self.completed = 0


class FakeProgress:
    """The slice of Rich's Progress that RichTaskDisplay uses."""

    def __init__(self):
        """Start with an empty task table."""
        self.tasks = []
        self._next_id = 0
        self.removed = []
        self.stopped = []

    def add_task(self, description, total=None):
        self._next_id += 1
        self.tasks.append(FakeTask(self._next_id, description, total))
        return self._next_id

    def _task(self, task_id):
        return next((t for t in self.tasks if t.id == task_id), None)

    def update(self, task_id, total=None, completed=None, advance=None):
        task = self._task(task_id)
        if task is None:
            raise KeyError(task_id)
        if total is not None:
            task.total = total
        if completed is not None:
            task.completed = completed
        if advance is not None:
            task.completed += advance

    def stop_task(self, task_id):
        self.stopped.append(task_id)

    def remove_task(self, task_id):
        task = self._task(task_id)
        if task is None:
            raise KeyError(task_id)
        self.tasks.remove(task)
        self.removed.append(task_id)


def make_cache(netbox=None, graphql=None, handle=None, **kwargs):
    """Build a real ComponentCache over fakes."""
    return ComponentCache(
        netbox or FakeNetBox(),
        graphql or FakeGraphQL(),
        handle or FakeHandle(),
        kwargs.pop("new_filters", True),
        kwargs.pop("max_threads", 4),
        **kwargs,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────


def test_chunked_splits_and_keeps_the_remainder():
    assert list(_chunked([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]


def test_chunked_of_nothing_yields_nothing():
    assert list(_chunked([], 3)) == []


def test_device_only_endpoints_share_the_graphql_source():
    assert NO_MODULE_TYPE_ENDPOINTS is _NO_MODULE_TYPE


# ── Index ─────────────────────────────────────────────────────────────────────


class TestIndexing:
    """populate() turns a flat record list into the per-parent index lookups read."""

    def test_records_are_indexed_under_their_parent(self):
        cache = make_cache()

        count = cache.populate(
            "interface_templates",
            [Record("eth0", device_type=1), Record("eth1", device_type=1), Record("xe-0", module_type=7)],
        )

        assert count == 3
        assert set(cache.entries("interface_templates", "device", 1)) == {"eth0", "eth1"}
        assert set(cache.entries("interface_templates", "module", 7)) == {"xe-0"}

    def test_a_record_with_no_parent_is_skipped(self):
        cache = make_cache()

        assert cache.populate("interface_templates", [Record("orphan")]) == 0

    def test_a_second_populate_merges_rather_than_replaces(self):
        cache = make_cache()

        cache.populate("interface_templates", [Record("eth0", device_type=1)])
        cache.populate("interface_templates", [Record("eth1", device_type=2)])

        assert cache.entries("interface_templates", "device", 1)
        assert cache.entries("interface_templates", "device", 2)

    def test_entries_returns_empty_for_an_unknown_parent(self):
        assert make_cache().entries("interface_templates", "device", 999) == {}

    def test_record_stores_a_known_empty_set(self):
        """An empty entry means "no components", which must read as a hit."""
        cache = make_cache()

        cache.record("interface_templates", "device", 1, {})

        assert cache.entries("interface_templates", "device", 1) == {}


class TestLookupFallback:
    """get() reaches NetBox only on a miss, and remembers the answer."""

    def test_a_hit_does_not_touch_netbox(self):
        cache = make_cache()
        cache.populate("interface_templates", [Record("eth0", device_type=1)])
        endpoint = FakeEndpoint()

        result = cache.get("interface_templates", "device", 1, endpoint)

        assert set(result) == {"eth0"}
        assert endpoint.filter_calls == []

    def test_a_miss_filters_by_device_type_and_caches_the_answer(self):
        cache = make_cache()
        endpoint = FakeEndpoint([Record("eth0", device_type=1)])

        first = cache.get("interface_templates", "device", 1, endpoint)
        second = cache.get("interface_templates", "device", 1, endpoint)

        assert set(first) == {"eth0"} and first == second
        assert endpoint.filter_calls == [{"device_type_id": 1}]

    def test_a_miss_filters_by_module_type_for_a_module_parent(self):
        cache = make_cache()
        endpoint = FakeEndpoint()

        cache.get("interface_templates", "module", 5, endpoint)

        assert endpoint.filter_calls == [{"module_type_id": 5}]

    def test_old_netbox_filter_names_are_used_when_asked(self):
        cache = make_cache(new_filters=False)
        endpoint = FakeEndpoint()

        cache.get("interface_templates", "device", 1, endpoint)

        assert endpoint.filter_calls == [{"devicetype_id": 1}]

    def test_an_empty_result_still_becomes_a_hit(self):
        """Otherwise every parent with no components is re-read on each lookup."""
        cache = make_cache()
        endpoint = FakeEndpoint([])

        cache.get("interface_templates", "device", 1, endpoint)
        cache.get("interface_templates", "device", 1, endpoint)

        assert len(endpoint.filter_calls) == 1

    def test_invalidate_forces_the_next_lookup_to_re_read(self):
        cache = make_cache()
        cache.populate("interface_templates", [Record("eth0", device_type=1)])
        endpoint = FakeEndpoint([Record("eth1", device_type=1)])

        cache.invalidate("interface_templates", "device", 1)
        result = cache.get("interface_templates", "device", 1, endpoint)

        assert set(result) == {"eth1"}

    def test_invalidating_an_absent_entry_is_harmless(self):
        make_cache().invalidate("interface_templates", "device", 1)


# ── Prefetch ──────────────────────────────────────────────────────────────────


class TestPrefetch:
    """The cache owns the futures, so callers never sequence them by hand."""

    def test_ensure_ready_fetches_every_endpoint_and_indexes_it(self):
        graphql = FakeGraphQL({"interface_templates": [Record("eth0", device_type=1)]})
        cache = make_cache(graphql=graphql)

        cache.ensure_ready()

        assert cache.ready is True
        assert set(cache.entries("interface_templates", "device", 1)) == {"eth0"}

    def test_ensure_ready_starts_the_prefetch_when_none_is_in_flight(self):
        """The self-healing path: a later stage may be the first to need the data."""
        graphql = FakeGraphQL({"interface_templates": [Record("eth0", device_type=1)]})
        cache = make_cache(graphql=graphql)

        cache.ensure_ready()

        assert cache.entries("interface_templates", "device", 1)

    def test_ensure_ready_is_idempotent(self):
        graphql = FakeGraphQL({"interface_templates": [Record("eth0", device_type=1)]})
        cache = make_cache(graphql=graphql)

        cache.ensure_ready()
        fetches = len(graphql.slugs_seen)
        cache.ensure_ready()

        assert len(graphql.slugs_seen) == fetches

    def test_begin_prefetch_scopes_the_fetch_to_one_vendor(self):
        graphql = FakeGraphQL()
        cache = make_cache(graphql=graphql)

        cache.begin_prefetch(manufacturer_slug="cisco")
        cache.ensure_ready()

        assert set(graphql.slugs_seen) == {"cisco"}

    def test_begin_prefetch_twice_does_not_start_a_second_job(self):
        graphql = FakeGraphQL()
        cache = make_cache(graphql=graphql)

        cache.begin_prefetch()
        cache.begin_prefetch()
        cache.ensure_ready()

        assert len(graphql.slugs_seen) == len(PRELOAD_TARGETS)

    def test_a_prefetch_cannot_be_collected_for_another_vendor(self):
        cache = make_cache()
        cache.begin_prefetch(manufacturer_slug="cisco")

        with pytest.raises(ValueError, match="cisco.*juniper"):
            cache.ensure_ready(manufacturer_slug="juniper")

        cache.close()

    def test_begin_prefetch_after_ready_is_a_no_op(self):
        graphql = FakeGraphQL()
        cache = make_cache(graphql=graphql)
        cache.ensure_ready()

        cache.begin_prefetch()

        assert cache._job is None

    def test_a_failed_endpoint_is_logged_and_raised(self):
        class Boom(FakeGraphQL):
            def get_component_templates(self, endpoint_name, manufacturer_slug=None, on_page=None):
                raise RuntimeError("upstream is down")

        handle = FakeHandle()
        cache = make_cache(graphql=Boom(), handle=handle)

        with pytest.raises(RuntimeError, match="upstream is down"):
            cache.ensure_ready()

        assert any("Preload failed for" in message for message in handle.logged)

    def test_reset_drops_everything_so_the_next_vendor_starts_clean(self):
        graphql = FakeGraphQL({"interface_templates": [Record("eth0", device_type=1)]})
        cache = make_cache(graphql=graphql)
        cache.ensure_ready()

        cache.reset()

        assert cache.ready is False
        assert cache.entries("interface_templates", "device", 1) == {}

    def test_close_without_a_prefetch_is_harmless(self):
        make_cache().close()

    def test_close_cancels_a_prefetch_still_in_flight(self):
        cache = make_cache()
        cache.begin_prefetch()

        cache.close()

        assert cache._job is None

    def test_the_cache_can_scope_a_prefetch_to_a_with_block(self):
        with make_cache() as cache:
            cache.begin_prefetch()

        assert cache._job is None

    def test_begin_prefetch_releases_the_executor_when_submitting_fails(self, monkeypatch):
        import core.component_cache as module

        class Broken:
            """An executor that refuses to submit."""

            def __init__(self, max_workers=None):
                """Record itself so the test can inspect the shutdown."""
                self.shutdown_calls = []
                Broken.instance = self

            def submit(self, *args, **kwargs):
                raise RuntimeError("no threads")

            def shutdown(self, wait=True, cancel_futures=False):
                self.shutdown_calls.append(cancel_futures)

        monkeypatch.setattr(module.concurrent.futures, "ThreadPoolExecutor", Broken)
        progress = FakeProgress()
        cache = make_cache()

        with pytest.raises(RuntimeError, match="no threads"):
            cache.begin_prefetch(display=RichTaskDisplay(progress))

        assert Broken.instance.shutdown_calls == [True]
        assert progress.tasks == []


class TestPrefetchProgress:
    """Progress leaves through the display, so the cache never imports Rich."""

    def test_pump_without_a_prefetch_reports_nothing(self):
        assert make_cache().pump() is False

    def test_pump_advances_and_completes_each_endpoint(self):
        graphql = FakeGraphQL({"interface_templates": [Record("eth0", device_type=1)]})
        cache = make_cache(graphql=graphql)
        progress = FakeProgress()

        cache.begin_prefetch(display=RichTaskDisplay(progress))
        cache.ensure_ready()

        # Every task finished, so an owning display removed all tasks.
        assert len(progress.removed) == len(PRELOAD_TARGETS)

    def test_pump_returns_true_once_an_endpoint_finishes(self):
        with make_cache() as cache:
            cache.begin_prefetch()

            for _ in range(200):
                if cache.pump():
                    break
                time.sleep(0.001)
            else:
                pytest.fail("no endpoint completed")

        assert cache._job is None

    def test_a_run_without_a_display_still_drains_the_update_queue(self):
        graphql = FakeGraphQL({"interface_templates": [Record("eth0", device_type=1)]})
        cache = make_cache(graphql=graphql)

        cache.begin_prefetch(display=NullTaskDisplay())
        cache.ensure_ready()

        assert cache.ready is True


class TestRichTaskDisplay:
    """The Rich adapter, including the shared-registry mode that keeps tasks on screen."""

    def test_a_task_is_created_per_endpoint(self):
        progress = FakeProgress()
        display = RichTaskDisplay(progress)

        display.add("interface_templates", "Interfaces")

        assert [t.description for t in progress.tasks] == ["Caching Interfaces"]

    def test_a_registry_reuses_one_task_across_vendors(self):
        progress = FakeProgress()
        registry = {}

        RichTaskDisplay(progress, registry=registry).add("interface_templates", "Interfaces")
        RichTaskDisplay(progress, registry=registry).add("interface_templates", "Interfaces")

        assert len(progress.tasks) == 1

    def test_a_registry_owner_keeps_the_task_after_it_finishes(self):
        """The caller finalizes cumulative tasks, so the display must not remove them."""
        progress = FakeProgress()
        display = RichTaskDisplay(progress, registry={})
        display.add("interface_templates", "Interfaces")

        display.finish("interface_templates", 5)

        assert len(progress.tasks) == 1
        assert progress.removed == []

    def test_advance_moves_the_bar_forward(self):
        progress = FakeProgress()
        display = RichTaskDisplay(progress)
        display.add("interface_templates", "Interfaces")

        display.advance("interface_templates", 3)

        assert progress.tasks[0].completed == 3

    def test_a_rewind_clamps_at_zero(self):
        """A retry rewinds the count; a negative bar would be nonsense."""
        progress = FakeProgress()
        display = RichTaskDisplay(progress)
        display.add("interface_templates", "Interfaces")
        display.advance("interface_templates", 2)

        display.advance("interface_templates", -5)

        assert progress.tasks[0].completed == 0

    def test_advancing_an_unknown_or_zero_amount_does_nothing(self):
        progress = FakeProgress()
        display = RichTaskDisplay(progress)
        display.add("interface_templates", "Interfaces")

        display.advance("power_port_templates", 4)
        display.advance("interface_templates", 0)

        assert progress.tasks[0].completed == 0

    def test_a_rewind_of_an_already_removed_task_is_ignored(self):
        progress = FakeProgress()
        display = RichTaskDisplay(progress)
        display.add("interface_templates", "Interfaces")
        progress.tasks.clear()

        display.advance("interface_templates", -1)

    def test_finish_completes_and_removes_an_owned_task(self):
        progress = FakeProgress()
        display = RichTaskDisplay(progress)
        display.add("interface_templates", "Interfaces")

        display.finish("interface_templates", 12)

        assert progress.tasks == []
        assert progress.stopped == [1]

    def test_finishing_an_unknown_endpoint_is_ignored(self):
        RichTaskDisplay(FakeProgress()).finish("interface_templates", 1)

    def test_discard_drops_an_owned_task(self):
        progress = FakeProgress()
        display = RichTaskDisplay(progress)
        display.add("interface_templates", "Interfaces")

        display.discard("interface_templates")

        assert progress.tasks == []

    def test_discard_leaves_a_registry_task_alone(self):
        progress = FakeProgress()
        display = RichTaskDisplay(progress, registry={})
        display.add("interface_templates", "Interfaces")

        display.discard("interface_templates")

        assert len(progress.tasks) == 1

    def test_a_display_that_already_dropped_the_task_does_not_raise(self):
        progress = FakeProgress()
        display = RichTaskDisplay(progress)
        display.add("interface_templates", "Interfaces")
        progress.tasks.clear()

        display.discard("interface_templates")

    def test_a_non_key_error_while_clearing_a_task_propagates(self):
        class BrokenProgress(FakeProgress):
            def stop_task(self, task_id):
                raise RuntimeError("display failed")

        with pytest.raises(RuntimeError, match="display failed"):
            RichTaskDisplay(BrokenProgress())._clear(1)

    def test_the_null_display_accepts_every_call(self):
        display = NullTaskDisplay()

        display.add("k", "Label")
        display.advance("k", 1)
        display.finish("k", 2)
        display.discard("k")


# ── Fetching ──────────────────────────────────────────────────────────────────


class TestFetching:
    """Where each endpoint is read from, and what wraps the result."""

    def test_front_port_records_are_wrapped(self):
        """Change detection needs one mappings shape across NetBox versions."""

        class Wrapped:
            """Stand-in for the front-port mappings wrapper."""

            def __init__(self, record):
                """Keep the fields the index reads."""
                self.record = record
                self.name = record.name
                self.device_type = record.device_type
                self.module_type = record.module_type

        graphql = FakeGraphQL({"front_port_templates": [Record("fp0", device_type=1)]})
        cache = make_cache(graphql=graphql, wrap_record=Wrapped)

        cache.ensure_ready()

        assert isinstance(cache.entries("front_port_templates", "device", 1)["fp0"], Wrapped)

    def test_a_rest_only_endpoint_is_read_over_rest(self, monkeypatch):
        import core.component_cache as module

        monkeypatch.setattr(module, "REST_ONLY_ENDPOINTS", frozenset({"interface_templates"}))
        endpoint = FakeEndpoint([Record("eth0", device_type=1)])
        netbox = FakeNetBox({"interface_templates": endpoint})
        graphql = FakeGraphQL()
        cache = make_cache(netbox=netbox, graphql=graphql)

        cache.ensure_ready()

        assert set(cache.entries("interface_templates", "device", 1)) == {"eth0"}
        assert "interface_templates" not in graphql.endpoints_seen

    def test_a_rest_only_endpoint_with_no_records_reports_no_progress(self, monkeypatch):
        import core.component_cache as module

        monkeypatch.setattr(module, "REST_ONLY_ENDPOINTS", frozenset({"interface_templates"}))
        netbox = FakeNetBox({"interface_templates": FakeEndpoint([])})
        cache = make_cache(netbox=netbox)

        cache.ensure_ready()

        assert cache.ready is True

    def test_records_arrive_unwrapped_when_no_wrapper_is_given(self):
        graphql = FakeGraphQL({"front_port_templates": [Record("fp0", device_type=1)]})
        cache = make_cache(graphql=graphql)

        cache.ensure_ready()

        assert cache.entries("front_port_templates", "device", 1)["fp0"].name == "fp0"


# ── Vendor-scoped guards ──────────────────────────────────────────────────────


class TestVendorGuards:
    """Cross-vendor contamination and silent GraphQL truncation both corrupt a run."""

    def _cache_for(self, records, module_types=None, counts=None, **kwargs):
        endpoints = {name: FakeEndpoint(count=count) for name, count in (counts or {}).items()}
        return make_cache(
            netbox=FakeNetBox(endpoints),
            graphql=FakeGraphQL(records, module_types=module_types or {}),
            **kwargs,
        )

    def test_a_matching_vendor_keeps_its_records(self):
        cache = self._cache_for(
            {"interface_templates": [Record("eth0", device_type=1)]},
            counts={"interface_templates": 1},
        )

        cache.ensure_ready(manufacturer_slug="cisco", device_type_ids={1})

        assert set(cache.entries("interface_templates", "device", 1)) == {"eth0"}

    def test_records_from_another_vendor_are_cleared(self):
        handle = FakeHandle()
        cache = self._cache_for(
            {"interface_templates": [Record("eth0", device_type=99)]},
            handle=handle,
        )

        cache.ensure_ready(manufacturer_slug="cisco", device_type_ids={1})

        assert cache.entries("interface_templates", "device", 99) == {}
        assert any("cross-vendor contamination" in message for message in handle.logged)

    def test_a_truncated_fetch_stops_the_run(self):
        """Fewer cached records than REST reports means GraphQL dropped some silently."""
        cache = self._cache_for(
            {"interface_templates": [Record("eth0", device_type=1)]},
            counts={"interface_templates": 7},
        )

        with pytest.raises(GraphQLCountMismatchError, match="interface_templates"):
            cache.ensure_ready(manufacturer_slug="cisco", device_type_ids={1})

        assert cache.ready is False

    def test_a_mismatch_after_foreign_records_are_cleared_names_the_scope_failure(self):
        cache = self._cache_for(
            {"interface_templates": [Record("eth0", device_type=99)]},
            counts={"interface_templates": 1},
        )

        with pytest.raises(GraphQLCountMismatchError, match="cross-vendor contamination"):
            cache.ensure_ready(manufacturer_slug="cisco", device_type_ids={1})

    def test_module_types_of_the_vendor_count_towards_the_check(self):
        cache = self._cache_for(
            {"interface_templates": [Record("xe-0", module_type=8)]},
            module_types={"cisco": {"M1": _Parent(8)}},
            counts={"interface_templates": 1},
        )

        cache.ensure_ready(manufacturer_slug="cisco", device_type_ids=set())

        assert set(cache.entries("interface_templates", "module", 8)) == {"xe-0"}

    def test_device_bays_are_not_counted_against_module_types(self):
        """device_bay_templates has no module-type path, so a module filter would 404."""
        cache = self._cache_for({}, module_types={"cisco": {"M1": _Parent(8)}})

        cache.ensure_ready(manufacturer_slug="cisco", device_type_ids=set())

        assert cache.netbox.endpoints["device_bay_templates"].count_calls == []

    def test_a_rejected_schema_skips_the_guard_with_a_warning(self):
        handle = FakeHandle()
        cache = make_cache(
            graphql=FakeGraphQL(module_types_error=GraphQLSchemaError("unknown field")),
            handle=handle,
        )

        cache.ensure_ready(manufacturer_slug="cisco", device_type_ids={1})

        assert any("integrity check skipped" in message for message in handle.logged)

    def test_a_transport_failure_does_not_skip_the_guard(self):
        """Only a rejected query shape is safe to ignore; a dead connection is not."""
        cache = make_cache(graphql=FakeGraphQL(module_types_error=ConnectionError("refused")))

        with pytest.raises(ConnectionError):
            cache.ensure_ready(manufacturer_slug="cisco", device_type_ids={1})

    def test_rest_counts_are_chunked_to_keep_the_url_short(self):
        cache = self._cache_for({}, counts={"interface_templates": 0})

        cache.ensure_ready(manufacturer_slug="cisco", device_type_ids=set(range(250)))

        chunks = [call["device_type_id"] for call in cache.netbox.endpoints["interface_templates"].count_calls]
        assert [len(chunk) for chunk in chunks] == [100, 100, 50]

    def test_a_rest_only_endpoint_is_not_compared_with_itself(self, monkeypatch):
        import core.component_cache as module

        monkeypatch.setattr(module, "REST_ONLY_ENDPOINTS", frozenset({"interface_templates"}))
        cache = self._cache_for({}, counts={"interface_templates": 99})

        cache.ensure_ready(manufacturer_slug="cisco", device_type_ids={1})

        assert cache.netbox.endpoints["interface_templates"].count_calls == []
