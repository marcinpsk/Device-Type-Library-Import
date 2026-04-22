# Code Review Action Plan

Generated from a full-repo review (2026-04-09). Items are ordered by priority.
Each item links to a concrete file/line and includes the rationale so context is
preserved when the work is picked up later.

---

## P1 — Should fix

### 1. ~~`change_by_key` slug fallback in `create_device_types`~~ — verified non-issue
- **Where:** `core/netbox_api.py` (was ~line 514)
- **Verdict:** Both `ChangeDetector.detect_changes` and `create_device_types`
  iterate the same YAML list and key on the YAML `model` field. On a slug-fallback
  match (model rename) `c.model` = YAML model and `device_type.get("model")` =
  YAML model — they are always equal. No fix needed.

### 2. ~~De-duplicate `_values_equal` / `_normalize_values`~~ — done
- **Where:** `core/normalization.py` (new)
- **Done:** Extracted unified `normalize_values` / `values_equal` into
  `core/normalization.py`. Both `change_detector.py` and `netbox_api.py` now use
  the shared helpers. Behavior decisions taken in the unified version:
  - pynetbox `.value` unwrapping (was only in `_normalize_values`; fixes a latent
    bug for rack-type choice fields like `weight_unit`)
  - all trailing whitespace stripped (was only `\n` in `_values_equal`)
  - numeric coercion in both directions (was only yaml→nb in `_values_equal`)
  - int type preserved when non-string side is int (was only in `_values_equal`)
- **Tests:** Consolidated into `tests/test_normalization.py`; includes regression
  for the bool-as-int trap (`True` must not equal `"1"` or `"1.0"`).

### 3. ~~Pin Docker base to a Python version exercised by CI~~ — done
- **Where:** `.github/workflows/tests.yml`
- **Decision:** Keep Dockerfile on `python:3.14-slim`; instead, expanded CI to a
  matrix covering `["3.12", "3.14"]` so the Docker version is exercised on every PR.

---

## P2 — Nice to have

### 4. Split `core/netbox_api.py`
- **Where:** `core/netbox_api.py` (2 727 lines, two big classes + helpers)
- **Problem:** Despite excellent helper decomposition, the file is the single
  biggest navigation cost in the repo.
- **Fix:** Mechanical split, no behavior change. Suggested seams:
  - `core/netbox_api/connection.py` — `NetBox.__init__`, `connect_api`,
    `verify_compatibility`, retry helper, `_build_auth_header`.
  - `core/netbox_api/preload.py` — `start_component_preload`,
    `stop_component_preload`, `_preload_*`, `_drain_pending`,
    `pump_preload_progress`, `_FrontPortRecordWithMappings`.
  - `core/netbox_api/components.py` — per-type `create_*`, `update_components`,
    `remove_components`, `_apply_updates_for_type`, `_apply_additions_for_type`,
    `_apply_mappings_change`, `_build_mappings_patch`, `_create_generic`.
  - `core/netbox_api/images.py` — `upload_images`, `upload_image_attachment`,
    `count_device_type_images`, `count_module_type_images`,
    `_discover_module_image_files`, `_resolve_image_paths`,
    `_upload_module_type_images`, `_image_dir_for_yaml` helper (item 6).
  - `core/netbox_api/__init__.py` — re-exports `NetBox`, `DeviceTypes` so callers
    don't need to update imports.
- **Test:** Existing 493 tests should pass unchanged. Run `ruff check` and
  `pytest --cov` to verify coverage gate (96%) still passes.

### 5. Drop no-op `__new__` overrides
- **Where:** `core/netbox_api.py:115` (`NetBox.__new__`),
  `core/netbox_api.py:1153` (`DeviceTypes.__new__`)
- **Problem:** Both just call `super().__new__(cls)` — they read like leftovers
  from a mocking experiment. They add noise without behavior.
- **Fix:** Delete both, OR add a one-line comment explaining why they exist
  (e.g. "kept so test mocks can patch __new__").
- **Also check:** `core/repo.py` — `DTLRepo` may have the same pattern.

### 6. Single `_image_dir_for_yaml` helper
- **Where:**
  - `core/netbox_api.py:283` (`_resolve_image_paths`)
  - `core/netbox_api.py:905` (`count_device_type_images`)
  - `core/netbox_api.py:998` (`_discover_module_image_files`)
- **Problem:** Three near-identical implementations of "take YAML src path,
  reverse-find a directory segment, swap it for the image segment".
- **Fix:** Extract `_image_dir_for_yaml(src_file, src_segment, dst_segment)`
  returning `Path | None`. The three callers each become 2–3 lines.
- **Test:** Add direct tests for the helper covering: missing segment, segment
  appearing twice, empty src, "Unknown" src.

### 7. Drop dead `bool` return from `_handle_existing_device_type`
- **Where:** `core/netbox_api.py:417` (always returns `True`)
- **Problem:** Caller (`create_device_types`) uses the return value to `continue`,
  but the function has no path that returns anything else. The signature
  misleadingly suggests there's a fall-through.
- **Fix:** Make the function return `None`, have the caller `continue`
  unconditionally after the call.

### 8. Bulk PATCH component updates in `_apply_updates_for_type`
- **Where:** `core/netbox_api.py:2027` (per-component `endpoint.update([update_data])`)
- **Problem:** Each component is patched in its own API call. NetBox's bulk
  endpoint accepts a list. Acceptable today (~50 changed components per device
  type) but a hot spot if `--update` runs ever get slow on big diffs.
- **Fix:** Collect all `update_data` for the type, issue one
  `endpoint.update(updates_list)` call, walk `excep.error` positionally on
  failure (mirroring the pattern in `_create_generic`).
- **Test:** Add a test that verifies a single bulk PATCH is sent for N component
  changes.

### 9. Replace `_drain_pending` busy loop with a Condition
- **Where:** `core/netbox_api.py:1506`
- **Problem:** Two interleaved poll loops (`progress_updates.get_nowait()` +
  `concurrent.futures.wait(timeout=0.1)`). Spins fast when many small endpoints
  are already done. Acceptable today but inelegant.
- **Fix:** Only worth doing if profiling shows it; otherwise leave alone.

### 10. Speed up pre-commit pytest hook
- **Where:** `.pre-commit-config.yaml:20`
- **Problem:** Every commit runs the full 493-test suite with coverage. A
  one-line typo fix takes seconds it shouldn't.
- **Fix options:**
  - Drop `pytest` from pre-commit and rely on CI (current is belt+braces).
  - Use `pytest-testmon` to only re-run tests touching changed files.
  - Add a `slow` marker and run `pytest -m "not slow"` in pre-commit.

---

## P3 — Documentation polish

### 11. Document image-comparison semantics
- **Where:** `core/change_detector.py:274` (`_compare_image_properties`)
- **Problem:** The function only flags `YAML=true / NetBox=empty`. It does NOT
  re-upload when an image file changed on disk (filename is the only fingerprint).
  This may be intentional, but it's not documented.
- **Fix:** Add a sentence to the docstring: "Note: this only detects images
  missing from NetBox; modifications to local files with the same name are not
  redetected because NetBox stores only the URL, not a content hash."

### 12. CONTRIBUTING note: keep `--update` and `--only-new` paths in sync
- **Where:** new `CONTRIBUTING.md` (or a section in README)
- **Problem:** `_process_device_types` has three branches (only_new / update /
  default), each with its own `_image_progress_scope` block. Easy to update one
  and forget the others.
- **Fix:** Add a brief contributor note pointing at `_process_device_types` and
  the same triplet in `_process_module_types` / `_process_rack_types`.

---

## Out of scope (noted, not actioned)

These showed up in the review but don't justify a fix today:

- `verify_compatibility` version parsing is brittle for pathological strings
  like `"4..5"`. NetBox itself never emits these.
- `_fetch_global_endpoint_records` REST progress callback fires only once.
  Currently dead code (`REST_ONLY_ENDPOINTS` is empty).
- `IGNORE_SSL_ERRORS` does not call `urllib3.disable_warnings()` — intentional
  per existing comment, leaves the user with noisy warnings as a reminder.
- `release.yml` PAT scope — verify minimum permissions during next rotation.

---

## Risk register (snapshot at review time)

| Risk | Likelihood | Impact | Status |
| --- | --- | --- | --- |
| Update silently skipped on model rename (slug match only) | Med | Med | Open — see P1 #1 |
| `_values_equal` / `_normalize_values` drift further | Med | Low–Med | Fixed — see P1 #2 |
| Docker image breaks on future Python release | Low | Med | Fixed — see P1 #3 |
| Image attachment name collision | Low | Low | Already handled |
| Component updates slow on large diffs | Low | Low | Open — see P2 #8 |
| Integration suite drifts vs NetBox `main` | Built-in | Built-in | Detected weekly |
