"""Tests for ``core.outcomes.OutcomeRegistry``."""

from __future__ import annotations

from core.outcomes import EntityKind, Outcome, OutcomeRegistry


def test_registry_starts_empty():
    reg = OutcomeRegistry()
    assert reg.records == []
    assert reg.failures() == []
    assert reg.partials() == []
    assert reg.summary_by_kind() == {}
    assert reg.render_failure_report() == []


def test_registry_records_failures_and_partials():
    reg = OutcomeRegistry()
    reg.record(
        EntityKind.DEVICE_TYPE,
        "Supermicro/SuperServer",
        Outcome.FAILED,
        reason="subdevice_role flip blocked",
        blocking_objects=["bay-1", "bay-2"],
        hint="re-run with --force-resolve-conflicts",
    )
    reg.record(
        EntityKind.MODULE_TYPE,
        "Cisco/SFP-X",
        Outcome.PARTIAL,
        reason="component PATCH failed",
    )
    reg.record(EntityKind.DEVICE_TYPE, "ok/ok", Outcome.UPDATED)

    failures = reg.failures()
    assert len(failures) == 1
    assert failures[0].identity == "Supermicro/SuperServer"
    assert failures[0].blocking_objects == ["bay-1", "bay-2"]

    partials = reg.partials()
    assert len(partials) == 1
    assert partials[0].identity == "Cisco/SFP-X"

    summary = reg.summary_by_kind()
    assert summary[EntityKind.DEVICE_TYPE] == {Outcome.FAILED: 1, Outcome.UPDATED: 1}
    assert summary[EntityKind.MODULE_TYPE] == {Outcome.PARTIAL: 1}


def test_render_failure_report_includes_identity_and_reason():
    reg = OutcomeRegistry()
    reg.record(
        EntityKind.DEVICE_TYPE,
        "Supermicro/SYS-6028TR-HTR",
        Outcome.FAILED,
        reason="subdevice_role parent->child blocked",
        blocking_objects=["bay-A"],
        hint="re-run with --force-resolve-conflicts",
    )
    lines = reg.render_failure_report()
    text = "\n".join(lines)
    assert "Failed entities: 1" in text
    assert "Supermicro/SYS-6028TR-HTR" in text
    assert "subdevice_role parent->child blocked" in text
    assert "bay-A" in text
    assert "--force-resolve-conflicts" in text


def test_render_failure_report_truncates_long_blocking_lists():
    reg = OutcomeRegistry()
    blockers = [f"bay-{i}" for i in range(12)]
    reg.record(
        EntityKind.DEVICE_TYPE,
        "Vendor/Model",
        Outcome.FAILED,
        reason="constraint",
        blocking_objects=blockers,
    )
    text = "\n".join(reg.render_failure_report())
    assert "bay-0" in text
    assert "bay-4" in text
    # Truncation marker appears for >5 items.
    assert "+7 more" in text


def test_render_failure_report_empty_when_only_successes():
    reg = OutcomeRegistry()
    reg.record(EntityKind.DEVICE_TYPE, "a/b", Outcome.UPDATED)
    reg.record(EntityKind.MODULE_TYPE, "c/d", Outcome.CREATED)
    assert reg.render_failure_report() == []


def test_render_failure_report_includes_partials_section():
    """Partial outcomes get their own section in the rendered report."""
    reg = OutcomeRegistry()
    reg.record(
        EntityKind.MODULE_TYPE,
        "Nokia/IOM-s-3.0T",
        Outcome.PARTIAL,
        reason="image upload failed but properties applied",
    )
    reg.record(EntityKind.DEVICE_TYPE, "v/no-reason-partial", Outcome.PARTIAL)
    text = "\n".join(reg.render_failure_report())
    assert "Partial updates: 2" in text
    assert "Nokia/IOM-s-3.0T" in text
    assert "image upload failed but properties applied" in text
    assert "v/no-reason-partial" in text
