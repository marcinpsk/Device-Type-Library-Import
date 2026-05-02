"""Centralised tracking of per-entity outcomes for end-of-run reporting.

The legacy ``Counter`` on :class:`core.netbox_api.NetBox` aggregates counts but
loses the per-entity context needed to tell operators *which* device types
failed and *why*.  :class:`OutcomeRegistry` records one row per processed
entity so the summary can render a structured failure report alongside the
existing counts.

Designed to be additive: existing call sites keep using the legacy ``Counter``;
only failure paths must call :meth:`OutcomeRegistry.record` to populate the
new report.  Future PRs can migrate count call sites to the registry and
derive the legacy ``Counter`` from it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class EntityKind(str, Enum):
    """Categorisation of which kind of NetBox entity an outcome refers to."""

    DEVICE_TYPE = "device_type"
    MODULE_TYPE = "module_type"
    RACK_TYPE = "rack_type"
    COMPONENT = "component"
    IMAGE = "image"
    MANUFACTURER = "manufacturer"


class Outcome(str, Enum):
    """Terminal outcomes for a single processed entity."""

    CREATED = "created"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"


@dataclass
class OutcomeRecord:
    """Single recorded outcome for one entity."""

    kind: EntityKind
    identity: str  # human-readable identifier (e.g. "Supermicro/SuperServer-6028TR-HTR")
    outcome: Outcome
    reason: Optional[str] = None
    blocking_objects: List[str] = field(default_factory=list)
    hint: Optional[str] = None


class OutcomeRegistry:
    """Append-only registry of entity outcomes.

    Failure-path call sites should use :meth:`record` after they decide an
    entity failed, so the end-of-run summary can render an itemised report.
    """

    def __init__(self) -> None:
        """Initialise an empty registry."""
        self._records: List[OutcomeRecord] = []

    def record(
        self,
        kind: EntityKind,
        identity: str,
        outcome: Outcome,
        *,
        reason: Optional[str] = None,
        blocking_objects: Optional[List[str]] = None,
        hint: Optional[str] = None,
    ) -> None:
        """Append a new outcome record."""
        self._records.append(
            OutcomeRecord(
                kind=kind,
                identity=identity,
                outcome=outcome,
                reason=reason,
                blocking_objects=list(blocking_objects) if blocking_objects else [],
                hint=hint,
            )
        )

    @property
    def records(self) -> List[OutcomeRecord]:
        """All recorded outcomes (read-only view)."""
        return list(self._records)

    def failures(self) -> List[OutcomeRecord]:
        """Return only the FAILED records."""
        return [r for r in self._records if r.outcome == Outcome.FAILED]

    def partials(self) -> List[OutcomeRecord]:
        """Return only the PARTIAL records (some but not all changes applied)."""
        return [r for r in self._records if r.outcome == Outcome.PARTIAL]

    def summary_by_kind(self) -> Dict[EntityKind, Dict[Outcome, int]]:
        """Aggregate counts grouped by ``(kind, outcome)``."""
        agg: Dict[EntityKind, Dict[Outcome, int]] = {}
        for r in self._records:
            agg.setdefault(r.kind, {}).setdefault(r.outcome, 0)
            agg[r.kind][r.outcome] += 1
        return agg

    def render_failure_report(self) -> List[str]:
        """Render a multi-line operator-facing failure report.

        Returns an empty list when no failures or partials were recorded.
        Each string is one log line, ready to pass to ``handle.log``.
        """
        failures = self.failures()
        partials = self.partials()
        if not failures and not partials:
            return []

        lines: List[str] = []
        lines.append("=" * 60)
        lines.append("FAILED / PARTIAL UPDATE REPORT")
        lines.append("=" * 60)

        if failures:
            lines.append(f"Failed entities: {len(failures)}")
            for r in failures:
                lines.append(f"  ✗ [{r.kind.value}] {r.identity}")
                if r.reason:
                    lines.append(f"      reason: {r.reason}")
                if r.blocking_objects:
                    blockers = ", ".join(r.blocking_objects[:5])
                    if len(r.blocking_objects) > 5:
                        blockers += f", … (+{len(r.blocking_objects) - 5} more)"
                    lines.append(f"      blocked by: {blockers}")
                if r.hint:
                    lines.append(f"      hint: {r.hint}")

        if partials:
            lines.append(f"Partial updates: {len(partials)}")
            for r in partials:
                lines.append(f"  ~ [{r.kind.value}] {r.identity}")
                if r.reason:
                    lines.append(f"      reason: {r.reason}")
                if r.blocking_objects:
                    blockers = ", ".join(r.blocking_objects[:5])
                    if len(r.blocking_objects) > 5:
                        blockers += f", … (+{len(r.blocking_objects) - 5} more)"
                    lines.append(f"      blocked by: {blockers}")
                if r.hint:
                    lines.append(f"      hint: {r.hint}")

        lines.append("=" * 60)
        return lines
