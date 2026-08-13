#!/usr/bin/env python3
"""Import NetBox device and module types from the community library."""

from contextlib import contextmanager
from datetime import datetime
import sys

from pynetbox.core.query import RequestError as NetBoxRequestError
import requests
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    ProgressBar,
    ProgressColumn,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.text import Text

from core.config import ConfigError, resolve_run_config
from core.errors import FatalError
from core.graphql_client import GraphQLError
from core.import_run import ImportRun
from core.log_handler import LogHandler
from core.netbox_api import NetBox, _fmt_connection_error
from core.repo import DTLRepo


class NoPulseBarColumn(BarColumn):
    """Render a static empty bar when the task total is unknown."""

    def render(self, task):
        """Render a progress bar without a pulse animation."""
        if task.total is None:
            total: float = 1.0
            completed: float = 0.0
        else:
            total = max(0.0, task.total)
            completed = max(0.0, task.completed)
        return ProgressBar(
            total=total,
            completed=completed,
            width=None if self.bar_width is None else max(1, self.bar_width),
            pulse=False,
            animation_time=task.get_time(),
            style=self.style,
            complete_style=self.complete_style,
            finished_style=self.finished_style,
            pulse_style=self.pulse_style,
        )


class MyProgress(Progress):
    """Render the progress task table in a bordered panel."""

    def get_renderables(self):
        """Yield the panel that contains the task table."""
        yield Panel(self.make_tasks_table(self.tasks))


class ItemsPerSecondColumn(ProgressColumn):
    """Display processing speed in items per second."""

    @staticmethod
    def _effective_speed(task, primary_attr):
        """Return the reported speed or an elapsed-time fallback."""
        speed = getattr(task, primary_attr, None)
        if speed is not None:
            return speed
        elapsed = getattr(task, "elapsed", None)
        completed = getattr(task, "completed", 0)
        if elapsed and completed:
            return completed / elapsed
        return None

    def render(self, task):
        """Render the current or finished speed."""
        if task.finished:
            speed = self._effective_speed(task, "finished_speed")
        else:
            speed = self._effective_speed(task, "speed")
        if speed is None:
            return Text("- it/s")
        return Text(f"{speed:.1f} it/s")


@contextmanager
def get_progress_panel(show_remaining_time=False):
    """Yield a progress display for a TTY, or None for other output."""
    if not sys.stdout.isatty():
        yield None
        return

    columns = [
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        NoPulseBarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        ItemsPerSecondColumn(),
    ]
    if show_remaining_time:
        columns.append(TimeRemainingColumn())

    with MyProgress(*columns, refresh_per_second=4) as progress:
        yield progress


def _run_export_diff(config, handle):
    """Run the export-diff pipeline."""
    from core.export import Exporter

    exporter = Exporter(
        config=config,
        handle=handle,
        export_dir=config.export_diff_dir,
        force_overwrite=config.force_export_overwrite,
        vendor_slugs=config.vendors if config.vendors else None,
    )
    with get_progress_panel(config.show_remaining_time) as progress:
        if progress is not None:
            handle.set_console(progress.console)
        try:
            exporter.run(progress=progress)
        finally:
            if progress is not None:
                handle.set_console(None)


def _run(config):
    """Build and execute the selected run pipeline."""
    started_at = datetime.now()
    handle = LogHandler(config.verbose)
    for notice in config.notices:
        handle.log(notice)

    if config.export_diff:
        _run_export_diff(config, handle)
        return None

    repo = DTLRepo(config, handle)
    netbox = NetBox(config, handle)
    return ImportRun(
        config,
        repo,
        netbox,
        handle,
        get_progress_panel,
        started_at=started_at,
    ).execute()


def main():
    """Resolve the configuration and execute one run."""
    try:
        config = resolve_run_config()
    except ConfigError as exc:
        raise SystemExit(str(exc))
    try:
        return _run(config)
    except FatalError as exc:
        if config.verbose and exc.stack_trace:
            print(exc.stack_trace)
        raise SystemExit(str(exc))
    except requests.exceptions.ConnectionError as exc:
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] Error: {_fmt_connection_error(config.netbox_url, exc)}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except GraphQLError as exc:
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] Error: NetBox GraphQL request failed — {exc}\n"
            f"[{datetime.now().strftime('%H:%M:%S')}] This may be a temporary connectivity issue. "
            "Check that NetBox is reachable and try again.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except NetBoxRequestError as exc:
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] Error: NetBox REST API request failed — {exc}\n"
            f"[{datetime.now().strftime('%H:%M:%S')}] Check that NetBox is reachable and"
            " the API token has the required permissions.",
            file=sys.stderr,
        )
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Interrupted by user (Ctrl-C). Exiting.")
        raise SystemExit(130)
