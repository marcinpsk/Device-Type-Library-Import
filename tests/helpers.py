"""Shared test utilities for the NetBox device-type importer test suite."""

from unittest.mock import MagicMock


def paginate_dispatch(data_dict):
    """Return a ``requests.post`` side-effect that simulates a single-page result.

    Returns *data_dict* when the request uses ``offset=0`` (first page) and empty
    lists for every subsequent page, so tests that contain non-empty data don't loop
    forever under ``query_all``'s empty-page termination logic.

    Usage::

        mock_post.side_effect = paginate_dispatch({"manufacturer_list": [{...}]})
    """

    def handler(url, json=None, **kwargs):
        r = MagicMock()
        r.status_code = 200
        r.raise_for_status = MagicMock()
        offset = (((json or {}).get("variables") or {}).get("pagination") or {}).get("offset", 0)
        if offset == 0:
            r.json.return_value = {"data": data_dict}
        else:
            r.json.return_value = {"data": {k: [] for k in data_dict}}
        return r

    return handler


class RecordingConsole:
    """Capture what the real LogHandler emits."""

    def __init__(self):
        """Start with no recorded lines."""
        self.lines = []

    def print(self, message, markup=False):
        """Record one emitted line."""
        self.lines.append(message)


def recording_handle():
    """Return a real LogHandler writing into a RecordingConsole."""
    from core.log_handler import LogHandler

    handle = LogHandler(False)
    console = RecordingConsole()
    handle.set_console(console)
    return handle, console
