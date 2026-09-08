"""Shared test utilities for the NetBox device-type importer test suite."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pynetbox


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


class FakeNetBox:
    """A local HTTP server answering the slice of the NetBox REST API the importer uses.

    Collections are addressed by their URL segment with dashes turned into underscores,
    so ``module-bay-types`` is ``module_bay_types``.  GET filters, POST creates and PATCH
    bulk-updates behave the way pynetbox expects, so a real client drives it and the
    serialising, filtering and paginating under test are the production ones.

    ``/graphql/`` answers every query with an empty list, which is enough to bring a real
    :class:`~core.netbox_api.NetBox` up; the REST half is where the assertions live.

    A test using this must carry the ``real_http`` marker.  Without it the suite patches
    ``requests.Session`` and no request ever leaves the client.
    """

    _IGNORED_FILTERS = ("limit", "offset", "brief", "exclude")

    # GraphQL collections are named "<thing>_list"; the client asks for one per query.
    _LIST_KEY = re.compile(r"\b(\w+_list)\b")

    def __init__(self, errors=None, netbox_version="4.7.0", **collections):
        """Start the server with *collections* seeded, keyed by collection name.

        *errors* maps a collection name to an HTTP status the server answers it with, so a
        test can drive a rejection the importer has to survive.  *netbox_version* is what
        ``/api/status/`` reports, which is how the export side decides what it may select.
        """
        self.collections = {name: [dict(r) for r in records] for name, records in collections.items()}
        self.errors = dict(errors or {})
        self.netbox_version = netbox_version
        self.requests = []
        self._server = HTTPServer(("127.0.0.1", 0), self._handler())
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self):
        """Return the base URL a client should talk to."""
        return f"http://127.0.0.1:{self._server.server_port}"

    def api(self, token="test-token"):
        """Return a real pynetbox client pointed at this server."""
        return pynetbox.api(self.url, token=token)

    def close(self):
        """Stop serving and release the listening socket."""
        self._server.shutdown()
        self._server.server_close()

    def collection(self, name):
        """Return the stored records for a collection, creating it empty when unseen."""
        return self.collections.setdefault(name, [])

    def sent(self, verb, name):
        """Return the payload of each *verb* request made to collection *name*.

        A bulk create or update sends a list; its entries are returned individually, so a
        caller asserting on what was written does not have to care which shape was used.
        """
        out = []
        for method, collection, payload in self.requests:
            if method != verb or collection != name:
                continue
            out.extend(payload) if isinstance(payload, list) else out.append(payload)
        return out

    def matches(self, name, query):
        """Filter a collection the way the NetBox REST API filters it."""
        out = []
        for record in self.collection(name):
            ok = True
            for key, values in query.items():
                if key in self._IGNORED_FILTERS:
                    continue
                field = key[:-3] if key.endswith("_id") else key
                actual = record.get(field)
                if isinstance(actual, dict):
                    actual = actual.get("id")
                if str(actual) not in values:
                    ok = False
                    break
            if ok:
                out.append(record)
        return out

    def _create(self, name, payload):
        """Store the new record(s) and echo them back the way NetBox does.

        A list payload is a bulk create, which is how the importer adds components, and it
        answers with a list.
        """
        if isinstance(payload, list):
            return [self._create_one(name, item) for item in payload]
        return self._create_one(name, payload)

    def _create_one(self, name, payload):
        """Store one new record and return it as NetBox would echo it back."""
        collection = self.collection(name)
        record = {"id": 1000 + len(collection), **payload}
        # NetBox echoes a foreign key back as a nested object, not the id it was given.
        if isinstance(record.get("manufacturer"), int):
            owner = next((m for m in self.collection("manufacturers") if m["id"] == record["manufacturer"]), {})
            record["manufacturer"] = {"id": record["manufacturer"], "name": owner.get("name")}
        collection.append(record)
        return record

    def _patch(self, name, payload):
        """Merge a bulk update into the stored records and return the updated ones."""
        updated = []
        for entry in payload if isinstance(payload, list) else [payload]:
            record = next((r for r in self.collection(name) if r["id"] == entry.get("id")), None)
            if record is None:
                continue
            record.update(entry)
            updated.append(record)
        return updated

    def _handler(self):
        """Build the request handler class bound to this server's state."""
        state = self

        class Handler(BaseHTTPRequestHandler):
            def _collection_name(self):
                return urlparse(self.path).path.rstrip("/").rsplit("/", 1)[-1].replace("-", "_")

            def _body(self):
                return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

            def _reply(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _refused(self, name):
                """Answer with the configured status for *name*, if the test set one."""
                status = state.errors.get(name)
                if status is None:
                    return False
                self._reply(status, {"detail": f"{name} refused with {status}"})
                return True

            def do_GET(self):
                parsed = urlparse(self.path)
                name = self._collection_name()
                state.requests.append(("GET", name, parsed.query))
                if name == "status":
                    self._reply(200, {"netbox-version": state.netbox_version})
                    return
                if self._refused(name):
                    return
                results = state.matches(name, parse_qs(parsed.query))
                self._reply(200, {"count": len(results), "next": None, "previous": None, "results": results})

            def do_POST(self):
                name = self._collection_name()
                payload = self._body()
                if name == "graphql":
                    state.requests.append(("POST", name, payload))
                    key = state._LIST_KEY.search(payload.get("query", ""))
                    self._reply(200, {"data": {key.group(1) if key else "unknown_list": []}})
                    return
                state.requests.append(("POST", name, payload))
                if self._refused(name):
                    return
                self._reply(201, state._create(name, payload))

            def do_PATCH(self):
                name = self._collection_name()
                payload = self._body()
                state.requests.append(("PATCH", name, payload))
                if self._refused(name):
                    return
                self._reply(200, state._patch(name, payload))

            def log_message(self, *args):
                """Silence the default stderr access log."""

        return Handler


def write_module_bay_type(root, manufacturer, slug, name, description=None):
    """Write one module-bay-type catalog file where the devicetype-library puts it."""
    directory = root / "module-bay-types" / manufacturer
    directory.mkdir(parents=True, exist_ok=True)
    body = f"name: {name}\nslug: {slug}\nmanufacturer: {manufacturer}\n"
    if description:
        body += f"description: {description}\n"
    (directory / f"{slug}.yaml").write_text(body, encoding="utf-8")
