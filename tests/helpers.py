"""Shared test utilities for the NetBox device-type importer test suite."""

import copy
import json
import re
import threading
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
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


class _Refused(Exception):
    """A request NetBox answers with 400 and *body*."""

    def __init__(self, body):
        """Keep the body to answer with."""
        super().__init__(body)
        self.body = body


class FakeNetBox:
    """A local HTTP server answering the slice of the NetBox REST API the importer uses.

    Collections are addressed by their URL segment with dashes turned into underscores,
    so ``module-bay-types`` is ``module_bay_types``.  GET filters, POST creates, PATCH
    bulk-updates and DELETE bulk-deletes behave the way pynetbox expects, so a real client
    drives it and the serialising, filtering and paginating under test are the production ones.
    A create that repeats a natural key gets NetBox's 400, as does a delete of a missing id.
    A PATCH to one object's URL updates that object.  A multipart write stores each file as
    a media URL and keeps the received bytes in ``uploads``.

    ``/graphql/`` answers every query with an empty list, which is enough to bring a real
    :class:`~core.netbox_api.NetBox` up; the REST half is where the assertions live.

    A test using this must carry the ``real_http`` marker.  Without it the suite patches
    ``requests.Session`` and no request ever leaves the client.
    """

    _IGNORED_FILTERS = ("limit", "offset", "brief", "exclude")

    # GraphQL collections are named "<thing>_list"; the client asks for one per query.
    _LIST_KEY = re.compile(r"\b(\w+_list)\b")

    # A nested reference NetBox looks up by its attributes, keyed by field name.
    _NESTED_REFERENCES = (("manufacturer", "manufacturers"), ("profile", "module_type_profiles"))

    # Fields that together identify one record, as NetBox's unique constraints do.
    _UNIQUE_TOGETHER: ClassVar[dict[str, tuple[tuple[str, ...], ...]]] = {
        "manufacturers": (("slug",),),
        "device_types": (("manufacturer", "model"),),
        "rack_types": (("manufacturer", "model"),),
        "module_types": (("manufacturer", "model"),),
        "module_bay_types": (("manufacturer", "name"),),
    }
    _COMPONENT_UNIQUE = (("device_type", "name"), ("module_type", "name"))

    def __init__(self, errors=None, netbox_version="4.7.0", **collections):
        """Start the server with *collections* seeded, keyed by collection name.

        *errors* maps a collection name to an HTTP status the server answers it with, so a
        test can drive a rejection the importer has to survive.  A ``(status, text)`` pair
        answers with that raw body instead of a JSON detail.  *netbox_version* is what
        ``/api/status/`` reports, which is how the export side decides what it may select.
        """
        self.collections = {name: [dict(r) for r in records] for name, records in collections.items()}
        self.errors = dict(errors or {})
        self.netbox_version = netbox_version
        # A GET whose request target is longer than this gets 414, as from a proxy URL limit.
        self.max_url_length = None
        self.requests = []
        # (verb, 1-based number of that verb) -> "lost", "truncated" or "garbled": the request runs, the reply breaks.
        # "dropped": the connection closes before the request runs, so nothing commits.
        # "stalled": the request runs, and the reply never comes until close().
        self.broken_replies = {}
        # (field, filename, bytes) of each file a multipart write carried, in arrival order.
        self.uploads = []
        self._released = threading.Event()  # ends every "stalled" reply
        # Threaded, so a request can still be answered while a "stalled" reply holds its thread.
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = True
        # A short poll lets close() return at once instead of after the default half second.
        threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    @property
    def url(self):
        """Return the base URL a client should talk to."""
        return f"http://127.0.0.1:{self._server.server_port}"

    def api(self, token="test-token"):
        """Return a real pynetbox client pointed at this server."""
        return pynetbox.api(self.url, token=token)

    def close(self):
        """Stop serving and release the listening socket."""
        self._released.set()
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
                # A plain field such as object_id matches itself; device_type_id filters the device_type reference.
                field = key[:-3] if key.endswith("_id") and key not in record else key
                actual = record.get(field)
                if isinstance(actual, dict):
                    # NetBox filters a nested reference by id with "<field>_id", by slug with "<field>".
                    actual = actual.get("id" if key.endswith("_id") else "slug")
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
        records = [self._build_record(item) for item in (payload if isinstance(payload, list) else [payload])]
        errors = [self._duplicate_error(name, record) for record in records]
        if any(errors):
            # A bulk create is atomic: one duplicate refuses the whole batch.
            raise _Refused(errors if isinstance(payload, list) else errors[0])
        collection = self.collection(name)
        for record in records:
            record["id"] = 1000 + len(collection)
            collection.append(record)
        return records if isinstance(payload, list) else records[0]

    def _duplicate_error(self, name, item):
        """Return NetBox's error for an item that repeats a stored natural key, else an empty dict."""
        constraints = self._UNIQUE_TOGETHER.get(name, self._COMPONENT_UNIQUE if name.endswith("_templates") else ())
        for fields in constraints:
            wanted = [self._reference_id(item.get(field)) for field in fields]
            if None in wanted:
                continue
            if any(wanted == [self._reference_id(r.get(f)) for f in fields] for r in self.collection(name)):
                return {"non_field_errors": [f"The fields {', '.join(fields)} must make a unique set."]}
        return {}

    @staticmethod
    def _reference_id(value):
        """Return the id of a nested reference, or the value itself."""
        return value.get("id") if isinstance(value, dict) else value

    def _delete(self, name, payload):
        """Remove the records a bulk delete names, refusing the batch as NetBox does if one is missing."""
        wanted = [entry["id"] for entry in payload]
        stored = self.collection(name)
        missing = [i for i in wanted if not any(r["id"] == i for r in stored)]
        if missing:
            raise _Refused(
                {
                    "detail": f"{len(missing)} of {len(wanted)} objects could not be found.",
                    "errors": [{"id": i, "errors": {"id": [f"Object with ID {i} does not exist"]}} for i in missing],
                }
            )
        stored[:] = [r for r in stored if r["id"] not in wanted]

    def _resolve_references(self, payload):
        """Replace each nested reference with the object it names, as NetBox does.

        Raises _Refused with NetBox's own 400 body when no object matches.
        """
        for field, collection in self._NESTED_REFERENCES:
            wanted = payload.get(field)
            if not isinstance(wanted, dict):
                continue
            match = next((r for r in self.collection(collection) if wanted.items() <= r.items()), None)
            if match is None:
                raise _Refused({field: [f"Related object not found using the provided attributes: {wanted}"]})
            payload[field] = self._nested(match)
        return payload

    @staticmethod
    def _nested(record):
        """Return *record* as NetBox nests it in another object: id, name, and slug when it has one."""
        nested = {"id": record.get("id"), "name": record.get("name")}
        if "slug" in record:
            nested["slug"] = record["slug"]
        return nested

    def _build_record(self, payload):
        """Return one new record as NetBox would echo it back, without storing it."""
        record = self._resolve_references(payload)
        # NetBox echoes a foreign key back as a nested object, not the id it was given.
        if isinstance(record.get("manufacturer"), int):
            owner = next((m for m in self.collection("manufacturers") if m["id"] == record["manufacturer"]), {})
            record["manufacturer"] = {**self._nested(owner), "id": record["manufacturer"]}
        return record

    @staticmethod
    def _answer(status, produce):
        """Return (status, body) for what *produce* returns, or the 400 it raises."""
        try:
            return status, produce()
        except _Refused as refusal:
            return 400, refusal.body

    def _patch(self, name, payload):
        """Merge a bulk update into the stored records and return the updated ones."""
        updated = []
        for entry in payload if isinstance(payload, list) else [payload]:
            record = next((r for r in self.collection(name) if r["id"] == entry.get("id")), None)
            if record is None:
                continue
            entry = self._resolve_references(entry)  # a refused entry changes nothing
            if "attributes" in entry:
                # NetBox's AttributesField merges a non-empty value into the stored attributes.
                attributes = entry.pop("attributes")
                stored = record.get("attribute_data")
                merge = attributes and isinstance(stored, dict)
                record["attribute_data"] = {**stored, **attributes} if merge else attributes
            if "profile" in entry and entry["profile"] is None:
                record["attribute_data"] = None  # ModuleType.clean() drops the attributes of a type without a profile
            record.update(entry)
            updated.append(record)
        return updated

    @staticmethod
    def _target(path):
        """Return the collection name in *path* and, for one object's URL, its id."""
        segments = urlparse(path).path.rstrip("/").split("/")
        object_id = int(segments.pop()) if segments[-1].isdigit() else None
        return segments[-1].replace("-", "_"), object_id

    def _collection_name(self, path):
        """Return the collection name in *path*, which must be a collection URL."""
        name, object_id = self._target(path)
        assert object_id is None, f"the fake answers only PATCH on one object's URL, not {path}"
        return name

    def _decode(self, headers, raw):
        """Return a request body as a payload: JSON, or a multipart form."""
        if headers.get_content_type() == "multipart/form-data":
            return self._form(headers["Content-Type"], raw)
        return json.loads(raw or b"{}")

    def _refused(self, handler, name):
        """Answer with the status (and raw body, when given) the test set for *name*; return True if it did."""
        error = self.errors.get(name)
        if error is None:
            return False
        if isinstance(error, tuple):
            status, text = error
        else:
            status, text = error, json.dumps({"detail": f"{name} refused with {error}"})
        handler._send(status, text.encode())
        return True

    def _form(self, content_type, raw):
        """Return a multipart form body as a payload; each file becomes the media URL NetBox echoes."""
        message = BytesParser(policy=HTTP).parsebytes(f"Content-Type: {content_type}\r\n\r\n".encode() + raw)
        payload = {}
        for part in message.iter_parts():
            field = part.get_param("name", header="content-disposition")
            filename = part.get_filename()
            if filename is None:
                payload[field] = part.get_payload(decode=True).decode()
                continue
            self.uploads.append((field, filename, part.get_payload(decode=True)))
            payload[field] = f"/media/{filename}"
        return payload

    def _broken(self, verb):
        """Return how the test chose to break the latest *verb* request, or None."""
        number = sum(method == verb for method, name, _ in self.requests if name != "graphql")
        return self.broken_replies.get((verb, number))

    def _reply_to(self, handler, verb, answer):
        """Send *answer*, or break the reply the way the test chose for this request."""
        broken = self._broken(verb)
        if broken == "stalled":
            self._released.wait()
            handler.close_connection = True
            return
        if broken == "lost":
            handler.close_connection = True
            return
        if broken in ("truncated", "garbled"):
            handler.send_response(answer[0])
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", "1000" if broken == "truncated" else "2")
            handler.end_headers()
            handler.wfile.write(b"[{")
            handler.close_connection = True
            return
        handler._reply(*answer)

    def _write(self, handler, verb, name, payload, status, apply):
        """Record a write, then answer with *apply*'s result or the refusal it raises."""
        self.requests.append((verb, name, payload))
        if self._broken(verb) == "dropped":
            handler.close_connection = True
            return
        if self._refused(handler, name):
            return
        self._reply_to(handler, verb, self._answer(status, lambda: apply(name, copy.deepcopy(payload))))

    def _write_patch(self, handler, name, object_id, payload):
        """Record a PATCH: a bulk update on a collection URL, or one object's update on its own URL."""
        if object_id is None:
            self._write(handler, "PATCH", name, payload, 200, self._patch)
            return
        self._write(handler, "PATCH", name, {**payload, "id": object_id}, 200, lambda n, p: self._patch(n, p)[0])

    def _handler(self):
        """Build the request handler class bound to this server's state."""
        state = self

        class Handler(BaseHTTPRequestHandler):
            def _collection_name(self):
                return state._collection_name(self.path)

            def _body(self):
                return state._decode(self.headers, self.rfile.read(int(self.headers.get("Content-Length", 0))))

            def _reply(self, status, payload):
                self._send(status, b"" if payload is None else json.dumps(payload).encode())

            def _send(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("API-Version", ".".join(state.netbox_version.split(".")[:2]))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                name = self._collection_name()
                state.requests.append(("GET", name, parsed.query))
                if state.max_url_length is not None and len(self.path) > state.max_url_length:
                    self._reply(414, {"detail": "Request-URI Too Long"})
                    return
                if name == "status":
                    self._reply(200, {"netbox-version": state.netbox_version})
                    return
                if state._refused(self, name):
                    return
                results = state.matches(name, parse_qs(parsed.query))
                page = {"count": len(results), "next": None, "previous": None, "results": results}
                state._reply_to(self, "GET", (200, page))

            def do_POST(self):
                name = self._collection_name()
                payload = self._body()
                if name != "graphql":
                    state._write(self, "POST", name, payload, 201, state._create)
                    return
                state.requests.append(("POST", name, payload))
                key = state._LIST_KEY.search(payload.get("query", ""))
                self._reply(200, {"data": {key.group(1) if key else "unknown_list": []}})

            def do_PATCH(self):
                state._write_patch(self, *state._target(self.path), self._body())

            def do_DELETE(self):
                state._write(self, "DELETE", self._collection_name(), self._body(), 204, state._delete)

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
