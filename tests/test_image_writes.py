"""Tests for the image writes: device-type image uploads and module-type image attachments.

A local HTTP server answers a real ``pynetbox`` client.  It parses each multipart upload and
keeps the bytes it received, so a retry that sends an empty file fails visibly.  It can drop,
cut off or garble a reply, and it refuses a request the way NetBox does.
"""

import pynetbox
import pytest
from helpers import FakeNetBox, recording_handle

from core.graphql_client import NetBoxGraphQLClient
from core.netbox_api import DeviceTypes, NetBox

# The suite patches requests.Session by default, which would stop every request below.
pytestmark = pytest.mark.real_http

SWITCH = {"id": 5, "model": "C9300", "slug": "c9300", "manufacturer": {"id": 1, "name": "Cisco", "slug": "cisco"}}
REPLIES = ["lost", "truncated", "garbled"]
# Bytes that a careless multipart encoder or parser would change: CRLF, a fake boundary, NUL.
IMAGE_BYTES = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 20 + b"\r\n--boundary\r\n\x00"

# The real 400 NetBox >= 4.6.5 returns for an image above its 25 MP cap.
_OVERSIZE_BODY = (
    '{"front_image":["Upload a valid image. The file you uploaded was either not an image or a corrupted image."]}'
)


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch):
    """Skip the wait between attempts."""
    monkeypatch.setattr("core.retry.time.sleep", lambda _seconds: None)


@pytest.fixture
def server():
    """Run a local NetBox-shaped server holding one device type."""
    fake = FakeNetBox(device_types=[SWITCH])
    yield fake
    fake.close()


@pytest.fixture
def device_types(server, tmp_path):
    """Build a real DeviceTypes against the local server, with a recording log and a progress sink."""
    handle, console = recording_handle()
    dt = DeviceTypes(
        server.api(),
        handle,
        {"images": 0},
        graphql=NetBoxGraphQLClient(server.url, "test-token"),
        repo_path=str(tmp_path),
    )
    progress = []
    dt._image_progress = progress.append
    return dt, console, progress


@pytest.fixture
def image(tmp_path):
    """Write one image file and return its path."""
    path = tmp_path / "c9300.front.png"
    path.write_bytes(IMAGE_BYTES)
    return str(path)


def requests_to(server, verb, name):
    """Count the *verb* requests sent to collection *name*."""
    return sum(v == verb and n == name for v, n, _payload in server.requests)


def logged(console):
    """Return every emitted log line as one string."""
    return " ".join(console.lines)


def break_every(server, verb, count, how):
    """Break the next *count* *verb* requests the same way."""
    done = sum(v == verb for v, n, _payload in server.requests if n != "graphql")
    server.broken_replies.update({(verb, done + n): how for n in range(1, count + 1)})


class TestUploadImageAttachment:
    """An attachment upload creates exactly one attachment, whatever happens to the reply."""

    def test_an_upload_creates_the_attachment(self, device_types, server, image):
        dt, console, progress = device_types

        assert dt.upload_image_attachment(image, "dcim.moduletype", 42) is True

        [stored] = server.collection("image_attachments")
        assert stored["object_type"] == "dcim.moduletype"
        assert stored["object_id"] == "42"
        assert stored["name"] == "c9300.front"
        assert server.uploads == [("image", "c9300.front.png", IMAGE_BYTES)]
        assert dt.counter["images"] == 1
        assert progress == [1]
        assert console.lines == []

    @pytest.mark.parametrize("reply", REPLIES)
    def test_a_broken_reply_does_not_create_a_second_attachment(self, device_types, server, image, reply):
        dt, console, progress = device_types
        server.broken_replies = {("POST", 1): reply}

        assert dt.upload_image_attachment(image, "dcim.moduletype", 42) is True

        assert len(server.collection("image_attachments")) == 1
        assert requests_to(server, "POST", "image_attachments") == 1
        assert dt.counter["images"] == 1
        assert progress == [1]
        assert console.lines == []

    def test_an_upload_sent_again_carries_the_whole_file(self, device_types, server, image):
        """The first attempt read the file to its end; the second must start from byte 0."""
        dt, _, _ = device_types
        server.broken_replies = {("POST", 1): "dropped"}

        assert dt.upload_image_attachment(image, "dcim.moduletype", 42) is True

        assert [data for _field, _name, data in server.uploads] == [IMAGE_BYTES, IMAGE_BYTES]
        assert len(server.collection("image_attachments")) == 1

    def test_a_rejected_upload_returns_false_and_logs_netbox_reason(self, device_types, server, image):
        dt, console, progress = device_types
        server.errors = {"image_attachments": (400, '{"image":["Upload a valid image."]}')}

        assert dt.upload_image_attachment(image, "dcim.moduletype", 7) is False

        assert "Error uploading image attachment for dcim.moduletype 7" in logged(console)
        assert "400" in logged(console)
        assert "Upload a valid image." in logged(console)
        assert dt.counter["images"] == 0
        assert progress == []

    def test_retries_exhausted_fail_only_that_upload(self, device_types, server, image):
        dt, console, _ = device_types
        break_every(server, "POST", 4, "dropped")

        assert dt.upload_image_attachment(image, "dcim.moduletype", 42) is False
        assert "after 3 retries" in logged(console)
        assert server.collection("image_attachments") == []

        assert dt.upload_image_attachment(image, "dcim.moduletype", 43) is True
        assert [r["object_id"] for r in server.collection("image_attachments")] == ["43"]

    def test_an_ambiguous_lookup_after_a_lost_reply_fails_that_upload(self, device_types, server, image):
        """Two attachments with the name: nothing tells which one the lost reply created."""
        dt, console, _ = device_types
        old = {"object_type": "dcim.moduletype", "object_id": "42", "name": "c9300.front"}
        server.collection("image_attachments").append({**old, "id": 1})
        server.broken_replies = {("POST", 1): "lost"}

        assert dt.upload_image_attachment(image, "dcim.moduletype", 42) is False

        assert "Cannot tell if the image attachment for dcim.moduletype 42 was created" in logged(console)
        assert requests_to(server, "POST", "image_attachments") == 1

    def test_an_unreadable_file_returns_false(self, device_types, server, tmp_path):
        dt, console, _ = device_types

        assert dt.upload_image_attachment(str(tmp_path / "gone.png"), "dcim.moduletype", 42) is False

        assert "Error reading image file" in logged(console)
        assert requests_to(server, "POST", "image_attachments") == 0


class TestUploadDeviceTypeImages:
    """A device-type image PATCH is idempotent, so a broken reply sends it again in full."""

    def test_front_and_rear_images_are_set(self, device_types, server, image, tmp_path):
        dt, console, progress = device_types
        rear = tmp_path / "c9300.rear.png"
        rear.write_bytes(b"rear")

        assert dt.upload_images({"front_image": image, "rear_image": str(rear)}, SWITCH["id"]) is True

        [stored] = server.collection("device_types")
        assert stored["front_image"] == "/media/c9300.front.png"
        assert stored["rear_image"] == "/media/c9300.rear.png"
        assert sorted(data for _f, _n, data in server.uploads) == sorted([IMAGE_BYTES, b"rear"])
        assert requests_to(server, "PATCH", "device_types") == 1
        assert dt.counter["images"] == 2
        assert progress == [2]
        assert console.lines == []

    @pytest.mark.parametrize("reply", REPLIES)
    def test_a_broken_reply_sends_the_whole_file_again(self, device_types, server, image, reply):
        dt, console, progress = device_types
        server.broken_replies = {("PATCH", 1): reply}

        assert dt.upload_images({"front_image": image}, SWITCH["id"]) is True

        assert [data for _field, _name, data in server.uploads] == [IMAGE_BYTES, IMAGE_BYTES]
        assert server.collection("device_types")[0]["front_image"] == "/media/c9300.front.png"
        assert dt.counter["images"] == 1
        assert progress == [1]
        assert console.lines == []

    def test_a_rejected_upload_logs_netbox_reason(self, device_types, server, image):
        dt, console, progress = device_types
        server.errors = {"device_types": (400, _OVERSIZE_BODY)}

        assert dt.upload_images({"front_image": image}, 42) is False

        assert "Error uploading images for device type 42" in logged(console)
        assert "400" in logged(console)
        assert "not an image or a corrupted image" in logged(console)
        assert dt.counter["images"] == 0
        assert progress == []

    def test_a_server_error_logs_its_body(self, device_types, server, image):
        """A 500 surfaces the body too: this is the case issue #102 could not diagnose."""
        dt, console, _ = device_types
        server.errors = {"device_types": (500, "PermissionError: [Errno 13] Permission denied: '/media'")}

        assert dt.upload_images({"front_image": image}, 30) is False

        assert "500" in logged(console)
        assert "Permission denied" in logged(console)

    def test_a_long_error_body_is_truncated(self, device_types, server, image):
        """A DEBUG-mode HTML traceback page is capped instead of flooding the log."""
        dt, console, _ = device_types
        server.errors = {"device_types": (500, "<html>" + ("x" * 5000) + "</html>")}

        dt.upload_images({"front_image": image}, 1)

        assert "truncated" in logged(console)
        assert len(logged(console)) < 1000

    def test_control_characters_in_the_body_are_escaped(self, device_types, server, image):
        """A response body cannot inject line breaks that forge more log records."""
        dt, console, _ = device_types
        forged = '{"detail":"boom"}\r\n[12:34:56] Device Type Created: FORGED - 999\x1b[31m'
        server.errors = {"device_types": (400, forged)}

        dt.upload_images({"front_image": image}, 1)

        assert "\n" not in logged(console)
        assert "\r" not in logged(console)
        assert "\x1b" not in logged(console)
        assert "\\r\\n" in logged(console)
        assert "FORGED" in logged(console)

    def test_retries_exhausted_fail_only_that_device_type(self, device_types, server, image):
        dt, console, _ = device_types
        break_every(server, "PATCH", 4, "dropped")

        assert dt.upload_images({"front_image": image}, SWITCH["id"]) is False
        assert "Error uploading images for device type 5 after 3 retries" in logged(console)
        assert "front_image" not in server.collection("device_types")[0]

        assert dt.upload_images({"front_image": image}, SWITCH["id"]) is True
        assert server.collection("device_types")[0]["front_image"] == "/media/c9300.front.png"

    def test_an_unreadable_file_sends_nothing(self, device_types, server, image, tmp_path):
        dt, console, _ = device_types

        assert dt.upload_images({"front_image": image, "rear_image": str(tmp_path / "gone.png")}, 5) is False

        assert "Error reading image file for device type 5" in logged(console)
        assert requests_to(server, "PATCH", "device_types") == 0


class TestDeleteImageAttachment:
    """A delete whose reply broke counts as done; a delete NetBox refuses does not."""

    @pytest.fixture(autouse=True)
    def stored(self, server):
        """Hold one attachment to delete."""
        server.collection("image_attachments").append({"id": 12, "name": "c9300.front", "object_id": "42"})

    def test_a_delete_removes_the_attachment(self, device_types, server):
        dt, console, _ = device_types

        assert dt.delete_image_attachment(12) is True

        assert server.collection("image_attachments") == []
        assert console.lines == []

    @pytest.mark.parametrize("reply", ["lost", "dropped"])
    def test_a_broken_reply_counts_as_deleted(self, device_types, server, reply):
        dt, console, _ = device_types
        server.broken_replies = {("DELETE", 1): reply}

        assert dt.delete_image_attachment(12) is True

        assert server.collection("image_attachments") == []
        assert console.lines == []

    def test_a_first_attempt_delete_of_a_missing_attachment_fails(self, device_types, server):
        dt, console, _ = device_types

        assert dt.delete_image_attachment(99) is False

        assert "Error deleting image attachment 99" in logged(console)
        assert "could not be found" in logged(console)
        assert len(server.collection("image_attachments")) == 1

    def test_a_refused_delete_logs_netbox_reason(self, device_types, server):
        dt, console, _ = device_types
        server.errors = {"image_attachments": (409, '{"detail":"Attachment is in use."}')}

        assert dt.delete_image_attachment(12) is False

        assert "409" in logged(console)
        assert "Attachment is in use." in logged(console)

    def test_retries_exhausted_return_false(self, device_types, server):
        dt, console, _ = device_types
        break_every(server, "DELETE", 1, "dropped")
        break_every(server, "GET", 3, "lost")

        assert dt.delete_image_attachment(12) is False

        assert "Error deleting image attachment 12 after 3 retries" in logged(console)


class TestImageHashes:
    """A failed upload stores no hash, so --verify-images uploads the changed file next run."""

    @pytest.fixture
    def netbox(self, make_config, mock_pynetbox, server, tmp_path):
        """Build a real NetBox whose device types talk to the local server."""
        mock_pynetbox.RequestError = pynetbox.RequestError
        handle, _console = recording_handle()
        nb = NetBox(make_config(netbox_url=server.url, repo_path=str(tmp_path)), handle)
        nb.netbox = nb.device_types.netbox = server.api()
        return nb

    @pytest.mark.parametrize(("errors", "stored"), [({}, True), ({"device_types": 400}, False)])
    def test_a_hash_is_stored_only_after_the_upload(self, netbox, server, image, errors, stored):
        server.errors = errors
        dt = pynetbox.core.response.Record({**SWITCH, "front_image": None}, server.api(), None)

        netbox._handle_existing_device_type(dt, {"model": "C9300"}, "cisco", {"front_image": image}, True, None, False)

        assert (image in netbox._image_hash_cache) is stored
