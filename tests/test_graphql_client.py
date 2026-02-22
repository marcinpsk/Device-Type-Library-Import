"""Tests for the NetBox GraphQL client module (TDD - tests written first)."""

import pytest
from unittest.mock import MagicMock
import requests

from graphql_client import DotDict


def _make_paged_responses(data, list_key):
    """Return a ``[data_response, empty_response]`` pair for paginated query mocks.

    *data* is the dict payload for the first page (e.g. ``{"manufacturer_list": [...]}``)
    and *list_key* is the key to use for the empty termination page.
    """
    data_r = MagicMock()
    data_r.status_code = 200
    data_r.raise_for_status = MagicMock()
    data_r.json.return_value = {"data": data}
    empty_r = MagicMock()
    empty_r.status_code = 200
    empty_r.raise_for_status = MagicMock()
    empty_r.json.return_value = {"data": {list_key: []}}
    return [data_r, empty_r]


# ── DotDict adapter tests ──────────────────────────────────────────────────


class TestDotDict:
    """Tests for the DotDict adapter that bridges GraphQL dicts to attribute access."""

    def test_attribute_access(self):

        d = DotDict({"name": "Cisco", "slug": "cisco", "id": "1"})
        assert d.name == "Cisco"
        assert d.slug == "cisco"
        assert d.id == "1"

    def test_nested_attribute_access(self):

        d = DotDict({"manufacturer": {"name": "Cisco", "slug": "cisco"}})
        assert d.manufacturer.name == "Cisco"
        assert d.manufacturer.slug == "cisco"

    def test_str_returns_name(self):
        """str() should return the name, matching pynetbox Record behavior."""

        d = DotDict({"name": "Cisco", "slug": "cisco"})
        assert str(d) == "Cisco"

    def test_str_without_name_returns_repr(self):

        d = DotDict({"slug": "cisco"})
        result = str(d)
        assert isinstance(result, str)

    def test_getattr_with_default(self):

        d = DotDict({"name": "Test"})
        assert getattr(d, "front_image", None) is None
        assert getattr(d, "name", "default") == "Test"

    def test_dict_access_still_works(self):

        d = DotDict({"name": "Cisco"})
        assert d["name"] == "Cisco"

    def test_get_method(self):

        d = DotDict({"name": "Cisco"})
        assert d.get("name") == "Cisco"
        assert d.get("missing", "default") == "default"

    def test_in_operator(self):

        d = DotDict({"name": "Cisco", "slug": "cisco"})
        assert "name" in d
        assert "missing" not in d

    def test_equality_by_data(self):

        d1 = DotDict({"name": "Cisco"})
        d2 = DotDict({"name": "Cisco"})
        assert d1 == d2

    def test_none_attribute_returns_none(self):

        d = DotDict({"front_image": None})
        assert d.front_image is None

    def test_update_method(self):
        """DotDict.update() should work for property updates like pynetbox."""

        d = DotDict({"name": "Old", "slug": "old"})
        d.update({"name": "New"})
        assert d.name == "New"
        assert d["name"] == "New"


# ── Core client tests ──────────────────────────────────────────────────────


class TestNetBoxGraphQLClient:
    """Tests for NetBoxGraphQLClient initialization and configuration."""

    def test_init_stores_config(self):
        from graphql_client import NetBoxGraphQLClient

        client = NetBoxGraphQLClient("http://netbox.local", "mytoken", ignore_ssl=True)
        assert client.url == "http://netbox.local"
        assert client.graphql_url == "http://netbox.local/graphql/"
        assert client.token == "mytoken"
        assert client.ignore_ssl is True

    def test_init_strips_trailing_slash(self):
        from graphql_client import NetBoxGraphQLClient

        client = NetBoxGraphQLClient("http://netbox.local/", "tok")
        assert client.graphql_url == "http://netbox.local/graphql/"

    def test_init_defaults_ignore_ssl_false(self):
        from graphql_client import NetBoxGraphQLClient

        client = NetBoxGraphQLClient("http://netbox.local", "tok")
        assert client.ignore_ssl is False


class TestGraphQLQuery:
    """Tests for the low-level query() method."""

    def _make_client(self, **kwargs):
        from graphql_client import NetBoxGraphQLClient

        return NetBoxGraphQLClient("http://netbox.local", "testtoken", **kwargs)

    def test_query_posts_to_graphql_endpoint(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"manufacturer_list": []}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        client.query("{ manufacturer_list { id name } }")

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "http://netbox.local/graphql/"
        assert kwargs["json"]["query"] == "{ manufacturer_list { id name } }"
        # Headers and verify are configured on the session at init time
        client._session.headers.update.assert_called_once_with(
            {"Authorization": "Token testtoken", "Content-Type": "application/json"}
        )
        assert client.ignore_ssl is False

    def test_query_passes_variables(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        client.query("query($id: Int!) { manufacturer(id: $id) { name } }", variables={"id": 1})

        payload = mock_post.call_args[1]["json"]
        assert payload["variables"] == {"id": 1}

    def test_query_returns_data(self, mock_post):
        expected = {"manufacturer_list": [{"id": "1", "name": "Cisco", "slug": "cisco"}]}
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": expected}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        result = client.query("{ manufacturer_list { id name slug } }")

        assert result == expected

    def test_query_ignores_ssl_when_configured(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client(ignore_ssl=True)
        client.query("{ manufacturer_list { id } }")

        # verify is configured on the session at init time
        assert client.ignore_ssl is True
        assert client._session.verify is False

    def test_query_verifies_ssl_by_default(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        client.query("{ manufacturer_list { id } }")

        assert client.ignore_ssl is False
        assert client._session.verify is True

    def test_query_raises_on_http_error(self, mock_post):
        from graphql_client import GraphQLError

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.HTTPError("Server Error")
        mock_post.return_value = mock_response

        client = self._make_client()
        with pytest.raises(GraphQLError, match="Server Error"):
            client.query("{ manufacturer_list { id } }")

    def test_query_raises_on_graphql_errors(self, mock_post):
        from graphql_client import GraphQLError

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "errors": [{"message": "Field 'foo' not found"}],
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        with pytest.raises(GraphQLError, match="Field 'foo' not found"):
            client.query("{ foo { id } }")


class TestGraphQLQueryAll:
    """Tests for paginated query_all() method."""

    def _make_client(self):
        from graphql_client import NetBoxGraphQLClient

        return NetBoxGraphQLClient("http://netbox.local", "tok")

    def test_query_all_single_page(self, mock_post):
        """Single page: data response followed by empty page to confirm end of data."""
        items = [{"id": "1", "name": "Cisco"}]
        r_data = MagicMock()
        r_data.status_code = 200
        r_data.json.return_value = {"data": {"manufacturer_list": items}}
        r_data.raise_for_status = MagicMock()
        r_empty = MagicMock()
        r_empty.status_code = 200
        r_empty.json.return_value = {"data": {"manufacturer_list": []}}
        r_empty.raise_for_status = MagicMock()
        mock_post.side_effect = [r_data, r_empty]

        client = self._make_client()
        result = client.query_all(
            "query($pagination: OffsetPaginationInput) { manufacturer_list(pagination: $pagination) { id name } }",
            list_key="manufacturer_list",
            page_size=100,
        )

        assert result == items
        assert mock_post.call_count == 2

    def test_query_all_multiple_pages(self, mock_post):
        """Fetches additional pages when results == page_size."""
        page1 = [{"id": str(i)} for i in range(3)]
        page2 = [{"id": "3"}]

        responses = []
        for page_data in [page1, page2]:
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = {"data": {"device_type_list": page_data}}
            r.raise_for_status = MagicMock()
            responses.append(r)
        mock_post.side_effect = responses

        client = self._make_client()
        result = client.query_all(
            "query($pagination: OffsetPaginationInput) { device_type_list(pagination: $pagination) { id } }",
            list_key="device_type_list",
            page_size=3,
        )

        assert len(result) == 4
        assert mock_post.call_count == 2
        # Verify pagination variables were passed correctly
        first_call_vars = mock_post.call_args_list[0][1]["json"]["variables"]
        assert first_call_vars["pagination"] == {"offset": 0, "limit": 3}
        second_call_vars = mock_post.call_args_list[1][1]["json"]["variables"]
        assert second_call_vars["pagination"] == {"offset": 3, "limit": 3}

    def test_query_all_empty_result(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"manufacturer_list": []}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        result = client.query_all(
            "query($pagination: OffsetPaginationInput) { manufacturer_list(pagination: $pagination) { id } }",
            list_key="manufacturer_list",
        )

        assert result == []

    def test_query_all_merges_extra_variables(self, mock_post):
        """Extra variables are merged alongside pagination."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"device_type_list": []}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        client.query_all(
            "query($pagination: OffsetPaginationInput, $name: String) { device_type_list(pagination: $pagination, filters: {name: $name}) { id } }",
            list_key="device_type_list",
            variables={"name": "test"},
        )

        sent_vars = mock_post.call_args[1]["json"]["variables"]
        assert sent_vars["name"] == "test"
        assert "pagination" in sent_vars

    def test_query_all_warns_when_server_clamps_page_size(self, mock_post):
        """Server clamping detection: warns once when effective page < requested."""
        # Server caps at 2, we request 10; three pages total with 2+2+1 items.
        # Page 3 has 1 item (< effective_page_size=2), so query_all stops there
        # without needing a terminal empty page.
        pages = [
            [{"id": "1"}, {"id": "2"}],
            [{"id": "3"}, {"id": "4"}],
            [{"id": "5"}],
        ]
        responses = []
        for page_data in pages:
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = {"data": {"device_type_list": page_data}}
            r.raise_for_status = MagicMock()
            responses.append(r)
        mock_post.side_effect = responses

        warned_msgs = []

        class FakeLog:
            def log(self, msg):
                warned_msgs.append(msg)

        from graphql_client import NetBoxGraphQLClient

        client = NetBoxGraphQLClient("http://netbox.local", "tok", log_handler=FakeLog())
        result = client.query_all(
            "query($p: OffsetPaginationInput) { device_type_list(pagination: $p) { id } }",
            list_key="device_type_list",
            page_size=10,
        )

        assert len(result) == 5
        assert mock_post.call_count == 3
        assert len(warned_msgs) == 1
        assert "2" in warned_msgs[0]  # effective page size in warning
        assert "10" in warned_msgs[0]  # requested page size in warning

    def test_query_all_clamping_warning_emitted_only_once(self, mock_post):
        """Clamping warning is emitted at most once per client instance."""

        # Two separate query_all calls, each seeing clamping.
        def make_pages(n_pages, page_size=2):
            pages = [[{"id": str(i * page_size + j)} for j in range(page_size)] for i in range(n_pages)]
            pages.append([])
            return pages

        all_pages = make_pages(2) + make_pages(2)
        responses = []
        for page_data in all_pages:
            r = MagicMock()
            r.status_code = 200
            r.json.return_value = {"data": {"device_type_list": page_data}}
            r.raise_for_status = MagicMock()
            responses.append(r)
        mock_post.side_effect = responses

        warned_msgs = []

        class FakeLog:
            def log(self, msg):
                warned_msgs.append(msg)

        from graphql_client import NetBoxGraphQLClient

        client = NetBoxGraphQLClient("http://netbox.local", "tok", log_handler=FakeLog())
        client.query_all(
            "query($p: OffsetPaginationInput) { device_type_list(pagination: $p) { id } }",
            list_key="device_type_list",
            page_size=10,
        )
        client.query_all(
            "query($p: OffsetPaginationInput) { device_type_list(pagination: $p) { id } }",
            list_key="device_type_list",
            page_size=10,
        )

        assert mock_post.call_count == 6
        assert len(warned_msgs) == 1


# ── Query method tests ─────────────────────────────────────────────────────


class TestGetManufacturers:
    """Tests for the get_manufacturers() convenience method."""

    def _make_client(self):
        from graphql_client import NetBoxGraphQLClient

        client = NetBoxGraphQLClient("http://netbox.local", "tok")
        return client

    def test_returns_dict_keyed_by_name(self, mock_post):
        data = {
            "manufacturer_list": [
                {"id": "1", "name": "Cisco", "slug": "cisco"},
                {"id": "2", "name": "Juniper", "slug": "juniper"},
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "manufacturer_list")

        client = self._make_client()
        result = client.get_manufacturers()

        assert "Cisco" in result
        assert "Juniper" in result
        # Dict access
        assert result["Cisco"]["slug"] == "cisco"
        assert result["Cisco"]["id"] == 1  # GraphQL string IDs are coerced to int
        # Attribute access (pynetbox Record compatibility)
        assert result["Cisco"].slug == "cisco"
        assert result["Cisco"].name == "Cisco"
        # str() returns name (matching pynetbox behavior)
        assert str(result["Cisco"]) == "Cisco"

    def test_returns_empty_dict_when_no_manufacturers(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"manufacturer_list": []}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        result = client.get_manufacturers()

        assert result == {}


class TestGetDeviceTypes:
    """Tests for the get_device_types() convenience method."""

    def _make_client(self):
        from graphql_client import NetBoxGraphQLClient

        return NetBoxGraphQLClient("http://netbox.local", "tok")

    def test_returns_two_indexes(self, mock_post):
        data = {
            "device_type_list": [
                {
                    "id": "1",
                    "model": "Catalyst 9300",
                    "slug": "catalyst-9300",
                    "front_image": None,
                    "rear_image": None,
                    "manufacturer": {"id": "10", "name": "Cisco", "slug": "cisco"},
                },
                {
                    "id": "2",
                    "model": "MX480",
                    "slug": "mx480",
                    "front_image": "http://netbox/media/front.jpg",
                    "rear_image": None,
                    "manufacturer": {"id": "20", "name": "Juniper", "slug": "juniper"},
                },
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "device_type_list")

        client = self._make_client()
        by_model, by_slug = client.get_device_types()

        # by_model index
        assert ("cisco", "Catalyst 9300") in by_model
        assert ("juniper", "MX480") in by_model
        assert by_model[("cisco", "Catalyst 9300")]["id"] == 1
        # Attribute access (pynetbox Record compatibility)
        dt = by_model[("cisco", "Catalyst 9300")]
        assert dt.model == "Catalyst 9300"
        assert dt.slug == "catalyst-9300"
        assert dt.manufacturer.slug == "cisco"
        assert dt.manufacturer.name == "Cisco"
        assert dt.id == 1
        # front_image / rear_image
        assert getattr(dt, "front_image", None) is None
        dt2 = by_model[("juniper", "MX480")]
        assert dt2.front_image == "http://netbox/media/front.jpg"

        # by_slug index
        assert ("cisco", "catalyst-9300") in by_slug
        assert ("juniper", "mx480") in by_slug

    def test_empty_device_types(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"device_type_list": []}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        by_model, by_slug = client.get_device_types()

        assert by_model == {}
        assert by_slug == {}

    def test_image_dict_flattened_to_url(self, mock_post):
        """When GraphQL returns image fields as {url: ...} dicts they should be flattened to strings."""
        data = {
            "device_type_list": [
                {
                    "id": "5",
                    "model": "Nexus 9000",
                    "slug": "nexus-9000",
                    "front_image": {"url": "http://netbox/media/nexus.front.jpg"},
                    "rear_image": {"url": "http://netbox/media/nexus.rear.jpg"},
                    "manufacturer": {"id": "30", "name": "Cisco", "slug": "cisco"},
                }
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "device_type_list")

        client = self._make_client()
        by_model, by_slug = client.get_device_types()

        dt = by_model[("cisco", "Nexus 9000")]
        assert dt.front_image == "http://netbox/media/nexus.front.jpg"
        assert dt.rear_image == "http://netbox/media/nexus.rear.jpg"
        assert ("cisco", "nexus-9000") in by_slug

    def test_image_dict_with_none_url_flattened_to_none(self, mock_post):
        """When the image dict has url=None the record should store None."""
        data = {
            "device_type_list": [
                {
                    "id": "6",
                    "model": "ASR 9000",
                    "slug": "asr-9000",
                    "front_image": {"url": None},
                    "rear_image": None,
                    "manufacturer": {"id": "30", "name": "Cisco", "slug": "cisco"},
                }
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "device_type_list")

        client = self._make_client()
        by_model, _ = client.get_device_types()

        dt = by_model[("cisco", "ASR 9000")]
        assert dt.front_image is None
        assert dt.rear_image is None


class TestGetModuleTypes:
    """Tests for the get_module_types() convenience method."""

    def _make_client(self):
        from graphql_client import NetBoxGraphQLClient

        return NetBoxGraphQLClient("http://netbox.local", "tok")

    def test_returns_nested_dict_by_manufacturer_and_model(self, mock_post):
        data = {
            "module_type_list": [
                {
                    "id": "42",
                    "model": "Linecard 1",
                    "manufacturer": {"id": "20", "name": "Juniper", "slug": "juniper"},
                },
                {
                    "id": "43",
                    "model": "Linecard 2",
                    "manufacturer": {"id": "20", "name": "Juniper", "slug": "juniper"},
                },
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "module_type_list")

        client = self._make_client()
        result = client.get_module_types()

        assert "juniper" in result
        assert "Linecard 1" in result["juniper"]
        assert result["juniper"]["Linecard 1"]["id"] == 42
        assert result["juniper"]["Linecard 2"]["id"] == 43
        # Attribute access (pynetbox Record compatibility)
        mt = result["juniper"]["Linecard 1"]
        assert mt.id == 42
        assert mt.model == "Linecard 1"
        assert mt.manufacturer.slug == "juniper"

    def test_returns_empty_dict_when_no_modules(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"module_type_list": []}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        result = client.get_module_types()

        assert result == {}


class TestGetModuleTypeImages:
    """Tests for the get_module_type_images() convenience method."""

    def _make_client(self):
        from graphql_client import NetBoxGraphQLClient

        return NetBoxGraphQLClient("http://netbox.local", "tok")

    def test_returns_mapping_of_ids_to_name_sets(self, mock_post):
        data = {
            "image_attachment_list": [
                {"id": "1", "name": "front", "object_id": 42},
                {"id": "2", "name": "rear", "object_id": 42},
                {"id": "3", "name": "top", "object_id": 43},
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "image_attachment_list")

        client = self._make_client()
        result = client.get_module_type_images()

        assert result[42] == {"front", "rear"}
        assert result[43] == {"top"}

    def test_skips_entries_without_name(self, mock_post):
        data = {
            "image_attachment_list": [
                {"id": "1", "name": "", "object_id": 42},
                {"id": "2", "name": None, "object_id": 42},
                {"id": "3", "name": "valid", "object_id": 42},
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "image_attachment_list")

        client = self._make_client()
        result = client.get_module_type_images()

        assert result[42] == {"valid"}

    def test_returns_empty_dict_when_no_attachments(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"image_attachment_list": []}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        result = client.get_module_type_images()

        assert result == {}

    def test_falls_back_to_python_filter_on_schema_error(self, mock_post):
        """When the filtered query raises GraphQLError, fall back to fetch-all + Python filter."""

        error_response = MagicMock()
        error_response.status_code = 200
        error_response.raise_for_status = MagicMock()
        error_response.json.return_value = {"errors": [{"message": "Expected value of type 'ContentTypeFilter'"}]}

        fallback_response = MagicMock()
        fallback_response.status_code = 200
        fallback_response.raise_for_status = MagicMock()
        fallback_response.json.return_value = {
            "data": {
                "image_attachment_list": [
                    {
                        "id": "1",
                        "name": "front",
                        "object_id": 10,
                        "object_type": {"app_label": "dcim", "model": "moduletype"},
                    },
                    {
                        "id": "2",
                        "name": "other",
                        "object_id": 20,
                        "object_type": {"app_label": "dcim", "model": "devicetype"},
                    },
                ]
            }
        }
        empty_response = MagicMock()
        empty_response.status_code = 200
        empty_response.raise_for_status = MagicMock()
        empty_response.json.return_value = {"data": {"image_attachment_list": []}}
        mock_post.side_effect = [error_response, fallback_response, empty_response]

        client = self._make_client()
        result = client.get_module_type_images()

        assert result == {10: {"front"}}


# ── get_component_templates tests ──────────────────────────────────────────


class TestGetComponentTemplates:
    """Tests for the get_component_templates() convenience method."""

    def _make_client(self):
        from graphql_client import NetBoxGraphQLClient

        return NetBoxGraphQLClient("http://netbox.local", "tok")

    def test_returns_dotdict_records_with_parent_info(self, mock_post):
        """Records should be DotDicts with device_type/module_type and correct id types."""

        data = {
            "interface_template_list": [
                {
                    "id": "10",
                    "name": "eth0",
                    "type": "1000base-t",
                    "label": "",
                    "mgmt_only": False,
                    "enabled": True,
                    "poe_mode": None,
                    "poe_type": None,
                    "device_type": {"id": "1"},
                    "module_type": None,
                },
                {
                    "id": "11",
                    "name": "eth1",
                    "type": "1000base-t",
                    "label": "uplink",
                    "mgmt_only": False,
                    "enabled": True,
                    "poe_mode": None,
                    "poe_type": None,
                    "device_type": {"id": "1"},
                    "module_type": None,
                },
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "interface_template_list")

        client = self._make_client()
        records = client.get_component_templates("interface_templates")

        assert len(records) == 2
        assert isinstance(records[0], DotDict)
        assert records[0].name == "eth0"
        assert records[0].id == 10
        assert records[0].device_type.id == 1
        assert records[1].label == "uplink"

    def test_returns_empty_list_when_no_records(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"power_port_template_list": []}}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        records = client.get_component_templates("power_port_templates")

        assert records == []

    def test_all_endpoint_names_are_supported(self):
        """Every component endpoint name used by DeviceTypes should be recognized."""
        from graphql_client import COMPONENT_TEMPLATE_FIELDS

        expected_endpoints = [
            "interface_templates",
            "power_port_templates",
            "console_port_templates",
            "console_server_port_templates",
            "power_outlet_templates",
            "rear_port_templates",
            "front_port_templates",
            "device_bay_templates",
            "module_bay_templates",
        ]
        for endpoint in expected_endpoints:
            assert endpoint in COMPONENT_TEMPLATE_FIELDS, f"{endpoint} not in COMPONENT_TEMPLATE_FIELDS"

    def test_raises_for_unknown_endpoint(self):
        """An unknown endpoint name should raise ValueError."""
        client = self._make_client()
        with pytest.raises(ValueError, match="Unknown component endpoint"):
            client.get_component_templates("nonexistent_endpoint")

    def test_module_type_parent_preserved(self, mock_post):
        """Records with module_type parent should have module_type.id as int."""
        data = {
            "console_port_template_list": [
                {
                    "id": "20",
                    "name": "console0",
                    "type": "rj-45",
                    "label": "",
                    "device_type": None,
                    "module_type": {"id": "5"},
                },
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "console_port_template_list")

        client = self._make_client()
        records = client.get_component_templates("console_port_templates")

        assert records[0].module_type.id == 5
        assert records[0].device_type is None

    def test_device_bay_templates_fields(self, mock_post):
        """device_bay_templates has no 'type' field — should not error."""
        data = {
            "device_bay_template_list": [
                {
                    "id": "30",
                    "name": "Bay 1",
                    "label": "",
                    "device_type": {"id": "2"},
                },
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "device_bay_template_list")

        client = self._make_client()
        records = client.get_component_templates("device_bay_templates")

        assert records[0].name == "Bay 1"
        assert records[0].id == 30

    def test_module_bay_templates_fields(self, mock_post):
        """module_bay_templates should return records with the expected fields."""
        data = {
            "module_bay_template_list": [
                {
                    "id": "40",
                    "name": "Bay 1",
                    "position": "1",
                    "label": "",
                    "device_type": {"id": "3"},
                },
            ]
        }
        mock_post.side_effect = _make_paged_responses(data, "module_bay_template_list")

        client = self._make_client()
        records = client.get_component_templates("module_bay_templates")

        assert records[0].name == "Bay 1"
        assert records[0].id == 40
        # Verify the generated query does not include module_type (not in schema for module_bay_templates)
        sent_query = mock_post.call_args_list[0][1]["json"]["query"]
        assert "module_type" not in sent_query


class TestCustomPageSize:
    """Verify that the page_size constructor parameter is respected."""

    def test_default_page_size(self, graphql_client):
        assert graphql_client.DEFAULT_PAGE_SIZE == 5000

    def test_custom_page_size(self):
        from graphql_client import NetBoxGraphQLClient

        client = NetBoxGraphQLClient("http://netbox.local", "tok", page_size=500)
        assert client.DEFAULT_PAGE_SIZE == 500

    def test_custom_page_size_used_in_query_all(self, mock_post):
        from graphql_client import NetBoxGraphQLClient

        client = NetBoxGraphQLClient("http://netbox.local", "tok", page_size=100)
        mock_post.return_value.json.return_value = {"data": {"items": []}}
        client.query_all("query($pagination: OffsetPaginationInput) { items }", "items")
        sent_vars = mock_post.call_args[1]["json"]["variables"]
        assert sent_vars["pagination"]["limit"] == 100
