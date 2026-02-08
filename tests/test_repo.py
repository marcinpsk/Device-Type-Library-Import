from unittest.mock import MagicMock, mock_open, patch
from repo import DTLRepo


def test_slug_format():
    # We need to mock settings because DTLRepo might use it or be used by it,
    # but here we are just testing a method.
    # However, creating DTLRepo instance requires args, repo_path, handler.

    mock_args = MagicMock()
    mock_args.url = "http://example.com"
    mock_args.branch = "master"

    mock_handle = MagicMock()

    # We mock 'os.path.isdir' to avoid git operations in __init__
    with patch("os.path.isdir", return_value=True), patch("repo.Repo"):
        repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)

        assert repo.slug_format("Cisco Systems") == "cisco-systems"
        assert repo.slug_format("HP Enterprise") == "hp-enterprise"
        assert repo.slug_format("Juniper") == "juniper"


def test_parse_files():
    mock_args = MagicMock()
    mock_args.url = "http://example.com"
    mock_args.branch = "master"
    mock_handle = MagicMock()

    with patch("os.path.isdir", return_value=True), patch("repo.Repo"):
        repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)

        # Mock file content
        yaml_content = """
manufacturer: Cisco
model: C9300-24T
slug: c9300-24t
part_number: C9300-24T-A
"""
        with patch("builtins.open", mock_open(read_data=yaml_content)):
            # We pass a dummy file path
            files = ["/tmp/repo/cisco/c9300.yaml"]

            # Test without slug filtering
            results = repo.parse_files(files)
            assert len(results) == 1
            assert results[0]["manufacturer"]["slug"] == "cisco"
            assert results[0]["model"] == "C9300-24T"

            # Test with matching slug filtering
            results_filtered = repo.parse_files(files, slugs=["c9300"])
            assert len(results_filtered) == 1

            # Test with non-matching slug filtering
            results_filtered_out = repo.parse_files(files, slugs=["juniper"])
            assert len(results_filtered_out) == 0
