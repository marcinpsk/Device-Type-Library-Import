import pytest
from unittest.mock import MagicMock, call, mock_open, patch
from git import exc as git_exc
from core.repo import DTLRepo, validate_git_url, normalize_port_mappings


class TestValidateGitUrl:
    """Tests for Git URL validation logic (HTTPS, SSH, file://, and invalid cases)."""

    def test_https_valid(self):
        ok, err = validate_git_url("https://github.com/org/repo.git")
        assert ok is True
        assert err is None

    def test_https_no_hostname_invalid(self):
        ok, err = validate_git_url("https://")
        assert ok is False

    def test_git_at_scp_valid(self):
        ok, err = validate_git_url("git@github.com:org/repo.git")
        assert ok is True

    def test_git_at_no_colon_invalid(self):
        ok, err = validate_git_url("git@github.com/org/repo.git")
        assert ok is False

    def test_ssh_valid(self):
        ok, err = validate_git_url("ssh://git@github.com/org/repo.git")
        assert ok is True

    def test_ssh_no_hostname_invalid(self):
        ok, err = validate_git_url("ssh://")
        assert ok is False

    def test_file_valid(self):
        ok, err = validate_git_url("file:///tmp/repo")
        assert ok is True

    def test_file_empty_path_invalid(self):
        ok, err = validate_git_url("file://")
        assert ok is False

    def test_empty_url_invalid(self):
        ok, err = validate_git_url("")
        assert ok is False
        assert "Empty" in err

    def test_ftp_invalid(self):
        ok, err = validate_git_url("ftp://example.com/repo.git")
        assert ok is False

    def test_none_invalid(self):
        ok, err = validate_git_url(None)
        assert ok is False


class TestDTLRepoInit:
    """Tests for DTLRepo initialisation: path validation, clone vs pull branching."""

    def _make_repo(self, isdir=True, mock_repo=None):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=isdir),
            patch("core.repo.Repo") as MockRepo,
        ):
            if mock_repo:
                MockRepo.return_value = mock_repo
                MockRepo.clone_from.return_value = mock_repo
            repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)
        return repo, mock_handle

    def test_pulls_when_dir_exists(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            ref = MagicMock()
            ref.name = "origin/master"
            mock_git_repo.remotes.origin.refs = [ref]
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_git_repo.remotes.origin.fetch.assert_called_once_with(prune=True)
        mock_git_repo.git.checkout.assert_called_with("-B", "master", "origin/master")

    def test_clones_when_dir_missing(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=False),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_cloned = MagicMock()
            MockRepo.clone_from.return_value = mock_cloned
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        MockRepo.clone_from.assert_called_once()

    def test_invalid_url_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "ftp://bad.url"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=False), patch("core.repo.Repo"):
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called_with(
            "InvalidGitURL",
            "ftp://bad.url",
            "URL must use HTTPS, SSH, or file protocol",
        )


class TestDTLRepoPathMethods:
    """Tests for DTLRepo path helper methods (get_relative_path, get_absolute_path, etc.)."""

    def _make_repo(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            ref = MagicMock()
            ref.name = "origin/master"
            mock_git_repo.remotes.origin.refs = [ref]
            MockRepo.return_value = mock_git_repo
            repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)
        return repo

    def test_get_relative_path(self):
        repo = self._make_repo()
        assert repo.get_relative_path() == "/tmp/repo"

    def test_get_devices_path(self):
        repo = self._make_repo()
        assert repo.get_devices_path().endswith("device-types")

    def test_get_modules_path(self):
        repo = self._make_repo()
        assert repo.get_modules_path().endswith("module-types")


class TestPullRepo:
    """Tests for DTLRepo.pull_repo(): origin URL validation, pull success, and error handling."""

    def test_pull_repo_invalid_origin_calls_exception(self):
        """When origin URL equals configured URL and both are invalid, exception is called."""
        mock_args = MagicMock()
        mock_args.url = "ftp://bad"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            # origin URL matches configured URL → validate origin path
            mock_git_repo.remotes.origin.url = "ftp://bad"
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()

    def test_pull_repo_invalid_configured_url_calls_exception(self):
        """When configured REPO_URL differs from origin and is invalid, exception is called."""
        mock_args = MagicMock()
        mock_args.url = "ftp://bad-config"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_any_call(
            "InvalidGitURL",
            "ftp://bad-config",
            "URL must use HTTPS, SSH, or file protocol",
        )

    def test_pull_repo_updates_remote_url_when_different(self):
        """When REPO_URL differs from origin URL, the remote is updated before fetching."""
        mock_args = MagicMock()
        mock_args.url = "https://github.com/new-org/repo.git"
        mock_args.branch = "main"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/old-org/repo.git"
            ref = MagicMock()
            ref.name = "origin/main"
            mock_git_repo.remotes.origin.refs = [ref]
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        assert mock_git_repo.remotes.origin.method_calls[:2] == [
            call.set_url("https://github.com/new-org/repo.git"),
            call.fetch(prune=True),
        ]

    def test_pull_repo_branch_not_found_calls_exception(self):
        """When the configured branch does not exist on the remote, GitBranchNotFound is reported."""
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "missing-branch"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            ref = MagicMock()
            ref.name = "origin/master"
            mock_git_repo.remotes.origin.refs = [ref]
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called_with("GitBranchNotFound", "missing-branch")

    def test_pull_repo_git_command_error_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            mock_git_repo.remotes.origin.fetch.side_effect = git_exc.GitCommandError("fetch", 1)
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()

    def test_pull_repo_generic_error_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            mock_git_repo.remotes.origin.fetch.side_effect = RuntimeError("network error")
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()


class TestCloneRepo:
    """Tests for DTLRepo.clone_repo(): successful clone and git error handling."""

    def test_clone_repo_git_error_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=False),
            patch("core.repo.Repo") as MockRepo,
        ):
            MockRepo.clone_from.side_effect = git_exc.GitCommandError("clone", 128)
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()

    def test_clone_repo_generic_error_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=False),
            patch("core.repo.Repo") as MockRepo,
        ):
            MockRepo.clone_from.side_effect = RuntimeError("failed")
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()


class TestGetDevices:
    """Tests for DTLRepo.get_devices(): vendor filtering, YAML file discovery, and testing folder exclusion."""

    def _make_repo(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            ref = MagicMock()
            ref.name = "origin/master"
            mock_git_repo.remotes.origin.refs = [ref]
            MockRepo.return_value = mock_git_repo
            repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)
        return repo

    def test_get_devices_all_vendors(self):
        repo = self._make_repo()
        with (
            patch("os.listdir", return_value=["Cisco", "Juniper"]),
            patch("core.repo.glob", return_value=[]),
        ):
            files, vendors = repo.get_devices("/base/path")
        assert len(vendors) == 2
        assert any(v["name"] == "Cisco" for v in vendors)

    def test_get_devices_filters_vendors(self):
        repo = self._make_repo()
        with (
            patch("os.listdir", return_value=["Cisco", "Juniper"]),
            patch("core.repo.glob", return_value=[]),
        ):
            files, vendors = repo.get_devices("/base/path", vendors=["cisco"])
        assert len(vendors) == 1
        assert vendors[0]["name"] == "Cisco"

    def test_get_devices_skips_testing_folder(self):
        repo = self._make_repo()
        with (
            patch("os.listdir", return_value=["Cisco", "testing"]),
            patch("core.repo.glob", return_value=[]),
        ):
            files, vendors = repo.get_devices("/base/path")
        assert not any(v["name"] == "testing" for v in vendors)


class TestParseFilesExtended:
    """Tests for DTLRepo.parse_files(): parallel parsing, slug filtering, error handling, and progress iteration."""

    def _make_repo(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with (
            patch("os.path.isdir", return_value=True),
            patch("core.repo.Repo") as MockRepo,
        ):
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            ref = MagicMock()
            ref.name = "origin/master"
            mock_git_repo.remotes.origin.refs = [ref]
            MockRepo.return_value = mock_git_repo
            repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)
        return repo, mock_handle

    def test_error_files_logged_and_skipped(self):
        repo, mock_handle = self._make_repo()
        bad_yaml = "---\n: invalid: [yaml: !!!"
        with patch("builtins.open", mock_open(read_data=bad_yaml)):
            results = repo.parse_files(["/tmp/repo/cisco/bad.yaml"])
        assert results == []
        mock_handle.verbose_log.assert_called()

    def test_progress_iterable_consumed(self):
        repo, _ = self._make_repo()
        yaml_content = "manufacturer: Cisco\nmodel: Switch\nslug: switch\n"
        it = iter([None])
        with patch("builtins.open", mock_open(read_data=yaml_content)):
            repo.parse_files(["/tmp/repo/cisco/switch.yaml"], progress=it)
        with pytest.raises(StopIteration):
            next(it)


def test_slug_format():
    # We need to mock settings because DTLRepo might use it or be used by it,
    # but here we are just testing a method.
    # However, creating DTLRepo instance requires args, repo_path, handler.

    mock_args = MagicMock()
    mock_args.url = "http://example.com"
    mock_args.branch = "master"

    mock_handle = MagicMock()

    # We mock 'os.path.isdir' to avoid git operations in __init__
    with patch("os.path.isdir", return_value=True), patch("core.repo.Repo"):
        repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)

        assert repo.slug_format("Cisco Systems") == "cisco-systems"
        assert repo.slug_format("HP Enterprise") == "hp-enterprise"
        assert repo.slug_format("Juniper") == "juniper"


def test_parse_files():
    mock_args = MagicMock()
    mock_args.url = "http://example.com"
    mock_args.branch = "master"
    mock_handle = MagicMock()

    with patch("os.path.isdir", return_value=True), patch("core.repo.Repo"):
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


def test_parse_files_missing_slug_does_not_crash():
    mock_args = MagicMock()
    mock_args.url = "http://example.com"
    mock_args.branch = "master"
    mock_handle = MagicMock()

    with patch("os.path.isdir", return_value=True), patch("core.repo.Repo"):
        repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)

        yaml_content = """
manufacturer: Cisco
model: AP4431-Module
"""
        with patch("builtins.open", mock_open(read_data=yaml_content)):
            files = ["/tmp/repo/cisco/module.yaml"]

            # Missing slug should still allow matching by model text
            results_filtered = repo.parse_files(files, slugs=["ap4431"])
            assert len(results_filtered) == 1

            # Non-matching filter should skip without raising KeyError
            results_filtered_out = repo.parse_files(files, slugs=["juniper"])
            assert len(results_filtered_out) == 0


# ---------------------------------------------------------------------------
# normalize_port_mappings tests
# ---------------------------------------------------------------------------


class TestNormalizePortMappings:
    """Tests for normalize_port_mappings."""

    # ── Old inline format ────────────────────────────────────────────────

    def test_inline_single_mapping(self):
        """Old inline rear_port/rear_port_position is converted to _mappings."""
        data = {
            "front-ports": [
                {
                    "name": "FP1",
                    "type": "8p8c",
                    "rear_port": "RP1",
                    "rear_port_position": 2,
                }
            ],
            "rear-ports": [{"name": "RP1"}],
        }
        err = normalize_port_mappings(data)
        assert err is None
        fp = data["front-ports"][0]
        assert "rear_port" not in fp
        assert "rear_port_position" not in fp
        assert fp["_mappings"] == [{"rear_port": "RP1", "front_port_position": 1, "rear_port_position": 2}]

    def test_inline_default_rear_port_position(self):
        """rear_port_position defaults to 1 when omitted."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c", "rear_port": "RP1"}],
            "rear-ports": [{"name": "RP1"}],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert data["front-ports"][0]["_mappings"] == [
            {"rear_port": "RP1", "front_port_position": 1, "rear_port_position": 1}
        ]

    def test_inline_multiple_front_ports(self):
        """Each inline front port gets its own _mappings list."""
        data = {
            "front-ports": [
                {"name": "FP1", "type": "8p8c", "rear_port": "RP1"},
                {"name": "FP2", "type": "8p8c", "rear_port": "RP2"},
            ],
            "rear-ports": [{"name": "RP1"}, {"name": "RP2"}],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert data["front-ports"][0]["_mappings"][0]["rear_port"] == "RP1"
        assert data["front-ports"][1]["_mappings"][0]["rear_port"] == "RP2"

    def test_no_front_ports_noop(self):
        """No front-ports and no port-mappings stanza returns None and doesn't modify data."""
        data = {"interfaces": [{"name": "eth0"}]}
        err = normalize_port_mappings(data)
        assert err is None
        assert "interfaces" in data

    def test_front_ports_without_rear_port_key_noop(self):
        """Front ports without rear_port inline key are left unchanged."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c"}],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert "_mappings" not in data["front-ports"][0]

    # ── New port-mappings stanza ─────────────────────────────────────────

    def test_stanza_single_mapping(self):
        """New port-mappings stanza is converted to _mappings on front port."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c"}],
            "rear-ports": [{"name": "RP1"}],
            "port-mappings": [{"front_port": "FP1", "rear_port": "RP1"}],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert "port-mappings" not in data
        assert data["front-ports"][0]["_mappings"] == [
            {"rear_port": "RP1", "front_port_position": 1, "rear_port_position": 1}
        ]

    def test_stanza_explicit_positions(self):
        """Explicit front_port_position and rear_port_position are preserved."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c"}],
            "rear-ports": [{"name": "RP1", "positions": 4}],
            "port-mappings": [
                {
                    "front_port": "FP1",
                    "rear_port": "RP1",
                    "front_port_position": 2,
                    "rear_port_position": 3,
                }
            ],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert data["front-ports"][0]["_mappings"] == [
            {"rear_port": "RP1", "front_port_position": 2, "rear_port_position": 3}
        ]

    def test_stanza_multi_mapping_one_front_port(self):
        """Multiple port-mappings for the same front port produce a list."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c"}],
            "rear-ports": [{"name": "RP1", "positions": 2}],
            "port-mappings": [
                {
                    "front_port": "FP1",
                    "rear_port": "RP1",
                    "front_port_position": 1,
                    "rear_port_position": 1,
                },
                {
                    "front_port": "FP1",
                    "rear_port": "RP1",
                    "front_port_position": 2,
                    "rear_port_position": 2,
                },
            ],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert sorted(
            data["front-ports"][0]["_mappings"],
            key=lambda m: (m["front_port_position"], m["rear_port_position"]),
        ) == [
            {"rear_port": "RP1", "front_port_position": 1, "rear_port_position": 1},
            {"rear_port": "RP1", "front_port_position": 2, "rear_port_position": 2},
        ]

    def test_stanza_missing_front_port_key_returns_error(self):
        """Missing front_port in a stanza entry returns an error string."""
        data = {
            "front-ports": [{"name": "FP1"}],
            "rear-ports": [{"name": "RP1"}],
            "port-mappings": [{"rear_port": "RP1"}],  # no front_port
        }
        err = normalize_port_mappings(data)
        assert err is not None
        assert err.startswith("Error:")

    def test_stanza_unknown_front_port_returns_error(self):
        """Stanza referencing a front port not in front-ports list returns error."""
        data = {
            "front-ports": [{"name": "FP1"}],
            "rear-ports": [{"name": "RP1"}],
            "port-mappings": [{"front_port": "UNKNOWN", "rear_port": "RP1"}],
        }
        err = normalize_port_mappings(data)
        assert err is not None
        assert "UNKNOWN" in err

    def test_stanza_unknown_rear_port_returns_error(self):
        """Stanza referencing a rear port not in rear-ports list returns error."""
        data = {
            "front-ports": [{"name": "FP1"}],
            "rear-ports": [{"name": "RP1"}],
            "port-mappings": [{"front_port": "FP1", "rear_port": "MISSING"}],
        }
        err = normalize_port_mappings(data)
        assert err is not None
        assert "MISSING" in err

    # ── Conflict detection ───────────────────────────────────────────────

    def test_both_formats_identical_is_accepted(self):
        """Both inline and stanza present with identical content is accepted."""
        data = {
            "front-ports": [
                {
                    "name": "FP1",
                    "type": "8p8c",
                    "rear_port": "RP1",
                    "rear_port_position": 1,
                }
            ],
            "rear-ports": [{"name": "RP1"}],
            "port-mappings": [
                {
                    "front_port": "FP1",
                    "rear_port": "RP1",
                    "front_port_position": 1,
                    "rear_port_position": 1,
                }
            ],
        }
        err = normalize_port_mappings(data)
        assert err is None

    def test_both_formats_conflicting_returns_error(self):
        """Both inline and stanza present with different mappings returns error."""
        data = {
            "front-ports": [
                {
                    "name": "FP1",
                    "type": "8p8c",
                    "rear_port": "RP1",
                    "rear_port_position": 1,
                }
            ],
            "rear-ports": [{"name": "RP1"}, {"name": "RP2"}],
            "port-mappings": [{"front_port": "FP1", "rear_port": "RP2"}],  # different rear port
        }
        err = normalize_port_mappings(data)
        assert err is not None
        assert "conflict" in err.lower() or "Error" in err

    def test_empty_stanza_is_deleted(self):
        """An explicit empty port-mappings list is removed and produces no error."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c"}],
            "rear-ports": [{"name": "RP1"}],
            "port-mappings": [],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert "port-mappings" not in data

    def test_null_stanza_is_deleted(self):
        """An explicit null port-mappings value is removed and produces no error."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c"}],
            "rear-ports": [{"name": "RP1"}],
            "port-mappings": None,
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert "port-mappings" not in data

    def test_empty_stanza_no_front_ports_still_deleted(self):
        """Empty port-mappings stanza with no front-ports is cleaned up (not silently skipped)."""
        data = {
            "port-mappings": [],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert "port-mappings" not in data

    def test_inline_unknown_rear_port_returns_error(self):
        """Inline rear_port reference to unknown rear port returns an error."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c", "rear_port": "MISSING"}],
            "rear-ports": [{"name": "RP1"}],
        }
        err = normalize_port_mappings(data)
        assert err is not None
        assert "MISSING" in err

    def test_inline_no_rear_ports_list_skips_validation(self):
        """Inline rear_port reference is accepted when rear-ports list is absent."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c", "rear_port": "ANY_NAME"}],
        }
        err = normalize_port_mappings(data)
        assert err is None
        assert data["front-ports"][0]["_mappings"][0]["rear_port"] == "ANY_NAME"

    def test_inline_empty_rear_ports_list_validates(self):
        """Inline rear_port reference fails when rear-ports: [] is declared (empty but present)."""
        data = {
            "front-ports": [{"name": "FP1", "type": "8p8c", "rear_port": "MISSING"}],
            "rear-ports": [],
        }
        err = normalize_port_mappings(data)
        assert err is not None
        assert "MISSING" in err

    def test_stanza_empty_rear_ports_list_validates(self):
        """Stanza rear_port reference fails when rear-ports: [] is declared (empty but present)."""
        data = {
            "front-ports": [{"name": "FP1"}],
            "rear-ports": [],
            "port-mappings": [{"front_port": "FP1", "rear_port": "MISSING"}],
        }
        err = normalize_port_mappings(data)
        assert err is not None
        assert "MISSING" in err


# ============================================================
# validate_repo_path tests
# ============================================================


class TestValidateRepoPath:
    """Tests for the validate_repo_path() helper."""

    def test_path_exists_is_file_returns_false(self, tmp_path):
        """Existing path that is a file (not directory) returns False."""
        from core.repo import validate_repo_path

        f = tmp_path / "not_a_dir.txt"
        f.write_text("x")
        ok, msg = validate_repo_path(str(f))
        assert ok is False
        assert "not a directory" in msg

    def test_path_exists_not_writable_returns_false(self, tmp_path):
        """Existing directory without write permission returns False."""
        from core.repo import validate_repo_path

        d = tmp_path / "readonly"
        d.mkdir()
        d.chmod(0o555)
        try:
            ok, msg = validate_repo_path(str(d))
            assert ok is False
            assert "not writable" in msg
        finally:
            d.chmod(0o755)

    def test_parent_not_writable_returns_false(self, tmp_path):
        """Non-existent path whose parent is not writable returns False."""
        from core.repo import validate_repo_path

        parent = tmp_path / "readonly_parent"
        parent.mkdir()
        parent.chmod(0o555)
        target = str(parent / "new_repo")
        try:
            ok, msg = validate_repo_path(target)
            assert ok is False
            assert "not writable" in msg
        finally:
            parent.chmod(0o755)

    def test_valid_new_path_returns_true(self, tmp_path):
        """Non-existent path with writable parent returns True."""
        from core.repo import validate_repo_path

        target = str(tmp_path / "new_repo")
        ok, msg = validate_repo_path(target)
        assert ok is True
        assert msg == ""

    def test_valid_existing_dir_returns_true(self, tmp_path):
        """Existing writable directory returns True."""
        from core.repo import validate_repo_path

        ok, msg = validate_repo_path(str(tmp_path))
        assert ok is True


# ============================================================
# parse_single_file error path tests
# ============================================================


def test_parse_device_type_returns_error_when_normalize_fails(tmp_path):
    """normalize_port_mappings returning an error propagates as return value.

    Covers repo.py lines 225-226: 'if err: return err'.
    """
    from unittest.mock import patch
    from core.repo import parse_single_file

    yaml_file = tmp_path / "test.yaml"
    yaml_file.write_text("manufacturer: Test\nmodel: M1\nslug: m1\n")

    with patch("core.repo.normalize_port_mappings", return_value="Error: invalid mapping"):
        result = parse_single_file(str(yaml_file))
    assert result == "Error: invalid mapping"
