from unittest.mock import MagicMock, mock_open, patch
from git import exc as git_exc
from core.repo import DTLRepo, validate_git_url


class TestValidateGitUrl:
    """Tests for TestValidateGitUrl."""

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
    """Tests for TestDTLRepoInit."""

    def _make_repo(self, isdir=True, mock_repo=None):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=isdir), patch("core.repo.Repo") as MockRepo:
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
        with patch("os.path.isdir", return_value=True), patch("core.repo.Repo") as MockRepo:
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_git_repo.remotes.origin.pull.assert_called_once()

    def test_clones_when_dir_missing(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=False), patch("core.repo.Repo") as MockRepo:
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
            "InvalidGitURL", "ftp://bad.url", "URL must use HTTPS, SSH, or file protocol"
        )


class TestDTLRepoPathMethods:
    """Tests for TestDTLRepoPathMethods."""

    def _make_repo(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=True), patch("core.repo.Repo") as MockRepo:
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
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
    """Tests for TestPullRepo."""

    def test_pull_repo_invalid_origin_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=True), patch("core.repo.Repo") as MockRepo:
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "ftp://bad"
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()

    def test_pull_repo_git_command_error_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=True), patch("core.repo.Repo") as MockRepo:
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            mock_git_repo.remotes.origin.pull.side_effect = git_exc.GitCommandError("pull", 1)
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()

    def test_pull_repo_generic_error_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=True), patch("core.repo.Repo") as MockRepo:
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            mock_git_repo.remotes.origin.pull.side_effect = RuntimeError("network error")
            MockRepo.return_value = mock_git_repo
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()


class TestCloneRepo:
    """Tests for TestCloneRepo."""

    def test_clone_repo_git_error_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=False), patch("core.repo.Repo") as MockRepo:
            MockRepo.clone_from.side_effect = git_exc.GitCommandError("clone", 128)
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()

    def test_clone_repo_generic_error_calls_exception(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=False), patch("core.repo.Repo") as MockRepo:
            MockRepo.clone_from.side_effect = RuntimeError("failed")
            DTLRepo(mock_args, "/tmp/repo", mock_handle)
        mock_handle.exception.assert_called()


class TestGetDevices:
    """Tests for TestGetDevices."""

    def _make_repo(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=True), patch("core.repo.Repo") as MockRepo:
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
            MockRepo.return_value = mock_git_repo
            repo = DTLRepo(mock_args, "/tmp/repo", mock_handle)
        return repo

    def test_get_devices_all_vendors(self):
        repo = self._make_repo()
        with patch("os.listdir", return_value=["Cisco", "Juniper"]), patch("glob.glob", return_value=[]):
            files, vendors = repo.get_devices("/base/path")
        assert len(vendors) == 2
        assert any(v["name"] == "Cisco" for v in vendors)

    def test_get_devices_filters_vendors(self):
        repo = self._make_repo()
        with patch("os.listdir", return_value=["Cisco", "Juniper"]), patch("glob.glob", return_value=[]):
            files, vendors = repo.get_devices("/base/path", vendors=["cisco"])
        assert len(vendors) == 1
        assert vendors[0]["name"] == "Cisco"

    def test_get_devices_skips_testing_folder(self):
        repo = self._make_repo()
        with patch("os.listdir", return_value=["Cisco", "testing"]), patch("glob.glob", return_value=[]):
            files, vendors = repo.get_devices("/base/path")
        assert not any(v["name"] == "testing" for v in vendors)


class TestParseFilesExtended:
    """Tests for TestParseFilesExtended."""

    def _make_repo(self):
        mock_args = MagicMock()
        mock_args.url = "https://github.com/org/repo.git"
        mock_args.branch = "master"
        mock_handle = MagicMock()
        with patch("os.path.isdir", return_value=True), patch("core.repo.Repo") as MockRepo:
            mock_git_repo = MagicMock()
            mock_git_repo.remotes.origin.url = "https://github.com/org/repo.git"
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
        with patch("builtins.open", mock_open(read_data=yaml_content)):
            repo.parse_files(["/tmp/repo/cisco/switch.yaml"], progress=iter([None]))


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
