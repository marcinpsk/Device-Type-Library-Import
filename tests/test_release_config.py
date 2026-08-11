"""Checks that the release configuration agrees with the CI that enforces it."""

import pathlib
import tomllib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"
_PR_TITLE_WORKFLOW = _ROOT / ".github" / "workflows" / "pr-title.yml"


def _allowed_tags():
    """Return the commit types semantic-release parses, from pyproject.toml."""
    config = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return config["tool"]["semantic_release"]["commit_parser_options"]["allowed_tags"]


def _pr_title_types():
    """Return the commit types the PR-title check accepts, from the workflow."""
    workflow = yaml.safe_load(_PR_TITLE_WORKFLOW.read_text(encoding="utf-8"))
    step = workflow["jobs"]["conventional-commits"]["steps"][0]
    return step["with"]["types"].split()


def test_pr_title_types_match_the_release_parser():
    """A type accepted by one and not the other silently skips or blocks a release.

    A squash merge takes the PR title as the commit subject, so a type the workflow
    allows but the parser rejects lands on main as an unparseable subject.
    """
    assert sorted(_pr_title_types()) == sorted(_allowed_tags())
