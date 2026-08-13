"""Security checks for the Docker build and publish workflow."""

from pathlib import Path

import yaml


_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "docker.yml"


def _jobs():
    """Load the workflow jobs from the repository document."""
    return yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))["jobs"]


def test_pull_request_image_build_has_no_package_write_permission():
    """A pull request can build untrusted code, so its token must be read-only."""
    jobs = _jobs()
    job = jobs["build-images"]

    assert job["if"] == "github.event_name == 'pull_request'"
    assert job["permissions"] == {"contents": "read"}
    build = next(step for step in job["steps"] if step.get("uses", "").startswith("docker/build-push-action@"))
    assert build["with"]["push"] is False


def test_package_publish_job_runs_only_for_trusted_events():
    """Only non-pull-request events may receive package write access and push images."""
    job = _jobs()["publish-images"]

    assert job["if"] == "github.event_name != 'pull_request'"
    assert job["permissions"] == {"contents": "read", "packages": "write"}
    login = next(step for step in job["steps"] if step.get("uses", "").startswith("docker/login-action@"))
    assert "if" not in login
    build = next(step for step in job["steps"] if step.get("uses", "").startswith("docker/build-push-action@"))
    assert build["with"]["push"] is True
