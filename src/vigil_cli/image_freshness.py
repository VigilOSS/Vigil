from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from . import docker

_PROXY_CONTAINER_NAME = "vigil-proxy"
_PROXY_IMAGE = "vigil-proxy:latest"


def image_outdated(image: str, inputs: list[Path], *, runner: docker.Runner) -> bool:
    """True when any build input is newer than the image (or the image is absent).

    Compares the image's ``Created`` timestamp against the latest mtime across the
    Dockerfile / addon sources. A missing image reads as outdated so callers rebuild.
    """
    created = image_created_at(image, runner=runner)
    if created is None:
        return True
    latest_input = latest_mtime(inputs)
    return latest_input is not None and latest_input > created.timestamp()


def image_created_at(image: str, *, runner: docker.Runner) -> datetime | None:
    result = runner(["docker", "image", "inspect", "-f", "{{.Created}}", image])
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    if not value:
        return None
    try:
        return parse_docker_timestamp(value).astimezone(timezone.utc)
    except ValueError:
        return None


def parse_docker_timestamp(value: str) -> datetime:
    normalized = value
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    if "." in normalized:
        prefix, suffix = normalized.split(".", 1)
        tz_index = len(suffix)
        for marker in ("+", "-"):
            index = suffix.find(marker)
            if index != -1:
                tz_index = index
                break
        fraction = suffix[:tz_index]
        timezone_part = suffix[tz_index:]
        normalized = f"{prefix}.{fraction[:6].ljust(6, '0')}{timezone_part}"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def latest_mtime(paths: list[Path]) -> float | None:
    latest: float | None = None
    for path in paths:
        if path.is_file():
            latest = max(latest or 0, path.stat().st_mtime)
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file():
                    latest = max(latest or 0, child.stat().st_mtime)
    return latest


def proxy_image_drift(*, runner: docker.Runner = docker.run_command) -> bool:
    """True when the running ``vigil-proxy`` container predates the current image.

    Compares the container's image id against the ``vigil-proxy:latest`` tag id;
    a mismatch means the tag was rebuilt after the container started, so a
    restart is needed to pick it up. Returns False when either id is unavailable
    (no container / no image), mirroring the runtime's drift check in ``up.py``.
    """
    container_id = docker.container_image_id(_PROXY_CONTAINER_NAME, runner=runner)
    configured_id = docker.image_id(_PROXY_IMAGE, runner=runner)
    return bool(container_id and configured_id and container_id != configured_id)
