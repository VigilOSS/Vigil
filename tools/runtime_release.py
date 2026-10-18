#!/usr/bin/env python3
"""Build and assemble release-pinned Vigil runtime images."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Callable, Sequence

from vigil_cli.image_freshness import IMAGE_INPUTS_LABEL
from vigil_cli.runtime import _runtime_build_context, runtime_inputs_digest
from vigil_cli.runtime_images import PIN_PATH, release_image_pin


IMAGE = "ghcr.io/vigiloss/vigil-runtime"
SOURCE = "https://github.com/VigilOSS/Vigil"
LICENSE = "Apache-2.0"
PLATFORM_SUFFIXES = {
    "linux/amd64": "amd64",
    "linux/arm64": "arm64",
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_RELEASE_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
Runner = Callable[..., Any]


def _validate_identity(release_tag: str, revision: str) -> None:
    if not _RELEASE_TAG.fullmatch(release_tag):
        raise SystemExit(f"Invalid release tag: {release_tag}")
    if not _REVISION.fullmatch(revision):
        raise SystemExit("Release revision must be a lowercase 40-character Git object ID")


def platform_build_command(
    *,
    context: Path,
    release_tag: str,
    platform: str,
    suffix: str,
    inputs_digest: str,
    revision: str,
) -> list[str]:
    """Return the exact native-platform registry build command."""
    _validate_identity(release_tag, revision)
    expected_suffix = PLATFORM_SUFFIXES.get(platform)
    if expected_suffix is None or suffix != expected_suffix:
        raise SystemExit(f"Unsupported release platform/suffix: {platform}/{suffix}")
    if not re.fullmatch(r"[0-9a-f]{64}", inputs_digest):
        raise SystemExit("Runtime inputs digest must be lowercase SHA256")
    return [
        "docker",
        "buildx",
        "build",
        "--platform",
        platform,
        "--push",
        "--provenance=mode=max",
        "--sbom=true",
        "--label",
        f"{IMAGE_INPUTS_LABEL}={inputs_digest}",
        "--label",
        f"org.opencontainers.image.source={SOURCE}",
        "--label",
        f"org.opencontainers.image.revision={revision}",
        "--label",
        f"org.opencontainers.image.version={release_tag}",
        "--label",
        f"org.opencontainers.image.licenses={LICENSE}",
        "--tag",
        f"{IMAGE}:{release_tag}-{suffix}",
        "--file",
        str(context / "agent/docker/runtime-full/Dockerfile"),
        str(context),
    ]


def build_platform(
    root: Path,
    *,
    release_tag: str,
    platform: str,
    suffix: str,
    revision: str,
    runner: Runner = subprocess.run,
) -> None:
    digest = runtime_inputs_digest(root)
    with _runtime_build_context(root, variant="full") as context:
        runner(
            platform_build_command(
                context=context,
                release_tag=release_tag,
                platform=platform,
                suffix=suffix,
                inputs_digest=digest,
                revision=revision,
            ),
            check=True,
        )


def _manifest_platforms(manifest: dict[str, Any]) -> set[str]:
    platforms: set[str] = set()
    for descriptor in manifest.get("manifests", []):
        platform = descriptor.get("platform", {})
        operating_system = platform.get("os")
        architecture = platform.get("architecture")
        if isinstance(operating_system, str) and isinstance(architecture, str):
            platforms.add(f"{operating_system}/{architecture}")
    return platforms


def _write_pin(root: Path, payload: dict[str, Any]) -> None:
    destination = root / PIN_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=destination.parent, delete=False
    ) as stream:
        temporary = Path(stream.name)
        json.dump(payload, stream, indent=2)
        stream.write("\n")
    try:
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def publish_index(
    root: Path,
    *,
    release_tag: str,
    revision: str,
    runner: Runner = subprocess.run,
) -> str:
    """Create the release index, validate both platforms, and write its pin."""
    _validate_identity(release_tag, revision)
    target = f"{IMAGE}:{release_tag}"
    sources = [f"{IMAGE}:{release_tag}-{suffix}" for suffix in PLATFORM_SUFFIXES.values()]
    annotations = {
        "org.opencontainers.image.source": SOURCE,
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.version": release_tag,
        "org.opencontainers.image.licenses": LICENSE,
    }
    create = ["docker", "buildx", "imagetools", "create", "--tag", target]
    for name, value in annotations.items():
        create.extend(["--annotation", f"index:{name}={value}"])
    runner([*create, *sources], check=True)
    inspected = runner(
        [
            "docker",
            "buildx",
            "imagetools",
            "inspect",
            target,
            "--format",
            "{{json .Manifest}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        manifest = json.loads(inspected.stdout)
    except (AttributeError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit("Published runtime index did not return valid manifest metadata") from exc
    digest = manifest.get("digest")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise SystemExit("Published runtime index did not return an immutable digest")
    platforms = _manifest_platforms(manifest)
    required = set(PLATFORM_SUFFIXES)
    if not required <= platforms:
        missing = ", ".join(sorted(required - platforms))
        raise SystemExit(f"Published runtime index is missing required platforms: {missing}")
    reference = f"{IMAGE}@{digest}"
    _write_pin(
        root,
        {
            "schema_version": 1,
            "reference": reference,
            "inputs_digest": runtime_inputs_digest(root),
            "platforms": list(PLATFORM_SUFFIXES),
        },
    )
    release_image_pin(root)
    return reference


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    build = subparsers.add_parser("build-platform")
    build.add_argument("--release-tag", required=True)
    build.add_argument("--platform", required=True, choices=tuple(PLATFORM_SUFFIXES))
    build.add_argument("--suffix", required=True, choices=tuple(PLATFORM_SUFFIXES.values()))
    build.add_argument("--revision", required=True)
    publish = subparsers.add_parser("publish-index")
    publish.add_argument("--release-tag", required=True)
    publish.add_argument("--revision", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path.cwd()
    if args.action == "build-platform":
        build_platform(
            root,
            release_tag=args.release_tag,
            platform=args.platform,
            suffix=args.suffix,
            revision=args.revision,
        )
    else:
        print(
            publish_index(
                root,
                release_tag=args.release_tag,
                revision=args.revision,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
