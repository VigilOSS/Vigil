"""vigil assess code-ingest — walk a repo, fingerprint files, POST to code analysis backend."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from assess.lib.client import AssessmentClient, AssessError, require_write_result
from assess.lib.code_languages import detect_language
from assess.lib.code_snapshot import (
    RootedSourceTree,
    SnapshotBuilder,
    SourceSnapshotRaceError,
    capture_regular_file,
    validate_repo_key,
)
from assess.lib.config import load_config
from assess.lib.trusted_exec import (
    git_command,
    trusted_environment,
)
from assess.lib.trusted_exec import (
    resolve_trusted_tool as _resolve_trusted_tool,
)

_capture_regular_file = capture_regular_file


SKIP_DIRS = frozenset({
    '.git', '.svn', '.hg', '__pycache__', 'node_modules', '.tox',
    'venv', '.venv', 'env', '.env', 'dist', 'build', 'target',
    'vendor', '.next', '.nuxt', '.expo', '.gradle', '.idea',
    '.vscode', '.vs', 'coverage', '.nyc_output',
})

SKIP_EXTENSIONS = frozenset({
    '.pyc', '.pyo', '.o', '.so', '.a', '.dylib', '.exe', '.dll', '.lib',
    '.jar', '.class', '.dex', '.war', '.ear',
    '.min.js', '.bundle.js', '.min.css', '.bundle.css', '.map',
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.bmp', '.webp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
    '.sqlite', '.sqlite3', '.db',
})

BUILD_ARTIFACT_DIRS = frozenset({'dist', 'build', '.next', '.nuxt'})

# Generated symbol/cross-reference indexes. They carry no extension, so the
# extension denylist never sees them, and a multi-megabyte ctags file admitted
# as source poisons every grep and every LOC-based percentage downstream.
SKIP_BASENAMES = frozenset({
    'tags', 'TAGS', 'cscope.out', 'cscope.in.out', 'cscope.po.out',
    'GPATH', 'GRTAGS', 'GTAGS', 'ID',
})

# Policy presets shape which build-output directories count as generated.
# `package` is for a shipped-bundle repo where dist/ IS the executed bytes;
# node_modules stays excluded either way because it is someone else's code.
POLICY_PRESETS = ('application', 'package')
_PACKAGE_PRESET_ADMITTED_DIRS = frozenset({'dist', 'build', '.next', '.nuxt'})

DEFAULT_MAX_INCLUDED_SKIPPED_BYTES = 2_000_000

# A collapsed admitted/total ratio is warned about, never refused: a
# legitimately doc-heavy monorepo hits the same ratio, and a hard refusal on
# the first Phase 0 command is worse than a loud one.
_COLLAPSED_ADMISSION_RATIO = 0.25
_COLLAPSED_ADMISSION_MIN_SKIPPED = 100


_C_EXTENSIONS = frozenset({'.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh'})
_PYTHON_EXTENSIONS = frozenset({'.py', '.pyx', '.pyi'})
_JS_TS_EXTENSIONS = frozenset({'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'})
_GIT_LOG_TIMEOUT_SECONDS = 120
_GIT_REV_LIST_TIMEOUT_SECONDS = 30
_GIT_LARGE_HISTORY_COMMIT_THRESHOLD = 50_000
_GIT_SECURITY_LOOKBACK = '3years'
_GIT_CHURN_LOOKBACK = '1year'
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def _refresh_receipt_error(operation: str, fields: str) -> AssessError:
    return AssessError(
        f"{operation}: backend response did not identify the durable result "
        f"({fields}); the write may have committed, so inspect the canonical "
        "code repository state and do not retry automatically"
    )


def _require_refresh_start_receipt(response: object) -> tuple[int, str]:
    if not isinstance(response, dict):
        raise _refresh_receipt_error(
            "start code repository refresh", "response object"
        )
    repo_id = response.get("repo_id")
    refresh_token = response.get("refresh_token")
    invalid: list[str] = []
    if not isinstance(repo_id, int) or isinstance(repo_id, bool) or repo_id < 1:
        invalid.append("repo_id")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        invalid.append("refresh_token")
    if invalid:
        raise _refresh_receipt_error(
            "start code repository refresh", ", ".join(invalid)
        )
    return repo_id, refresh_token


def _require_refresh_commit_receipt(
    response: object, *, requested_repo_id: int
) -> tuple[int, str]:
    if not isinstance(response, dict):
        raise _refresh_receipt_error(
            "commit code repository refresh", "response object"
        )
    returned_repo_id = response.get("repo_id")
    repo_generation = response.get("repo_generation")
    source_manifest_digest = response.get("source_manifest_digest")
    invalid: list[str] = []
    if (
        not isinstance(returned_repo_id, int)
        or isinstance(returned_repo_id, bool)
        or returned_repo_id != requested_repo_id
    ):
        invalid.append("repo_id")
    if (
        not isinstance(repo_generation, int)
        or isinstance(repo_generation, bool)
        or repo_generation < 1
    ):
        invalid.append("repo_generation")
    if (
        not isinstance(source_manifest_digest, str)
        or _SHA256_PATTERN.fullmatch(source_manifest_digest) is None
    ):
        invalid.append("source_manifest_digest")
    if invalid:
        raise _refresh_receipt_error(
            "commit code repository refresh", ", ".join(invalid)
        )
    return repo_generation, source_manifest_digest


def _which(binary: str, *, source_root: str | os.PathLike[str] | None = None) -> str | None:
    """Compatibility wrapper around repository-safe absolute tool lookup."""
    return _resolve_trusted_tool(binary, source_root=source_root or os.getcwd())


def _setup_ctags(
    repo_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    selected_files: list[dict[str, str]],
    *,
    repo_generation: int,
    source_manifest_digest: str,
) -> dict[str, object]:
    """Generate a generation-bound ctags index outside the sealed source."""
    source_root = Path(repo_path).resolve()
    bound_output = Path(output_dir).resolve()
    config: dict[str, object] = {
        'available': False,
        'tags_path': '',
        'universal': False,
        'repo_generation': int(repo_generation),
        'source_manifest_digest': source_manifest_digest,
    }

    ctags_path = _resolve_trusted_tool('ctags', source_root=source_root)
    if not ctags_path:
        print("  ctags: not found", file=sys.stderr)
        return config

    try:
        bound_output.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise ValueError("ctags output must be outside the sealed source tree")

    environment = trusted_environment(source_root=source_root)
    explicit_files: list[str] = []
    with RootedSourceTree(source_root) as source_tree:
        for binding in selected_files:
            rel_path = str(binding.get("file_path") or "")
            try:
                captured = source_tree.capture(rel_path, retain_spool=False)
            except (OSError, ValueError) as exc:
                raise ValueError(f"unsafe ctags source path: {rel_path!r}") from exc
            if captured.sha256 != binding.get("source_sha256"):
                raise ValueError(f"ctags source hash mismatch: {rel_path}")
            explicit_files.append(f"./{rel_path}")
        source_tree.verify_root_identity()

    # Detect Universal vs BSD ctags
    try:
        version_result = subprocess.run(
            [ctags_path, '--options=NONE', '--version'],
            capture_output=True,
            text=True,
            timeout=5,
            env=environment,
            cwd=str(source_root),
            check=False,
        )
        is_universal = version_result.returncode == 0 and (
            'Universal' in version_result.stdout or 'Universal' in version_result.stderr
        )
    except (subprocess.TimeoutExpired, OSError):
        is_universal = False

    config['universal'] = is_universal
    if not is_universal:
        print(
            "  ctags: unavailable (only Universal Ctags with --options=NONE is trusted)",
            file=sys.stderr,
        )
        return config
    if not explicit_files:
        print("  ctags: no manifest-selected files", file=sys.stderr)
        return config
    bound_output.mkdir(parents=True, exist_ok=True)
    tags_path = bound_output / 'tags'
    temp_fd, temp_name = tempfile.mkstemp(prefix='.tags-', suffix='.tmp', dir=bound_output)
    os.close(temp_fd)
    temp_tags_path = Path(temp_name)

    try:
        result = subprocess.run(
            [
                ctags_path,
                '--options=NONE',
                '--fields=+S+K+n',
                '--extras=+q',
                '--output-format=e-ctags',
                '-f', str(temp_tags_path),
                *explicit_files,
            ],
            capture_output=True,
            timeout=120,
            env=environment,
            cwd=str(source_root),
            check=False,
        )

        if result.returncode == 0 and temp_tags_path.is_file() and not temp_tags_path.is_symlink():
            os.chmod(temp_tags_path, 0o444)
            os.replace(temp_tags_path, tags_path)
            with tags_path.open('r', encoding='utf-8', errors='replace') as f:
                tag_count = sum(1 for line in f if not line.startswith('!'))
            config['available'] = True
            config['tags_path'] = str(tags_path)
            print(f"  ctags: {tag_count} tags generated (Universal)")
        else:
            print("  ctags: generation failed", file=sys.stderr)

    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  ctags: error: {e}", file=sys.stderr)
    finally:
        try:
            temp_tags_path.unlink()
        except FileNotFoundError:
            pass

    return config


def register(subparsers) -> None:
    p = subparsers.add_parser("code-ingest", help="Ingest a code repository for analysis")
    p.add_argument("repo_path", help="Path to the repository root")
    p.add_argument("--name", default=None, help="Repository name (default: directory basename)")
    p.add_argument("--language", default=None, help="Override repository primary language (does NOT auto-tag unknown files; use --default-language-for-unknown for that)")
    p.add_argument(
        "--default-language-for-unknown",
        default=None,
        help="Explicit language to stamp on files whose extension is unrecognized. "
             "Opt-in replacement for the old --language fallback behavior. Use sparingly: "
             "stamping unknown files with a wrong language pollutes coverage math and "
             "structural indexing.",
    )
    p.add_argument("--repo-key", default=None, help="Explicit repository key (default: stable name+path hash)")
    p.add_argument(
        "--include-minified",
        action="store_true",
        help="Include .min.js/.bundle.js and .min.css/.bundle.css files instead of only listing them in the skipped manifest.",
    )
    p.add_argument(
        "--include-skipped",
        action="store_true",
        help=(
            "Include otherwise skipped generated/binary-extension files when they are encountered. "
            "Skipped directories still require --include-path or build-artifact/minified handling."
        ),
    )
    p.add_argument(
        "--include-path",
        action="append",
        default=[],
        help=(
            "Glob matched against the full relative FILE path, to include even if normally "
            "skipped; repeatable (e.g. '**/ResetPassword.min.js'). A bare directory is not an "
            "implicit glob \u2014 'dist' is auto-expanded to 'dist/**' and a pattern that matches "
            "nothing is reported."
        ),
    )
    p.add_argument(
        "--policy-preset",
        choices=POLICY_PRESETS,
        default="application",
        help=(
            "Skip policy for this ingest. 'application' (default) treats dist/build/.next/.nuxt "
            "as generated output; 'package' admits them because a shipped-bundle repo's dist/ IS "
            "the executed bytes. node_modules stays excluded under both."
        ),
    )
    p.add_argument(
        "--max-included-skipped-bytes",
        type=int,
        default=DEFAULT_MAX_INCLUDED_SKIPPED_BYTES,
        help=f"Maximum size for an explicitly included skipped artifact (default {DEFAULT_MAX_INCLUDED_SKIPPED_BYTES}).",
    )
    p.add_argument(
        "--skipped-manifest",
        default=None,
        help=(
            "Optional skipped-artifact projection root (default: "
            "tools/analysis-state/skipped-artifacts/<repo-id>/<generation>/)."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compare the scanned manifest with the active backend generation without staging or committing it.",
    )
    p.set_defaults(func=run)


def _max_included_skipped_bytes(args) -> int:
    return int(
        getattr(args, "max_included_skipped_bytes", DEFAULT_MAX_INCLUDED_SKIPPED_BYTES)
    )


def _effective_skip_dirs(args) -> frozenset[str]:
    """Return the directory denylist this invocation ingests against.

    Presets are threaded through the callers rather than mutating the
    module-level frozensets: `code_index` imports `SKIP_DIRS`/`_should_skip_file`
    and re-walks with them, and its view of the policy must not shift under it.
    """
    if getattr(args, "policy_preset", "application") == "package":
        return SKIP_DIRS - _PACKAGE_PRESET_ADMITTED_DIRS
    return SKIP_DIRS


def _skip_file_reason(
    rel_path: str, filename: str, skip_dirs: frozenset[str] = SKIP_DIRS
) -> str | None:
    """Return the skip reason for a file, or None if it is normally ingestible."""
    if filename in SKIP_BASENAMES:
        return f'skipped_basename:{filename}'
    ext = Path(filename).suffix.lower()
    if ext in SKIP_EXTENSIONS:
        if ext in {'.min.js', '.bundle.js', '.min.css', '.bundle.css'}:
            return 'minified_or_bundle'
        if ext == '.map':
            return 'source_map'
        return f'skipped_extension:{ext}'
    # Check for compound extensions like .min.js, .bundle.js
    lower_name = filename.lower()
    if lower_name.endswith(('.min.js', '.bundle.js', '.min.css', '.bundle.css')):
        return 'minified_or_bundle'
    # Check for .woff variants
    if lower_name.endswith(('.woff', '.woff2')):
        return 'skipped_extension:font'
    for part in PurePosixPath(rel_path.replace(os.sep, "/")).parts[:-1]:
        if part in skip_dirs:
            return f"skipped_dir:{part}"
    return None


def _should_skip_file(rel_path: str, filename: str) -> bool:
    """Return True if the file is normally skipped.

    Kept as the boolean compatibility helper for code_index; code_ingest uses
    _skip_file_reason when it needs auditable skip details.
    """
    return _skip_file_reason(rel_path, filename) is not None


def _pattern_matches(normalized: str, pattern: str) -> bool:
    return fnmatch.fnmatch(normalized, pattern) or (
        pattern.startswith("**/")
        and fnmatch.fnmatch(normalized, pattern.removeprefix("**/"))
    )


def _include_path_matches(rel_path: str, patterns: list[str] | None) -> list[str]:
    """Every supplied pattern this path satisfies, not just the first."""
    normalized = rel_path.replace(os.sep, '/')
    return [pattern for pattern in patterns or [] if _pattern_matches(normalized, pattern)]


def _include_path_match(rel_path: str, patterns: list[str] | None) -> str | None:
    matches = _include_path_matches(rel_path, patterns)
    return matches[0] if matches else None


def _expand_directory_include_patterns(repo_path: str, args) -> None:
    """Turn a metacharacter-free `--include-path` directory into a real glob.

    `--include-path` is documented as a glob and matched against the full
    relative FILE path, so a bare directory can never match anything — while
    the walker still descends into it. Expand only a pattern that names a real
    directory and carries no glob metacharacter, so an invocation that already
    works cannot widen.
    """
    patterns = list(getattr(args, "include_path", []) or [])
    if not patterns:
        return
    expanded: list[str] = []
    for pattern in patterns:
        candidate = pattern.rstrip('/')
        if (
            candidate
            and not any(char in candidate for char in '*?[')
            and os.path.isdir(os.path.join(repo_path, candidate))
        ):
            replacement = f"{candidate}/**"
            print(
                f"code-ingest: --include-path '{pattern}' names a directory; "
                f"expanded to '{replacement}'.",
                file=sys.stderr,
            )
            expanded.append(replacement)
            continue
        expanded.append(pattern)
    args.include_path = expanded


def _size_capped_include_patterns(records: list[dict[str, object]]) -> set[str]:
    """Patterns that DID match, but whose file exceeded the include size cap.

    Reporting those as "matched 0 files" would send the operator after a glob
    bug that is not there; the real remedy is --max-included-skipped-bytes.
    """
    capped: set[str] = set()
    for record in records:
        reason = str(record.get("reason", ""))
        marker = "include requested by include_path:"
        if marker not in reason:
            continue
        remainder = reason.split(marker, 1)[1]
        capped.add(remainder.split(" but ", 1)[0])
    return capped


def _report_unmatched_include_patterns(
    matched: set[str], capped: set[str], args
) -> bool:
    """Warn per pattern that admitted nothing.

    Returns True when EVERY supplied pattern matched nothing — the run did not
    do what was asked, so the caller refuses rather than committing a
    generation that silently omits all of it.
    """
    patterns = list(getattr(args, "include_path", []) or [])
    if not patterns:
        return False
    for pattern in patterns:
        if pattern in capped and pattern not in matched:
            print(
                f"code-ingest: --include-path '{pattern}' matched a file that "
                "exceeds --max-included-skipped-bytes; it is recorded in the "
                "exclusion manifest, not ingested.",
                file=sys.stderr,
            )
    unmatched = [
        pattern
        for pattern in patterns
        if pattern not in matched and pattern not in capped
    ]
    for pattern in unmatched:
        message = f"code-ingest: --include-path '{pattern}' matched 0 files."
        if not any(char in pattern for char in '*?['):
            bare = pattern.rstrip('/')
            message += (
                " Directory patterns are not implicit globs — use "
                f"'{bare}/**' or '**/{bare}/*'."
            )
        print(message, file=sys.stderr)
    ineffective = [pattern for pattern in patterns if pattern not in matched]
    if len(ineffective) != len(patterns):
        return False
    print(
        "code-ingest: no --include-path pattern admitted a single file; refusing "
        "to commit a generation that omits everything you asked to include.",
        file=sys.stderr,
    )
    return True


def _skip_reason_census(records: list[dict[str, object]]) -> list[tuple[str, int]]:
    """Per-reason skipped-file census, most-discarded first.

    Directory records are excluded: each skipped directory is also enumerated
    file-by-file, so counting both would double-count the same bytes.
    """
    counts: dict[str, int] = {}
    for record in records:
        if record.get("kind") == "directory":
            continue
        reason = str(record.get("reason", "")) or "unknown"
        counts[reason] = counts.get(reason, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _print_skip_census(census: list[tuple[str, int]], admitted: int, stream) -> None:
    total = admitted + sum(count for _, count in census)
    print(f"Admitted files: {admitted} of {total} total ({total - admitted} skipped)", file=stream)
    for reason, count in census:
        print(f"  skipped {reason}: {count}", file=stream)


def _warn_on_collapsed_admission(census: list[tuple[str, int]], admitted: int) -> None:
    """Say so, loudly, when the skip policy discarded almost the whole repo."""
    skipped = sum(count for _, count in census)
    total = admitted + skipped
    if not total or skipped < _COLLAPSED_ADMISSION_MIN_SKIPPED:
        return
    if admitted / total >= _COLLAPSED_ADMISSION_RATIO:
        return
    print(
        f"code-ingest: WARNING — admitted {admitted} of {total} files "
        f"({admitted / total:.1%}); the default skip policy discarded most of "
        "this repository.",
        file=sys.stderr,
    )
    for reason, count in census[:3]:
        print(f"  {reason}: {count}", file=sys.stderr)
    dominant = census[0][0] if census else ""
    if dominant.startswith("skipped_dir:"):
        directory = dominant.split(":", 1)[1]
        remedy = (
            "--policy-preset package"
            if directory in BUILD_ARTIFACT_DIRS
            else f"--include-path '**/{directory}/**'"
        )
    elif dominant == "minified_or_bundle":
        remedy = "--include-minified"
    elif dominant:
        remedy = "--include-skipped"
    else:
        remedy = "--include-path '<glob>'"
    print(
        "  If those bytes are the executed product (a shipped bundle repo), "
        f"re-run with {remedy} — it advances the repository generation by design.",
        file=sys.stderr,
    )


def _should_descend_skipped_dir(rel_dir: str, dirname: str, args) -> bool:
    """Descend into a skipped directory only when an explicit include can need it."""
    patterns = getattr(args, "include_path", []) or []
    normalized = rel_dir.replace(os.sep, '/')
    if getattr(args, "include_minified", False) and dirname in BUILD_ARTIFACT_DIRS:
        return True
    if getattr(args, "include_skipped", False) and dirname in BUILD_ARTIFACT_DIRS:
        return True
    for pattern in patterns:
        if dirname in BUILD_ARTIFACT_DIRS and ("**" in pattern or ".min." in pattern or ".bundle." in pattern):
            return True
        if pattern.startswith((f"{normalized}/", f"**/{normalized}/")):
            return True
        if fnmatch.fnmatch(normalized, pattern.rstrip('/')):
            return True
        # Pattern names dirname as a path segment (e.g. '**/vendor/foo.min.js'
        # for rel_dir='src/vendor'). Walking pattern segments lets nested
        # skipped directories be reached without the user having to pre-encode
        # the parent prefix.
        if pattern == dirname or pattern.startswith(f"{dirname}/") or f"/{dirname}/" in pattern:
            return True
    return False


def _include_reason(rel_path: str, skip_reason: str | None, args) -> str | None:
    pattern = _include_path_match(rel_path, getattr(args, "include_path", []) or [])
    if pattern:
        return f'include_path:{pattern}'
    if skip_reason == 'minified_or_bundle' and getattr(args, "include_minified", False):
        return 'include_minified'
    if skip_reason and getattr(args, "include_skipped", False):
        return 'include_skipped'
    return None


def _admitted_source_paths(
    source_tree: RootedSourceTree,
    args,
    snapshots_root: Path,
):
    """Yield the exact path set eligible for the sealed source manifest.

    This predicate and `_collect_excluded_records` partition the same tree, so
    every admission rule here needs its exact mirror there — otherwise
    `_verify_source_inventory` raises on every run.
    """
    skip_dirs = _effective_skip_dirs(args)
    repo_root = source_tree.root.resolve()
    snapshots_resolved = snapshots_root.resolve(strict=False)
    try:
        snapshots_relative = snapshots_resolved.relative_to(repo_root)
    except ValueError:
        snapshots_relative = None
    for listing in source_tree.walk():
        kept: list[str] = []
        for dirname in listing.directories:
            rel_dir = f"{listing.relative_dir}/{dirname}" if listing.relative_dir else dirname
            relative = Path(rel_dir)
            if dirname == ".git":
                continue
            if snapshots_relative is not None and (
                relative == snapshots_relative or relative.is_relative_to(snapshots_relative)
            ):
                continue
            if dirname in skip_dirs and not _should_descend_skipped_dir(rel_dir, dirname, args):
                continue
            kept.append(dirname)
        listing.directories[:] = kept
        for filename in listing.regular_files:
            rel_path = (
                f"{listing.relative_dir}/{filename}" if listing.relative_dir else filename
            )
            if rel_path == ".git" or rel_path.startswith(".git/"):
                continue
            skip_reason = _skip_file_reason(rel_path, filename, skip_dirs)
            include_reason = _include_reason(rel_path, skip_reason, args)
            if skip_reason and not include_reason:
                continue
            if skip_reason and include_reason:
                try:
                    size = source_tree.regular_file_size(rel_path)
                except (OSError, ValueError) as exc:
                    raise SourceSnapshotRaceError(
                        f"{rel_path} changed while verifying the sealed source"
                    ) from exc
                if size > _max_included_skipped_bytes(args):
                    continue
            yield rel_path


def _verify_source_inventory(
    source_tree: RootedSourceTree,
    args,
    snapshots_root: Path,
    expected: dict[str, tuple[str, int, bool]],
    expected_excluded: list[dict[str, object]],
) -> None:
    verified: dict[str, tuple[str, int, bool]] = {}
    for rel_path in _admitted_source_paths(source_tree, args, snapshots_root):
        captured = source_tree.capture(rel_path, retain_spool=False)
        verified[rel_path] = (captured.sha256, captured.size, captured.executable)
    source_tree.verify_root_identity()
    if verified != expected:
        added = sorted(set(verified) - set(expected))
        removed = sorted(set(expected) - set(verified))
        changed = sorted(
            path for path in set(expected) & set(verified) if expected[path] != verified[path]
        )
        raise SourceSnapshotRaceError(
            "source inventory changed after capture "
            f"(added={added}, removed={removed}, changed={changed})"
        )
    verified_excluded = _collect_excluded_records(source_tree, args, snapshots_root)
    if verified_excluded != expected_excluded:
        raise SourceSnapshotRaceError(
            "excluded source inventory changed after capture; retry code-ingest"
        )


def _source_hints(rel_path: str) -> dict[str, str]:
    lower = rel_path.lower()
    hints: dict[str, str] = {}
    if lower.endswith(('.min.js', '.min.css')):
        stem = rel_path.rsplit('.min.', 1)
        if len(stem) == 2:
            hints['source_equivalent_candidate'] = f"{stem[0]}.{stem[1]}"
        hints['source_map_candidate'] = f"{rel_path}.map"
    elif lower.endswith(('.bundle.js', '.bundle.css')):
        stem = rel_path.rsplit('.bundle.', 1)
        if len(stem) == 2:
            hints['source_equivalent_candidate'] = f"{stem[0]}.{stem[1]}"
        hints['source_map_candidate'] = f"{rel_path}.map"
    elif lower.endswith('.map'):
        hints['mapped_artifact_candidate'] = rel_path[:-4]
    return hints


def _skipped_record(repo_path: str, rel_path: str, reason: str, *, kind: str = 'file') -> dict[str, object]:
    filepath = os.path.join(repo_path, rel_path)
    record: dict[str, object] = {
        'path': rel_path,
        'kind': kind,
        'reason': reason,
    }
    if kind == 'file' and os.path.isfile(filepath):
        try:
            record['size'] = os.path.getsize(filepath)
        except OSError:
            record['size'] = 0
        record['sha256'] = _sha256_file(filepath)
        record['language'] = _detect_language(os.path.basename(filepath)) or ''
        record.update(_source_hints(rel_path))
    return record


def _captured_skipped_record(
    rel_path: str,
    reason: str,
    captured,
) -> dict[str, object]:
    record: dict[str, object] = {
        "path": rel_path,
        "kind": "file",
        "reason": reason,
        "size": captured.size,
        "sha256": captured.sha256,
        "language": _detect_language(Path(rel_path).name) or "",
    }
    record.update(_source_hints(rel_path))
    return record


def _enumerate_rooted_skipped_dir(
    source_tree: RootedSourceTree,
    rel_dir: str,
    dirname: str,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    reason = f"skipped_dir:{dirname}"
    for listing in source_tree.walk(rel_dir):
        for child_dirname in listing.directories:
            records.append(
                {
                    "path": f"{listing.relative_dir}/{child_dirname}",
                    "kind": "directory",
                    "reason": reason,
                }
            )
        for filename in listing.regular_files:
            rel_path = f"{listing.relative_dir}/{filename}"
            captured = source_tree.capture(rel_path, retain_spool=False)
            records.append(_captured_skipped_record(rel_path, reason, captured))
        for name in listing.other_entries:
            rel_path = f"{listing.relative_dir}/{name}"
            records.append(
                {
                    "path": rel_path,
                    "kind": source_tree.entry_kind(rel_path),
                    "reason": reason,
                }
            )
    return records


def _enumerate_skipped_dir(repo_path: str, rel_dir: str, dirname: str) -> list[dict[str, object]]:
    """Walk inside a skipped directory and emit per-file skipped records.

    The dir-level record alone hides large file counts (e.g. vendor/ with 378 PHP files
    reads as a single skipped row). Returning per-file records makes the skipped surface
    auditable from skipped-artifact manifests and code-coverage reports.
    """
    records: list[dict[str, object]] = []
    dir_abs = os.path.join(repo_path, rel_dir)
    if not os.path.isdir(dir_abs):
        return records
    reason = f'skipped_dir:{dirname}'
    try:
        for inner_dirpath, inner_dirnames, inner_filenames in os.walk(dir_abs):
            # Don't follow symlinked dirs while accounting.
            inner_dirnames[:] = [
                d for d in inner_dirnames
                if not os.path.islink(os.path.join(inner_dirpath, d))
            ]
            for fname in inner_filenames:
                fpath = os.path.join(inner_dirpath, fname)
                if not _is_regular_file(fpath):
                    continue
                inner_rel = os.path.relpath(fpath, repo_path)
                records.append(_skipped_record(repo_path, inner_rel, reason))
    except OSError:
        # Best-effort accounting; partial enumeration is better than none.
        pass
    return records


def _collect_excluded_records(
    source_tree: RootedSourceTree,
    args,
    snapshots_root: Path,
) -> list[dict[str, object]]:
    """Capture every excluded file/special entry for the sealed audit boundary.

    The exclusion predicate here is the exact complement of
    `_admitted_source_paths`; the two are verified against each other on every
    run by `_verify_source_inventory`.
    """
    skip_dirs = _effective_skip_dirs(args)
    records: list[dict[str, object]] = []
    repo_root = source_tree.root.resolve()
    snapshots_resolved = snapshots_root.resolve(strict=False)
    try:
        snapshots_relative = snapshots_resolved.relative_to(repo_root)
    except ValueError:
        snapshots_relative = None
    for listing in source_tree.walk():
        kept: list[str] = []
        for dirname in listing.directories:
            rel_dir = (
                f"{listing.relative_dir}/{dirname}"
                if listing.relative_dir
                else dirname
            )
            relative = Path(rel_dir)
            if dirname == ".git":
                continue
            if snapshots_relative is not None and (
                relative == snapshots_relative
                or relative.is_relative_to(snapshots_relative)
            ):
                continue
            if dirname in skip_dirs and not _should_descend_skipped_dir(
                rel_dir, dirname, args
            ):
                records.append(
                    {
                        "path": rel_dir,
                        "kind": "directory",
                        "reason": f"skipped_dir:{dirname}",
                    }
                )
                records.extend(
                    _enumerate_rooted_skipped_dir(source_tree, rel_dir, dirname)
                )
                continue
            kept.append(dirname)
        listing.directories[:] = kept

        for name in listing.other_entries:
            rel_path = (
                f"{listing.relative_dir}/{name}"
                if listing.relative_dir
                else name
            )
            records.append(
                {
                    "path": rel_path,
                    "kind": source_tree.entry_kind(rel_path),
                    "reason": "unsupported_entry_type",
                }
            )

        for filename in listing.regular_files:
            rel_path = (
                f"{listing.relative_dir}/{filename}"
                if listing.relative_dir
                else filename
            )
            if rel_path == ".git" or rel_path.startswith(".git/"):
                continue
            skip_reason = _skip_file_reason(rel_path, filename, skip_dirs)
            include_reason = _include_reason(rel_path, skip_reason, args)
            if not skip_reason:
                continue
            captured = source_tree.capture(rel_path, retain_spool=False)
            if not include_reason:
                records.append(
                    _captured_skipped_record(rel_path, skip_reason, captured)
                )
                continue
            max_bytes = _max_included_skipped_bytes(args)
            if captured.size > max_bytes:
                records.append(
                    _captured_skipped_record(
                        rel_path,
                        (
                            f"{skip_reason}; include requested by {include_reason} but "
                            f"size {captured.size} exceeds max {max_bytes}"
                        ),
                        captured,
                    )
                )
    return sorted(
        records,
        key=lambda record: (
            str(record["path"]),
            str(record["kind"]),
            str(record["reason"]),
        ),
    )


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while publishing exclusion manifest")
        view = view[written:]


def _write_skipped_manifest(
    args,
    *,
    cfg,
    repo_id: int,
    repo_key: str,
    repo_name: str,
    repo_path: str,
    repo_generation: int,
    source_manifest_digest: str,
    snapshot_digest: str,
    snapshot_manifest_path: str,
    records: list[dict[str, object]],
) -> str | None:
    if not records:
        return None
    configured_root = getattr(args, "skipped_manifest", None)
    if configured_root:
        root = Path(configured_root).expanduser()
    else:
        eng_dir = Path(getattr(cfg, "engagement_dir", "") or repo_path)
        root = eng_dir / "tools" / "analysis-state" / "skipped-artifacts"
    path = (
        root
        / str(repo_id)
        / str(repo_generation)
        / f"{source_manifest_digest}-{snapshot_digest}.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "code-exclusion-manifest/v1",
        "repo_id": repo_id,
        "repo_key": repo_key,
        "repo_name": repo_name,
        "source_origin_path": repo_path,
        "repo_generation": repo_generation,
        "source_manifest_digest": source_manifest_digest,
        "snapshot_digest": snapshot_digest,
        "snapshot_manifest_path": snapshot_manifest_path,
        "policy": {
            "preset": str(getattr(args, "policy_preset", "application")),
            "default_skip_generated_output": (
                str(getattr(args, "policy_preset", "application")) != "package"
            ),
            "include_minified": bool(getattr(args, "include_minified", False)),
            "include_skipped": bool(getattr(args, "include_skipped", False)),
            "include_path": list(getattr(args, "include_path", []) or []),
            "max_included_skipped_bytes": _max_included_skipped_bytes(args),
        },
        "excluded_entries": records,
    }
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temp_fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        _write_all(temp_fd, content)
        os.fsync(temp_fd)
    finally:
        os.close(temp_fd)
    os.chmod(temp_path, 0o444, follow_symlinks=False)
    try:
        os.link(temp_path, path, follow_symlinks=False)
    except FileExistsError:
        existing = (
            capture_regular_file(path, retain_spool=False)
            if path.is_file() and not path.is_symlink()
            else None
        )
        if (
            existing is None
            or existing.size != len(content)
            or existing.sha256 != hashlib.sha256(content).hexdigest()
        ):
            raise ValueError(f"conflicting generation-scoped exclusion manifest: {path}")
    finally:
        temp_path.unlink(missing_ok=True)
    return str(path)


def _is_regular_file(filepath: str) -> bool:
    """Return True for regular repo files, excluding symlinks and special files."""
    return os.path.isfile(filepath) and not os.path.islink(filepath)


def _detect_language(filename: str) -> str | None:
    """Compatibility wrapper around the shared code-language classifier."""

    return detect_language(filename)


def _sha256_file(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
    except OSError:
        return ''
    return h.hexdigest()


def _repo_key_for_path(repo_name: str, repo_path: str) -> str:
    normalized_name = re.sub(r"[^a-z0-9._-]+", "-", repo_name.lower()).strip("._-")
    normalized_name = normalized_name[:242].rstrip("._-") or "repo"
    canonical_path = os.path.realpath(repo_path)
    path_hash = hashlib.sha256(canonical_path.encode('utf-8')).hexdigest()[:12]
    return validate_repo_key(f"{normalized_name}-{path_hash}")


def _count_lines(filepath: str) -> int:
    """Count lines in a file."""
    try:
        with open(filepath, 'rb') as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def _read_header(filepath: str, max_lines: int = 50, max_chars: int = 8192) -> str:
    """Read the first N lines of a file as a bounded header snippet."""
    lines = []
    char_count = 0
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= max_lines or char_count >= max_chars:
                    break
                remaining = max_chars - char_count
                if len(line) > remaining:
                    lines.append(line[:remaining])
                    char_count = max_chars
                    break
                lines.append(line)
                char_count += len(line)
    except OSError:
        return ''
    return ''.join(lines)


def _git_warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def _run_git(repo_path: str, git_path: str, arguments: list[str], **kwargs):
    options = {
        "env": trusted_environment(source_root=repo_path),
        **kwargs,
    }
    return subprocess.run(git_command(git_path, repo_path, *arguments), check=False, **options)


def _git_provenance(repo_path: str, git_path: str) -> dict[str, object]:
    """Validate a worktree and return its HEAD, branch, and dirty bit."""
    common = {"capture_output": True, "text": True, "timeout": 30}
    inside = _run_git(repo_path, git_path, ["rev-parse", "--is-inside-work-tree"], **common)
    if inside.returncode != 0 or inside.stdout.strip().lower() != "true":
        detail = inside.stderr.strip()
        raise ValueError(f"repository marker is not a usable Git worktree: {detail or repo_path}")

    head = _run_git(repo_path, git_path, ["rev-parse", "--verify", "HEAD^{commit}"], **common)
    if head.returncode != 0 or not head.stdout.strip():
        detail = head.stderr.strip()
        raise ValueError(f"cannot resolve repository HEAD: {detail or repo_path}")

    branch_result = _run_git(
        repo_path,
        git_path,
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        **common,
    )
    branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""
    status_result = _run_git(
        repo_path,
        git_path,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--", "."],
        **common,
    )
    if status_result.returncode != 0:
        detail = status_result.stderr.strip()
        raise ValueError(f"cannot inspect repository worktree status: {detail or repo_path}")
    return {
        "head": head.stdout.strip(),
        "branch": branch,
        "dirty": bool(status_result.stdout),
    }


def _verify_git_provenance(
    repo_path: str,
    git_path: str,
    expected: dict[str, object],
) -> None:
    """Reject a source snapshot whose Git provenance changed during sealing."""
    current = _git_provenance(repo_path, git_path)
    if current != expected:
        changed = sorted(key for key in expected if current.get(key) != expected.get(key))
        raise SourceSnapshotRaceError(
            f"Git provenance changed while sealing source (changed={changed})"
        )


def _prepare_git_source(repo_path: str) -> tuple[str, dict[str, object]]:
    marker = Path(repo_path) / ".git"
    try:
        marker_stat = marker.lstat()
    except OSError as exc:
        raise ValueError(f"repository has no .git marker: {repo_path}") from exc
    if stat.S_ISLNK(marker_stat.st_mode) or not (
        stat.S_ISDIR(marker_stat.st_mode) or stat.S_ISREG(marker_stat.st_mode)
    ):
        raise ValueError(f"repository .git marker is not a directory or gitfile: {marker}")
    git_path = _resolve_trusted_tool("git", source_root=repo_path)
    if not git_path:
        raise ValueError("trusted Git executable not found on absolute non-repository PATH entries")
    return git_path, _git_provenance(repo_path, git_path)


def _prepare_source(repo_path: str) -> tuple[str | None, str, dict[str, object]]:
    marker = Path(repo_path) / ".git"
    if not marker.exists() and not marker.is_symlink():
        return None, "directory", {"head": "", "branch": "", "dirty": None}
    git_path, provenance = _prepare_git_source(repo_path)
    return git_path, "git", provenance


def _git_commit_count(repo_path: str) -> int | None:
    """Return the total commit count for *repo_path*, or None if unavailable."""
    try:
        git_path = _resolve_trusted_tool("git", source_root=repo_path)
        if not git_path:
            _git_warn("trusted Git executable disappeared before history scan")
            return None
        result = _run_git(
            repo_path,
            git_path,
            ['rev-list', '--count', '--all'],
            capture_output=True,
            text=True,
            timeout=_GIT_REV_LIST_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            detail = result.stderr.strip()
            suffix = f": {detail}" if detail else ""
            _git_warn(f"could not count commits for {repo_path}{suffix}")
            return None
        return int(result.stdout.strip())
    except subprocess.TimeoutExpired:
        _git_warn(
            f"timed out counting commits for {repo_path} after {_GIT_REV_LIST_TIMEOUT_SECONDS}s; "
            "using default git history scan scope"
        )
    except (OSError, ValueError) as exc:
        _git_warn(f"could not count commits for {repo_path}: {exc}")
    return None


def _git_security_history_args(commit_count: int | None) -> list[str]:
    """Return the git log scope for security-history scanning."""
    if commit_count is not None and commit_count > _GIT_LARGE_HISTORY_COMMIT_THRESHOLD:
        return [f'--since={_GIT_SECURITY_LOOKBACK}']
    return ['--all']


def _git_churn_scores(repo_path: str, since: str = _GIT_CHURN_LOOKBACK) -> dict[str, int]:
    """Compute per-file churn scores from git log --numstat over a bounded time window."""
    churn: dict[str, int] = {}
    try:
        with tempfile.TemporaryFile(mode='w+t', encoding='utf-8') as stdout, tempfile.TemporaryFile(
            mode='w+t', encoding='utf-8'
        ) as stderr:
            git_path = _resolve_trusted_tool("git", source_root=repo_path)
            if not git_path:
                _git_warn("trusted Git executable disappeared before churn scan")
                return churn
            result = _run_git(
                repo_path,
                git_path,
                ['log', '--numstat', f'--since={since}', '--format=%H'],
                stdout=stdout,
                stderr=stderr,
                text=True,
                timeout=_GIT_LOG_TIMEOUT_SECONDS,
            )
            if result.returncode != 0:
                stderr.seek(0)
                detail = stderr.read().strip()
                suffix = f": {detail}" if detail else ""
                _git_warn(f"git churn scan failed for {repo_path}{suffix}")
                return churn

            stdout.seek(0)
            for line in stdout:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) == 3:
                    added, deleted, filepath = parts
                    try:
                        total = int(added) + int(deleted)
                    except ValueError:
                        # Binary files show '-' for added/deleted
                        continue
                    churn[filepath] = churn.get(filepath, 0) + total
    except subprocess.TimeoutExpired:
        _git_warn(
            f"git churn scan timed out for {repo_path} after {_GIT_LOG_TIMEOUT_SECONDS}s; "
            "git churn data will be incomplete"
        )
    except OSError as exc:
        _git_warn(f"git churn scan failed for {repo_path}: {exc}")
    return churn


def _git_security_files(repo_path: str, history_args: list[str] | None = None) -> set[str]:
    """Identify files with past security-related commits."""
    sec_files: set[str] = set()
    history_args = history_args or ['--all']
    try:
        with tempfile.TemporaryFile(mode='w+t', encoding='utf-8') as stdout, tempfile.TemporaryFile(
            mode='w+t', encoding='utf-8'
        ) as stderr:
            git_path = _resolve_trusted_tool("git", source_root=repo_path)
            if not git_path:
                _git_warn("trusted Git executable disappeared before security-history scan")
                return sec_files
            result = _run_git(
                repo_path,
                git_path,
                [
                    'log',
                    *history_args,
                    '--grep=CVE\\|security\\|vulnerability\\|fix.*vuln\\|buffer.overflow\\|use.after.free',
                    '--format=commit:%H',
                    '--name-only',
                ],
                stdout=stdout,
                stderr=stderr,
                text=True,
                timeout=_GIT_LOG_TIMEOUT_SECONDS,
            )
            if result.returncode != 0:
                stderr.seek(0)
                detail = stderr.read().strip()
                suffix = f": {detail}" if detail else ""
                _git_warn(f"git security-history scan failed for {repo_path}{suffix}")
                return sec_files

            stdout.seek(0)
            for line in stdout:
                line = line.strip()
                if not line or line.startswith('commit:'):
                    continue
                sec_files.add(line)
    except subprocess.TimeoutExpired:
        _git_warn(
            f"git security-history scan timed out for {repo_path} after {_GIT_LOG_TIMEOUT_SECONDS}s; "
            "security-history annotations will be incomplete"
        )
    except OSError as exc:
        _git_warn(f"git security-history scan failed for {repo_path}: {exc}")
    return sec_files


def run(args) -> None:
    repo_path = os.path.realpath(os.path.abspath(args.repo_path))
    if not os.path.isdir(repo_path):
        print(f"Repository path not found: {repo_path}", file=sys.stderr)
        sys.exit(1)

    _expand_directory_include_patterns(repo_path, args)
    repo_name = args.name or os.path.basename(repo_path)
    try:
        repo_key = (
            validate_repo_key(args.repo_key)
            if args.repo_key is not None
            else _repo_key_for_path(repo_name, repo_path)
        )
    except ValueError as exc:
        print(f"Cannot ingest repository: {exc}", file=sys.stderr)
        sys.exit(1)
    try:
        git_path, source_kind, git_provenance = _prepare_source(repo_path)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Cannot ingest repository: {exc}", file=sys.stderr)
        sys.exit(1)

    # A present Git marker is validated before configuration lookup or artifact
    # creation. Marker-free directories intentionally use directory provenance.
    cfg = load_config(args.engagement_dir)
    engagement_value = getattr(cfg, "engagement_dir", "") or ""
    if not getattr(args, "dry_run", False) and not engagement_value:
        print("Cannot determine engagement directory for sealed source snapshot", file=sys.stderr)
        sys.exit(1)
    engagement_dir = Path(engagement_value) if engagement_value else Path(repo_path)
    snapshots_root = engagement_dir / "tools" / "analysis-state" / "code-snapshots"

    # Collect Git-derived ranking metadata through the same trusted executable
    # boundary used for provenance.
    churn_scores: dict[str, int] = {}
    security_files: set[str] = set()
    if source_kind == "git":
        print("Scanning git history for churn and security commits...", file=sys.stderr)
        commit_count = _git_commit_count(repo_path)
        security_history_args = _git_security_history_args(commit_count)
        if commit_count is not None and commit_count > _GIT_LARGE_HISTORY_COMMIT_THRESHOLD:
            print(
                f"  git history: {commit_count:,} commits detected; "
                f"limiting security scan to current branch over the last {_GIT_SECURITY_LOOKBACK}",
                file=sys.stderr,
            )
        churn_scores = _git_churn_scores(repo_path)
        security_files = _git_security_files(repo_path, security_history_args)

    # Walk the directory tree
    files: list[dict[str, object]] = []
    total_loc = 0
    skipped = 0
    skipped_records: list[dict[str, object]] = []
    included_skipped = 0
    effective_skip_dirs = _effective_skip_dirs(args)
    include_patterns = list(getattr(args, "include_path", []) or [])
    matched_include_patterns: set[str] = set()
    source_bindings: dict[str, tuple[str, int, bool]] = {}
    builder = None if getattr(args, "dry_run", False) else SnapshotBuilder(snapshots_root, repo_key)
    try:
        repo_root = Path(repo_path)
        with RootedSourceTree(repo_root) as source_tree:
            skipped_records = _collect_excluded_records(source_tree, args, snapshots_root)
            for rel_path in _admitted_source_paths(source_tree, args, snapshots_root):
                try:
                    captured = source_tree.capture(
                        rel_path,
                        retain_spool=builder is not None,
                    )
                except (OSError, ValueError, SourceSnapshotRaceError) as exc:
                    raise SourceSnapshotRaceError(
                        f"{rel_path} changed while being sealed; retry code-ingest"
                    ) from exc
                try:
                    filename = Path(rel_path).name
                    skip_reason = _skip_file_reason(rel_path, filename, effective_skip_dirs)
                    matched_include_patterns.update(
                        _include_path_matches(rel_path, include_patterns)
                    )
                    if skip_reason and _include_reason(rel_path, skip_reason, args):
                        included_skipped += 1

                    lang = _detect_language(filename)
                    if lang is None and getattr(args, "default_language_for_unknown", None):
                        lang = args.default_language_for_unknown
                    total_loc += captured.loc
                    file_record = {
                        "file_path": rel_path,
                        "language": lang or "",
                        "loc": captured.loc,
                        "file_hash": captured.sha256,
                        "header_snippet": captured.header,
                        "git_churn_score": churn_scores.get(rel_path, 0),
                        "has_past_cve_fix": rel_path in security_files,
                    }
                    files.append(file_record)
                    source_bindings[rel_path] = (
                        captured.sha256,
                        captured.size,
                        captured.executable,
                    )
                    if builder is not None:
                        builder.add(rel_path, captured, language=lang or "")
                finally:
                    captured.close()

            _verify_source_inventory(
                source_tree,
                args,
                snapshots_root,
                source_bindings,
                skipped_records,
            )
            if source_kind == "git":
                assert git_path is not None
                _verify_git_provenance(repo_path, git_path, git_provenance)
    except (OSError, ValueError, SourceSnapshotRaceError) as exc:
        if builder is not None:
            builder.abort()
        print(f"Cannot seal source snapshot: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        if builder is not None:
            builder.abort()
        raise

    skipped = sum(record.get("kind") != "directory" for record in skipped_records)
    skip_census = _skip_reason_census(skipped_records)
    # Language support controls structural indexing, not whether sealed source
    # remains reviewable through direct source analysis.
    analyzable_files = len(files)
    if not files:
        print(
            "No analyzable files found; committing a complete empty manifest.",
            file=sys.stderr,
        )

    _warn_on_collapsed_admission(skip_census, len(files))
    # A --dry-run must produce the same warnings as a real run, or the warning
    # is untestable by the operator before the generation is committed.
    if _report_unmatched_include_patterns(
        matched_include_patterns,
        _size_capped_include_patterns(skipped_records),
        args,
    ):
        if builder is not None:
            builder.abort()
        sys.exit(1)

    if getattr(args, "dry_run", False):
        _print_skip_census(skip_census, len(files), sys.stderr)
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            preview = client.post(
                "code/repos/refresh/preview", {"repo_key": repo_key, "files": files}
            )
        print(json.dumps(preview, indent=2, ensure_ascii=False))
        return

    assert builder is not None
    snapshot = builder.finish(
        repo_key=repo_key,
        repo_name=repo_name,
        source_origin_path=str(Path(repo_path).resolve()),
        git=git_provenance,
        excluded_entries=skipped_records,
    )
    if source_kind == "git":
        assert git_path is not None
        try:
            _verify_git_provenance(repo_path, git_path, git_provenance)
        except (OSError, ValueError, subprocess.SubprocessError, SourceSnapshotRaceError) as exc:
            print(f"Cannot publish source snapshot: {exc}", file=sys.stderr)
            sys.exit(1)

    # POST to backend
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        # Stage a complete generation. The backend only promotes it after every
        # batch arrives, so a crash or transport failure cannot expose a
        # half-refreshed source tree.
        repo_payload = {
            'repo_key': repo_key,
            'name': repo_name,
            'language': args.language or '',
            'repo_path': str(snapshot.source_path),
            'source_origin_path': str(Path(repo_path).resolve()),
            'source_kind': source_kind,
            'snapshot_manifest_path': str(snapshot.manifest_path),
            'snapshot_digest': snapshot.snapshot_digest,
            'source_manifest_version': 'v1',
            'source_snapshot_quality': 'verified',
            'worktree_dirty': git_provenance['dirty'],
            'total_files': len(files) + skipped,
            'analyzable_files': analyzable_files,
            'total_loc': total_loc,
            'commit_hash': str(git_provenance['head']),
            'branch': str(git_provenance['branch']),
            'git_churn': {'churn_scores': dict(sorted(churn_scores.items(), key=lambda x: -x[1])[:30])} if churn_scores else {},
        }
        refresh = client.post('code/repos/refresh/start', repo_payload)
        repo_id, refresh_token = _require_refresh_start_receipt(refresh)

        # Bulk-create files in batches
        batch_size = 200
        created_count = 0
        for i in range(0, len(files), batch_size):
            batch = files[i:i + batch_size]
            files_payload = {
                'refresh_token': refresh_token,
                'files': batch,
            }
            resp = client.post(f'code/repos/{repo_id}/refresh/files', files_payload)
            require_write_result(
                resp,
                operation="stage code repository files",
                expected={"staged": len(batch)},
                nonnegative_counts=("staged",),
            )
            created_count += resp["staged"]
        commit = client.post(
            f'code/repos/{repo_id}/refresh/commit',
            {'refresh_token': refresh_token, 'manifest_complete': True},
        )
        repo_generation, committed_digest = _require_refresh_commit_receipt(
            commit,
            requested_repo_id=repo_id,
        )

        ctags_output = (
            engagement_dir
            / "tools"
            / "analysis-state"
            / "ctags"
            / repo_key
            / f"{repo_generation}-{committed_digest[:12]}"
        )
        try:
            lsp_ctags = _setup_ctags(
                snapshot.source_path,
                ctags_output,
                [
                    {
                        "file_path": str(item["file_path"]),
                        "source_sha256": str(item["file_hash"]),
                    }
                    for item in sorted(files, key=lambda row: str(row["file_path"]))
                ],
                repo_generation=repo_generation,
                source_manifest_digest=committed_digest,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"  ctags: error: {exc}", file=sys.stderr)
            lsp_ctags = {
                "available": False,
                "tags_path": "",
                "universal": False,
                "repo_generation": repo_generation,
                "source_manifest_digest": committed_digest,
            }
        published_lsp = client.post(
            f"code/repos/{repo_id}/lsp-config",
            {
                "repo_generation": repo_generation,
                "source_manifest_digest": committed_digest,
                "lsp_config": {"ctags": lsp_ctags},
            },
        )
        require_write_result(
            published_lsp,
            operation="publish code repository LSP config",
            expected={
                "id": repo_id,
                "active_generation": repo_generation,
                "source_manifest_digest": committed_digest,
                "lsp_config": {"ctags": lsp_ctags},
            },
            positive_ids=("id",),
        )

    try:
        skipped_manifest = _write_skipped_manifest(
            args,
            cfg=cfg,
            repo_id=repo_id,
            repo_key=repo_key,
            repo_name=repo_name,
            repo_path=repo_path,
            repo_generation=repo_generation,
            source_manifest_digest=committed_digest,
            snapshot_digest=snapshot.snapshot_digest,
            snapshot_manifest_path=str(snapshot.manifest_path),
            records=skipped_records,
        )
    except (OSError, ValueError) as exc:
        skipped_manifest = None
        print(
            "Warning: could not publish the generation-bound skipped-artifact "
            f"projection: {exc}",
            file=sys.stderr,
        )

    # Print summary
    print("\n=== Code Ingest Summary ===")
    print(f"Repository: {repo_name} (id: {repo_id})")
    print(f"Sealed source: {snapshot.source_path}")
    print(f"Snapshot digest: {snapshot.snapshot_digest}")
    print(f"Source manifest digest: {committed_digest}")
    print(f"Repository generation: {repo_generation}")
    _print_skip_census(skip_census, len(files), sys.stdout)
    print(f"Analyzable files: {analyzable_files}")
    if included_skipped:
        print(f"Included skipped artifacts: {included_skipped}")
    if skipped_manifest:
        print(f"Skipped artifact manifest: {skipped_manifest}")
    print(f"Total LOC: {total_loc:,}")

    if churn_scores:
        # Top 10 highest-churn files
        sorted_churn = sorted(churn_scores.items(), key=lambda x: x[1], reverse=True)[:10]
        print("\nTop 10 highest-churn files (last year):")
        for path, score in sorted_churn:
            marker = " [security-history]" if path in security_files else ""
            print(f"  {score:>6}  {path}{marker}")

    if security_files:
        print(f"\nFiles with security-related commit history: {len(security_files)}")

    if not lsp_ctags.get('available'):
        print("\nSymbol index: ctags not available", file=sys.stderr)
