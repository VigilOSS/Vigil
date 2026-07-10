"""vigil assess code-ingest — walk a repo, fingerprint files, POST to code analysis backend."""
from __future__ import annotations

import hashlib
import fnmatch
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


LANG_MAP = {
    '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
    '.py': 'python', '.pyx': 'python',
    '.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.go': 'go', '.rs': 'rust', '.java': 'java', '.kt': 'kotlin',
    '.rb': 'ruby', '.php': 'php', '.swift': 'swift', '.m': 'objectivec',
    '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.lua': 'lua',
    # Keep these aligned with treesitter_index.EXTENSION_LANG_MAP so a file the
    # structural indexer recognizes is also stamped with a language at ingest
    # (otherwise it gets an index but a language-less code_files row).
    '.sql': 'sql', '.html': 'html', '.htm': 'html', '.tpl': 'html', '.twig': 'html',
    '.css': 'css', '.scss': 'css', '.xml': 'xml',
    '.json': 'json', '.yaml': 'yaml', '.yml': 'yaml', '.toml': 'toml',
    '.md': 'markdown', '.txt': 'text', '.rst': 'rst',
    'Makefile': 'makefile', 'CMakeLists.txt': 'cmake', 'Dockerfile': 'dockerfile',
}

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
DEFAULT_MAX_INCLUDED_SKIPPED_BYTES = 2_000_000


_C_EXTENSIONS = frozenset({'.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh'})
_PYTHON_EXTENSIONS = frozenset({'.py', '.pyx', '.pyi'})
_JS_TS_EXTENSIONS = frozenset({'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'})
_GIT_LOG_TIMEOUT_SECONDS = 120
_GIT_REV_LIST_TIMEOUT_SECONDS = 30
_GIT_LARGE_HISTORY_COMMIT_THRESHOLD = 50_000
_GIT_SECURITY_LOOKBACK = '3years'
_GIT_CHURN_LOOKBACK = '1year'


def _which(binary: str) -> str | None:
    """Find a binary on PATH, return full path or None."""
    try:
        result = subprocess.run(
            ['which', binary], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _setup_ctags(repo_path: str) -> dict[str, object]:
    """Generate ctags symbol index for a repository."""
    config: dict[str, object] = {
        'available': False,
        'tags_path': '',
        'universal': False,
    }

    ctags_path = _which('ctags')
    if not ctags_path:
        print("  ctags: not found", file=sys.stderr)
        return config

    # Detect Universal vs BSD ctags
    try:
        version_result = subprocess.run(
            ['ctags', '--version'], capture_output=True, text=True, timeout=5,
        )
        is_universal = 'Universal' in version_result.stdout or 'Universal' in version_result.stderr
    except (subprocess.TimeoutExpired, OSError):
        is_universal = False

    config['universal'] = is_universal

    tags_path = os.path.join(repo_path, 'tags')

    try:
        if is_universal:
            subprocess.run(
                [
                    'ctags', '-R',
                    '--fields=+S+K+n',
                    '--extras=+q',
                    '--output-format=e-ctags',
                    '-f', tags_path,
                    repo_path,
                ],
                capture_output=True, timeout=120,
            )
        else:
            # BSD ctags (macOS default) — limited, must list files explicitly
            source_files = []
            for dirpath, dirnames, filenames in os.walk(repo_path):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if not _is_regular_file(filepath):
                        continue
                    ext = Path(filename).suffix.lower()
                    if ext in _C_EXTENSIONS or ext in _PYTHON_EXTENSIONS or ext in _JS_TS_EXTENSIONS:
                        source_files.append(filepath)
            if source_files:
                subprocess.run(
                    ['ctags', '-f', tags_path] + source_files,
                    capture_output=True, timeout=120,
                )

        if os.path.isfile(tags_path):
            with open(tags_path, 'r', encoding='utf-8', errors='replace') as f:
                tag_count = sum(1 for line in f if not line.startswith('!'))
            config['available'] = True
            config['tags_path'] = 'tags'
            kind = 'Universal' if is_universal else 'BSD (limited)'
            print(f"  ctags: {tag_count} tags generated ({kind})")
        else:
            print("  ctags: generation failed", file=sys.stderr)

    except (subprocess.TimeoutExpired, OSError) as e:
        print(f"  ctags: error: {e}", file=sys.stderr)

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
        help="Glob path to include even if it is normally skipped; repeatable (e.g. '**/ResetPassword.min.js').",
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
        help="Optional path for skipped-artifacts manifest (default: tools/analysis-state/skipped-artifacts/<repo-key>.json).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compare the scanned manifest with the active backend generation without staging or committing it.",
    )
    p.set_defaults(func=run)


def _skip_file_reason(rel_path: str, filename: str) -> str | None:
    """Return the skip reason for a file, or None if it is normally ingestible."""
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
    if lower_name.endswith('.woff') or lower_name.endswith('.woff2'):
        return 'skipped_extension:font'
    return None


def _should_skip_file(rel_path: str, filename: str) -> bool:
    """Return True if the file is normally skipped.

    Kept as the boolean compatibility helper for code_index; code_ingest uses
    _skip_file_reason when it needs auditable skip details.
    """
    return _skip_file_reason(rel_path, filename) is not None


def _include_path_match(rel_path: str, patterns: list[str] | None) -> str | None:
    normalized = rel_path.replace(os.sep, '/')
    for pattern in patterns or []:
        if fnmatch.fnmatch(normalized, pattern):
            return pattern
    return None


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
        if pattern.startswith(f"{normalized}/") or pattern.startswith(f"**/{normalized}/"):
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


def _write_skipped_manifest(args, *, cfg, repo_key: str, repo_name: str, repo_path: str, records: list[dict[str, object]]) -> str | None:
    if not records:
        return None
    manifest_path = getattr(args, "skipped_manifest", None)
    if manifest_path:
        path = Path(manifest_path).expanduser()
    else:
        eng_dir = Path(getattr(cfg, 'engagement_dir', '') or repo_path)
        path = eng_dir / 'tools' / 'analysis-state' / 'skipped-artifacts' / f'{repo_key}.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        'repo_key': repo_key,
        'repo_name': repo_name,
        'repo_path': repo_path,
        'policy': {
            'default_skip_generated_output': True,
            'include_minified': bool(getattr(args, 'include_minified', False)),
            'include_skipped': bool(getattr(args, 'include_skipped', False)),
            'include_path': list(getattr(args, 'include_path', []) or []),
            'max_included_skipped_bytes': int(getattr(args, 'max_included_skipped_bytes', DEFAULT_MAX_INCLUDED_SKIPPED_BYTES)),
        },
        'skipped_artifacts': records,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path)


def _is_regular_file(filepath: str) -> bool:
    """Return True for regular repo files, excluding symlinks and special files."""
    return os.path.isfile(filepath) and not os.path.islink(filepath)


def _detect_language(filename: str) -> str | None:
    """Detect programming language from filename or extension."""
    # Check full filename first (Makefile, Dockerfile, CMakeLists.txt)
    if filename in LANG_MAP:
        return LANG_MAP[filename]
    # Dockerfile variants (Dockerfile.dev, Dockerfile.prod) — match the basename
    # rule used by treesitter_index.language_for_file so ingest and index agree.
    base = os.path.basename(filename)
    if base == "Dockerfile" or base.startswith("Dockerfile."):
        return "dockerfile"
    ext = Path(filename).suffix.lower()
    return LANG_MAP.get(ext)


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
    normalized_name = repo_name.lower().replace(' ', '-')
    canonical_path = os.path.realpath(repo_path)
    path_hash = hashlib.sha256(canonical_path.encode('utf-8')).hexdigest()[:12]
    return f"{normalized_name}-{path_hash}"


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


def _git_commit_count(repo_path: str) -> int | None:
    """Return the total commit count for *repo_path*, or None if unavailable."""
    try:
        result = subprocess.run(
            ['git', 'rev-list', '--count', '--all'],
            capture_output=True, text=True, cwd=repo_path, timeout=_GIT_REV_LIST_TIMEOUT_SECONDS,
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
            result = subprocess.run(
                ['git', 'log', '--numstat', f'--since={since}', '--format=%H'],
                stdout=stdout,
                stderr=stderr,
                text=True,
                cwd=repo_path,
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
            result = subprocess.run(
                [
                    'git', 'log',
                    *history_args,
                    '--grep=CVE\\|security\\|vulnerability\\|fix.*vuln\\|buffer.overflow\\|use.after.free',
                    '--format=commit:%H',
                    '--name-only',
                ],
                stdout=stdout,
                stderr=stderr,
                text=True,
                cwd=repo_path,
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
    repo_path = os.path.abspath(args.repo_path)
    if not os.path.isdir(repo_path):
        print(f"Repository path not found: {repo_path}", file=sys.stderr)
        sys.exit(1)

    repo_name = args.name or os.path.basename(repo_path)
    repo_key = args.repo_key or _repo_key_for_path(repo_name, repo_path)
    cfg = load_config(args.engagement_dir)
    has_git = os.path.isdir(os.path.join(repo_path, '.git'))

    # Collect git metadata if available
    churn_scores: dict[str, int] = {}
    security_files: set[str] = set()
    if has_git:
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
    files = []
    total_loc = 0
    skipped = 0
    skipped_records: list[dict[str, object]] = []
    included_skipped = 0

    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune skip directories unless an explicit include may need descendants.
        kept_dirs: list[str] = []
        for dirname in dirnames:
            rel_dir = os.path.relpath(os.path.join(dirpath, dirname), repo_path)
            if dirname in SKIP_DIRS and not _should_descend_skipped_dir(rel_dir, dirname, args):
                skipped_records.append(_skipped_record(repo_path, rel_dir, f'skipped_dir:{dirname}', kind='directory'))
                # Also enumerate per-file accounting so the dir's contents are auditable.
                skipped_records.extend(_enumerate_skipped_dir(repo_path, rel_dir, dirname))
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        # Skip symlinked directories to prevent traversal outside repo
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)

            # Skip symlinks and special files (FIFOs, sockets, devices) that are not safe to read.
            if not _is_regular_file(filepath):
                skipped += 1
                continue

            rel_path = os.path.relpath(filepath, repo_path)

            skip_reason = _skip_file_reason(rel_path, filename)
            include_reason = _include_reason(rel_path, skip_reason, args)
            if skip_reason and not include_reason:
                skipped += 1
                skipped_records.append(_skipped_record(repo_path, rel_path, skip_reason))
                continue
            if skip_reason and include_reason:
                size = os.path.getsize(filepath)
                max_bytes = int(getattr(args, "max_included_skipped_bytes", DEFAULT_MAX_INCLUDED_SKIPPED_BYTES))
                if size > max_bytes:
                    skipped += 1
                    skipped_records.append(
                        _skipped_record(
                            repo_path,
                            rel_path,
                            f'{skip_reason}; include requested by {include_reason} but size {size} exceeds max {max_bytes}',
                        )
                    )
                    continue
                included_skipped += 1

            lang = _detect_language(filename)
            if lang is None and getattr(args, "default_language_for_unknown", None):
                lang = args.default_language_for_unknown

            loc = _count_lines(filepath)
            total_loc += loc
            sha = _sha256_file(filepath)
            header = _read_header(filepath)
            churn = churn_scores.get(rel_path, 0)
            has_security_history = rel_path in security_files

            file_record = {
                'file_path': rel_path,
                'language': lang or '',
                'loc': loc,
                'file_hash': sha,
                'header_snippet': header,
                'git_churn_score': churn,
                'has_past_cve_fix': has_security_history,
            }
            files.append(file_record)

    if not files:
        print(
            "No analyzable files found; committing a complete empty manifest.",
            file=sys.stderr,
        )

    # POST to backend
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        # Stage a complete generation. The backend only promotes it after every
        # batch arrives, so a crash or transport failure cannot expose a
        # half-refreshed source tree.
        repo_payload = {
            'repo_key': repo_key,
            'name': repo_name,
            'language': args.language or '',
            'repo_path': repo_path,
            'total_files': len(files) + skipped,
            'analyzable_files': len(files),
            'total_loc': total_loc,
            'git_churn': {'churn_scores': dict(sorted(churn_scores.items(), key=lambda x: -x[1])[:30])} if churn_scores else {},
        }
        if getattr(args, "dry_run", False):
            preview = client.post(
                'code/repos/refresh/preview', {'repo_key': repo_key, 'files': files}
            )
            print(json.dumps(preview, indent=2, ensure_ascii=False))
            return
        refresh = client.post('code/repos/refresh/start', repo_payload)
        repo_id = refresh.get('repo_id')
        refresh_token = refresh.get('refresh_token')
        if not repo_id or not refresh_token:
            print("Backend did not return a repo refresh claim", file=sys.stderr)
            sys.exit(1)

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
            created_count += resp.get('staged', len(batch))
        client.post(
            f'code/repos/{repo_id}/refresh/commit',
            {'refresh_token': refresh_token, 'manifest_complete': True},
        )


    skipped_manifest = _write_skipped_manifest(
        args,
        cfg=cfg,
        repo_key=repo_key,
        repo_name=repo_name,
        repo_path=repo_path,
        records=skipped_records,
    )

    # Update scope.json with source_repos entry so operator-core-code.md can discover it
    eng_dir = getattr(cfg, 'engagement_dir', None)
    if eng_dir:
        scope_path = os.path.join(eng_dir, 'scope.json')
        if os.path.isfile(scope_path):
            try:
                with open(scope_path, 'r', encoding='utf-8') as f:
                    scope = json.load(f)
                source_repos = scope.get('source_repos', [])
                repo_entry = {'repo_id': repo_id, 'name': repo_name, 'path': repo_path, 'language': args.language or ''}
                # Avoid duplicates by repo_id
                if not any(r.get('repo_id') == repo_id for r in source_repos):
                    source_repos.append(repo_entry)
                scope['source_repos'] = source_repos
                with open(scope_path, 'w', encoding='utf-8') as f:
                    json.dump(scope, f, indent=2, ensure_ascii=False)
            except (json.JSONDecodeError, OSError) as e:
                print(f"Warning: could not update scope.json with source_repos: {e}", file=sys.stderr)

    # Print summary
    analyzable = len([f for f in files if f['language']])
    print("\n=== Code Ingest Summary ===")
    print(f"Repository: {repo_name} (id: {repo_id})")
    print(f"Total files: {len(files)} ({skipped} skipped)")
    print(f"Analyzable files: {analyzable}")
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

    # Generate ctags symbol index (non-blocking — failure is OK)
    try:
        result = _setup_ctags(repo_path)
        if not result.get('available'):
            print("\nSymbol index: ctags not available (install Universal ctags for better cross-references)", file=sys.stderr)
    except Exception:
        print("\nSymbol index: ctags not available", file=sys.stderr)
