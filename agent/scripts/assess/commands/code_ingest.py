"""assess.py code-ingest — walk a repo, fingerprint files, POST to code analysis backend."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


LANG_MAP = {
    '.c': 'c', '.h': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
    '.py': 'python', '.pyx': 'python',
    '.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.go': 'go', '.rs': 'rust', '.java': 'java', '.kt': 'kotlin',
    '.rb': 'ruby', '.php': 'php', '.swift': 'swift', '.m': 'objectivec',
    '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell',
    '.sql': 'sql', '.html': 'html', '.css': 'css', '.xml': 'xml',
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


_C_EXTENSIONS = frozenset({'.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh'})
_PYTHON_EXTENSIONS = frozenset({'.py', '.pyx', '.pyi'})
_JS_TS_EXTENSIONS = frozenset({'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'})


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
                    if os.path.islink(os.path.join(dirpath, filename)):
                        continue
                    ext = Path(filename).suffix.lower()
                    if ext in _C_EXTENSIONS or ext in _PYTHON_EXTENSIONS or ext in _JS_TS_EXTENSIONS:
                        source_files.append(os.path.join(dirpath, filename))
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
    p.add_argument("--language", default=None, help="Override primary language detection")
    p.add_argument("--repo-key", default=None, help="Explicit repository key (default: stable name+path hash)")
    p.set_defaults(func=run)


def _should_skip_file(rel_path: str, filename: str) -> bool:
    """Return True if the file should be skipped based on patterns."""
    ext = Path(filename).suffix.lower()
    if ext in SKIP_EXTENSIONS:
        return True
    # Check for compound extensions like .min.js, .bundle.js
    lower_name = filename.lower()
    if lower_name.endswith('.min.js') or lower_name.endswith('.bundle.js'):
        return True
    # Check for .woff variants
    if lower_name.endswith('.woff') or lower_name.endswith('.woff2'):
        return True
    return False


def _detect_language(filename: str) -> str | None:
    """Detect programming language from filename or extension."""
    # Check full filename first (Makefile, Dockerfile, CMakeLists.txt)
    if filename in LANG_MAP:
        return LANG_MAP[filename]
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


def _git_churn_scores(repo_path: str) -> dict[str, int]:
    """Compute per-file churn scores from git log --numstat over the last year."""
    churn: dict[str, int] = {}
    try:
        result = subprocess.run(
            ['git', 'log', '--numstat', '--since=1year', '--format=%H'],
            capture_output=True, text=True, cwd=repo_path, timeout=120,
        )
        if result.returncode != 0:
            return churn
        for line in result.stdout.splitlines():
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
    except (subprocess.TimeoutExpired, OSError):
        pass
    return churn


def _git_security_files(repo_path: str) -> set[str]:
    """Identify files with past security-related commits."""
    sec_files: set[str] = set()
    try:
        result = subprocess.run(
            [
                'git', 'log', '--all',
                '--grep=CVE\\|security\\|vulnerability\\|fix.*vuln\\|buffer.overflow\\|use.after.free',
                '--oneline', '--name-only',
            ],
            capture_output=True, text=True, cwd=repo_path, timeout=120,
        )
        if result.returncode != 0:
            return sec_files
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip the oneline commit summary (contains a hash prefix)
            if ' ' in line and len(line.split()[0]) >= 7:
                # Likely a commit summary line like "abc1234 Fix security bug"
                continue
            # This is a filename
            sec_files.add(line)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return sec_files


def run(args) -> None:
    repo_path = os.path.abspath(args.repo_path)
    if not os.path.isdir(repo_path):
        print(f"Repository path not found: {repo_path}", file=sys.stderr)
        sys.exit(1)

    repo_name = args.name or os.path.basename(repo_path)
    has_git = os.path.isdir(os.path.join(repo_path, '.git'))

    # Collect git metadata if available
    churn_scores: dict[str, int] = {}
    security_files: set[str] = set()
    if has_git:
        print("Scanning git history for churn and security commits...", file=sys.stderr)
        churn_scores = _git_churn_scores(repo_path)
        security_files = _git_security_files(repo_path)

    # Walk the directory tree
    files = []
    total_loc = 0
    skipped = 0

    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Prune skip directories
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        # Skip symlinked directories to prevent traversal outside repo
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)

            # Skip symlinks — prevents traversal to /etc/passwd or outside the repo
            if os.path.islink(filepath):
                skipped += 1
                continue

            rel_path = os.path.relpath(filepath, repo_path)

            if _should_skip_file(rel_path, filename):
                skipped += 1
                continue

            lang = _detect_language(filename)
            if args.language and lang is None:
                lang = args.language

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
        print("No analyzable files found.", file=sys.stderr)
        sys.exit(1)

    # POST to backend
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        # Create the repo record
        repo_payload = {
            'repo_key': args.repo_key or _repo_key_for_path(repo_name, repo_path),
            'name': repo_name,
            'language': args.language or '',
            'repo_path': repo_path,
            'total_files': len(files) + skipped,
            'analyzable_files': len(files),
            'total_loc': total_loc,
            'git_churn': {'churn_scores': dict(sorted(churn_scores.items(), key=lambda x: -x[1])[:30])} if churn_scores else {},
        }
        repo_resp = client.post('code/repos', repo_payload)
        repo_id = repo_resp.get('id') or repo_resp.get('repo_id')
        if not repo_id:
            print("Backend did not return a repo ID", file=sys.stderr)
            sys.exit(1)

        # Bulk-create files in batches
        batch_size = 200
        created_count = 0
        for i in range(0, len(files), batch_size):
            batch = files[i:i + batch_size]
            files_payload = {
                'repo_id': repo_id,
                'files': batch,
            }
            resp = client.post('code/files', files_payload)
            created_count += resp.get('inserted', len(batch))

    finally:
        client.close()

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
    analyzable = len([f for f in files if f['language'] is not None])
    print(f"\n=== Code Ingest Summary ===")
    print(f"Repository: {repo_name} (id: {repo_id})")
    print(f"Total files: {len(files)} ({skipped} skipped)")
    print(f"Analyzable files: {analyzable}")
    print(f"Total LOC: {total_loc:,}")

    if churn_scores:
        # Top 10 highest-churn files
        sorted_churn = sorted(churn_scores.items(), key=lambda x: x[1], reverse=True)[:10]
        print(f"\nTop 10 highest-churn files (last year):")
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
