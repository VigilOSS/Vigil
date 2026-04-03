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
    '.git', '.svn', '__pycache__', 'node_modules', '.tox', 'venv',
})

SKIP_EXTENSIONS = frozenset({
    '.pyc', '.o', '.so', '.a', '.dylib', '.exe', '.dll',
    '.min.js', '.bundle.js', '.map',
    '.png', '.jpg', '.gif', '.ico', '.svg', '.pdf',
    '.woff', '.woff2', '.ttf', '.eot',
})


def register(subparsers) -> None:
    p = subparsers.add_parser("code-ingest", help="Ingest a code repository for analysis")
    p.add_argument("repo_path", help="Path to the repository root")
    p.add_argument("--name", default=None, help="Repository name (default: directory basename)")
    p.add_argument("--language", default=None, help="Override primary language detection")
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


def _count_lines(filepath: str) -> int:
    """Count lines in a file."""
    try:
        with open(filepath, 'rb') as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def _read_header(filepath: str, max_lines: int = 50) -> str:
    """Read the first N lines of a file as a header snippet."""
    lines = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                lines.append(line)
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

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
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
                'path': rel_path,
                'filename': filename,
                'language': lang,
                'loc': loc,
                'sha256': sha,
                'header_snippet': header,
                'churn_score': churn,
                'has_security_history': has_security_history,
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
            'name': repo_name,
            'path': repo_path,
            'primary_language': args.language,
            'has_git': has_git,
            'total_files': len(files),
            'total_loc': total_loc,
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
            created_count += resp.get('created', len(batch))

    finally:
        client.close()

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
