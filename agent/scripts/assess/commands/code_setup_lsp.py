"""assess.py code-setup-lsp — set up LSP and cross-reference infrastructure for a code repository."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


# Language detection reuses the same extension map as code_ingest
_C_EXTENSIONS = frozenset({'.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh'})
_PYTHON_EXTENSIONS = frozenset({'.py', '.pyx', '.pyi'})
_JS_TS_EXTENSIONS = frozenset({'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'})

SKIP_DIRS = frozenset({
    '.git', '.svn', '.hg', '__pycache__', 'node_modules', '.tox',
    'venv', '.venv', 'env', '.env', 'dist', 'build', 'target',
    'vendor', '.next', '.nuxt', '.expo', '.gradle', '.idea',
    '.vscode', '.vs', 'coverage', '.nyc_output',
})


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "code-setup-lsp",
        help="Set up LSP and cross-reference infrastructure for a code repository",
    )
    p.add_argument("repo_path", help="Path to the repository root")
    p.add_argument("--repo-id", required=True, type=int, help="Repository ID from code-ingest")
    p.set_defaults(func=run)


def _detect_languages(repo_path: str) -> dict[str, int]:
    """Walk repo and count files by language family."""
    counts: dict[str, int] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for filename in filenames:
            if os.path.islink(os.path.join(dirpath, filename)):
                continue
            ext = Path(filename).suffix.lower()
            if ext in _C_EXTENSIONS:
                counts['c'] = counts.get('c', 0) + 1
            elif ext in _PYTHON_EXTENSIONS:
                counts['python'] = counts.get('python', 0) + 1
            elif ext in _JS_TS_EXTENSIONS:
                counts['typescript'] = counts.get('typescript', 0) + 1
    return counts


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


def _setup_c(repo_path: str) -> dict[str, object]:
    """Set up C/C++ cross-reference infrastructure."""
    config: dict[str, object] = {
        'server': 'clangd',
        'available': False,
        'compile_commands': False,
    }

    # Check clangd
    clangd_path = _which('clangd')
    if not clangd_path:
        print("  clangd: not found", file=sys.stderr)
        return config

    config['available'] = True

    # Check for existing compile_commands.json
    cc_path = os.path.join(repo_path, 'compile_commands.json')
    build_cc_path = os.path.join(repo_path, 'build', 'compile_commands.json')
    if os.path.isfile(cc_path) or os.path.isfile(build_cc_path):
        config['compile_commands'] = True
        print("  clangd: available, compile_commands.json found")
        return config

    # Try CMake
    cmake_path = os.path.join(repo_path, 'CMakeLists.txt')
    if os.path.isfile(cmake_path) and _which('cmake'):
        try:
            subprocess.run(
                ['cmake', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-B', 'build', '-S', '.'],
                cwd=repo_path, capture_output=True, timeout=120,
            )
            if os.path.isfile(build_cc_path):
                # Symlink to root for clangd
                if not os.path.exists(cc_path):
                    os.symlink(build_cc_path, cc_path)
                config['compile_commands'] = True
                print("  clangd: available, compile_commands.json generated via CMake")
                return config
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Try bear
    makefile_path = os.path.join(repo_path, 'Makefile')
    if os.path.isfile(makefile_path) and _which('bear'):
        try:
            subprocess.run(
                ['bear', '--', 'make', '-j4'],
                cwd=repo_path, capture_output=True, timeout=120,
            )
            if os.path.isfile(cc_path):
                config['compile_commands'] = True
                print("  clangd: available, compile_commands.json generated via bear")
                return config
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Try compiledb
    if os.path.isfile(makefile_path) and _which('compiledb'):
        try:
            subprocess.run(
                ['compiledb', '-n', 'make'],
                cwd=repo_path, capture_output=True, timeout=120,
            )
            if os.path.isfile(cc_path):
                config['compile_commands'] = True
                print("  clangd: available, compile_commands.json generated via compiledb")
                return config
        except (subprocess.TimeoutExpired, OSError):
            pass

    # Last resort: generate synthetic compile_commands.json
    print("  clangd: generating synthetic compile_commands.json...", file=sys.stderr)
    _generate_synthetic_compile_commands(repo_path)
    if os.path.isfile(cc_path):
        config['compile_commands'] = True
        print("  clangd: available, synthetic compile_commands.json generated")
    else:
        print("  clangd: available but no compile_commands.json (limited navigation)")

    return config


def _generate_synthetic_compile_commands(repo_path: str) -> None:
    """Generate a minimal compile_commands.json by walking C/C++ files."""
    # Detect include directories
    include_dirs: set[str] = set()
    source_files: list[str] = []

    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for filename in filenames:
            if os.path.islink(os.path.join(dirpath, filename)):
                continue
            ext = Path(filename).suffix.lower()
            if ext in ('.c', '.cpp', '.cc', '.cxx'):
                filepath = os.path.join(dirpath, filename)
                source_files.append(filepath)
            elif ext in ('.h', '.hpp', '.hh'):
                include_dirs.add(dirpath)

    if not source_files:
        return

    # Build include flags
    include_flags = []
    for d in sorted(include_dirs):
        rel = os.path.relpath(d, repo_path)
        include_flags.extend(['-I', rel])

    # Generate compile_commands.json
    entries = []
    for filepath in source_files:
        rel = os.path.relpath(filepath, repo_path)
        ext = Path(filepath).suffix.lower()
        compiler = 'cc' if ext == '.c' else 'c++'
        cmd = [compiler, '-c', rel] + include_flags
        entries.append({
            'directory': repo_path,
            'command': ' '.join(cmd),
            'file': rel,
        })

    cc_path = os.path.join(repo_path, 'compile_commands.json')
    with open(cc_path, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2)


def _setup_python(repo_path: str) -> dict[str, object]:
    """Set up Python cross-reference infrastructure."""
    config: dict[str, object] = {
        'server': 'pyright-langserver',
        'available': False,
    }

    # Check for pyright
    pyright_path = _which('pyright-langserver') or _which('pyright')
    if not pyright_path:
        print("  pyright: not found", file=sys.stderr)
        return config

    config['available'] = True

    # Check for existing pyrightconfig.json
    pyright_config = os.path.join(repo_path, 'pyrightconfig.json')
    if not os.path.isfile(pyright_config):
        # Generate minimal config
        pyright_conf = {
            'include': ['.'],
            'exclude': ['**/node_modules', '**/__pycache__', '**/.*'],
        }
        # Detect venv
        for venv_name in ('.venv', 'venv', 'env'):
            venv_path = os.path.join(repo_path, venv_name)
            if os.path.isdir(venv_path):
                pyright_conf['venvPath'] = '.'
                pyright_conf['venv'] = venv_name
                break
        with open(pyright_config, 'w', encoding='utf-8') as f:
            json.dump(pyright_conf, f, indent=2)
        print("  pyright: available, pyrightconfig.json generated")
    else:
        print("  pyright: available, pyrightconfig.json found")

    return config


def _setup_typescript(repo_path: str) -> dict[str, object]:
    """Set up TypeScript/JavaScript cross-reference infrastructure."""
    config: dict[str, object] = {
        'server': 'typescript-language-server',
        'available': False,
    }

    # Check for typescript-language-server
    ts_path = _which('typescript-language-server')
    if not ts_path:
        print("  typescript-language-server: not found", file=sys.stderr)
        return config

    config['available'] = True

    # Check for existing tsconfig.json or jsconfig.json
    tsconfig = os.path.join(repo_path, 'tsconfig.json')
    jsconfig = os.path.join(repo_path, 'jsconfig.json')
    if not os.path.isfile(tsconfig) and not os.path.isfile(jsconfig):
        # Generate minimal jsconfig.json
        js_conf = {
            'compilerOptions': {
                'target': 'es2020',
                'module': 'commonjs',
                'checkJs': True,
            },
            'include': ['.'],
            'exclude': ['node_modules', 'dist', 'build'],
        }
        with open(jsconfig, 'w', encoding='utf-8') as f:
            json.dump(js_conf, f, indent=2)
        print("  typescript-language-server: available, jsconfig.json generated")
    else:
        existing = 'tsconfig.json' if os.path.isfile(tsconfig) else 'jsconfig.json'
        print(f"  typescript-language-server: available, {existing} found")

    return config


def _setup_ctags(repo_path: str) -> dict[str, object]:
    """Set up ctags symbol index as fallback."""
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
            # BSD ctags (macOS default) — no -R flag, must list files explicitly
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
            # Count tags
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


def run(args) -> None:
    repo_path = os.path.abspath(args.repo_path)
    if not os.path.isdir(repo_path):
        print(f"Repository path not found: {repo_path}", file=sys.stderr)
        sys.exit(1)

    repo_id = args.repo_id
    print(f"Setting up cross-reference infrastructure for repo {repo_id} at {repo_path}")

    # Detect languages
    lang_counts = _detect_languages(repo_path)
    print(f"\nDetected languages: {lang_counts}")

    lsp_config: dict[str, object] = {
        'languages': {},
        'ctags': {},
        'env_required': 'ENABLE_LSP_TOOL=1',
    }

    # Set up language-specific infrastructure
    languages: dict[str, object] = {}

    if lang_counts.get('c', 0) > 0:
        print("\n[C/C++]")
        languages['c'] = _setup_c(repo_path)

    if lang_counts.get('python', 0) > 0:
        print("\n[Python]")
        languages['python'] = _setup_python(repo_path)

    if lang_counts.get('typescript', 0) > 0:
        print("\n[TypeScript/JavaScript]")
        languages['typescript'] = _setup_typescript(repo_path)

    lsp_config['languages'] = languages

    # Always try ctags as fallback
    print("\n[ctags fallback]")
    lsp_config['ctags'] = _setup_ctags(repo_path)

    # Write lsp-config.json to repo directory
    config_path = os.path.join(repo_path, 'lsp-config.json')
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(lsp_config, f, indent=2)

    # PATCH repo record with lsp_config_json
    cfg = load_config(args.engagement_dir)
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        client.patch(f'code/repos/{repo_id}', {'lsp_config_json': lsp_config})
    except Exception as e:
        print(f"Warning: failed to update repo record: {e}", file=sys.stderr)
    finally:
        client.close()

    # Print summary
    available_lsps = [
        lang for lang, conf in languages.items()
        if isinstance(conf, dict) and conf.get('available')
    ]
    ctags_status = lsp_config.get('ctags', {})
    ctags_avail = ctags_status.get('available', False) if isinstance(ctags_status, dict) else False

    print(f"\n=== LSP Setup Complete ===")
    for lang, conf in languages.items():
        if isinstance(conf, dict):
            status = 'available' if conf.get('available') else 'not available'
            print(f"  {lang}: {conf.get('server', '?')} ({status})")
    ctags_kind = 'Universal' if (isinstance(ctags_status, dict) and ctags_status.get('universal')) else 'BSD, limited'
    print(f"  ctags: {'available' if ctags_avail else 'not available'} ({ctags_kind})")

    print(f"\nTo enable LSP for subagents:")
    print(f"  Claude Code: export ENABLE_LSP_TOOL=1")
    print(f"  Codex CLI:   LSP is auto-detected from compile_commands.json / language server configs")
    print(f"\nConfig written to: {config_path}")
