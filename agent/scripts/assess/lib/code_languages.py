"""Canonical filename-to-language classification for code ingestion and indexing."""
from __future__ import annotations

from pathlib import Path


LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".py": "python",
    ".pyi": "python",
    ".pyx": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    # TypeScript's explicit module-kind extensions, the `.mjs`/`.cjs` pair's
    # typed siblings. Node resolves them as ESM/CJS; tree-sitter reads them as
    # TypeScript like any other.
    ".mts": "typescript",
    ".cts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    # Gradle's Kotlin DSL. `build.gradle.kts` is the dependency-declaring
    # surface of a Kotlin-DSL build and is literally Kotlin script.
    ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    # C# script files (`dotnet script`, Roslyn `.csx`). Same language as `.cs`;
    # tree-sitter reads them with the C# grammar like any other source.
    ".csx": "csharp",
    ".swift": "swift",
    ".m": "objectivec",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".lua": "lua",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".tpl": "html",
    ".twig": "html",
    # FreeMarker server templates. ``.ftlh``/``.ftlx`` are the same language
    # with an implied HTML/XML output format.
    ".ftl": "freemarker",
    ".ftlh": "freemarker",
    ".ftlx": "freemarker",
    ".css": "css",
    ".scss": "css",
    ".xml": "xml",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".md": "markdown",
    ".txt": "text",
    ".rst": "rst",
}

# Suffixes the `Path(name).suffix` lookup below can never see, because it only
# ever returns the last extension. A Blade template is `.blade.php`, and
# reading it as PHP hands a template full of `{{ }}`/`{!! !!}` directives to
# the PHP grammar, which parses them as inline text and reports nothing.
# Matched before the single-suffix table, longest key first.
LANGUAGE_BY_COMPOUND_SUFFIX: dict[str, str] = {
    ".blade.php": "blade",
}

LANGUAGE_BY_BASENAME: dict[str, str] = {
    "Makefile": "makefile",
    "CMakeLists.txt": "cmake",
    "Dockerfile": "dockerfile",
    # Dependency surfaces whose extension says nothing but whose content is a
    # language Vigil already names. Classifying them honestly keeps lockfiles
    # out of the unknown-language bucket that made them invisible at ingest.
    "Pipfile": "toml",
    "Pipfile.lock": "json",
    "poetry.lock": "toml",
}

STRUCTURAL_SUPPORTED_LANGUAGES = frozenset(
    {
        "java",
        "c",
        "cpp",
        "python",
        "javascript",
        "typescript",
        "go",
        "ruby",
        "php",
        "csharp",
        "blade",
        "dockerfile",
        "shell",
        "powershell",
        "lua",
        "html",
        "css",
        "freemarker",
    }
)

CANONICAL_CODE_LANGUAGES = frozenset(
    {
        "",
        *LANGUAGE_BY_EXTENSION.values(),
        *LANGUAGE_BY_COMPOUND_SUFFIX.values(),
        *LANGUAGE_BY_BASENAME.values(),
    }
)

CODE_LANGUAGE_ALIASES = {
    "c++": "cpp",
}

# Longest first, so a future `.foo.blade.php` cannot be decided by a shorter
# sibling key that happens to be scanned earlier.
_COMPOUND_SUFFIXES: tuple[tuple[str, str], ...] = tuple(
    sorted(LANGUAGE_BY_COMPOUND_SUFFIX.items(), key=lambda item: -len(item[0]))
)


def detect_language(file_path: str) -> str | None:
    """Return the canonical language for a repository-relative filename."""

    name = Path(file_path).name
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "dockerfile"
    named = LANGUAGE_BY_BASENAME.get(name)
    if named is not None:
        return named
    lowered = name.lower()
    for suffix, language in _COMPOUND_SUFFIXES:
        if lowered.endswith(suffix) and lowered != suffix:
            return language
    return LANGUAGE_BY_EXTENSION.get(Path(name).suffix.lower())


def structural_language_for_file(file_path: str) -> str | None:
    """Return a language only when Vigil has a structural extractor for it."""

    language = detect_language(file_path)
    return language if language in STRUCTURAL_SUPPORTED_LANGUAGES else None


def canonical_backend_language(value: object) -> str:
    """Return the exact parser identity for a backend language classification.

    Backend classification is authoritative after ingest, including explicit
    non-structural and unknown-empty values. Only documented aliases are
    normalized; arbitrary labels must not silently fall back to the filename.
    """

    if not isinstance(value, str) or value != value.strip():
        raise ValueError("backend language classification must be a trimmed string")
    canonical = CODE_LANGUAGE_ALIASES.get(value, value)
    if canonical not in CANONICAL_CODE_LANGUAGES:
        raise ValueError(f"unsupported backend language classification: {value!r}")
    return canonical
