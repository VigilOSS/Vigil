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
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".m": "objectivec",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".lua": "lua",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".tpl": "html",
    ".twig": "html",
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

LANGUAGE_BY_BASENAME: dict[str, str] = {
    "Makefile": "makefile",
    "CMakeLists.txt": "cmake",
    "Dockerfile": "dockerfile",
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
        "dockerfile",
        "shell",
        "lua",
        "html",
        "css",
    }
)

CANONICAL_CODE_LANGUAGES = frozenset(
    {
        "",
        *LANGUAGE_BY_EXTENSION.values(),
        *LANGUAGE_BY_BASENAME.values(),
    }
)

CODE_LANGUAGE_ALIASES = {
    "c++": "cpp",
}


def detect_language(file_path: str) -> str | None:
    """Return the canonical language for a repository-relative filename."""

    name = Path(file_path).name
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        return "dockerfile"
    named = LANGUAGE_BY_BASENAME.get(name)
    if named is not None:
        return named
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
