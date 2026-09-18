"""Deterministic readers for the dependency-declaring files in a sealed snapshot.

A code engagement almost never starts from someone else's scan. It starts from
source, and the question source can answer is the one a scan cannot: what does
this build *ship*, as opposed to what does it *declare*? The two differ in ways
that decide whether a component is worth a reviewer's time at all --
``provided``/``compileOnly`` entries the container supplies, shaded artifacts
that ship under another name, peer dependencies the host application owns, and
copies vendored into the tree with no declaration anywhere.

This module owns the first half of that: the roster of files that declare
dependencies, and one reader per file format. Every reader is pure -- same bytes
in, same records out, no clock, no filesystem, no network -- so the command
layer stays I/O-only and the verdicts are reproducible. Nothing here decides
whether a component ships; readers report what the file *says*, verbatim, with
the line it said it on. ``dependency_picture`` turns those statements into
observations.

Formats with no reader are still rostered. An unread ``composer.json`` in the
tree is a hole in the picture, not an absence, and it is reported as one.
"""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Callable, Sequence
from xml.parsers import expat


@dataclass(frozen=True)
class Evidence:
    """One verbatim citation: where a statement was read, and what it said."""

    path: str
    line: int
    text: str


@dataclass(frozen=True)
class DeclaredDependency:
    """One dependency statement, exactly as a build file made it.

    Nothing here is a conclusion. ``declared_scope`` is the verbatim token the
    file used; whether that token means the component ships is decided in
    ``dependency_picture`` against the ecosystem's rules, and is recorded there
    as an observation rather than a verdict. ``qualifiers`` are reader-level
    facts in an open vocabulary (``optional``, ``marker:...``); the derivation's
    own closed ``unverified_*`` vocabulary is a separate field on the
    observation, so a build-file word can never be mistaken for a Vigil verdict.
    """

    ecosystem: str
    coordinate: str
    version: str
    version_source: str
    declared_scope: str
    declaration: str
    manifest_path: str
    module_path: str
    evidence: tuple[Evidence, ...] = ()
    qualifiers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Relocation:
    """A shade/shadow rule that republishes packages under another prefix."""

    source_prefix: str
    shaded_prefix: str
    evidence: Evidence


@dataclass(frozen=True)
class BuildFacts:
    """What a build file says about the artifact it produces, not its inputs."""

    packaging: str = ""
    relocations: tuple[Relocation, ...] = ()


@dataclass(frozen=True)
class AnalysisGap:
    """Something the reader could not settle, named so it cannot pass as absence."""

    path: str
    gap: str
    detail: str = ""


@dataclass(frozen=True)
class ManifestParse:
    """The complete result of reading one dependency-declaring file."""

    kind: str
    path: str
    module_path: str
    ecosystem: str = ""
    dependencies: tuple[DeclaredDependency, ...] = ()
    facts: BuildFacts = field(default_factory=BuildFacts)
    gaps: tuple[AnalysisGap, ...] = ()


# --------------------------------------------------------------------------- #
# The roster
#
# One table for every file Vigil recognizes as declaring dependencies, keyed by
# the exact basename, mapping to the reader kind. This is the single source of
# truth for the roster: `classify_buckets` derives its web-recon URL fragments
# from it rather than keeping a second hand-typed list, so an ecosystem is added
# in exactly one place.
#
# A name is in this table only when it is unambiguous wherever it appears --
# `pom.xml` is a Maven POM anywhere in a tree, while a bare `requirements.txt`
# needs the pattern rule below and `modules.txt` needs a `vendor/` parent.
# --------------------------------------------------------------------------- #
RECOGNIZED_MANIFESTS: dict[str, str] = {
    "pom.xml": "maven_pom",
    "build.gradle": "gradle_build",
    "build.gradle.kts": "gradle_build",
    "settings.gradle": "gradle_settings",
    "settings.gradle.kts": "gradle_settings",
    "gradle.lockfile": "gradle_lockfile",
    "libs.versions.toml": "gradle_version_catalog",
    "package.json": "npm_package",
    "package-lock.json": "npm_lock",
    "npm-shrinkwrap.json": "npm_lock",
    "yarn.lock": "yarn_lock",
    "pnpm-lock.yaml": "pnpm_lock",
    "go.mod": "go_mod",
    "go.sum": "go_sum",
    "pyproject.toml": "python_pyproject",
    "requirements.txt": "python_requirements",
    "Pipfile": "python_pipfile",
    "Pipfile.lock": "python_pipfile_lock",
    "poetry.lock": "python_poetry_lock",
    "composer.json": "composer_manifest",
    "composer.lock": "composer_lock",
    "Gemfile": "bundler_manifest",
    "Gemfile.lock": "bundler_lock",
    "Cargo.toml": "cargo_manifest",
    "Cargo.lock": "cargo_lock",
}

ECOSYSTEM_BY_KIND: dict[str, str] = {
    "maven_pom": "maven",
    "gradle_build": "gradle",
    "gradle_settings": "gradle",
    "gradle_lockfile": "gradle",
    "gradle_version_catalog": "gradle",
    "npm_package": "npm",
    "npm_lock": "npm",
    "yarn_lock": "npm",
    "pnpm_lock": "npm",
    "go_mod": "go",
    "go_sum": "go",
    "go_vendor_modules": "go",
    "python_pyproject": "python",
    "python_requirements": "python",
    "python_pipfile": "python",
    "python_pipfile_lock": "python",
    "python_poetry_lock": "python",
    "composer_manifest": "composer",
    "composer_lock": "composer",
    "bundler_manifest": "bundler",
    "bundler_lock": "bundler",
    "cargo_manifest": "cargo",
    "cargo_lock": "cargo",
}

# `requirements-dev.txt`, `requirements/base.txt`, ... are the same format under
# a hundred names, so the roster matches the family by pattern. The `-dev`/
# `-test` suffix is NOT read as "not shipped": a suffix is a filename, and the
# picture records what the file says, not what its name implies.
_REQUIREMENTS_RE = re.compile(r"^requirements[\w.-]*\.txt$", re.IGNORECASE)
_REQUIREMENTS_DIR = "requirements"

# `modules.txt` is only a Go vendor inventory directly under `vendor/`.
_GO_VENDOR_MODULES = "vendor/modules.txt"

# Directories that hold a build file by convention rather than owning a module,
# so the module a file belongs to is its grandparent.
_CONVENTION_DIRS = frozenset({"gradle", "vendor", _REQUIREMENTS_DIR})


def manifest_kind_for_path(rel_path: str) -> str | None:
    """Return the reader kind for a repository-relative path, or None."""

    posix = PurePosixPath(rel_path.replace("\\", "/"))
    name = posix.name
    if not name:
        return None
    if posix.as_posix() == _GO_VENDOR_MODULES or posix.as_posix().endswith(
        f"/{_GO_VENDOR_MODULES}"
    ):
        return "go_vendor_modules"
    kind = RECOGNIZED_MANIFESTS.get(name)
    if kind is not None:
        return kind
    if _REQUIREMENTS_RE.match(name):
        return "python_requirements"
    # `requirements/base.txt` is the split-requirements convention; only a
    # `.txt` directly inside a directory named `requirements` qualifies, so an
    # ordinary `docs/base.txt` is not swept in.
    if posix.suffix.lower() == ".txt" and posix.parent.name == _REQUIREMENTS_DIR:
        return "python_requirements"
    return None


def module_path_for_manifest(rel_path: str) -> str:
    """Return the module directory a manifest belongs to."""

    parent = PurePosixPath(rel_path.replace("\\", "/")).parent
    if parent.name in _CONVENTION_DIRS:
        parent = parent.parent
    text = parent.as_posix()
    return "" if text == "." else text


def url_path_fragments() -> tuple[str, ...]:
    """Boundary-anchored URL fragments for the rostered manifest filenames.

    An exposed manifest on a live host is the same dependency-disclosure signal
    as one found in source, so the web-recon classifier consumes this roster
    instead of keeping its own partial copy. Only the exact-filename roster is
    exported: the pattern rules above widen on a directory context a URL path
    does not carry.
    """

    return tuple(sorted({f"/{name.lower()}" for name in RECOGNIZED_MANIFESTS}))


def parse_manifest(kind: str, rel_path: str, text: str) -> ManifestParse:
    """Read one dependency-declaring file. Pure: same bytes in, same records out."""

    module_path = module_path_for_manifest(rel_path)
    ecosystem = ECOSYSTEM_BY_KIND.get(kind, "")
    reader = _READERS.get(kind)
    if reader is None:
        return ManifestParse(
            kind=kind,
            path=rel_path,
            module_path=module_path,
            ecosystem=ecosystem,
            gaps=(
                AnalysisGap(
                    path=rel_path,
                    gap="unparsed_ecosystem",
                    detail=(
                        f"{kind} is recognized but has no reader; this ecosystem's "
                        "components are absent from the picture, not absent from the build"
                    ),
                ),
            ),
        )
    context = _ReaderContext(
        kind=kind,
        path=rel_path,
        module_path=module_path,
        ecosystem=ecosystem,
        text=text,
        lines=text.splitlines(),
    )
    try:
        return reader(context)
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        # A build file is project-supplied text in an open shape: a key a reader
        # expects to be a table can be a string, and chaining onto it raises.
        # One file that defeats its reader is a hole in that file -- the same
        # discipline the index loader already applies -- never a lost run.
        AttributeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        return ManifestParse(
            kind=kind,
            path=rel_path,
            module_path=module_path,
            ecosystem=ecosystem,
            gaps=(AnalysisGap(path=rel_path, gap="unreadable_manifest", detail=str(exc)),),
        )


# --------------------------------------------------------------------------- #
# Reader plumbing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _ReaderContext:
    kind: str
    path: str
    module_path: str
    ecosystem: str
    text: str
    lines: list[str]
    # Quoted text per line number. Records that cite one line share one string:
    # a minified manifest is a single megabyte-long line, and a copy per record
    # would turn one large file into hundreds of megabytes of identical text.
    quoted_lines: dict[int, str] = field(default_factory=dict, compare=False, repr=False)

    def parse(self, **kwargs) -> ManifestParse:
        return ManifestParse(
            kind=self.kind,
            path=self.path,
            module_path=self.module_path,
            ecosystem=self.ecosystem,
            **kwargs,
        )

    def evidence(self, line: int, text: str) -> Evidence:
        return Evidence(path=self.path, line=line, text=_quote(text))

    def evidence_at(self, line: int, fallback: str = "") -> Evidence:
        """Evidence quoting the file's own line, or `fallback` if there is none."""

        if not line:
            return Evidence(path=self.path, line=0, text=_quote(fallback))
        quoted = self.quoted_lines.get(line)
        if quoted is None:
            quoted = _quote(self.lines[line - 1])
            self.quoted_lines[line] = quoted
        return Evidence(path=self.path, line=line, text=quoted)

    def line_span(self, start: int, end: int) -> str:
        return " ".join(part.strip() for part in self.lines[start - 1 : end] if part.strip())

    def line_in_span(self, needle: str, span: tuple[int, int]) -> int:
        """The first line inside `span` that quotes `needle`, else the span start.

        Bounded on purpose: searching a whole file for a statement finds the
        first line that happens to contain it, which for a requirement repeated
        in two tables is the other table's line.
        """
        start, end = span
        for number in range(max(start, 1), min(end, len(self.lines)) + 1):
            if needle in self.lines[number - 1]:
                return number
        return start


def _quote(text: str) -> str:
    """Collapse whitespace; quote everything else verbatim.

    Length is the renderer's problem (ADR 0019): a record that truncates loses
    text `--json` can never get back, so the cap lives where it can state the
    elision instead.
    """

    return " ".join(text.split())


def _dependency(
    context: _ReaderContext,
    *,
    coordinate: str,
    version: str = "",
    version_source: str = "unresolved",
    declared_scope: str = "",
    declaration: str = "direct",
    evidence: tuple[Evidence, ...] = (),
    qualifiers: tuple[str, ...] = (),
) -> DeclaredDependency:
    return DeclaredDependency(
        ecosystem=context.ecosystem,
        coordinate=coordinate,
        version=version,
        version_source=version_source if version else "unresolved",
        declared_scope=declared_scope,
        declaration=declaration,
        manifest_path=context.path,
        module_path=context.module_path,
        evidence=evidence,
        qualifiers=qualifiers,
    )


def _table(
    value: Any, *, path: str, name: str, gaps: list[AnalysisGap]
) -> dict[str, Any]:
    """A table, or an empty one plus a gap naming the block that was not one.

    `tool = "setuptools"` is valid TOML and is not a table. Reading it as one
    raises, and the raise costs the operator every other manifest in the run, so
    a block that cannot be read is reported as a hole in this file rather than
    passing as an absence of declarations.
    """

    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    gaps.append(
        AnalysisGap(
            path=path,
            gap="unreadable_declaration_block",
            detail=(
                f"`{name}` is {type(value).__name__}, not a table; whatever it "
                "declares is absent from the picture, not absent from the build"
            ),
        )
    )
    return {}


# --------------------------------------------------------------------------- #
# Where a key was written
#
# A record cites the line its statement was made on, and the same name appears
# in several places in one file -- `lodash` in `overrides` and in
# `devDependencies` at different versions, one requirement in two tables, one
# package locked twice. Searching the whole file for the name finds the first of
# those, so every reader would quote a line stating a different fact than the
# record holds. Each index below is built in ONE pass and answers by path, which
# also takes lockfile reading from quadratic to linear.
# --------------------------------------------------------------------------- #


@dataclass
class _JsonFrame:
    is_object: bool
    current_key: str | None = None


def _json_key_lines(text: str) -> dict[tuple[str, ...], int]:
    """The line each JSON key was written on, keyed by its path from the root.

    Array elements contribute no path segment: no reader needs to cite one, and
    every key a reader does look up is reached through object members.
    """

    found: dict[tuple[str, ...], int] = {}
    stack: list[_JsonFrame] = []
    expect_key = False
    line = 1
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\n":
            line += 1
            index += 1
        elif char == '"':
            start_line = line
            index += 1
            chunk: list[str] = []
            while index < length:
                current = text[index]
                if current == "\\" and index + 1 < length:
                    chunk.append(text[index : index + 2])
                    index += 2
                    continue
                if current == '"':
                    break
                if current == "\n":
                    line += 1
                chunk.append(current)
                index += 1
            index += 1
            if expect_key and stack:
                raw = "".join(chunk)
                key = _json_string(raw)
                prefix = tuple(
                    frame.current_key
                    for frame in stack[:-1]
                    if frame.is_object and frame.current_key is not None
                )
                found.setdefault(prefix + (key,), start_line)
                stack[-1].current_key = key
                expect_key = False
        elif char in "{[":
            stack.append(_JsonFrame(is_object=char == "{"))
            expect_key = char == "{"
            index += 1
        elif char in "}]":
            if stack:
                stack.pop()
            expect_key = False
            index += 1
        elif char == ",":
            expect_key = bool(stack) and stack[-1].is_object
            index += 1
        else:
            index += 1
    return found


def _json_string(raw: str) -> str:
    if "\\" not in raw:
        return raw
    try:
        decoded = json.loads(f'"{raw}"')
    except ValueError:
        return raw
    return decoded if isinstance(decoded, str) else raw


_TOML_SEGMENT = r"(?:[A-Za-z0-9_-]+|\"[^\"]*\"|'[^']*')"
_TOML_HEADER_RE = re.compile(
    rf"^\s*(?P<array>\[\[|\[)\s*(?P<path>{_TOML_SEGMENT}(?:\s*\.\s*{_TOML_SEGMENT})*)\s*\]"
)
_TOML_KEY_RE = re.compile(
    rf"^\s*(?P<key>{_TOML_SEGMENT}(?:\s*\.\s*{_TOML_SEGMENT})*)\s*="
)
_TOML_STRING_RE = re.compile(r"\"[^\"]*\"|'[^']*'")


def _toml_path(text: str) -> tuple[str, ...]:
    return tuple(
        segment.strip().strip("\"'") for segment in re.split(r"\s*\.\s*", text.strip())
    )


def _toml_key_lines(lines: Sequence[str]) -> dict[tuple[str, ...], tuple[int, int]]:
    """The line span each TOML key occupies, keyed by its full table path.

    An array-of-tables occurrence carries its index (`("package", "3", "name")`)
    so two entries for one package are told apart, and a key whose value runs
    over several lines carries the whole span, which is what lets a reader cite
    the element's own line inside a multi-line array.
    """

    found: dict[tuple[str, ...], tuple[int, int]] = {}
    table: tuple[str, ...] = ()
    array_prefix: tuple[str, ...] = ()
    array_indexed: tuple[str, ...] = ()
    array_counts: dict[tuple[str, ...], int] = {}
    for offset, raw in enumerate(lines):
        number = offset + 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        header = _TOML_HEADER_RE.match(raw)
        if header is not None:
            declared = _toml_path(header.group("path"))
            if header.group("array") == "[[":
                index = array_counts.get(declared, 0)
                array_counts[declared] = index + 1
                array_prefix = declared
                array_indexed = declared + (str(index),)
                table = array_indexed
            elif array_prefix and declared[: len(array_prefix)] == array_prefix:
                # A sub-table of the array entry currently being written.
                table = array_indexed + declared[len(array_prefix) :]
            else:
                array_prefix = ()
                array_indexed = ()
                table = declared
            continue
        key = _TOML_KEY_RE.match(raw)
        if key is None:
            continue
        path = table + _toml_path(key.group("key"))
        found.setdefault(path, (number, _toml_value_end(lines, offset)))
    return found


def _toml_value_end(lines: Sequence[str], offset: int) -> int:
    """The last line of the value that starts on `lines[offset]`."""

    depth = 0
    for index in range(offset, len(lines)):
        bare = _TOML_STRING_RE.sub("", lines[index])
        depth += bare.count("[") + bare.count("{") - bare.count("]") - bare.count("}")
        if depth <= 0:
            return index + 1
    return len(lines)


# --------------------------------------------------------------------------- #
# Maven
#
# Read through expat rather than ElementTree for two reasons: expat reports the
# line each element opened on, which is what makes a Maven record auditable, and
# it lets entity handling be refused outright. A POM is project-supplied text;
# expanding entities buys an element reader nothing and only adds an
# expansion-bomb surface, so a DTD entity declaration is a read failure.
# --------------------------------------------------------------------------- #


class _XmlRefused(ValueError):
    pass


@dataclass(frozen=True)
class _XmlNode:
    tag: str
    line: int
    end_line: int
    text: str
    children: tuple["_XmlNode", ...]

    def first(self, tag: str) -> "_XmlNode | None":
        for child in self.children:
            if child.tag == tag:
                return child
        return None

    def value(self, tag: str) -> str:
        child = self.first(tag)
        return child.text.strip() if child is not None else ""

    def all(self, tag: str) -> tuple["_XmlNode", ...]:
        return tuple(child for child in self.children if child.tag == tag)

    def descendants(self, tag: str):
        for child in self.children:
            if child.tag == tag:
                yield child
            yield from child.descendants(tag)


def _local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _read_xml(text: str) -> _XmlNode:
    parser = expat.ParserCreate()
    parser.buffer_text = True
    stack: list[dict[str, Any]] = []
    root: list[_XmlNode] = []

    def refuse_entity(*_args) -> None:
        raise _XmlRefused("entity declarations are refused in dependency manifests")

    def refuse_external(*_args) -> int:
        return 0

    parser.EntityDeclHandler = refuse_entity
    parser.ExternalEntityRefHandler = refuse_external

    def start(name: str, _attributes: dict[str, str]) -> None:
        stack.append(
            {
                "tag": _local_name(name),
                "line": parser.CurrentLineNumber,
                "text": [],
                "children": [],
            }
        )

    def characters(data: str) -> None:
        if stack:
            stack[-1]["text"].append(data)

    def end(_name: str) -> None:
        frame = stack.pop()
        node = _XmlNode(
            tag=str(frame["tag"]),
            line=int(frame["line"]),
            end_line=parser.CurrentLineNumber,
            text="".join(frame["text"]),
            children=tuple(frame["children"]),
        )
        if stack:
            stack[-1]["children"].append(node)
        else:
            root.append(node)

    parser.StartElementHandler = start
    parser.CharacterDataHandler = characters
    parser.EndElementHandler = end
    try:
        parser.Parse(text.encode("utf-8"), True)
    except expat.ExpatError as exc:
        raise ValueError(f"malformed XML: {exc}") from exc
    if not root:
        raise ValueError("XML document has no root element")
    return root[0]


_MAVEN_PROPERTY_RE = re.compile(r"\$\{([^}]+)\}")
_MAVEN_INTERPOLATION_DEPTH = 8
_MAVEN_SHADE_PLUGINS = frozenset({"maven-shade-plugin", "maven-assembly-plugin"})


def _maven_interpolate(value: str, properties: dict[str, str]) -> tuple[str, bool]:
    """Resolve `${...}` against this file's own properties.

    Returns the resolved text and whether interpolation happened at all. A
    reference this file cannot resolve (it lives in a parent POM that is not in
    the tree) leaves the value unresolved rather than substituting a guess.
    """
    resolved = value
    interpolated = False
    for _ in range(_MAVEN_INTERPOLATION_DEPTH):
        match = _MAVEN_PROPERTY_RE.search(resolved)
        if match is None:
            return resolved, interpolated
        replacement = properties.get(match.group(1))
        if replacement is None:
            return "", interpolated
        resolved = resolved[: match.start()] + replacement + resolved[match.end() :]
        interpolated = True
    return "", interpolated


def _maven_dependency(
    context: _ReaderContext,
    node: _XmlNode,
    properties: dict[str, str],
    *,
    declaration: str,
    gaps: list[AnalysisGap],
    qualifiers: tuple[str, ...] = (),
) -> DeclaredDependency | None:
    declared_group = node.value("groupId")
    declared_artifact = node.value("artifactId")
    if not declared_group or not declared_artifact:
        gaps.append(
            AnalysisGap(
                path=context.path,
                gap="incomplete_declaration",
                detail=(
                    f"line {node.line}: dependency element has no groupId/artifactId pair"
                ),
            )
        )
        return None
    group, _ = _maven_interpolate(declared_group, properties)
    artifact, _ = _maven_interpolate(declared_artifact, properties)
    if not group or not artifact:
        # The coordinate itself is a property this file cannot resolve -- almost
        # always a parent POM outside the tree. Dropping it silently would make
        # the module look like it declares one dependency fewer than it does.
        gaps.append(
            AnalysisGap(
                path=context.path,
                gap="unresolved_coordinate",
                detail=(
                    f"line {node.line}: {declared_group}:{declared_artifact} "
                    "references a property this file does not define"
                ),
            )
        )
        return None
    declared_version = node.value("version")
    version, interpolated = _maven_interpolate(declared_version, properties)
    if not declared_version:
        version_source = "unresolved"
    elif not version:
        version_source = "unresolved"
    else:
        version_source = "property" if interpolated else "manifest"
    notes = list(qualifiers)
    if node.value("optional").lower() == "true":
        notes.append("optional")
    return _dependency(
        context,
        coordinate=f"{group}:{artifact}",
        version=version,
        version_source=version_source,
        # Maven's own default. Recording the applied default beats leaving the
        # field blank and re-deciding what blank meant further downstream.
        declared_scope=node.value("scope") or "compile",
        declaration=declaration,
        evidence=(context.evidence(node.line, context.line_span(node.line, node.end_line)),),
        qualifiers=tuple(notes),
    )


def _maven_profile_activation(profile: _XmlNode) -> str:
    """The condition this profile's declarations hang on, in the POM's own words.

    Maven activates a profile on `activeByDefault`, a JDK range, an OS, a
    property, the presence of a file, or a `-P` flag on the command line. None
    of those are decidable from the file, so the condition is quoted rather
    than evaluated.
    """

    activation = profile.first("activation")
    if activation is None:
        return "no <activation>; active only when -P names it"
    stated = []
    for child in activation.children:
        text = " ".join(child.text.split())
        stated.append(f"<{child.tag}>{text}" if text else f"<{child.tag}>")
    return ", ".join(stated) or "an empty <activation>"


def _maven_declaration_blocks(
    context: _ReaderContext,
    container: _XmlNode,
    properties: dict[str, str],
    *,
    declaration: str,
    gaps: list[AnalysisGap],
    qualifiers: tuple[str, ...] = (),
) -> list[DeclaredDependency]:
    """Every `<dependency>` in the `<dependencies>` blocks `container` owns."""

    found: list[DeclaredDependency] = []
    for block in container.all("dependencies"):
        for node in block.all("dependency"):
            parsed = _maven_dependency(
                context,
                node,
                properties,
                declaration=declaration,
                gaps=gaps,
                qualifiers=qualifiers,
            )
            if parsed is not None:
                found.append(parsed)
    return found


def _maven_declarations(
    context: _ReaderContext,
    container: _XmlNode,
    properties: dict[str, str],
    *,
    gaps: list[AnalysisGap],
    qualifiers: tuple[str, ...] = (),
) -> list[DeclaredDependency]:
    """A POM or profile's own declarations: its version policy, then its needs."""

    found: list[DeclaredDependency] = []
    management = container.first("dependencyManagement")
    if management is not None:
        found.extend(
            _maven_declaration_blocks(
                context,
                management,
                properties,
                declaration="managed",
                gaps=gaps,
                qualifiers=qualifiers,
            )
        )
    found.extend(
        _maven_declaration_blocks(
            context,
            container,
            properties,
            declaration="direct",
            gaps=gaps,
            qualifiers=qualifiers,
        )
    )
    return found


def _maven_declared_dependency_count(container: _XmlNode) -> int:
    """How many `<dependency>` elements a container states, resolvable or not.

    Counted from the tree rather than from the records, so a profile whose only
    dependency needs a parent POM still discloses its activation instead of
    looking like a profile that declares nothing.
    """

    management = container.first("dependencyManagement")
    owners = (container, management) if management is not None else (container,)
    return sum(
        len(block.all("dependency")) for owner in owners for block in owner.all("dependencies")
    )


def _read_maven_pom(context: _ReaderContext) -> ManifestParse:
    root = _read_xml(context.text)
    properties: dict[str, str] = {}
    property_block = root.first("properties")
    if property_block is not None:
        properties = {child.tag: child.text.strip() for child in property_block.children}
    parent = root.first("parent")
    project_version = root.value("version") or (parent.value("version") if parent else "")
    properties.setdefault("project.version", project_version)
    group = root.value("groupId") or (parent.value("groupId") if parent else "")
    properties.setdefault("project.groupId", group)

    dependencies: list[DeclaredDependency] = []
    gaps: list[AnalysisGap] = []
    dependencies.extend(_maven_declarations(context, root, properties, gaps=gaps))

    # A production profile is where a log4j, a JDBC driver or a native
    # transport is usually declared, and a root-only traversal reports none of
    # them -- not scoped out, not flagged, absent. They are read here with the
    # profile named on every record, and the activation, which no file reader
    # can evaluate, is disclosed as a gap beside them.
    profiles = root.first("profiles")
    for profile in profiles.all("profile") if profiles is not None else ():
        declared = _maven_declared_dependency_count(profile)
        if not declared:
            continue
        identifier = profile.value("id") or f"the profile opened on line {profile.line}"
        profile_properties = dict(properties)
        block = profile.first("properties")
        if block is not None:
            profile_properties.update(
                {child.tag: child.text.strip() for child in block.children}
            )
        dependencies.extend(
            _maven_declarations(
                context,
                profile,
                profile_properties,
                gaps=gaps,
                qualifiers=(f"profile:{identifier}",),
            )
        )
        gaps.append(
            AnalysisGap(
                path=context.path,
                gap="unresolved_profile_activation",
                detail=(
                    f"line {profile.line}: profile `{identifier}` declares "
                    f"{declared} dependency element(s) under "
                    f"{_maven_profile_activation(profile)}; whether the build "
                    "applies them is not decidable from this file"
                ),
            )
        )

    relocations: list[Relocation] = []
    for plugin in root.descendants("plugin"):
        if plugin.value("artifactId") not in _MAVEN_SHADE_PLUGINS:
            continue
        for node in plugin.descendants("relocation"):
            source_prefix = node.value("pattern")
            shaded_prefix = node.value("shadedPattern")
            if not source_prefix or not shaded_prefix:
                continue
            relocations.append(
                Relocation(
                    source_prefix=source_prefix,
                    shaded_prefix=shaded_prefix,
                    evidence=context.evidence(
                        node.line, context.line_span(node.line, node.end_line)
                    ),
                )
            )

    return context.parse(
        dependencies=tuple(dependencies),
        facts=BuildFacts(
            packaging=root.value("packaging") or "jar",
            relocations=tuple(relocations),
        ),
        gaps=tuple(gaps),
    )


# --------------------------------------------------------------------------- #
# Gradle
#
# A Gradle build script is a program, so a line scanner can only report what a
# line literally says. That is exactly why every conclusion drawn from it is
# published as an `unverified_` observation with the line quoted beside it.
# --------------------------------------------------------------------------- #

# Configurations that put an artifact somewhere. The set is closed so an
# ordinary DSL call (`id 'java'`, `exclude group: ...`) cannot be mistaken for a
# dependency declaration.
GRADLE_CONFIGURATIONS: frozenset[str] = frozenset(
    {
        "annotationProcessor",
        "api",
        "compileOnly",
        "compileOnlyApi",
        "developmentOnly",
        "implementation",
        "kapt",
        "ksp",
        "providedCompile",
        "providedRuntime",
        "runtimeOnly",
        "shadow",
        "testAnnotationProcessor",
        "testCompileOnly",
        "testImplementation",
        "testRuntimeOnly",
        "androidTestImplementation",
        "debugImplementation",
        "releaseImplementation",
    }
)

# The two halves of a version-catalog declaration: a build script names an
# accessor (`libs.jackson.databind`) and the catalog names the coordinate under
# the key that accessor is built from (`jackson-databind`). Both notes are
# reader-level facts in the build files' own words; `dependency_picture` owns
# the join they make possible.
CATALOG_ALIAS_NOTE = "catalog_alias"
CATALOG_ACCESSOR_NOTE = "version_catalog_alias"


def catalog_accessor(alias: str) -> str:
    """The accessor a build script uses for a catalog key.

    Gradle maps `-`, `_` and `.` in the key to `.` in the accessor, under the
    catalog's own name -- `libs` for the `libs.versions.toml` this roster reads.
    """

    return "libs." + re.sub(r"[-_.]+", ".", alias.strip())


_GRADLE_STRING_RE = re.compile(
    r"^\s*(?P<configuration>[A-Za-z][A-Za-z0-9_]*)\s*[(\s]\s*['\"](?P<coordinate>[^'\"]+)['\"]"
)
_GRADLE_ALIAS_RE = re.compile(
    r"^\s*(?P<configuration>[A-Za-z][A-Za-z0-9_]*)\s*[(\s]\s*(?P<alias>libs\.[A-Za-z0-9_.]+)"
)
# Groovy spells the coordinate map `group: 'x', name: 'y'`; the Kotlin DSL
# spells the same declaration with named arguments, `group = "x", name = "y"`,
# and orders them however the author liked. Accepting only the colon returns
# nothing at all for a `build.gradle.kts` written that way -- no dependency and
# no gap, which reads as a module that declares nothing.
_GRADLE_MAP_RE = re.compile(
    r"^\s*(?P<configuration>[A-Za-z][A-Za-z0-9_]*)\s*[(\s]*(?:group|name)\s*[:=]"
)
_GRADLE_MAP_FIELD_RE = re.compile(r"\b(group|name|version)\s*[:=]\s*['\"]([^'\"]*)['\"]")
_GRADLE_RELOCATE_RE = re.compile(
    r"relocate\s*\(?\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]"
)


def _read_gradle_build(context: _ReaderContext) -> ManifestParse:
    dependencies: list[DeclaredDependency] = []
    relocations: list[Relocation] = []
    for offset, line in enumerate(context.lines):
        number = offset + 1
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        for source_prefix, shaded_prefix in _GRADLE_RELOCATE_RE.findall(line):
            relocations.append(
                Relocation(
                    source_prefix=source_prefix,
                    shaded_prefix=shaded_prefix,
                    evidence=context.evidence_at(number),
                )
            )
        map_match = _GRADLE_MAP_RE.match(line)
        if map_match is not None and map_match.group("configuration") in GRADLE_CONFIGURATIONS:
            fields = dict(_GRADLE_MAP_FIELD_RE.findall(line))
            group = fields.get("group", "")
            name = fields.get("name", "")
            if group and name:
                dependencies.append(
                    _dependency(
                        context,
                        coordinate=f"{group}:{name}",
                        version=fields.get("version", ""),
                        version_source="manifest",
                        declared_scope=map_match.group("configuration"),
                        evidence=(context.evidence_at(number),),
                    )
                )
            continue
        string_match = _GRADLE_STRING_RE.match(line)
        if (
            string_match is not None
            and string_match.group("configuration") in GRADLE_CONFIGURATIONS
        ):
            parts = string_match.group("coordinate").split(":")
            if len(parts) >= 2 and parts[0] and parts[1]:
                dependencies.append(
                    _dependency(
                        context,
                        coordinate=f"{parts[0]}:{parts[1]}",
                        version=parts[2] if len(parts) > 2 else "",
                        version_source="manifest",
                        declared_scope=string_match.group("configuration"),
                        evidence=(context.evidence_at(number),),
                    )
                )
            continue
        alias_match = _GRADLE_ALIAS_RE.match(line)
        if (
            alias_match is not None
            and alias_match.group("configuration") in GRADLE_CONFIGURATIONS
        ):
            # A version-catalog alias names a catalog entry, not a coordinate.
            # Guessing the coordinate from the alias would invent a component,
            # so the alias is carried through as what it is.
            dependencies.append(
                _dependency(
                    context,
                    coordinate=alias_match.group("alias"),
                    declared_scope=alias_match.group("configuration"),
                    evidence=(context.evidence_at(number),),
                    qualifiers=(CATALOG_ACCESSOR_NOTE,),
                )
            )
    return context.parse(
        dependencies=tuple(dependencies),
        facts=BuildFacts(relocations=tuple(relocations)),
    )


def _read_gradle_settings(context: _ReaderContext) -> ManifestParse:
    """A settings script names the build's modules and declares no dependency.

    It is read rather than skipped so a `settings.gradle` beside a build script
    is not reported as an unread ecosystem: Gradle IS being read here, and the
    module list it carries is already derivable from the manifests themselves.
    """

    return context.parse()


def _read_gradle_lockfile(context: _ReaderContext) -> ManifestParse:
    dependencies: list[DeclaredDependency] = []
    for offset, line in enumerate(context.lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        coordinate, separator, configurations = stripped.partition("=")
        if not separator or coordinate == "empty":
            continue
        parts = coordinate.split(":")
        if len(parts) != 3:
            continue
        dependencies.append(
            _dependency(
                context,
                coordinate=f"{parts[0]}:{parts[1]}",
                version=parts[2],
                version_source="lockfile",
                # The resolving configurations ARE the shipment evidence: an
                # artifact on `runtimeClasspath` reaches the runtime, one on
                # `compileClasspath` alone does not.
                declared_scope=configurations,
                declaration="resolved",
                evidence=(context.evidence_at(offset + 1),),
            )
        )
    return context.parse(dependencies=tuple(dependencies))


def _unresolved_catalog_entry(
    context: _ReaderContext, alias: Any, span: tuple[int, int] | None, detail: str
) -> AnalysisGap:
    """An alias a build script can name that resolves to no component.

    A `libs.<alias>` row in a build script is joined back to a coordinate by the
    catalog alone. An entry that yields none leaves that row unresolvable for
    the rest of the run, so it is disclosed rather than skipped.
    """

    return AnalysisGap(
        path=context.path,
        gap="unresolved_catalog_entry",
        detail=(
            f"{f'line {span[0]}: ' if span else ''}`{alias}` {detail}; the "
            "component it names is absent from the picture, not absent from the build"
        ),
    )


def _read_gradle_version_catalog(context: _ReaderContext) -> ManifestParse:
    data = tomllib.loads(context.text)
    gaps: list[AnalysisGap] = []
    key_lines = _toml_key_lines(context.lines)
    versions = {
        str(key): str(value)
        for key, value in _table(
            data.get("versions"), path=context.path, name="versions", gaps=gaps
        ).items()
        if isinstance(value, str)
    }
    dependencies: list[DeclaredDependency] = []
    libraries = _table(
        data.get("libraries"), path=context.path, name="libraries", gaps=gaps
    )
    for alias, entry in sorted(libraries.items()):
        span = key_lines.get(("libraries", str(alias)))
        if isinstance(entry, str):
            parts = entry.split(":")
            coordinate = ":".join(parts[:2])
            version = parts[2] if len(parts) > 2 else ""
        elif isinstance(entry, dict):
            module = str(entry.get("module") or "")
            group = str(entry.get("group") or "")
            name = str(entry.get("name") or "")
            coordinate = module or (f"{group}:{name}" if group and name else "")
            declared = entry.get("version")
            if isinstance(declared, str):
                version = declared
            elif isinstance(declared, dict):
                version = versions.get(str(declared.get("ref") or ""), "")
            else:
                version = ""
        else:
            gaps.append(
                _unresolved_catalog_entry(
                    context, alias, span, f"is {type(entry).__name__}, not a table"
                )
            )
            continue
        if not coordinate or ":" not in coordinate:
            gaps.append(
                _unresolved_catalog_entry(
                    context, alias, span, "declares no group:artifact coordinate"
                )
            )
            continue
        dependencies.append(
            _dependency(
                context,
                coordinate=coordinate,
                version=version,
                version_source="version_catalog",
                declared_scope="version-catalog",
                declaration="managed",
                evidence=(context.evidence_at(span[0] if span else 0, str(alias)),),
                # The alias is the join key. A build script names the catalog
                # entry, not the coordinate, so without the key travelling on
                # the record nothing downstream can turn `libs.jackson.databind`
                # back into the component it stands for.
                qualifiers=(f"{CATALOG_ALIAS_NOTE}:{alias}",),
            )
        )
    return context.parse(dependencies=tuple(dependencies), gaps=tuple(gaps))


# --------------------------------------------------------------------------- #
# npm
# --------------------------------------------------------------------------- #

NPM_DEPENDENCY_BLOCKS: tuple[str, ...] = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)


def _read_npm_package(context: _ReaderContext) -> ManifestParse:
    data = json.loads(context.text)
    if not isinstance(data, dict):
        raise ValueError("package.json is not an object")
    key_lines = _json_key_lines(context.text)
    dependencies: list[DeclaredDependency] = []
    for block in NPM_DEPENDENCY_BLOCKS:
        entries = data.get(block)
        if not isinstance(entries, dict):
            continue
        for name, declared in sorted(entries.items()):
            if not isinstance(declared, str):
                continue
            # The name alone is not enough: `overrides` and `resolutions` name
            # the same packages at other versions, and the first match in the
            # file is as likely to be one of those as this block's own line.
            line = key_lines.get((block, str(name)), 0)
            dependencies.append(
                _dependency(
                    context,
                    coordinate=name,
                    version=declared,
                    version_source="manifest",
                    declared_scope=block,
                    evidence=(context.evidence_at(line, f"{name}: {declared}"),),
                )
            )
    return context.parse(dependencies=tuple(dependencies))


def _npm_lock_scope(entry: dict[str, Any]) -> str:
    if entry.get("dev"):
        return "dev"
    if entry.get("peer"):
        return "peer"
    if entry.get("optional"):
        return "optional"
    return "prod"


def _read_npm_lock(context: _ReaderContext) -> ManifestParse:
    data = json.loads(context.text)
    if not isinstance(data, dict):
        raise ValueError("lockfile is not an object")
    key_lines = _json_key_lines(context.text)
    dependencies: list[DeclaredDependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in sorted(packages.items()):
            if not key or not isinstance(entry, dict):
                continue
            if "node_modules/" not in key:
                # A key outside `node_modules/` is a workspace member -- this
                # project's own source, whose declarations are read from its own
                # package.json and whose installs are the `node_modules/` keys
                # above. Reading the directory as a package name publishes a
                # component called `packages/app`, one per workspace.
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            if not name:
                continue
            line = key_lines.get(("packages", str(key)), 0)
            declaration = "workspace_link" if entry.get("link") else (
                "resolved" if key.count("node_modules/") <= 1 else "transitive"
            )
            dependencies.append(
                _dependency(
                    context,
                    coordinate=name,
                    version=str(entry.get("version") or ""),
                    version_source="lockfile",
                    declared_scope=_npm_lock_scope(entry),
                    declaration=declaration,
                    # The install path IS the transitive story: the same package
                    # nested under two parents is two different copies.
                    evidence=(context.evidence(line, f"{key}: {json.dumps(entry, sort_keys=True)}"),),
                )
            )
        return context.parse(dependencies=tuple(dependencies))

    # lockfileVersion 1: a nested `dependencies` tree instead of a path map.
    def walk(
        entries: dict[str, Any], trail: tuple[str, ...], key_path: tuple[str, ...]
    ) -> None:
        for name, entry in sorted(entries.items()):
            if not isinstance(entry, dict):
                continue
            path = trail + (name,)
            line = key_lines.get(key_path + (str(name),), 0)
            dependencies.append(
                _dependency(
                    context,
                    coordinate=name,
                    version=str(entry.get("version") or ""),
                    version_source="lockfile",
                    declared_scope=_npm_lock_scope(entry),
                    declaration="resolved" if len(path) == 1 else "transitive",
                    evidence=(context.evidence(line, "node_modules/" + "/node_modules/".join(path)),),
                )
            )
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                walk(nested, path, key_path + (str(name), "dependencies"))

    top = data.get("dependencies")
    if isinstance(top, dict):
        walk(top, (), ("dependencies",))
    return context.parse(dependencies=tuple(dependencies))


_YARN_BERRY_MARKER = "__metadata:"
_YARN_VERSION_RE = re.compile(r"^\s+version[:\s]+\"?([^\"\s]+)\"?")


def _read_yarn_lock(context: _ReaderContext) -> ManifestParse:
    if _YARN_BERRY_MARKER in context.text:
        return context.parse(
            gaps=(
                AnalysisGap(
                    path=context.path,
                    gap="unparsed_lockfile_format",
                    detail=(
                        "yarn berry lockfiles are YAML and have no reader; this "
                        "project's resolved npm versions are absent from the picture"
                    ),
                ),
            )
        )
    dependencies: list[DeclaredDependency] = []
    header_names: list[str] = []
    header_line = 0
    for offset, line in enumerate(context.lines):
        number = offset + 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            header_names = []
            header_line = number
            for spec in line.rstrip().rstrip(":").split(", "):
                cleaned = spec.strip().strip('"')
                name = cleaned.rsplit("@", 1)[0] if "@" in cleaned[1:] else cleaned
                if name and name not in header_names:
                    header_names.append(name)
            continue
        version_match = _YARN_VERSION_RE.match(line)
        if version_match is None or not header_names:
            continue
        for name in header_names:
            dependencies.append(
                _dependency(
                    context,
                    coordinate=name,
                    version=version_match.group(1),
                    version_source="lockfile",
                    declaration="resolved",
                    evidence=(
                        context.evidence(
                            header_line, context.lines[header_line - 1] if header_line else name
                        ),
                    ),
                )
            )
        header_names = []
    return context.parse(dependencies=tuple(dependencies))


# --------------------------------------------------------------------------- #
# Go
# --------------------------------------------------------------------------- #

_GO_REQUIRE_RE = re.compile(r"^\s*(?P<module>[^\s]+)\s+(?P<version>v[^\s]+)(?P<rest>.*)$")
# `replace` takes a single directive or a parenthesised block of them, and the
# module being replaced is whatever stands to the left of the arrow in either
# form. Anchoring on the `replace` keyword alone reads the block's opening
# parenthesis as the replaced module and leaves the real ones unmarked.
#
# Both sides matter. The left may carry a version, and then the directive
# applies to that version alone; the right names what the build actually
# compiles, and go.mod requires a version there unless the target is a
# filesystem path. Keeping only the left reports the registry version of bytes
# the build never uses.
_GO_REPLACE_RE = re.compile(
    r"^\s*(?:replace\s+)?(?P<module>[^\s(]+)"
    r"(?:\s+(?P<replaced_version>v\S+))?"
    r"\s*=>\s*(?P<target>\S+)"
    r"(?:\s+(?P<version>v\S+))?"
)


@dataclass(frozen=True)
class _GoReplacement:
    """One `replace` directive: what it matches, and what it substitutes."""

    module: str
    replaced_version: str
    target: str
    version: str

    @property
    def note(self) -> str:
        target = f"{self.target}@{self.version}" if self.version else self.target
        return f"replaced_by:{target}"


def _go_replacement(match: re.Match[str]) -> _GoReplacement:
    return _GoReplacement(
        module=match.group("module"),
        replaced_version=match.group("replaced_version") or "",
        target=match.group("target"),
        version=match.group("version") or "",
    )


def _go_replacement_for(
    replacements: Sequence[_GoReplacement], module: str, version: str
) -> _GoReplacement | None:
    """The directive that governs this requirement, if one does.

    A version on the left of the arrow narrows the directive to exactly that
    version, so applying it to any other one reports a substitution the build
    does not perform.
    """

    for replacement in replacements:
        if replacement.module != module:
            continue
        if replacement.replaced_version and replacement.replaced_version != version:
            continue
        return replacement
    return None


def _read_go_mod(context: _ReaderContext) -> ManifestParse:
    replacements: list[_GoReplacement] = []
    requires: list[tuple[int, str, str, bool]] = []
    in_require = False
    in_replace = False
    for offset, raw in enumerate(context.lines):
        number = offset + 1
        line = raw.split("//")[0] if raw.strip().startswith("//") else raw
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("module "):
            # This file's own module path: the project, not a dependency of it.
            continue
        if stripped.startswith("replace ("):
            in_replace = True
            continue
        if in_replace:
            if stripped == ")":
                in_replace = False
                continue
            entry = _GO_REPLACE_RE.match(stripped)
            if entry is not None:
                replacements.append(_go_replacement(entry))
            continue
        if stripped.startswith("replace "):
            replace_match = _GO_REPLACE_RE.match(stripped)
            if replace_match is not None:
                replacements.append(_go_replacement(replace_match))
            continue
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        candidate = stripped
        if stripped.startswith("require "):
            candidate = stripped.split(None, 1)[1]
        elif not in_require:
            continue
        match = _GO_REQUIRE_RE.match(candidate)
        if match is None:
            continue
        requires.append(
            (
                number,
                match.group("module"),
                match.group("version"),
                "// indirect" in raw,
            )
        )
    dependencies: list[DeclaredDependency] = []
    for number, name, version, indirect in requires:
        replacement = _go_replacement_for(replacements, name, version)
        dependencies.append(
            _dependency(
                context,
                coordinate=name,
                # The replacement's version is what the build compiles. go.mod
                # demands one on the right of the arrow unless the target is a
                # directory in this tree, so a target without one is a local
                # checkout: nothing identifies those bytes, and repeating the
                # required version would pin every lookup to a release the
                # build never reads.
                version=replacement.version if replacement is not None else version,
                version_source="replace" if replacement is not None else "manifest",
                declared_scope="require-indirect" if indirect else "require",
                declaration="transitive" if indirect else "direct",
                evidence=(context.evidence_at(number),),
                qualifiers=(replacement.note,) if replacement is not None else (),
            )
        )
    return context.parse(dependencies=tuple(dependencies))


def _read_go_sum(context: _ReaderContext) -> ManifestParse:
    seen: set[tuple[str, str]] = set()
    dependencies: list[DeclaredDependency] = []
    for offset, line in enumerate(context.lines):
        parts = line.split()
        if len(parts) < 3:
            continue
        module, version = parts[0], parts[1].removesuffix("/go.mod")
        if (module, version) in seen:
            continue
        seen.add((module, version))
        dependencies.append(
            _dependency(
                context,
                coordinate=module,
                version=version,
                version_source="lockfile",
                declared_scope="module-graph",
                # go.sum records every version the graph ever considered, not
                # what a build links. Calling these dependencies of this build
                # would inflate the picture with modules nothing imports.
                declaration="graph",
                evidence=(context.evidence_at(offset + 1),),
            )
        )
    return context.parse(dependencies=tuple(dependencies))


def _read_go_vendor_modules(context: _ReaderContext) -> ManifestParse:
    dependencies: list[DeclaredDependency] = []
    for offset, line in enumerate(context.lines):
        stripped = line.strip()
        if not stripped.startswith("# "):
            continue
        parts = stripped[2:].split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        dependencies.append(
            _dependency(
                context,
                coordinate=parts[0],
                version=parts[1],
                version_source="lockfile",
                declared_scope="vendor",
                declaration="vendored",
                evidence=(context.evidence_at(offset + 1),),
            )
        )
    return context.parse(dependencies=tuple(dependencies))


# --------------------------------------------------------------------------- #
# Python
# --------------------------------------------------------------------------- #

_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*(?P<version>[^;#]*)$"
)
_REQUIREMENT_OPTION_RE = re.compile(r"\s--[A-Za-z-]+[=\s]\S+")

# A requirement can name a distribution or a LOCATION to install one from. The
# requirement grammar reads a bare URL as a distribution called `https` pinned
# at `://...`, and reads a path or a VCS reference as nothing at all -- a
# fabricated component and a silent drop from the same line shape. Both forms
# are recognized here so the first cannot happen and the second is disclosed.
_DIRECT_REFERENCE_SCHEMES = ("git+", "hg+", "bzr+", "svn+")
# PEP 508 spells a located requirement that DOES name its distribution
# `name @ url`; setuptools spells it `<url>#egg=name`. Either way the name is
# the component and the location is not a version.
_PEP508_DIRECT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*@\s*(?P<url>\S+)"
)
_EGG_FRAGMENT_RE = re.compile(
    r"#egg=(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[(?P<extras>[^\]]*)\])?"
)
# pip documents `-r, --requirement <file>` and `-c, --constraint <file>`, and
# accepts each in the compact (`-rbase.txt`), separated (`-r base.txt`) and
# equals (`--requirement=base.txt`) spellings. Only the separated form used to
# be recognized, so the other two fell through the generic option skip and the
# file they delegate to left the picture entirely.
_REQUIREMENT_INCLUDE_RE = re.compile(
    r"^(?:-[rc]\s*|--(?:requirement|constraint)\s*[=\s]\s*)\S"
)
# `-e` takes a path OR a VCS URL. The compact `-e<value>` spelling is NOT
# accepted here: optparse would read `-extra-index-url ...` as one, and an
# index URL is not an editable checkout.
_REQUIREMENT_EDITABLE_RE = re.compile(
    r"^(?:-e\s+|--editable\s*[=\s]\s*)(?P<target>\S.*)$"
)


def normalize_python_name(name: str) -> str:
    """PEP 503 normalization, so one distribution has one identity."""

    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def _parse_requirement(
    context: _ReaderContext,
    statement: str,
    *,
    line: int,
    declared_scope: str,
) -> DeclaredDependency | None:
    text, _, marker = statement.partition(";")
    text = _REQUIREMENT_OPTION_RE.sub("", text).strip()
    if not text:
        return None
    located, located_name, located_extras = _direct_reference_name(text)
    if located:
        # A location this reader cannot name is left to the caller to disclose:
        # returning a component called `https` pinned at `://example/x.tar.gz`
        # would be worse than saying nothing.
        if not located_name:
            return None
        match = None
        extras = located_extras.strip()
    else:
        match = _REQUIREMENT_RE.match(text)
        if match is None:
            return None
        extras = (match.group("extras") or "").strip()
    qualifiers: list[str] = ["direct_reference"] if located else []
    for extra in (part.strip() for part in extras.split(",")):
        if extra:
            qualifiers.append(f"extras:{extra}")
    if marker.strip():
        qualifiers.append(f"marker:{marker.strip()}")
    # A location is not a version: `@ https://host/pkg-2.0.whl` resolves to
    # whatever that URL serves today, which no pin here could honestly state.
    version = (match.group("version") or "").strip() if match is not None else ""
    return _dependency(
        context,
        coordinate=normalize_python_name(
            match.group("name") if match is not None else located_name
        ),
        version=version,
        version_source="manifest",
        declared_scope=declared_scope,
        evidence=(context.evidence_at(line, statement),),
        qualifiers=tuple(qualifiers),
    )


def _direct_reference_name(statement: str) -> tuple[bool, str, str]:
    """Is this requirement a location, and which distribution does it name?

    Returns whether the statement installs from a location at all, the
    distribution name it declares (empty when it declares none), and the extras
    it asked for. A location that names nothing is a hole in the picture: the
    file requires something this reader cannot identify.
    """

    text = statement.strip()
    pep508 = _PEP508_DIRECT_RE.match(text)
    if pep508 is not None:
        return True, pep508.group("name"), (pep508.group("extras") or "")
    located = text.startswith(_DIRECT_REFERENCE_SCHEMES) or text.startswith((".", "/"))
    if not located and "://" not in text.partition("#")[0]:
        return False, "", ""
    egg = _EGG_FRAGMENT_RE.search(text)
    if egg is None:
        return True, "", ""
    return True, egg.group("name"), egg.group("extras") or ""


def _read_python_requirements(context: _ReaderContext) -> ManifestParse:
    dependencies: list[DeclaredDependency] = []
    gaps: list[AnalysisGap] = []
    for offset, raw in enumerate(context.lines):
        number = offset + 1
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if _REQUIREMENT_INCLUDE_RE.match(line):
            # Part of the declaration lives elsewhere. Dropping it silently
            # would make this file look complete when it is not.
            gaps.append(
                AnalysisGap(
                    path=context.path,
                    gap="external_requirement_include",
                    detail=line,
                )
            )
            continue
        editable = _REQUIREMENT_EDITABLE_RE.match(line)
        if editable is not None:
            target = editable.group("target").strip()
            _, name, extras = _direct_reference_name(target)
            if name:
                # An editable VCS checkout installs the distribution its
                # fragment names. Recording the URL as the coordinate publishes
                # a component that exists in no registry, matches no import,
                # and can never merge with the lockfile or import observation
                # for the package it actually is.
                notes = ["editable", "direct_reference"]
                notes.extend(
                    f"extras:{extra.strip()}"
                    for extra in extras.split(",")
                    if extra.strip()
                )
                dependencies.append(
                    _dependency(
                        context,
                        coordinate=normalize_python_name(name),
                        declared_scope="requirements",
                        evidence=(context.evidence_at(number),),
                        qualifiers=tuple(notes),
                    )
                )
            elif "://" in target or target.startswith(_DIRECT_REFERENCE_SCHEMES):
                gaps.append(
                    AnalysisGap(
                        path=context.path,
                        gap="unnamed_requirement_reference",
                        detail=(
                            f"line {number}: {line} installs from a location and "
                            "names no distribution; what it installs is absent from "
                            "the picture, not absent from the environment"
                        ),
                    )
                )
            else:
                # A path is its own identity here: there is no distribution
                # name to recover, and the checkout is what the reviewer opens.
                dependencies.append(
                    _dependency(
                        context,
                        coordinate=target,
                        declared_scope="requirements",
                        declaration="local",
                        evidence=(context.evidence_at(number),),
                        qualifiers=("editable",),
                    )
                )
            continue
        if line.startswith("-"):
            continue
        parsed = _parse_requirement(
            context, line, line=number, declared_scope="requirements"
        )
        if parsed is not None:
            dependencies.append(parsed)
        elif _direct_reference_name(line)[0]:
            gaps.append(
                AnalysisGap(
                    path=context.path,
                    gap="unnamed_requirement_reference",
                    detail=(
                        f"line {number}: {line} installs from a location and names "
                        "no distribution; what it installs is absent from the "
                        "picture, not absent from the environment"
                    ),
                )
            )
    return context.parse(dependencies=tuple(dependencies), gaps=tuple(gaps))


# The two PEP 621 fields whose absence would otherwise read as "this project
# declares nothing". `dynamic` lists the fields the build backend supplies at
# build time, so `project.dependencies` is legitimately missing from the file
# and its runtime requirements are stated somewhere this reader is not looking.
_DYNAMIC_DEPENDENCY_FIELDS: tuple[str, ...] = ("dependencies", "optional-dependencies")


def _dynamic_declaration_source(tool: dict[str, Any], field: str) -> str:
    """Where a dynamic field says its declarations come from, in the file's words.

    setuptools is the one backend that names the source in the same file
    (`tool.setuptools.dynamic`), and a `file` entry usually points at a
    `requirements*.txt` this roster reads on its own. Quoting the entry tells
    the operator which file completes the declaration; evaluating it is not
    this reader's to do -- it reads one file's bytes and touches no others.
    """

    setuptools = tool.get("setuptools")
    dynamic = setuptools.get("dynamic") if isinstance(setuptools, dict) else None
    entry = dynamic.get(field) if isinstance(dynamic, dict) else None
    if entry is None:
        return (
            "no `tool.setuptools.dynamic` entry names where it comes from, so only "
            "the build backend knows"
        )
    return f"`tool.setuptools.dynamic.{field}` names {json.dumps(entry, sort_keys=True)}"


def _poetry_constraint(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        declared = value.get("version")
        return declared if isinstance(declared, str) else ""
    return ""


def _read_python_pyproject(context: _ReaderContext) -> ManifestParse:
    data = tomllib.loads(context.text)
    dependencies: list[DeclaredDependency] = []
    gaps: list[AnalysisGap] = []
    key_lines = _toml_key_lines(context.lines)

    def add_statements(statements: Any, scope: str, key: tuple[str, ...]) -> None:
        if not isinstance(statements, list):
            return
        span = key_lines.get(key)
        # Statements appear in the array in document order, so the cursor only
        # moves forward: one requirement listed in two tables is cited in the
        # table it was read from, and a repeat inside one array gets its own
        # line rather than the first one's.
        cursor = span[0] if span else 0
        for statement in statements:
            if not isinstance(statement, str):
                continue
            line = context.line_in_span(statement, (cursor, span[1])) if span else 0
            cursor = line
            parsed = _parse_requirement(
                context, statement, line=line, declared_scope=scope
            )
            if parsed is not None:
                dependencies.append(parsed)

    def block(container: dict[str, Any], name: str, path: tuple[str, ...]) -> dict[str, Any]:
        return _table(
            container.get(name), path=context.path, name=".".join(path), gaps=gaps
        )

    build_system = block(data, "build-system", ("build-system",))
    add_statements(
        build_system.get("requires"),
        "build-system.requires",
        ("build-system", "requires"),
    )
    project = block(data, "project", ("project",))
    add_statements(
        project.get("dependencies"), "project.dependencies", ("project", "dependencies")
    )
    optional = block(project, "optional-dependencies", ("project", "optional-dependencies"))
    for group, statements in sorted(optional.items()):
        add_statements(
            statements,
            f"project.optional-dependencies.{group}",
            ("project", "optional-dependencies", str(group)),
        )

    dynamic = project.get("dynamic")
    tool = block(data, "tool", ("tool",))
    for field_name in _DYNAMIC_DEPENDENCY_FIELDS:
        if field_name not in (dynamic if isinstance(dynamic, list) else ()):
            continue
        span = key_lines.get(("project", "dynamic"))
        gaps.append(
            AnalysisGap(
                path=context.path,
                gap="dynamic_dependency_declaration",
                detail=(
                    f"{f'line {span[0]}: ' if span else ''}`project.{field_name}` is "
                    f"declared dynamic, so this file lists none of it; "
                    f"{_dynamic_declaration_source(tool, field_name)}. Those "
                    "requirements are absent from this manifest's records, not "
                    "absent from the project"
                ),
            )
        )

    poetry = block(tool, "poetry", ("tool", "poetry"))

    def add_table(table: Any, scope: str, path: tuple[str, ...]) -> None:
        if not isinstance(table, dict):
            return
        for name, value in sorted(table.items()):
            if name == "python":
                continue
            span = key_lines.get(path + (str(name),))
            dependencies.append(
                _dependency(
                    context,
                    coordinate=normalize_python_name(str(name)),
                    version=_poetry_constraint(value),
                    version_source="manifest",
                    declared_scope=scope,
                    evidence=(context.evidence_at(span[0] if span else 0, str(name)),),
                    # `optional = true` means an extra has to ask for this
                    # package. Reading the table for its version alone loses
                    # that word and the opt-in reads as a default install --
                    # the same statement poetry.lock and Maven both carry here.
                    qualifiers=("optional",)
                    if isinstance(value, dict) and value.get("optional")
                    else (),
                )
            )

    add_table(
        poetry.get("dependencies"),
        "tool.poetry.dependencies",
        ("tool", "poetry", "dependencies"),
    )
    add_table(
        poetry.get("dev-dependencies"),
        "tool.poetry.dev-dependencies",
        ("tool", "poetry", "dev-dependencies"),
    )
    for group, table in sorted(
        block(poetry, "group", ("tool", "poetry", "group")).items()
    ):
        if isinstance(table, dict):
            add_table(
                table.get("dependencies"),
                f"tool.poetry.group.{group}.dependencies",
                ("tool", "poetry", "group", str(group), "dependencies"),
            )

    return context.parse(dependencies=tuple(dependencies), gaps=tuple(gaps))


def _read_python_poetry_lock(context: _ReaderContext) -> ManifestParse:
    data = tomllib.loads(context.text)
    key_lines = _toml_key_lines(context.lines)
    dependencies: list[DeclaredDependency] = []
    for index, entry in enumerate(data.get("package") or []):
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "")
        if not name:
            continue
        groups = entry.get("groups")
        if isinstance(groups, list) and groups:
            scope = ",".join(str(group) for group in groups)
        else:
            scope = str(entry.get("category") or "")
        # Two entries for one package at different versions is the case a
        # reviewer opens this file for; both citing the first entry hides it.
        span = key_lines.get(("package", str(index), "name"))
        dependencies.append(
            _dependency(
                context,
                coordinate=normalize_python_name(name),
                version=str(entry.get("version") or ""),
                version_source="lockfile",
                declared_scope=scope,
                declaration="resolved",
                evidence=(context.evidence_at(span[0] if span else 0, name),),
                qualifiers=("optional",) if entry.get("optional") else (),
            )
        )
    return context.parse(dependencies=tuple(dependencies))


def _read_python_pipfile_lock(context: _ReaderContext) -> ManifestParse:
    data = json.loads(context.text)
    if not isinstance(data, dict):
        raise ValueError("Pipfile.lock is not an object")
    key_lines = _json_key_lines(context.text)
    dependencies: list[DeclaredDependency] = []
    for block in ("default", "develop"):
        entries = data.get(block)
        if not isinstance(entries, dict):
            continue
        for name, entry in sorted(entries.items()):
            declared = entry.get("version") if isinstance(entry, dict) else ""
            line = key_lines.get((block, str(name)), 0)
            dependencies.append(
                _dependency(
                    context,
                    coordinate=normalize_python_name(str(name)),
                    version=str(declared or ""),
                    version_source="lockfile",
                    declared_scope=block,
                    declaration="resolved",
                    evidence=(context.evidence_at(line, str(name)),),
                )
            )
    return context.parse(dependencies=tuple(dependencies))


_READERS: dict[str, Callable[[_ReaderContext], ManifestParse]] = {
    "maven_pom": _read_maven_pom,
    "gradle_build": _read_gradle_build,
    "gradle_settings": _read_gradle_settings,
    "gradle_lockfile": _read_gradle_lockfile,
    "gradle_version_catalog": _read_gradle_version_catalog,
    "npm_package": _read_npm_package,
    "npm_lock": _read_npm_lock,
    "yarn_lock": _read_yarn_lock,
    "go_mod": _read_go_mod,
    "go_sum": _read_go_sum,
    "go_vendor_modules": _read_go_vendor_modules,
    "python_requirements": _read_python_requirements,
    "python_pyproject": _read_python_pyproject,
    "python_poetry_lock": _read_python_poetry_lock,
    "python_pipfile_lock": _read_python_pipfile_lock,
}

# The kinds a reader exists for -- the reader table itself, so the two can never
# disagree. Every other rostered kind is reported as an `unparsed_ecosystem`
# gap: the ecosystem is present and NOT analyzed, which is a different statement
# from "no dependencies here" and must never collapse into it.
PARSED_MANIFEST_KINDS: frozenset[str] = frozenset(_READERS)
