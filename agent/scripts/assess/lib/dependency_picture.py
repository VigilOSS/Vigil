"""Turn parsed build files into shipped-and-reachable dependency observations.

`dependency_manifests` reports what each build file *says*. This module decides
what those statements add up to, and it is deliberately the only place that
crosses from statement to observation.

Two questions decide whether a component is worth a reviewer's time:

* **Does the build ship it?** A ``provided`` jar, a ``compileOnly`` Gradle
  entry, a peer dependency, a build-system requirement and a ``devDependency``
  are all declared and none of them are in the artifact. A shaded jar ships
  under a name that appears in no manifest. A vendored copy ships with no
  declaration at all.
* **Does the reviewed code reach it?** A shipped component nothing imports is a
  different risk from one the request path runs through.

Only the intersection is a lead. Everything else is noise, and producing noise
is the failure mode this module exists to avoid.

**Degraded-signal discipline.** Every conclusion here is derived from build
files and an import index, neither of which settles what a built artifact
contains -- a Gradle script is a program, a Maven property can come from a
parent that is not in the tree, and a distribution name is not an import name.
So both vocabularies are observation vocabularies: every member is prefixed
``unverified_``, no member reads as a clearance, "we looked and saw nothing" is
spelled differently from "we could not look", every record carries a
``detection`` marker naming the reader that produced it, and the raw evidence
(file, line, verbatim text) travels with the record rather than being replaced
by it. A "not shipped" or "not reachable" conclusion is exactly as dangerous as
a false clean on a template, and gets the same treatment.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterable, Mapping, Sequence

from .dependency_manifests import (
    CATALOG_ACCESSOR_NOTE,
    CATALOG_ALIAS_NOTE,
    PARSED_MANIFEST_KINDS,
    AnalysisGap,
    DeclaredDependency,
    Evidence,
    ManifestParse,
    Relocation,
    catalog_accessor,
    normalize_python_name,
)


# Where a dependency observation came from. With no inbound scan the realistic
# values collapse to these two: a statement in a build file, or the shape of
# build output that is present in the tree (a vendored copy, a packaged jar, an
# installed module directory). A row correlated from an operator-supplied
# scanner report keeps the origin of the source-side record it matched and is
# marked with a qualifier instead, because the scan confirms nothing about this
# build on its own.
DEPENDENCY_OBSERVATION_ORIGINS: tuple[str, ...] = (
    "source_manifest",
    "build_output",
)

# What the build files say about whether a component reaches the artifact.
# There is deliberately no member that reads as "not shipped": the two negative
# members name the *reason they looked that way* (a declared scope, a runtime
# expectation), so a reader cannot quote one as proof the bytes are absent.
SHIPMENT_OBSERVATIONS: tuple[str, ...] = (
    "unverified_ships_by_default_scope",
    "unverified_excluded_by_declared_scope",
    "unverified_expected_from_runtime",
    "unverified_relocated_into_shaded_artifact",
    "unverified_present_without_declaration",
    "unverified_shipment_undetermined",
)

# What the import index says about whether the reviewed code names a component.
# `unverified_no_reference_observed` means the declaring module's own index was
# read and nothing matched; `unverified_reachability_unindexed` means there was
# no such index to read. Collapsing those two is how a dependency review
# produces a false clean, so they are separate members and the second is never
# counted as evidence of anything.
REACHABILITY_OBSERVATIONS: tuple[str, ...] = (
    "unverified_import_site_observed",
    "unverified_no_reference_observed",
    "unverified_reachability_unindexed",
)

# Additional observations that qualify a record without changing its shipment or
# reachability observation. Each is a machine-readable code, not prose, so a
# consumer can filter on it.
DEPENDENCY_QUALIFIERS: tuple[str, ...] = (
    "unverified_manifest_lock_divergence",
    "unverified_duplicate_version_in_lock",
    "unverified_optional_declaration",
    "unverified_conditional_profile",
    "unverified_relocation_declared",
    "unverified_aggregator_module",
    "unverified_version_unresolved",
    "unverified_scanner_row_correlated",
)

# The reader each observation came through. `gradle_script_regex` names the
# weakest of them on purpose: a Gradle build script is a program, and a line
# scanner reports only what a line literally said.
DETECTION_BY_KIND: dict[str, str] = {
    "maven_pom": "maven_pom_xml_parse",
    "gradle_build": "gradle_script_regex",
    "gradle_settings": "gradle_script_regex",
    "gradle_lockfile": "gradle_lockfile_parse",
    "gradle_version_catalog": "gradle_version_catalog_parse",
    "npm_package": "npm_manifest_parse",
    "npm_lock": "npm_lockfile_parse",
    "yarn_lock": "yarn_lockfile_parse",
    "go_mod": "go_mod_parse",
    "go_sum": "go_sum_parse",
    "go_vendor_modules": "go_vendor_modules_parse",
    "python_pyproject": "python_pyproject_parse",
    "python_requirements": "python_requirements_parse",
    "python_pipfile_lock": "python_pipfile_lock_parse",
    "python_poetry_lock": "python_poetry_lock_parse",
}
BUILD_OUTPUT_DETECTION = "build_output_layout"

# Which indexed languages could possibly import a component of an ecosystem. An
# index that covers none of them cannot produce a negative result for it.
ECOSYSTEM_LANGUAGES: dict[str, frozenset[str]] = {
    "maven": frozenset({"java", "kotlin"}),
    "gradle": frozenset({"java", "kotlin"}),
    "npm": frozenset({"javascript", "typescript"}),
    "go": frozenset({"go"}),
    "python": frozenset({"python"}),
}

# The separator that makes a module prefix a prefix. `org.apache.commons` must
# match `org.apache.commons.text` but never `org.apache.commonsx`.
_MODULE_SEPARATORS: dict[str, str] = {
    "maven": ".",
    "gradle": ".",
    "npm": "/",
    "go": "/",
    "python": ".",
}


@dataclass(frozen=True)
class ReferenceSite:
    """One place the reviewed code names a component, quoted verbatim."""

    path: str
    language: str
    raw_import: str


@dataclass(frozen=True)
class DependencyObservation:
    """One component, with what the build said and what the index showed."""

    ecosystem: str
    coordinate: str
    version: str
    version_source: str
    declared_scope: str
    declaration: str
    module_path: str
    manifest_path: str
    observation_origin: str
    shipment_observation: str
    reachability_observation: str
    detection: str
    declared_range: str = ""
    module_prefixes: tuple[str, ...] = ()
    reference_sites: tuple[ReferenceSite, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    qualifiers: tuple[str, ...] = ()
    # Reader-level facts in the build file's own words (`optional`,
    # `marker:...`, `lock_scope:dev`). Kept apart from `qualifiers` so a build
    # file's vocabulary can never be mistaken for one of Vigil's observations.
    declaration_notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class IndexedFile:
    """One file's import evidence, as published by `code-index`."""

    path: str
    language: str
    analysis_status: str
    imports: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyPicture:
    """Every observation plus every hole in the derivation that produced it."""

    observations: tuple[DependencyObservation, ...] = ()
    gaps: tuple[AnalysisGap, ...] = ()
    ecosystems: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Scope tables
#
# One table per ecosystem, mapping the verbatim scope token a build file used to
# what it says about the artifact. A token no table names resolves to
# `unverified_shipment_undetermined` — an unrecognized configuration is an
# unanswered question, never a negative answer.
# --------------------------------------------------------------------------- #

_SHIPS = "unverified_ships_by_default_scope"
_EXCLUDED = "unverified_excluded_by_declared_scope"
_RUNTIME = "unverified_expected_from_runtime"
_RELOCATED = "unverified_relocated_into_shaded_artifact"
_UNDECLARED = "unverified_present_without_declaration"
_UNDETERMINED = "unverified_shipment_undetermined"

_SCOPE_TABLES: dict[str, dict[str, str]] = {
    "maven": {
        "compile": _SHIPS,
        "runtime": _SHIPS,
        "provided": _RUNTIME,
        "system": _RUNTIME,
        "test": _EXCLUDED,
    },
    "gradle": {
        "implementation": _SHIPS,
        "api": _SHIPS,
        "runtimeOnly": _SHIPS,
        "shadow": _SHIPS,
        "releaseImplementation": _SHIPS,
        "providedCompile": _RUNTIME,
        "providedRuntime": _RUNTIME,
        "compileOnly": _EXCLUDED,
        "compileOnlyApi": _EXCLUDED,
        "developmentOnly": _EXCLUDED,
        "debugImplementation": _EXCLUDED,
        "annotationProcessor": _EXCLUDED,
        "testAnnotationProcessor": _EXCLUDED,
        "kapt": _EXCLUDED,
        "ksp": _EXCLUDED,
        "testImplementation": _EXCLUDED,
        "testCompileOnly": _EXCLUDED,
        "testRuntimeOnly": _EXCLUDED,
        "androidTestImplementation": _EXCLUDED,
    },
    "npm": {
        "dependencies": _SHIPS,
        "prod": _SHIPS,
        "devDependencies": _EXCLUDED,
        "dev": _EXCLUDED,
        "peerDependencies": _RUNTIME,
        "peer": _RUNTIME,
    },
    "go": {
        "require": _SHIPS,
        "require-indirect": _SHIPS,
        "vendor": _SHIPS,
        "module-graph": _UNDETERMINED,
    },
    "python": {
        "requirements": _SHIPS,
        "project.dependencies": _SHIPS,
        "tool.poetry.dependencies": _SHIPS,
        "default": _SHIPS,
        "main": _SHIPS,
        "build-system.requires": _EXCLUDED,
        "develop": _EXCLUDED,
        "tool.poetry.dev-dependencies": _EXCLUDED,
    },
}

# Scope tokens that mean "installed only when something asks for it". They are
# undetermined, not excluded: an optional extra that the deployment does enable
# is in the artifact.
_OPTIONAL_SCOPES: frozenset[str] = frozenset({"optionalDependencies", "optional"})

# A `profile:<id>` note means the manifest reader found the declaration inside a
# build profile. `dependency_manifests` stamps it; the picture reads it back
# rather than re-parsing, so the two cannot disagree about what is conditional.
_PROFILE_NOTE_PREFIX = "profile:"


def _profile_notes(notes: Iterable[str]) -> list[str]:
    return [note for note in notes if note.startswith(_PROFILE_NOTE_PREFIX)]

# Poetry and PEP 621 group names that conventionally hold non-shipping tooling.
# This is a naming convention, not a declaration, so a group outside the set is
# left undetermined rather than assumed to ship.
_NON_SHIPPING_GROUP_NAMES: frozenset[str] = frozenset(
    {"dev", "development", "test", "tests", "lint", "docs", "typing", "style", "bench"}
)

# A Gradle lock line lists the configurations that resolved the artifact. A
# runtime classpath is the shipment evidence; a test one is not.
_GRADLE_RUNTIME_CONFIGURATION = "runtimeclasspath"
_GRADLE_TEST_PREFIX = "test"


def _gradle_lock_shipment(configurations: str) -> str:
    resolved = [part.strip().lower() for part in configurations.split(",") if part.strip()]
    if any(
        _GRADLE_RUNTIME_CONFIGURATION in name and not name.startswith(_GRADLE_TEST_PREFIX)
        for name in resolved
    ):
        return _SHIPS
    if resolved:
        return _EXCLUDED
    return _UNDETERMINED


def _python_group_shipment(scope: str) -> str | None:
    if scope.startswith("project.optional-dependencies."):
        return _UNDETERMINED
    if scope.startswith("tool.poetry.group.") and scope.endswith(".dependencies"):
        group = scope.removeprefix("tool.poetry.group.").removesuffix(".dependencies")
        return _EXCLUDED if group in _NON_SHIPPING_GROUP_NAMES else _UNDETERMINED
    if "," in scope or scope in _NON_SHIPPING_GROUP_NAMES:
        # poetry.lock records the groups that resolved a package.
        groups = {part.strip() for part in scope.split(",") if part.strip()}
        if "main" in groups:
            return _SHIPS
        if groups and groups <= _NON_SHIPPING_GROUP_NAMES:
            return _EXCLUDED
        return _UNDETERMINED
    return None


def _shipment_for(ecosystem: str, declared_scope: str) -> str:
    if declared_scope in _OPTIONAL_SCOPES:
        return _UNDETERMINED
    if ecosystem == "gradle" and "classpath" in declared_scope.lower():
        return _gradle_lock_shipment(declared_scope)
    if ecosystem == "python":
        grouped = _python_group_shipment(declared_scope)
        if grouped is not None:
            return grouped
    return _SCOPE_TABLES.get(ecosystem, {}).get(declared_scope, _UNDETERMINED)


# --------------------------------------------------------------------------- #
# Coordinate -> module prefixes, and raw import -> module path
# --------------------------------------------------------------------------- #


def candidate_module_prefixes(ecosystem: str, coordinate: str) -> tuple[str, ...]:
    """Module prefixes a component's code would be imported under.

    Heuristic by construction: a Maven groupId is only conventionally the Java
    package root, and a Python distribution name is only conventionally its
    import name. That is precisely why a miss here is reported as
    `unverified_no_reference_observed` and never as absence of use.
    """

    corroborated, suggested = _module_prefix_tiers(ecosystem, coordinate)
    return tuple(sorted(corroborated | suggested))


def _module_prefix_tiers(
    ecosystem: str, coordinate: str
) -> tuple[frozenset[str], frozenset[str]]:
    """The prefixes both halves of a coordinate agree on, and the rest.

    A groupId on its own is the second tier: `org.springframework` is the
    package root of spring-core, spring-web AND spring-beans, so an import
    matched on it names some component in that group without saying which. The
    artifact id is what tells them apart, and a prefix built from both halves is
    corroborated rather than merely possible — which is what lets one import
    produce one lead instead of one per artifact published under the group.
    """

    if ecosystem in ("maven", "gradle"):
        group, _, artifact = coordinate.partition(":")
        if not artifact:
            return frozenset({coordinate}), frozenset()
        dotted = artifact.replace("-", ".")
        corroborated = {f"{group}.{dotted}"}
        head, _, rest = dotted.partition(".")
        if rest:
            # An artifact id conventionally repeats one of the group's segments,
            # and not always the last: `org.apache.commons:commons-text` is
            # `org.apache.commons.text` and
            # `com.fasterxml.jackson.core:jackson-databind` is
            # `com.fasterxml.jackson.databind`. The repeat is sometimes an
            # abbreviation (`org.springframework:spring-core`).
            segments = group.split(".")
            for index, segment in enumerate(segments):
                if segment.startswith(head):
                    corroborated.add(".".join([*segments[: index + 1], rest]))
        return frozenset(corroborated), frozenset({group})
    if ecosystem == "python":
        normalized = normalize_python_name(coordinate)
        return frozenset({normalized, normalized.replace("-", "_")}), frozenset()
    return frozenset({coordinate}), frozenset()


_JAVA_IMPORT_RE = re.compile(r"^\s*(?:import\s+)?(?:static\s+)?(?P<module>[\w.$]+(?:\.\*)?)\s*;?\s*$")
_PYTHON_FROM_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import")
_PYTHON_IMPORT_RE = re.compile(r"^\s*import\s+(.+)$")
_JS_SPECIFIER_RE = re.compile(r"""(?:from|require|import)\s*\(?\s*['"]([^'"]+)['"]""")
_QUOTED_RE = re.compile(r"""^\s*['"]([^'"]+)['"]\s*$""")


def normalize_import(language: str, raw_import: str) -> tuple[str, ...]:
    """Module paths a raw import statement could be naming."""

    raw = raw_import.strip()
    if not raw:
        return ()
    if language in ("java", "kotlin"):
        match = _JAVA_IMPORT_RE.match(raw)
        return (match.group("module").removesuffix(".*"),) if match else (raw.rstrip(";"),)
    if language == "python":
        from_match = _PYTHON_FROM_RE.match(raw)
        if from_match is not None:
            return (from_match.group(1),)
        import_match = _PYTHON_IMPORT_RE.match(raw)
        if import_match is not None:
            return tuple(
                part.strip().split(" as ")[0].strip()
                for part in import_match.group(1).split(",")
                if part.strip()
            )
        return (raw,)
    if language in ("javascript", "typescript"):
        specifiers = tuple(_JS_SPECIFIER_RE.findall(raw))
        if specifiers:
            return specifiers
        quoted = _QUOTED_RE.match(raw)
        return (quoted.group(1),) if quoted else (raw,)
    quoted = _QUOTED_RE.match(raw)
    return (quoted.group(1),) if quoted else (raw,)


def _matches_prefix(candidate: str, prefix: str, separator: str) -> bool:
    return candidate == prefix or candidate.startswith(prefix + separator)


# --------------------------------------------------------------------------- #
# Version-range satisfaction
#
# Deliberately conservative: the checker answers only for the range forms it
# fully understands and returns None for everything else. Claiming a lockfile
# diverges from a `github:` or `workspace:` specifier would be a fabricated
# finding, which is worse than saying nothing.
# --------------------------------------------------------------------------- #

_RELEASE_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_ANY_RANGE: frozenset[str] = frozenset({"", "*", "x", "latest"})


def _release(text: str) -> tuple[int, int, int] | None:
    match = _RELEASE_RE.match(text.strip())
    return (int(match.group(1)), int(match.group(2)), int(match.group(3))) if match else None


def _satisfies(range_text: str, version: str) -> bool | None:
    """True/False when the range form is fully understood, else None."""

    declared = range_text.strip()
    if declared in _ANY_RANGE:
        return True
    resolved = _release(version)
    if resolved is None:
        return None
    if declared.startswith("=="):
        declared = declared[2:].strip()
    operator = ""
    for candidate in (">=", "^", "~"):
        if declared.startswith(candidate):
            operator = candidate
            declared = declared[len(candidate) :].strip()
            break
    base = _release(declared)
    if base is None:
        return None
    if operator == "":
        return resolved == base
    if operator == ">=":
        return resolved >= base
    if operator == "~":
        return resolved[:2] == base[:2] and resolved >= base
    # Caret: compatible with the leftmost non-zero component.
    if base[0] > 0:
        return resolved[0] == base[0] and resolved >= base
    if base[1] > 0:
        return resolved[:2] == base[:2] and resolved >= base
    return resolved == base


# --------------------------------------------------------------------------- #
# Derivation
# --------------------------------------------------------------------------- #


@dataclass
class _Record:
    ecosystem: str
    coordinate: str
    version: str
    version_source: str
    declared_scope: str
    declaration: str
    module_path: str
    manifest_path: str
    observation_origin: str
    detection: str
    evidence: list[Evidence] = field(default_factory=list)
    declaration_notes: list[str] = field(default_factory=list)
    qualifiers: set[str] = field(default_factory=set)
    declared_range: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.module_path, self.coordinate)


def _record_from(dependency: DeclaredDependency, detection: str) -> _Record:
    return _Record(
        ecosystem=dependency.ecosystem,
        coordinate=dependency.coordinate,
        version=dependency.version,
        version_source=dependency.version_source,
        declared_scope=dependency.declared_scope,
        declaration=dependency.declaration,
        module_path=dependency.module_path,
        manifest_path=dependency.manifest_path,
        observation_origin="source_manifest",
        detection=detection,
        evidence=list(dependency.evidence),
        declaration_notes=list(dependency.qualifiers),
    )


def _is_ancestor_module(ancestor: str, module: str) -> bool:
    return ancestor == "" or module == ancestor or module.startswith(f"{ancestor}/")


def _catalog_entry_accessor(entry: _Record) -> str:
    """The `libs.` accessor a version-catalog entry answers to, if it is one."""

    marker = f"{CATALOG_ALIAS_NOTE}:"
    for note in entry.declaration_notes:
        if note.startswith(marker):
            return catalog_accessor(note[len(marker) :])
    return ""


def _resolve_catalog_alias(record: _Record, managed: list[_Record]) -> int | None:
    """Turn `libs.jackson.databind` into the component the catalog says it is.

    Both halves are in the same run: the script names an accessor and the
    catalog names the coordinate under the key that accessor is built from, so
    this is a lookup, not a guess. Leaving it unresolved publishes a row with a
    coordinate that exists in no registry and a second row the reachability pass
    cannot connect to it — two unusable rows in place of one component.
    """
    if CATALOG_ACCESSOR_NOTE not in record.declaration_notes:
        return None
    candidates = [
        (index, entry)
        for index, entry in enumerate(managed)
        if entry.ecosystem == record.ecosystem
        and _catalog_entry_accessor(entry) == record.coordinate
        and _is_ancestor_module(entry.module_path, record.module_path)
    ]
    if not candidates:
        return None
    index, entry = max(candidates, key=lambda item: len(item[1].module_path))
    record.coordinate = entry.coordinate
    record.version = entry.version
    record.version_source = entry.version_source
    record.evidence.extend(entry.evidence)
    return index


def _apply_managed_versions(
    records: list[_Record], managed: list[_Record]
) -> list[_Record]:
    """Resolve declarations against the policy entries that complete them.

    A managed entry is a version policy, not a component: `dependencyManagement`
    supplies the version a module left out, and a version catalog supplies the
    coordinate AND the version the accessor stands for. Once a module consumes
    one it stops being its own observation; one that nothing consumes stays
    visible, because an entry no module uses still tells a reviewer what the
    project intended.

    The entry's own notes travel with the version it supplied. A declaration
    that only a PROFILE's `dependencyManagement` completes resolves to that
    version under that activation and to nothing at all without it, so dropping
    the `profile:<id>` note republishes a conditional resolution as the plain
    one -- a version an operator would read as settled.
    """
    consumed: set[int] = set()
    for record in records:
        resolved = _resolve_catalog_alias(record, managed)
        if resolved is not None:
            consumed.add(resolved)
            continue
        if record.version:
            continue
        candidates = [
            (index, entry)
            for index, entry in enumerate(managed)
            if entry.ecosystem == record.ecosystem
            and entry.coordinate == record.coordinate
            and entry.version
            and _is_ancestor_module(entry.module_path, record.module_path)
        ]
        if not candidates:
            continue
        index, entry = max(candidates, key=lambda item: len(item[1].module_path))
        record.version = entry.version
        record.version_source = "managed"
        record.evidence.extend(entry.evidence)
        record.declaration_notes.extend(
            note for note in entry.declaration_notes if note not in record.declaration_notes
        )
        consumed.add(index)
    return [entry for index, entry in enumerate(managed) if index not in consumed]


def _collapse_profile_redeclarations(records: list[_Record]) -> list[_Record]:
    """Fold a profile's restatement of a component into the unconditional one.

    Re-declaring a root `<dependency>` inside a profile is the standard Maven
    override idiom, and the two statements are one component. Published as two
    rows they contradict each other -- same coordinate, same version, same
    scope, same file, one `ships by default scope` and one `shipment
    undetermined` -- and the conditional row is the false half: the component is
    declared outside every profile, so the build ships it whether or not one
    activates. A reviewer handed both has to decide which row to believe, which
    is the judgement this module exists to make for them.

    The profile's citation travels onto the surviving row, because the
    restatement is evidence about this component and what it means is the
    operator's call. A profile that states a different version or a different
    scope keeps its own row: that is a statement the unconditional declaration
    never made, and it really does hang on an activation.
    """

    unconditional: dict[tuple[str, str, str, str, str], int] = {}
    for index, record in enumerate(records):
        if _profile_notes(record.declaration_notes):
            continue
        unconditional.setdefault((*record.key, record.version, record.declared_scope), index)
    folded: set[int] = set()
    for index, record in enumerate(records):
        if not _profile_notes(record.declaration_notes):
            continue
        target = unconditional.get((*record.key, record.version, record.declared_scope))
        if target is None:
            continue
        records[target].evidence.extend(record.evidence)
        folded.add(index)
    return [record for index, record in enumerate(records) if index not in folded]


def _merge_manifest_and_lock(records: list[_Record]) -> list[_Record]:
    """Collapse a manifest declaration into the lock entry that resolved it.

    Keeping both would double-count every direct dependency and would report a
    version range as if it were an installed version.
    """
    by_key: dict[tuple[str, str, str], list[int]] = {}
    for index, record in enumerate(records):
        by_key.setdefault(record.key, []).append(index)
    dropped: set[int] = set()
    for group in by_key.values():
        declared = [
            index
            for index in group
            if records[index].declaration == "direct"
            and records[index].version_source != "lockfile"
        ]
        resolved = [index for index in group if records[index].declaration == "resolved"]
        graph = [index for index in group if records[index].declaration == "graph"]
        if graph and len(group) > len(graph):
            # go.sum lists every version the module graph considered; once
            # go.mod names the module, the graph row adds nothing.
            dropped.update(graph)
        if not declared or not resolved:
            continue
        target = records[resolved[0]]
        source = records[declared[0]]
        target.declared_range = source.version
        target.declaration_notes.append(f"lock_scope:{target.declared_scope}")
        target.declaration_notes.append(f"manifest_scope:{source.declared_scope}")
        # Prefer whichever scope the ecosystem's table can actually classify:
        # a Gradle lock line names the resolving classpaths (better evidence
        # than the script configuration), while an npm lock only says prod/dev.
        if _shipment_for(target.ecosystem, target.declared_scope) == _UNDETERMINED:
            target.declared_scope = source.declared_scope
        target.evidence.extend(source.evidence)
        target.declaration_notes.extend(source.declaration_notes)
        dropped.update(declared)
    return [record for index, record in enumerate(records) if index not in dropped]


# --------------------------------------------------------------------------- #
# Build output present in the tree
# --------------------------------------------------------------------------- #

# A `<name>-<version>.jar` under one of these directories is a shipped artifact
# by packaging convention, not a declaration.
_PACKAGED_LIB_DIRS: tuple[str, ...] = ("WEB-INF/lib/", "BOOT-INF/lib/")
_JAR_RE = re.compile(r"^(?P<name>.+?)-(?P<version>\d[\w.]*(?:-[A-Za-z][\w.]*)?)\.jar$")
# A Go module path starts with a hostname, and how many segments follow is a
# property of the host rather than a constant: `gopkg.in/yaml.v2`,
# `go.uber.org/zap` and `k8s.io/api` are two segments, `github.com/gorilla/mux`
# is three. `go mod vendor` answers it structurally — it copies each module's
# files under that module's own root — so the shallowest vendored directory that
# holds files IS the module, and a FILENAME is never a segment of one. Requiring
# a dot in the first segment keeps Composer's and Bundler's `vendor/` trees out
# of the Go reading.
_GO_MIN_MODULE_SEGMENTS = 2
# Forges that namespace by owner, where the module root is one level deeper than
# any directory that happens to hold a stray file.
_GO_FORGE_MODULE_SEGMENTS: dict[str, int] = {
    "github.com": 3,
    "gitlab.com": 3,
    "bitbucket.org": 3,
}


def _segment_start(posix: str, marker: str) -> int:
    """Where the text after `marker` begins, when `marker` is a whole segment."""

    start = 0
    while True:
        index = posix.find(marker, start)
        if index < 0:
            return -1
        if index == 0 or posix[index - 1] == "/":
            return index + len(marker)
        start = index + 1


def _vendored_go_modules(present_paths: Sequence[str]) -> dict[str, str]:
    directories: set[str] = set()
    entries: list[tuple[tuple[str, ...], str]] = []
    for path in sorted(present_paths):
        posix = path.replace("\\", "/")
        # Only a whole path segment named `vendor` opens a vendor tree, and the
        # first text match is not always one: `myvendor/vendor/...` has to keep
        # looking rather than reject the path, or the real vendor directory
        # behind a similarly named one contributes nothing at all.
        index = _segment_start(posix, "vendor/")
        if index < 0:
            continue
        segments = posix[index:].split("/")
        directory = tuple(segments[:-1])
        if len(directory) < _GO_MIN_MODULE_SEGMENTS or "." not in directory[0]:
            continue
        directories.add("/".join(directory))
        entries.append((directory, posix))

    found: dict[str, str] = {}
    for directory, posix in entries:
        depth = len(directory)
        for candidate in range(_GO_MIN_MODULE_SEGMENTS, len(directory) + 1):
            if "/".join(directory[:candidate]) in directories:
                depth = candidate
                break
        floor = _GO_FORGE_MODULE_SEGMENTS.get(directory[0], _GO_MIN_MODULE_SEGMENTS)
        depth = max(depth, min(floor, len(directory)))
        found.setdefault("/".join(directory[:depth]), posix)
    return found


def _installed_npm_packages(present_paths: Sequence[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for path in sorted(present_paths):
        segments = path.replace("\\", "/").split("/")
        if "node_modules" not in segments:
            continue
        index = len(segments) - 1 - segments[::-1].index("node_modules")
        remainder = segments[index + 1 :]
        if not remainder:
            continue
        name = remainder[0]
        if name.startswith("@") and len(remainder) > 1:
            name = f"{name}/{remainder[1]}"
        found.setdefault(name, path.replace("\\", "/"))
    return found


def _packaged_jars(present_paths: Sequence[str]) -> dict[tuple[str, str], str]:
    found: dict[tuple[str, str], str] = {}
    for path in sorted(present_paths):
        posix = path.replace("\\", "/")
        if not any(directory in posix for directory in _PACKAGED_LIB_DIRS):
            continue
        match = _JAR_RE.match(PurePosixPath(posix).name)
        if match is None:
            continue
        found.setdefault((match.group("name"), match.group("version")), posix)
    return found


def _build_output_records(
    present_paths: Sequence[str], declared: list[_Record]
) -> list[_Record]:
    """Components whose bytes are in the tree with nothing declaring them."""

    go_declared = {r.coordinate for r in declared if r.ecosystem == "go"}
    npm_declared = {r.coordinate for r in declared if r.ecosystem == "npm"}
    maven_artifacts = {
        r.coordinate.partition(":")[2] for r in declared if r.ecosystem in ("maven", "gradle")
    }
    records: list[_Record] = []

    def output_record(ecosystem: str, coordinate: str, version: str, path: str) -> _Record:
        return _Record(
            ecosystem=ecosystem,
            coordinate=coordinate,
            version=version,
            version_source="build_output" if version else "unresolved",
            declared_scope="",
            declaration="vendored",
            module_path="",
            manifest_path="",
            observation_origin="build_output",
            detection=BUILD_OUTPUT_DETECTION,
            evidence=[Evidence(path=path, line=0, text=path)],
        )

    for module, path in sorted(_vendored_go_modules(present_paths).items()):
        if any(
            module == name or module.startswith(f"{name}/") or name.startswith(f"{module}/")
            for name in go_declared
        ):
            continue
        records.append(output_record("go", module, "", path))
    for name, path in sorted(_installed_npm_packages(present_paths).items()):
        if name in npm_declared:
            continue
        records.append(output_record("npm", name, "", path))
    for (name, version), path in sorted(_packaged_jars(present_paths).items()):
        if name in maven_artifacts:
            continue
        records.append(output_record("maven", name, version, path))
    return records


# --------------------------------------------------------------------------- #
# Relocation, reachability, scanner correlation
# --------------------------------------------------------------------------- #

_PACKAGE_ROOT_SEGMENTS = 2


def _shares_package_root(left: str, right: str) -> bool:
    if left.startswith(right) or right.startswith(left):
        return True
    return (
        left.split(".")[:_PACKAGE_ROOT_SEGMENTS] == right.split(".")[:_PACKAGE_ROOT_SEGMENTS]
    )


def _matching_relocations(
    relocations: Sequence[Relocation], prefixes: Iterable[str]
) -> list[Relocation]:
    """Relocations whose rewritten package could belong to this component.

    A shade rule names a package prefix, not an artifact, so the link is a
    heuristic — which is why a component it matches carries
    `unverified_relocation_declared` alongside the conclusion.
    """
    return [
        relocation
        for relocation in relocations
        if any(_shares_package_root(relocation.source_prefix, prefix) for prefix in prefixes)
    ]


@dataclass(frozen=True)
class _Match:
    """One import site a component matched, and how well the two agree."""

    site: ReferenceSite
    corroborated: bool

    @property
    def import_key(self) -> tuple[str, str]:
        return (self.site.path, self.site.raw_import)


def _reference_matches(
    record: _Record,
    prefixes: Sequence[str],
    suggested: frozenset[str],
    indexed_files: Sequence[IndexedFile],
) -> tuple[bool, list[_Match]]:
    """Whether there was an index to read, and every import site that matched.

    `suggested` holds the prefixes this coordinate only half-explains (a bare
    groupId). A match on one of those is kept but marked, so the caller can
    decide it against the other components competing for the same import.
    """

    languages = ECOSYSTEM_LANGUAGES.get(record.ecosystem, frozenset())
    # A declaration reaches its own module and everything beneath it -- an
    # aggregator POM and a workspace root package.json really do govern their
    # descendants -- but never a sibling, which resolves its dependencies from
    # its own build file. Build output found in the tree declares no module, so
    # its empty `module_path` searches the whole index: its bytes are in the
    # artifact whatever ships them. Searching outside the declaring subtree
    # would credit a sibling's import to this module; searching a sibling's
    # index in place of a missing one would answer "we looked" for a module
    # nothing ever looked at.
    readable = [
        indexed
        for indexed in indexed_files
        if indexed.analysis_status == "complete"
        and indexed.language in languages
        and _is_ancestor_module(record.module_path, indexed.path)
    ]
    if not readable:
        # Either this module has no index, its index degraded, or the index
        # covers no language that could import this component. None of those is
        # a negative result.
        return False, []
    separator = _MODULE_SEPARATORS.get(record.ecosystem, "/")
    named = [prefix for prefix in prefixes if prefix]
    corroborating = [prefix for prefix in named if prefix not in suggested]
    matches: list[_Match] = []
    for indexed in readable:
        for raw in indexed.imports:
            candidates = normalize_import(indexed.language, raw)
            if not any(
                _matches_prefix(candidate, prefix, separator)
                for candidate in candidates
                for prefix in named
            ):
                continue
            # Which tier explained the site decides whether another component
            # can take it away. Asked only of a site that matched, so the common
            # case -- an import that names none of this component's prefixes --
            # costs exactly one pass.
            corroborated = len(corroborating) == len(named) or any(
                _matches_prefix(candidate, prefix, separator)
                for candidate in candidates
                for prefix in corroborating
            )
            matches.append(
                _Match(
                    site=ReferenceSite(
                        path=indexed.path, language=indexed.language, raw_import=raw
                    ),
                    corroborated=corroborated,
                )
            )
    return True, matches


# Maven and Gradle are one JVM coordinate space read through two build systems,
# so a scanner row for either names a component of both. Comparing the two
# ecosystem NAMES makes every row of a correctly scanned Gradle project
# unmatched -- and an unmatched row is read as evidence that the scan covered a
# different artifact than the repository builds.
_JVM_ECOSYSTEMS: frozenset[str] = frozenset({"maven", "gradle"})


def _ecosystem_family(ecosystem: str) -> str:
    return "jvm" if ecosystem in _JVM_ECOSYSTEMS else ecosystem


def _correlation_names(ecosystem: str, component: str) -> frozenset[str]:
    """Every spelling of one component's identity in its ecosystem's alphabet.

    Identity is not string equality across this boundary. PEP 503 says `PyYAML`
    and `pyyaml` are one distribution, and a JVM component is named
    `group:artifact` by Trivy and a POM but by the artifact id alone by Grype
    and by a jar on disk. A raw comparison reports the project's own components
    as belonging to someone else's image.
    """

    name = component.strip()
    if ecosystem in _JVM_ECOSYSTEMS:
        _group, separator, artifact = name.partition(":")
        return frozenset({name, artifact} - {""} if separator else {name})
    if ecosystem == "python":
        return frozenset({normalize_python_name(name)})
    return frozenset({name})


def _correlate_scan_rows(
    records: Sequence[_Record], scan_rows: Sequence[Mapping[str, object]]
) -> list[AnalysisGap]:
    """Mark records a scanner row names; report every row that names none.

    The scan is a secondary input. It annotates the source-derived picture and
    never creates a component or changes a shipment observation, because a row
    from someone else's image says nothing about what this build produces.
    """
    gaps: list[AnalysisGap] = []
    for row in scan_rows:
        component = str(row.get("component") or "").strip()
        if not component:
            continue
        ecosystem = str(row.get("ecosystem") or "").strip()
        family = _ecosystem_family(ecosystem)
        matched = [
            record
            for record in records
            if (not family or _ecosystem_family(record.ecosystem) == family)
            # The record's own ecosystem supplies the alphabet: a row this
            # scanner left untyped is still read the way the component it could
            # name is written.
            and _correlation_names(record.ecosystem, component)
            & _correlation_names(record.ecosystem, record.coordinate)
        ]
        if not matched:
            gaps.append(
                AnalysisGap(
                    path=str(row.get("source") or ""),
                    gap="unmatched_scanner_row",
                    detail=(
                        f"{component} {row.get('version') or ''}".strip()
                        + " names no component this build declares or vendors"
                    ),
                )
            )
            continue
        for record in matched:
            record.qualifiers.add("unverified_scanner_row_correlated")
    return gaps


@dataclass(frozen=True)
class _Derived:
    """One record with everything the index and the shade rules added to it."""

    record: _Record
    prefixes: list[str]
    relocations: list[Relocation]
    looked: bool
    matches: list[_Match]


def _derive(
    record: _Record,
    relocations_by_module: Mapping[str, Sequence[Relocation]],
    indexed_files: Sequence[IndexedFile],
) -> _Derived:
    corroborated, suggested = _module_prefix_tiers(record.ecosystem, record.coordinate)
    relocations = _matching_relocations(
        relocations_by_module.get(record.module_path, ()), corroborated | suggested
    )
    # A shade rule names its packages outright, so a relocated prefix is a
    # declaration rather than a convention and corroborates like the artifact id.
    for relocation in relocations:
        corroborated |= {relocation.source_prefix, relocation.shaded_prefix}
    suggested -= corroborated
    prefixes = sorted(corroborated | suggested)
    looked, matches = _reference_matches(record, prefixes, suggested, indexed_files)
    return _Derived(
        record=record,
        prefixes=prefixes,
        relocations=relocations,
        looked=looked,
        matches=matches,
    )


def build_dependency_picture(
    *,
    parses: Sequence[ManifestParse],
    present_paths: Sequence[str] = (),
    indexed_files: Sequence[IndexedFile] = (),
    scan_rows: Sequence[Mapping[str, object]] = (),
) -> DependencyPicture:
    """Derive the dependency picture. Pure: same inputs, same picture."""

    gaps: list[AnalysisGap] = []
    records: list[_Record] = []
    managed: list[_Record] = []
    aggregator_manifests: set[str] = set()
    relocations_by_module: dict[str, list[Relocation]] = {}
    for parse in parses:
        gaps.extend(parse.gaps)
        detection = DETECTION_BY_KIND.get(parse.kind, parse.kind)
        if parse.facts.packaging == "pom":
            aggregator_manifests.add(parse.path)
        if parse.facts.relocations:
            relocations_by_module.setdefault(parse.module_path, []).extend(
                parse.facts.relocations
            )
        for dependency in parse.dependencies:
            record = _record_from(dependency, detection)
            (managed if dependency.declaration == "managed" else records).append(record)

    unconsumed_policy = _apply_managed_versions(records, managed)
    records = _collapse_profile_redeclarations(records)
    records.extend(unconsumed_policy)
    records = _merge_manifest_and_lock(records)
    records.extend(_build_output_records(present_paths, records))
    # A scanner report is a secondary input: it annotates the identities the
    # source derivation already established, so it runs before the observations
    # are frozen and can never introduce one.
    gaps.extend(_correlate_scan_rows(records, scan_rows))

    # Duplicate versions of one component inside a module: the classic
    # "two parents pulled the same transitive at different versions".
    versions_by_key: dict[tuple[str, str, str], set[str]] = {}
    for record in records:
        if record.version and record.version_source == "lockfile":
            versions_by_key.setdefault(record.key, set()).add(record.version)

    # Reachability is decided in two passes because one import belongs to one
    # component: a match on a prefix the coordinate only half-explains is
    # dropped when another component's coordinate fully explains the same
    # import, and kept when none does -- reporting nothing there would be a
    # false clean on a component the code demonstrably reaches.
    derivations = [_derive(record, relocations_by_module, indexed_files) for record in records]
    corroborated_imports = {
        match.import_key
        for derived in derivations
        for match in derived.matches
        if match.corroborated
    }

    observations: list[DependencyObservation] = []
    for derived in derivations:
        record = derived.record
        prefixes = derived.prefixes
        relocations = derived.relocations

        if record.observation_origin == "build_output":
            shipment = _UNDECLARED
        elif record.declaration == "managed" or record.manifest_path in aggregator_manifests:
            shipment = _UNDETERMINED
        else:
            shipment = _shipment_for(record.ecosystem, record.declared_scope)
            if shipment == _SHIPS and relocations:
                shipment = _RELOCATED
            elif shipment == _SHIPS and "optional" in record.declaration_notes:
                shipment = _UNDETERMINED
            elif shipment == _SHIPS and _profile_notes(record.declaration_notes):
                # A profile dependency ships only when its profile activates, and
                # activation is undecidable from the manifest alone -- JDK, OS,
                # property, or file existence. Same conditionality as `optional`,
                # same answer; the manifest reader emits the activation gap.
                shipment = _UNDETERMINED

        qualifiers = set(record.qualifiers)
        if relocations:
            qualifiers.add("unverified_relocation_declared")
        if "optional" in record.declaration_notes or record.declared_scope in _OPTIONAL_SCOPES:
            qualifiers.add("unverified_optional_declaration")
        if _profile_notes(record.declaration_notes):
            qualifiers.add("unverified_conditional_profile")
        if record.manifest_path in aggregator_manifests:
            qualifiers.add("unverified_aggregator_module")
        if not record.version:
            qualifiers.add("unverified_version_unresolved")
        if len(versions_by_key.get(record.key, ())) > 1:
            qualifiers.add("unverified_duplicate_version_in_lock")
        if record.declared_range and _satisfies(record.declared_range, record.version) is False:
            qualifiers.add("unverified_manifest_lock_divergence")

        sites = tuple(
            sorted(
                (
                    match.site
                    for match in derived.matches
                    if match.corroborated or match.import_key not in corroborated_imports
                ),
                key=lambda site: (site.path, site.raw_import),
            )
        )
        if not derived.looked:
            reachability = "unverified_reachability_unindexed"
        elif sites:
            reachability = "unverified_import_site_observed"
        else:
            reachability = "unverified_no_reference_observed"
        observations.append(
            DependencyObservation(
                ecosystem=record.ecosystem,
                coordinate=record.coordinate,
                version=record.version,
                version_source=record.version_source,
                declared_scope=record.declared_scope,
                declaration=record.declaration,
                module_path=record.module_path,
                manifest_path=record.manifest_path,
                observation_origin=record.observation_origin,
                shipment_observation=shipment,
                reachability_observation=reachability,
                detection=record.detection,
                declared_range=record.declared_range,
                module_prefixes=tuple(sorted(set(prefixes))),
                reference_sites=sites,
                evidence=tuple(record.evidence),
                qualifiers=tuple(sorted(qualifiers)),
                declaration_notes=tuple(sorted(set(record.declaration_notes))),
            )
        )

    # The ecosystems this run actually READ. One whose manifests were recognized
    # but unread is deliberately absent here and present in `gaps` instead.
    ecosystems = {
        parse.ecosystem for parse in parses if parse.kind in PARSED_MANIFEST_KINDS
    }
    return DependencyPicture(
        observations=tuple(
            sorted(
                observations,
                key=lambda observation: (
                    observation.ecosystem,
                    observation.module_path,
                    observation.coordinate,
                    observation.version,
                    observation.manifest_path,
                ),
            )
        ),
        gaps=tuple(sorted(gaps, key=lambda gap: (gap.path, gap.gap, gap.detail))),
        ecosystems=tuple(sorted(name for name in ecosystems if name)),
        modules=tuple(sorted({parse.module_path for parse in parses})),
    )
