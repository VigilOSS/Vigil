"""Readers for the dependency-declaring files in a sealed snapshot.

These pin what each reader must extract *verbatim* from a build file: the
coordinate, the version the file actually resolves, the scope token the file
used, and the line it said it on. Nothing here asserts a shipped/not-shipped
conclusion — that belongs to `dependency_picture` and is tested there.
"""
from __future__ import annotations

import json
import time

import pytest

from assess.lib import dependency_manifests as dm
from assess.lib.code_languages import detect_language


def _parse(path: str, text: str) -> dm.ManifestParse:
    kind = dm.manifest_kind_for_path(path)
    assert kind is not None, f"{path!r} is not on the manifest roster"
    return dm.parse_manifest(kind, path, text)


def _by_coordinate(parse: dm.ManifestParse) -> dict[str, dm.DeclaredDependency]:
    return {dep.coordinate: dep for dep in parse.dependencies}


# --------------------------------------------------------------------------- #
# Roster
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("pom.xml", "maven_pom"),
        ("services/api/pom.xml", "maven_pom"),
        ("build.gradle.kts", "gradle_build"),
        ("gradle/libs.versions.toml", "gradle_version_catalog"),
        ("package-lock.json", "npm_lock"),
        ("requirements.txt", "python_requirements"),
        ("requirements-dev.txt", "python_requirements"),
        ("deploy/requirements/base.txt", "python_requirements"),
        ("vendor/modules.txt", "go_vendor_modules"),
        ("composer.json", "composer_manifest"),
    ],
)
def test_roster_resolves_manifest_kind(path: str, kind: str) -> None:
    assert dm.manifest_kind_for_path(path) == kind


@pytest.mark.parametrize(
    "path",
    ["README.md", "docs/modules.txt", "src/main/java/App.java", "notes/requirements.md"],
)
def test_roster_ignores_non_manifests(path: str) -> None:
    assert dm.manifest_kind_for_path(path) is None


def test_recognized_but_unparsed_ecosystems_stay_on_the_roster() -> None:
    # An ecosystem with no reader must still be recognized, so the picture can
    # report it as an unanalyzed hole instead of an absence.
    unparsed = {
        kind
        for kind in dm.RECOGNIZED_MANIFESTS.values()
        if kind not in dm.PARSED_MANIFEST_KINDS
    }
    assert {"composer_manifest", "bundler_lock", "cargo_manifest"} <= unparsed


def test_url_path_fragments_cover_the_roster_in_web_recon_form() -> None:
    fragments = dm.url_path_fragments()

    assert all(f.startswith("/") for f in fragments)
    assert all(f == f.lower() for f in fragments)
    # The six the web classifier already carried by hand must survive the move
    # to the shared roster, and the ones it never had must now be present.
    assert {
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/composer.json",
        "/composer.lock",
    } <= set(fragments)
    assert {"/pom.xml", "/go.sum", "/go.mod", "/gemfile.lock"} <= set(fragments)


# --------------------------------------------------------------------------- #
# Language detection for dependency surfaces
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("filename", "language"),
    [
        ("build.gradle.kts", "kotlin"),
        ("settings.gradle.kts", "kotlin"),
        ("poetry.lock", "toml"),
        ("Pipfile", "toml"),
        ("Pipfile.lock", "json"),
    ],
)
def test_dependency_surfaces_get_their_real_language(filename: str, language: str) -> None:
    assert detect_language(filename) == language


@pytest.mark.parametrize(
    ("filename", "language"),
    [
        ("pom.xml", "xml"),
        ("package-lock.json", "json"),
        ("pyproject.toml", "toml"),
        ("requirements.txt", "text"),
        ("App.java", "java"),
        ("login.ftl", "freemarker"),
    ],
)
def test_existing_language_detection_is_unchanged(filename: str, language: str) -> None:
    assert detect_language(filename) == language


# --------------------------------------------------------------------------- #
# Maven
# --------------------------------------------------------------------------- #


AGGREGATOR_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>platform</artifactId>
  <version>3.1.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>services/api</module>
    <module>libs/common</module>
  </modules>
  <properties>
    <commons.text.version>1.9</commons.text.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-text</artifactId>
        <version>${commons.text.version}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""

SERVICE_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>com.example</groupId>
    <artifactId>platform</artifactId>
    <version>3.1.0</version>
  </parent>
  <artifactId>api</artifactId>
  <packaging>war</packaging>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
    </dependency>
    <dependency>
      <groupId>jakarta.servlet</groupId>
      <artifactId>jakarta.servlet-api</artifactId>
      <version>6.0.0</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.0</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.1.2-jre</version>
      <optional>true</optional>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-shade-plugin</artifactId>
        <configuration>
          <relocations>
            <relocation>
              <pattern>com.google.common</pattern>
              <shadedPattern>com.example.shaded.guava</shadedPattern>
            </relocation>
          </relocations>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
"""


def test_maven_reads_scope_version_and_declaration_verbatim() -> None:
    parse = _parse("services/api/pom.xml", SERVICE_POM)
    deps = _by_coordinate(parse)

    assert parse.module_path == "services/api"
    assert set(deps) == {
        "org.apache.commons:commons-text",
        "jakarta.servlet:jakarta.servlet-api",
        "org.junit.jupiter:junit-jupiter",
        "com.google.guava:guava",
    }
    assert deps["jakarta.servlet:jakarta.servlet-api"].declared_scope == "provided"
    assert deps["org.junit.jupiter:junit-jupiter"].declared_scope == "test"
    # An omitted <scope> is Maven's `compile` default; the reader records the
    # default it applied rather than leaving the field blank and guessing later.
    assert deps["org.apache.commons:commons-text"].declared_scope == "compile"
    assert "optional" in deps["com.google.guava:guava"].qualifiers


def test_maven_evidence_quotes_the_declaring_line() -> None:
    parse = _parse("services/api/pom.xml", SERVICE_POM)
    servlet = _by_coordinate(parse)["jakarta.servlet:jakarta.servlet-api"]

    assert servlet.evidence, "a declaration with no evidence cannot be audited"
    cited = servlet.evidence[0]
    assert cited.path == "services/api/pom.xml"
    assert cited.line == 15
    assert "jakarta.servlet" in cited.text


def test_maven_unversioned_dependency_is_not_invented() -> None:
    # commons-text takes its version from the parent's dependencyManagement,
    # which this POM does not contain. The reader must say so rather than
    # emitting an empty version that reads as "unversioned".
    parse = _parse("services/api/pom.xml", SERVICE_POM)
    commons = _by_coordinate(parse)["org.apache.commons:commons-text"]

    assert commons.version == ""
    assert commons.version_source == "unresolved"


def test_maven_resolves_a_property_version_within_one_file() -> None:
    parse = _parse("pom.xml", AGGREGATOR_POM)
    managed = _by_coordinate(parse)["org.apache.commons:commons-text"]

    assert managed.version == "1.9"
    assert managed.version_source == "property"
    assert managed.declaration == "managed"


def test_maven_aggregator_declares_its_packaging() -> None:
    # `pom` packaging is what marks the module an aggregator downstream, so it
    # ships nothing of its own and its dependencyManagement reads as policy.
    parse = _parse("pom.xml", AGGREGATOR_POM)

    assert parse.facts.packaging == "pom"


def test_maven_shade_relocations_are_captured_with_both_prefixes() -> None:
    parse = _parse("services/api/pom.xml", SERVICE_POM)

    assert len(parse.facts.relocations) == 1
    relocation = parse.facts.relocations[0]
    assert relocation.source_prefix == "com.google.common"
    assert relocation.shaded_prefix == "com.example.shaded.guava"


def test_malformed_pom_reports_a_gap_instead_of_raising() -> None:
    parse = _parse("pom.xml", "<project><dependencies>\n<dependency>\n")

    assert parse.dependencies == ()
    assert [gap.gap for gap in parse.gaps] == ["unreadable_manifest"]


def test_pom_entity_declaration_is_refused_rather_than_expanded() -> None:
    # A POM is project-supplied text. Expanding entities buys an element reader
    # nothing and adds an expansion-bomb surface, so a declaration is a gap.
    hostile = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE project [<!ENTITY a 'aaaaaaaaaa'>]>\n"
        "<project><artifactId>&a;</artifactId></project>\n"
    )
    parse = _parse("pom.xml", hostile)

    assert [gap.gap for gap in parse.gaps] == ["unreadable_manifest"]


# --------------------------------------------------------------------------- #
# Gradle
# --------------------------------------------------------------------------- #


BUILD_GRADLE = """\
plugins {
    id 'java'
    id 'com.github.johnrengelman.shadow' version '8.1.1'
}

dependencies {
    implementation 'org.apache.commons:commons-text:1.9'
    api("com.squareup.okhttp3:okhttp:4.12.0")
    compileOnly 'jakarta.servlet:jakarta.servlet-api:6.0.0'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
    runtimeOnly group: 'org.postgresql', name: 'postgresql', version: '42.7.1'
    implementation libs.jackson.databind
}

shadowJar {
    relocate 'com.google.common', 'com.example.shaded.guava'
}
"""


def test_gradle_records_the_configuration_verbatim() -> None:
    parse = _parse("build.gradle", BUILD_GRADLE)
    deps = _by_coordinate(parse)

    assert deps["org.apache.commons:commons-text"].declared_scope == "implementation"
    assert deps["com.squareup.okhttp3:okhttp"].declared_scope == "api"
    assert deps["jakarta.servlet:jakarta.servlet-api"].declared_scope == "compileOnly"
    assert deps["org.junit.jupiter:junit-jupiter"].declared_scope == "testImplementation"
    assert deps["org.apache.commons:commons-text"].version == "1.9"


def test_gradle_map_notation_is_read_like_string_notation() -> None:
    deps = _by_coordinate(_parse("build.gradle", BUILD_GRADLE))

    postgres = deps["org.postgresql:postgresql"]
    assert postgres.version == "42.7.1"
    assert postgres.declared_scope == "runtimeOnly"


def test_gradle_version_catalog_alias_is_not_resolved_to_a_guess() -> None:
    deps = _by_coordinate(_parse("build.gradle", BUILD_GRADLE))

    alias = deps["libs.jackson.databind"]
    assert alias.version == ""
    assert alias.version_source == "unresolved"
    assert "version_catalog_alias" in alias.qualifiers


def test_gradle_shadow_relocation_is_captured() -> None:
    parse = _parse("build.gradle", BUILD_GRADLE)

    assert [(r.source_prefix, r.shaded_prefix) for r in parse.facts.relocations] == [
        ("com.google.common", "com.example.shaded.guava")
    ]


VERSION_CATALOG = """\
[versions]
jackson = "2.17.0"

[libraries]
jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
okhttp = { group = "com.squareup.okhttp3", name = "okhttp", version = "4.12.0" }
"""


def test_version_catalog_resolves_its_own_version_refs() -> None:
    deps = _by_coordinate(_parse("gradle/libs.versions.toml", VERSION_CATALOG))

    databind = deps["com.fasterxml.jackson.core:jackson-databind"]
    assert databind.version == "2.17.0"
    assert databind.version_source == "version_catalog"
    assert databind.declaration == "managed"
    assert deps["com.squareup.okhttp3:okhttp"].version == "4.12.0"


def test_version_catalog_carries_the_alias_the_build_script_will_name() -> None:
    # The alias is the join key: a build script says `libs.jackson.databind`,
    # and without the catalog key travelling on the record nothing downstream
    # can turn that accessor back into a coordinate.
    deps = _by_coordinate(_parse("gradle/libs.versions.toml", VERSION_CATALOG))

    assert "catalog_alias:jackson-databind" in (
        deps["com.fasterxml.jackson.core:jackson-databind"].qualifiers
    )


CATALOG_ALIAS_SHARED_WITH_A_VERSION = """\
[versions]
jackson = "2.17.0"

[libraries]
jackson = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
"""


def test_version_catalog_evidence_quotes_the_library_not_the_version_pin() -> None:
    # `jackson` names a version on line 2 and a library on line 5. Quoting the
    # first whole-file match cites a line that states a different fact than the
    # record holds.
    catalog = _parse("gradle/libs.versions.toml", CATALOG_ALIAS_SHARED_WITH_A_VERSION)
    cited = catalog.dependencies[0].evidence[0]

    assert cited.line == 5
    assert "module" in cited.text


CATALOG_WITH_AN_ENTRY_THAT_NAMES_NO_COORDINATE = """\
[libraries]
nameless = { name = "mystery", version = "1.0" }
notacoordinate = "okhttp"
listy = ["com.squareup.okhttp3", "okhttp"]
okhttp = { group = "com.squareup.okhttp3", name = "okhttp", version = "4.12.0" }
"""


def test_a_catalog_entry_with_no_coordinate_is_a_hole_not_a_silent_drop() -> None:
    # An alias a build script can name must resolve to a component. One that
    # resolves to nothing leaves the script's `libs.<alias>` row unresolvable
    # forever, so the entry is reported rather than skipped.
    parse = _parse(
        "gradle/libs.versions.toml", CATALOG_WITH_AN_ENTRY_THAT_NAMES_NO_COORDINATE
    )

    assert [dep.coordinate for dep in parse.dependencies] == ["com.squareup.okhttp3:okhttp"]
    reported = [gap for gap in parse.gaps if gap.gap == "unresolved_catalog_entry"]
    assert len(reported) == 3
    for alias in ("nameless", "notacoordinate", "listy"):
        assert any(alias in gap.detail for gap in reported), alias


GRADLE_LOCKFILE = """\
# This is a Gradle generated file for dependency locking.
org.apache.commons:commons-text:1.9=compileClasspath,runtimeClasspath
jakarta.servlet:jakarta.servlet-api:6.0.0=compileClasspath
org.junit.jupiter:junit-jupiter:5.10.0=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor
"""


def test_gradle_lockfile_keeps_the_resolving_configurations() -> None:
    deps = _by_coordinate(_parse("gradle.lockfile", GRADLE_LOCKFILE))

    assert deps["org.apache.commons:commons-text"].version == "1.9"
    assert (
        deps["org.apache.commons:commons-text"].declared_scope
        == "compileClasspath,runtimeClasspath"
    )
    # Present on compileClasspath only: the lockfile is saying this artifact is
    # resolved for compilation and not for the runtime classpath.
    assert deps["jakarta.servlet:jakarta.servlet-api"].declared_scope == "compileClasspath"
    assert deps["org.apache.commons:commons-text"].version_source == "lockfile"
    assert "empty" not in _by_coordinate(_parse("gradle.lockfile", GRADLE_LOCKFILE))


# --------------------------------------------------------------------------- #
# npm
# --------------------------------------------------------------------------- #


PACKAGE_JSON = """\
{
  "name": "storefront",
  "version": "2.4.0",
  "dependencies": {
    "lodash": "^4.17.20",
    "express": "4.18.2"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  },
  "peerDependencies": {
    "react": ">=17"
  },
  "optionalDependencies": {
    "fsevents": "^2.3.0"
  },
  "bundledDependencies": ["express"]
}
"""


def test_npm_package_json_keeps_each_dependency_block_distinct() -> None:
    deps = _by_coordinate(_parse("package.json", PACKAGE_JSON))

    assert deps["lodash"].declared_scope == "dependencies"
    assert deps["jest"].declared_scope == "devDependencies"
    assert deps["react"].declared_scope == "peerDependencies"
    assert deps["fsevents"].declared_scope == "optionalDependencies"
    assert deps["lodash"].version == "^4.17.20"
    assert deps["lodash"].version_source == "manifest"


PACKAGE_JSON_WITH_OVERRIDES = """\
{
  "name": "storefront",
  "overrides": {
    "lodash": "4.17.21"
  },
  "devDependencies": {
    "lodash": "^4.17.20"
  }
}
"""


def test_npm_evidence_quotes_the_block_the_dependency_was_declared_in() -> None:
    # `lodash` appears first in `overrides`, which pins a DIFFERENT version
    # than the devDependency this record came from. Evidence that quotes the
    # first whole-file match states a fact the record does not hold.
    deps = _by_coordinate(_parse("package.json", PACKAGE_JSON_WITH_OVERRIDES))

    cited = deps["lodash"].evidence[0]
    assert cited.line == 7
    assert "^4.17.20" in cited.text


PACKAGE_LOCK_V3 = """\
{
  "name": "storefront",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "storefront", "version": "2.4.0"},
    "node_modules/lodash": {"version": "4.17.21", "resolved": "https://r/lodash"},
    "node_modules/express": {"version": "4.18.2"},
    "node_modules/jest": {"version": "29.7.0", "dev": true},
    "node_modules/serve-static": {"version": "1.15.0"},
    "node_modules/serve-static/node_modules/lodash": {"version": "3.10.1"}
  }
}
"""


def test_npm_lock_reports_every_installed_path_with_its_version() -> None:
    deps = _parse("package-lock.json", PACKAGE_LOCK_V3).dependencies
    versions = sorted((d.coordinate, d.version) for d in deps)

    assert ("lodash", "4.17.21") in versions
    assert ("lodash", "3.10.1") in versions
    assert ("jest", "29.7.0") in versions
    # The root entry describes the project, not a dependency of it.
    assert all(d.coordinate != "storefront" for d in deps)


def test_npm_lock_marks_dev_only_installs() -> None:
    deps = _parse("package-lock.json", PACKAGE_LOCK_V3).dependencies
    jest = next(d for d in deps if d.coordinate == "jest")

    assert jest.declared_scope == "dev"
    assert jest.version_source == "lockfile"


def test_npm_lock_transitive_depth_is_preserved_as_evidence() -> None:
    deps = _parse("package-lock.json", PACKAGE_LOCK_V3).dependencies
    nested = next(d for d in deps if d.coordinate == "lodash" and d.version == "3.10.1")

    assert nested.declaration == "transitive"
    assert nested.evidence[0].text.startswith("node_modules/serve-static/node_modules/lodash")


PACKAGE_LOCK_NESTED_FIRST = """\
{
  "name": "storefront",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "storefront"},
    "node_modules/serve-static/node_modules/lodash": {"version": "3.10.1"},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}
"""


def test_npm_lock_evidence_cites_each_install_paths_own_line() -> None:
    # The nested install path CONTAINS the top-level one, so a substring search
    # hands the root copy the nested copy's line — and the two are different
    # versions of the same package, which is precisely what a reviewer is
    # reading this file to tell apart.
    deps = _parse("package-lock.json", PACKAGE_LOCK_NESTED_FIRST).dependencies
    by_version = {dep.version: dep for dep in deps}

    assert by_version["3.10.1"].evidence[0].line == 6
    assert by_version["4.17.21"].evidence[0].line == 7


PACKAGE_LOCK_WORKSPACES = """\
{
  "name": "mono",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "mono", "workspaces": ["packages/*"]},
    "node_modules/app": {"resolved": "packages/app", "link": true},
    "node_modules/lodash": {"version": "4.17.21"},
    "packages/app": {"name": "app", "version": "1.0.0"},
    "packages/lib": {"name": "lib", "version": "2.0.0"}
  }
}
"""


def test_npm_lock_workspace_entries_are_the_project_not_components_it_ships() -> None:
    # A `packages/*` key is a workspace member — this project's own source,
    # already read from its own package.json. Reading the key as a package name
    # invents a shipped component called `packages/app`, one per workspace, in
    # every monorepo.
    deps = _parse("package-lock.json", PACKAGE_LOCK_WORKSPACES).dependencies

    assert sorted(dep.coordinate for dep in deps) == ["app", "lodash"]
    assert next(d for d in deps if d.coordinate == "app").declaration == "workspace_link"


YARN_LOCK = """\
# yarn lockfile v1


lodash@^4.17.20:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

"@scope/widget@^1.0.0", "@scope/widget@^1.2.0":
  version "1.2.3"
"""


def test_yarn_lock_reads_scoped_and_unscoped_blocks() -> None:
    deps = _by_coordinate(_parse("yarn.lock", YARN_LOCK))

    assert deps["lodash"].version == "4.17.21"
    assert deps["@scope/widget"].version == "1.2.3"
    assert deps["lodash"].version_source == "lockfile"


# --------------------------------------------------------------------------- #
# Go
# --------------------------------------------------------------------------- #


GO_MOD = """\
module github.com/example/service

go 1.22

require (
	github.com/gorilla/mux v1.8.1
	golang.org/x/crypto v0.21.0 // indirect
)

require github.com/lib/pq v1.10.9

replace github.com/gorilla/mux => ./internal/mux

exclude golang.org/x/text v0.3.0
"""


def test_go_mod_separates_direct_from_indirect() -> None:
    deps = _by_coordinate(_parse("go.mod", GO_MOD))

    assert deps["github.com/gorilla/mux"].declaration == "direct"
    assert deps["golang.org/x/crypto"].declaration == "transitive"
    assert deps["github.com/lib/pq"].declaration == "direct"
    assert deps["github.com/gorilla/mux"].version == "v1.8.1"


def test_go_mod_replace_directive_is_recorded_on_the_dependency() -> None:
    deps = _by_coordinate(_parse("go.mod", GO_MOD))

    assert "replaced" in deps["github.com/gorilla/mux"].qualifiers


def test_go_mod_project_module_is_not_a_dependency_of_itself() -> None:
    parse = _parse("go.mod", GO_MOD)

    assert "github.com/example/service" not in _by_coordinate(parse)


GO_MOD_BLOCK_REPLACE = """\
module github.com/example/service

go 1.22

require (
\tgithub.com/gorilla/mux v1.8.1
\tgolang.org/x/crypto v0.21.0
)

replace (
\tgithub.com/gorilla/mux => ./internal/mux
\tgolang.org/x/crypto v0.21.0 => golang.org/x/crypto v0.20.0
)
"""


def test_go_mod_block_form_replace_is_read_like_the_single_line_form() -> None:
    # `replace (` opens a block whose entries are the replaced modules. Matching
    # the module on the `replace` line itself captures the literal `(`, so every
    # module a block replaces reads as un-replaced — and a replaced module is
    # not the code the registry version would be.
    deps = _by_coordinate(_parse("go.mod", GO_MOD_BLOCK_REPLACE))

    assert set(deps) == {"github.com/gorilla/mux", "golang.org/x/crypto"}
    assert "replaced" in deps["github.com/gorilla/mux"].qualifiers
    assert "replaced" in deps["golang.org/x/crypto"].qualifiers


GO_SUM = """\
github.com/gorilla/mux v1.8.1 h1:abc=
github.com/gorilla/mux v1.8.1/go.mod h1:def=
golang.org/x/text v0.3.0 h1:ghi=
"""


def test_go_sum_is_read_as_the_module_graph_not_the_build() -> None:
    # go.sum records every module version the graph ever considered, including
    # ones no build links. The reader must mark that rather than presenting
    # them as dependencies of this build.
    deps = _by_coordinate(_parse("go.sum", GO_SUM))

    assert set(deps) == {"github.com/gorilla/mux", "golang.org/x/text"}
    assert deps["golang.org/x/text"].declaration == "graph"


VENDOR_MODULES = """\
# github.com/gorilla/mux v1.8.1
## explicit; go 1.20
github.com/gorilla/mux
# golang.org/x/crypto v0.21.0
## explicit
golang.org/x/crypto/bcrypt
"""


def test_go_vendor_modules_reports_vendored_packages() -> None:
    parse = _parse("vendor/modules.txt", VENDOR_MODULES)
    deps = _by_coordinate(parse)

    assert deps["github.com/gorilla/mux"].version == "v1.8.1"
    assert deps["github.com/gorilla/mux"].declaration == "vendored"


# --------------------------------------------------------------------------- #
# Python
# --------------------------------------------------------------------------- #


REQUIREMENTS = """\
# runtime pins
Django==4.2.11
requests[security]>=2.31.0
PyYAML==6.0.1 ; python_version >= "3.8"
-r constraints.txt
-e ./libs/internal
urllib3
"""


def test_requirements_reads_pins_extras_and_markers() -> None:
    parse = _parse("requirements.txt", REQUIREMENTS)
    deps = _by_coordinate(parse)

    assert deps["django"].version == "==4.2.11"
    assert deps["requests"].version == ">=2.31.0"
    assert "extras:security" in deps["requests"].qualifiers
    assert 'marker:python_version >= "3.8"' in deps["pyyaml"].qualifiers
    # An unpinned requirement resolves to nothing; saying so beats inventing one.
    assert deps["urllib3"].version == ""
    assert deps["urllib3"].version_source == "unresolved"


def test_requirements_include_directive_is_reported_as_a_gap() -> None:
    # `-r constraints.txt` means part of the declaration lives in another file.
    # Silently dropping it would make this file look complete when it is not.
    parse = _parse("requirements.txt", REQUIREMENTS)

    assert any(gap.gap == "external_requirement_include" for gap in parse.gaps)


REQUIREMENTS_BY_LOCATION = """\
https://example.test/pkg-1.0.tar.gz
git+https://github.test/acme/widget.git@v1#egg=widget
./libs/local
telemetry @ https://example.test/telemetry-2.0-py3-none-any.whl
requests>=2.31.0
"""


def test_a_requirement_that_names_a_location_is_not_read_as_a_distribution() -> None:
    # `https://example.test/pkg-1.0.tar.gz` is a location, and the requirement
    # grammar happily reads its scheme as a name: the picture then carries a
    # component called `https` at version `://example.test/...`, which exists in
    # no registry and matches no import.
    deps = _by_coordinate(_parse("requirements.txt", REQUIREMENTS_BY_LOCATION))

    assert set(deps) == {"widget", "telemetry", "requests"}
    # The two forms that DO name a distribution keep their identity, and neither
    # pretends the URL is a resolved version.
    assert deps["widget"].version == ""
    assert deps["widget"].version_source == "unresolved"
    assert "direct_reference" in deps["widget"].qualifiers
    assert deps["telemetry"].version == ""
    assert "direct_reference" in deps["telemetry"].qualifiers
    assert deps["requests"].version == ">=2.31.0"


def test_a_location_naming_no_distribution_is_disclosed_rather_than_dropped() -> None:
    # A hole must be visible. Dropping these silently makes the file look like
    # it declares three requirements when it declares five.
    parse = _parse("requirements.txt", REQUIREMENTS_BY_LOCATION)
    reported = [gap for gap in parse.gaps if gap.gap == "unnamed_requirement_reference"]

    assert len(reported) == 2
    assert any("pkg-1.0.tar.gz" in gap.detail for gap in reported)
    assert any("./libs/local" in gap.detail for gap in reported)


PYPROJECT = """\
[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "storefront"
version = "1.0.0"
dependencies = ["Django==4.2.11", "requests>=2.31.0"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.poetry.dependencies]
httpx = "^0.27"

[tool.poetry.group.dev.dependencies]
ruff = "^0.4"
"""


def test_pyproject_keeps_build_runtime_and_group_declarations_apart() -> None:
    deps = _by_coordinate(_parse("pyproject.toml", PYPROJECT))

    assert deps["django"].declared_scope == "project.dependencies"
    assert deps["pytest"].declared_scope == "project.optional-dependencies.dev"
    assert deps["setuptools"].declared_scope == "build-system.requires"
    assert deps["httpx"].declared_scope == "tool.poetry.dependencies"
    assert deps["ruff"].declared_scope == "tool.poetry.group.dev.dependencies"


PYPROJECT_OPTIONAL_POETRY_EXTRA = """\
[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
boto3 = { version = "^1.34", optional = true }
"""


def test_poetry_marks_an_optional_dependency_the_way_the_lock_reader_does() -> None:
    # `optional = true` means the package is installed only when an extra asks
    # for it. Reading the table for its version alone drops that word, and the
    # opt-in extra then reads exactly like a dependency every install ships.
    deps = _by_coordinate(_parse("pyproject.toml", PYPROJECT_OPTIONAL_POETRY_EXTRA))

    assert "optional" in deps["boto3"].qualifiers
    assert "optional" not in deps["httpx"].qualifiers
    assert deps["boto3"].version == "^1.34"


PYPROJECT_REPEATED_STATEMENT = """\
[project]
name = "storefront"
dependencies = [
    "requests>=2.31.0",
]

[project.optional-dependencies]
http = [
    "requests>=2.31.0",
]

[tool.poetry.dependencies]
httpx = "^0.27"

[tool.poetry.group.dev.dependencies]
httpx = "^0.28"
"""


def test_pyproject_evidence_cites_the_table_each_declaration_was_read_from() -> None:
    # The same requirement in two tables, and the same package pinned twice.
    # Each record must quote its own line: an optional extra citing the runtime
    # line reads as a runtime dependency to anyone who checks the evidence.
    parse = _parse("pyproject.toml", PYPROJECT_REPEATED_STATEMENT)
    by_scope = {dep.declared_scope: dep for dep in parse.dependencies}

    assert by_scope["project.dependencies"].evidence[0].line == 4
    assert by_scope["project.optional-dependencies.http"].evidence[0].line == 9
    assert by_scope["tool.poetry.dependencies"].evidence[0].line == 13
    dev = by_scope["tool.poetry.group.dev.dependencies"]
    assert dev.evidence[0].line == 16
    assert "^0.28" in dev.evidence[0].text


PYPROJECT_WITH_A_NON_TABLE_TOOL_KEY = """\
tool = "setuptools"

[project]
name = "storefront"
dependencies = ["Django==4.2.11"]
"""


def test_a_valid_but_unusual_pyproject_is_still_read_for_what_it_declares() -> None:
    # `tool` as a string is valid TOML. Chaining `.get("poetry")` onto it raises
    # AttributeError, which used to escape the reader and abort the entire run
    # — every other manifest, the build output and the index lost to one file.
    parse = _parse("pyproject.toml", PYPROJECT_WITH_A_NON_TABLE_TOOL_KEY)

    assert [dep.coordinate for dep in parse.dependencies] == ["django"]
    unreadable = [gap for gap in parse.gaps if gap.gap == "unreadable_declaration_block"]
    assert unreadable, "a block we could not read is a hole and must be disclosed"
    assert "tool" in unreadable[0].detail


CATALOG_WITH_A_NON_TABLE_VERSIONS_KEY = """\
versions = "2.17.0"

[libraries]
okhttp = { group = "com.squareup.okhttp3", name = "okhttp", version = "4.12.0" }
"""


def test_a_version_catalog_with_an_unreadable_block_still_reports_its_libraries() -> None:
    parse = _parse("gradle/libs.versions.toml", CATALOG_WITH_A_NON_TABLE_VERSIONS_KEY)

    assert [dep.coordinate for dep in parse.dependencies] == ["com.squareup.okhttp3:okhttp"]
    assert any(gap.gap == "unreadable_declaration_block" for gap in parse.gaps)


def test_an_unexpected_reader_failure_is_one_gap_not_a_lost_run(monkeypatch) -> None:
    # The backstop behind the type guards: whatever shape a build file arrives
    # in, one file that defeats its reader is a hole in that file. The index
    # loader already degrades this way and the readers must match it.
    def explode(_context):
        raise AttributeError("'str' object has no attribute 'get'")

    monkeypatch.setitem(dm._READERS, "npm_package", explode)
    parse = _parse("package.json", PACKAGE_JSON)

    assert parse.dependencies == ()
    assert [gap.gap for gap in parse.gaps] == ["unreadable_manifest"]


POETRY_LOCK = """\
[[package]]
name = "Django"
version = "4.2.11"
optional = false
groups = ["main"]

[[package]]
name = "pytest"
version = "8.1.1"
optional = false
groups = ["dev"]
"""


def test_poetry_lock_carries_the_group_that_resolved_each_package() -> None:
    deps = _by_coordinate(_parse("poetry.lock", POETRY_LOCK))

    assert deps["django"].version == "4.2.11"
    assert deps["django"].declared_scope == "main"
    assert deps["pytest"].declared_scope == "dev"


POETRY_LOCK_TWO_VERSIONS_OF_ONE_PACKAGE = """\
[[package]]
name = "urllib3"
version = "1.26.18"
groups = ["main"]

[[package]]
name = "urllib3"
version = "2.2.1"
groups = ["main"]
"""


def test_poetry_lock_evidence_cites_each_packages_own_entry() -> None:
    # Two resolutions of one package is the case a reviewer is looking for.
    # Both records citing the first entry hides the second one entirely.
    deps = _parse("poetry.lock", POETRY_LOCK_TWO_VERSIONS_OF_ONE_PACKAGE).dependencies

    assert [dep.evidence[0].line for dep in deps] == [2, 7]


PIPFILE_LOCK_SHARED_NAME = """\
{
  "default": {"django": {"version": "==4.2.11"}},
  "develop": {"django": {"version": "==3.2.0"}}
}
"""


def test_pipfile_lock_evidence_cites_the_block_each_pin_came_from() -> None:
    deps = _parse("Pipfile.lock", PIPFILE_LOCK_SHARED_NAME).dependencies
    by_scope = {dep.declared_scope: dep for dep in deps}

    assert by_scope["default"].evidence[0].line == 2
    assert by_scope["develop"].evidence[0].line == 3
    assert "==3.2.0" in by_scope["develop"].evidence[0].text


PIPFILE_LOCK = """\
{
  "default": {"django": {"version": "==4.2.11"}},
  "develop": {"pytest": {"version": "==8.1.1"}}
}
"""


def test_pipfile_lock_separates_default_from_develop() -> None:
    deps = _by_coordinate(_parse("Pipfile.lock", PIPFILE_LOCK))

    assert deps["django"].declared_scope == "default"
    assert deps["pytest"].declared_scope == "develop"


# --------------------------------------------------------------------------- #
# Evidence and scale
# --------------------------------------------------------------------------- #


def test_the_record_carries_the_whole_line_it_quoted() -> None:
    # Truncating in the reader cuts the RECORD, so `--json` loses text the
    # operator has no way to recover. Bounding the rendered width belongs to
    # the renderer, which can state the elision; the record keeps the line.
    specifier = "git+https://example.test/" + "a" * 600 + ".git#v2"
    text = json.dumps({"name": "app", "dependencies": {"widget": specifier}}, indent=2)

    widget = _by_coordinate(_parse("package.json", text))["widget"]

    assert specifier in widget.evidence[0].text


def test_a_large_lockfile_is_read_in_one_pass_not_once_per_entry() -> None:
    # Locating each entry by rescanning the whole file is quadratic: a real
    # 3.6 MB lockfile took 21 seconds, and the reader accepts files up to 8 MB.
    # The ceiling is deliberately generous — it fails on the algorithm, not on
    # a slow machine.
    entries = 10_000
    packages = {"": {"name": "app", "version": "1.0.0"}}
    for index in range(entries):
        name = f"pkg{index:05d}"
        packages[f"node_modules/{name}"] = {
            "version": f"1.0.{index}",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.0.{index}.tgz",
            "integrity": "sha512-" + "a" * 80,
        }
    text = json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages}, indent=2)

    start = time.perf_counter()
    parse = dm.parse_manifest("npm_lock", "package-lock.json", text)
    elapsed = time.perf_counter() - start

    assert len(parse.dependencies) == entries
    assert elapsed < 5.0, f"reading {len(text) // 1024} KiB took {elapsed:.1f}s"


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("services/api/pom.xml", SERVICE_POM),
        ("build.gradle", BUILD_GRADLE),
        ("package-lock.json", PACKAGE_LOCK_V3),
        ("go.mod", GO_MOD),
        ("requirements.txt", REQUIREMENTS),
    ],
)
def test_readers_are_deterministic(path: str, text: str) -> None:
    assert _parse(path, text) == _parse(path, text)


PARENT_PROPERTY_POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <artifactId>api</artifactId>
  <dependencies>
    <dependency>
      <groupId>${vendor.groupId}</groupId>
      <artifactId>widget</artifactId>
      <version>1.0</version>
    </dependency>
  </dependencies>
</project>
"""


def test_a_coordinate_this_pom_cannot_resolve_is_reported_not_dropped() -> None:
    # The groupId is a property defined in a parent POM that is not in the tree.
    # Dropping the dependency silently would make the module look like it
    # declares one fewer than it does.
    parse = _parse("pom.xml", PARENT_PROPERTY_POM)

    assert parse.dependencies == ()
    gap = next(gap for gap in parse.gaps if gap.gap == "unresolved_coordinate")
    assert "widget" in gap.detail
