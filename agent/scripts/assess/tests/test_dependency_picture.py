"""Shipped-and-reachable derivation over parsed build files.

Two properties carry this module. First, precision: only a component the build
ships *and* the reviewed code reaches is a lead, and everything else must be
visibly not one. Second, and more important, no shape emitted here may be
readable as proof that a dependency is absent or unused — the derivation is
build-file and index driven, and neither settles what a built artifact
contains.
"""
from __future__ import annotations

import pytest

from assess.lib import dependency_manifests as dm
from assess.lib import dependency_picture as dp

from test_dependency_manifests import (
    AGGREGATOR_POM,
    BUILD_GRADLE,
    GO_MOD,
    GRADLE_LOCKFILE,
    PACKAGE_JSON,
    PACKAGE_LOCK_V3,
    SERVICE_POM,
    VERSION_CATALOG,
)


def _parse(path: str, text: str) -> dm.ManifestParse:
    kind = dm.manifest_kind_for_path(path)
    assert kind is not None, path
    return dm.parse_manifest(kind, path, text)


def _picture(files: dict[str, str], **kwargs) -> dp.DependencyPicture:
    parses = [_parse(path, text) for path, text in sorted(files.items())]
    return dp.build_dependency_picture(parses=parses, **kwargs)


def _observation(
    picture: dp.DependencyPicture, coordinate: str, version: str | None = None
) -> dp.DependencyObservation:
    matches = [
        obs
        for obs in picture.observations
        if obs.coordinate == coordinate and (version is None or obs.version == version)
    ]
    assert matches, f"no observation for {coordinate!r} {version or ''}"
    assert len(matches) == 1, f"expected one observation for {coordinate!r}, got {len(matches)}"
    return matches[0]


# --------------------------------------------------------------------------- #
# The vocabularies cannot be read as clearance
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "vocabulary",
    [dp.SHIPMENT_OBSERVATIONS, dp.REACHABILITY_OBSERVATIONS, dp.DEPENDENCY_QUALIFIERS],
)
def test_every_vocabulary_member_declares_itself_unverified(vocabulary) -> None:
    assert vocabulary
    assert all(member.startswith("unverified_") for member in vocabulary)


@pytest.mark.parametrize(
    "vocabulary",
    [dp.SHIPMENT_OBSERVATIONS, dp.REACHABILITY_OBSERVATIONS],
)
def test_no_vocabulary_member_reads_as_a_clean_result(vocabulary) -> None:
    # A value a reader could quote as "this dependency is fine" is the failure
    # mode; each member must name an observation, never a clearance.
    forbidden = ("safe", "clean", "unused", "absent", "not_shipped", "unreachable", "ok")
    offenders = [m for m in vocabulary if any(word in m for word in forbidden)]

    assert not offenders, f"these read as a verdict, not an observation: {offenders}"


def test_looking_and_finding_nothing_is_spelled_differently_from_not_looking() -> None:
    assert "unverified_no_reference_observed" in dp.REACHABILITY_OBSERVATIONS
    assert "unverified_reachability_unindexed" in dp.REACHABILITY_OBSERVATIONS


def test_every_observation_carries_a_detection_marker_and_its_evidence() -> None:
    picture = _picture({"services/api/pom.xml": SERVICE_POM})

    assert picture.observations
    for obs in picture.observations:
        assert obs.detection, f"{obs.coordinate} has no detection provenance"
        assert obs.shipment_observation in dp.SHIPMENT_OBSERVATIONS
        assert obs.reachability_observation in dp.REACHABILITY_OBSERVATIONS
        assert obs.observation_origin in dp.DEPENDENCY_OBSERVATION_ORIGINS
        assert obs.evidence, f"{obs.coordinate} states a conclusion with no evidence"
        assert all(q in dp.DEPENDENCY_QUALIFIERS for q in obs.qualifiers)


def test_without_an_index_nothing_is_reported_as_unreferenced() -> None:
    # The most dangerous possible output is "no code uses this" produced by a
    # run that never had an index to look in.
    picture = _picture({"services/api/pom.xml": SERVICE_POM})

    assert {obs.reachability_observation for obs in picture.observations} == {
        "unverified_reachability_unindexed"
    }


# --------------------------------------------------------------------------- #
# Ships vs declares
# --------------------------------------------------------------------------- #


def test_provided_scope_reads_as_expected_from_runtime_not_as_shipped() -> None:
    picture = _picture({"services/api/pom.xml": SERVICE_POM})

    servlet = _observation(picture, "jakarta.servlet:jakarta.servlet-api")
    assert servlet.shipment_observation == "unverified_expected_from_runtime"
    assert servlet.declared_scope == "provided"


def test_test_scope_reads_as_excluded_by_the_scope_it_declared() -> None:
    picture = _picture({"services/api/pom.xml": SERVICE_POM})

    junit = _observation(picture, "org.junit.jupiter:junit-jupiter")
    assert junit.shipment_observation == "unverified_excluded_by_declared_scope"
    # The evidence must quote the scope line, so the exclusion is auditable
    # rather than asserted.
    assert any("test" in citation.text for citation in junit.evidence)


def test_default_compile_scope_ships() -> None:
    picture = _picture({"services/api/pom.xml": SERVICE_POM, "pom.xml": AGGREGATOR_POM})

    commons = _observation(picture, "org.apache.commons:commons-text", version="1.9")
    assert commons.shipment_observation == "unverified_ships_by_default_scope"


def test_gradle_compile_only_is_excluded_and_implementation_ships() -> None:
    picture = _picture({"build.gradle": BUILD_GRADLE})

    assert (
        _observation(picture, "jakarta.servlet:jakarta.servlet-api").shipment_observation
        == "unverified_excluded_by_declared_scope"
    )
    assert (
        _observation(picture, "org.apache.commons:commons-text").shipment_observation
        == "unverified_ships_by_default_scope"
    )


def test_gradle_lockfile_compile_only_resolution_is_not_a_runtime_artifact() -> None:
    picture = _picture({"gradle.lockfile": GRADLE_LOCKFILE})

    servlet = _observation(picture, "jakarta.servlet:jakarta.servlet-api")
    assert servlet.shipment_observation == "unverified_excluded_by_declared_scope"
    assert (
        _observation(picture, "org.apache.commons:commons-text").shipment_observation
        == "unverified_ships_by_default_scope"
    )


def test_npm_peer_dependency_is_expected_from_the_host_application() -> None:
    picture = _picture({"package.json": PACKAGE_JSON})

    assert _observation(picture, "react").shipment_observation == (
        "unverified_expected_from_runtime"
    )
    assert _observation(picture, "jest").shipment_observation == (
        "unverified_excluded_by_declared_scope"
    )


def test_optional_dependency_shipment_is_left_undetermined() -> None:
    picture = _picture({"package.json": PACKAGE_JSON})

    fsevents = _observation(picture, "fsevents")
    assert fsevents.shipment_observation == "unverified_shipment_undetermined"
    assert "unverified_optional_declaration" in fsevents.qualifiers


def test_a_maven_profile_dependency_is_not_read_as_shipping_by_default() -> None:
    # A profile dependency ships only when its profile activates, and activation
    # is undecidable from the POM alone (JDK, OS, property, file existence). That
    # is the same conditionality `optional` carries, so it gets the same answer --
    # otherwise a build-profile-only library reads as shipping in every build.
    picture = _picture(
        {
            "pom.xml": (
                "<project><modelVersion>4.0.0</modelVersion>"
                "<profiles><profile><id>production</id>"
                "<activation><activeByDefault>true</activeByDefault></activation>"
                "<dependencies><dependency>"
                "<groupId>org.apache.logging.log4j</groupId>"
                "<artifactId>log4j-core</artifactId><version>2.14.1</version>"
                "</dependency></dependencies></profile></profiles></project>"
            )
        }
    )

    log4j = _observation(picture, "org.apache.logging.log4j:log4j-core")
    assert log4j.shipment_observation == "unverified_shipment_undetermined"
    assert "unverified_conditional_profile" in log4j.qualifiers
    # The profile that carries it stays nameable, so the operator can decide.
    assert "profile:production" in log4j.declaration_notes


def test_a_poetry_optional_extra_is_not_read_as_shipping_by_default() -> None:
    # `optional = true` means the package is installed only when an extra asks
    # for it, which is the same statement `optionalDependencies` makes in npm
    # and `<optional>` makes in Maven, and it gets the same answer.
    picture = _picture(
        {
            "pyproject.toml": (
                "[tool.poetry.dependencies]\npython = \"^3.11\"\n"
                "httpx = \"^0.27\"\nboto3 = { version = \"^1.34\", optional = true }\n"
            )
        }
    )

    boto3 = _observation(picture, "boto3")
    assert boto3.shipment_observation == "unverified_shipment_undetermined"
    assert "unverified_optional_declaration" in boto3.qualifiers
    assert _observation(picture, "httpx").shipment_observation == (
        "unverified_ships_by_default_scope"
    )


def test_python_build_system_requirement_is_not_a_shipped_component() -> None:
    picture = _picture(
        {
            "pyproject.toml": (
                "[build-system]\nrequires = [\"setuptools>=68\"]\n"
                "[project]\nname = \"x\"\ndependencies = [\"Django==4.2.11\"]\n"
            )
        }
    )

    assert _observation(picture, "setuptools").shipment_observation == (
        "unverified_excluded_by_declared_scope"
    )
    assert _observation(picture, "django").shipment_observation == (
        "unverified_ships_by_default_scope"
    )


# --------------------------------------------------------------------------- #
# Shading: the artifact ships under a name no manifest contains
# --------------------------------------------------------------------------- #


def test_a_relocated_dependency_is_reported_as_shipping_under_the_shaded_prefix() -> None:
    picture = _picture({"services/api/pom.xml": SERVICE_POM})

    guava = _observation(picture, "com.google.guava:guava")
    assert guava.shipment_observation == "unverified_relocated_into_shaded_artifact"
    assert "unverified_relocation_declared" in guava.qualifiers
    # Both prefixes must be searchable: source that survived the relocation
    # imports the original package, and a consumer of the shaded jar imports the
    # new one. Searching only one of the two is how a shaded jar disappears.
    assert "com.google.common" in guava.module_prefixes
    assert "com.example.shaded.guava" in guava.module_prefixes


# --------------------------------------------------------------------------- #
# Lockfile disagreements and duplicate transitives
# --------------------------------------------------------------------------- #


def test_the_same_transitive_at_two_versions_is_reported_as_two_observations() -> None:
    picture = _picture(
        {"package.json": PACKAGE_JSON, "package-lock.json": PACKAGE_LOCK_V3}
    )

    lodash = [obs for obs in picture.observations if obs.coordinate == "lodash"]
    assert sorted(obs.version for obs in lodash) == ["3.10.1", "4.17.21"]
    assert all("unverified_duplicate_version_in_lock" in obs.qualifiers for obs in lodash)


def test_a_lock_version_outside_the_declared_range_is_flagged() -> None:
    manifest = '{"name": "app", "dependencies": {"express": "4.18.2"}}'
    lock = (
        '{"name": "app", "lockfileVersion": 3, "packages": '
        '{"": {"name": "app"}, "node_modules/express": {"version": "4.19.0"}}}'
    )
    picture = _picture({"package.json": manifest, "package-lock.json": lock})

    express = _observation(picture, "express", version="4.19.0")
    assert "unverified_manifest_lock_divergence" in express.qualifiers


def test_a_lock_version_inside_the_declared_range_is_not_flagged() -> None:
    manifest = '{"name": "app", "dependencies": {"lodash": "^4.17.20"}}'
    lock = (
        '{"name": "app", "lockfileVersion": 3, "packages": '
        '{"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.21"}}}'
    )
    picture = _picture({"package.json": manifest, "package-lock.json": lock})

    assert "unverified_manifest_lock_divergence" not in _observation(
        picture, "lodash"
    ).qualifiers


def test_an_unparseable_range_never_produces_a_divergence_claim() -> None:
    # `github:` and `file:` specifiers are not semver ranges. Claiming
    # divergence there would be a fabricated finding, so the derivation must
    # decline rather than guess.
    manifest = '{"name": "app", "dependencies": {"widget": "github:acme/widget#v2"}}'
    lock = (
        '{"name": "app", "lockfileVersion": 3, "packages": '
        '{"": {"name": "app"}, "node_modules/widget": {"version": "2.0.0"}}}'
    )
    picture = _picture({"package.json": manifest, "package-lock.json": lock})

    assert "unverified_manifest_lock_divergence" not in _observation(
        picture, "widget"
    ).qualifiers


# --------------------------------------------------------------------------- #
# Gradle version catalogs
# --------------------------------------------------------------------------- #


def test_a_version_catalog_alias_resolves_to_the_component_it_names() -> None:
    # Both halves are in this run: the script says `libs.jackson.databind` and
    # the catalog says which coordinate that is. Publishing an alias row with a
    # fake coordinate and a separate undetermined row with the real one gives a
    # reviewer two unusable rows and gives reachability nothing to match.
    picture = _picture(
        {"build.gradle": BUILD_GRADLE, "gradle/libs.versions.toml": VERSION_CATALOG}
    )

    databind = _observation(picture, "com.fasterxml.jackson.core:jackson-databind")
    assert databind.version == "2.17.0"
    assert databind.declared_scope == "implementation"
    assert databind.shipment_observation == "unverified_ships_by_default_scope"
    assert "com.fasterxml.jackson.core.jackson.databind" in databind.module_prefixes
    # The alias is no longer a component of its own, and the evidence carries
    # both halves of the join.
    assert all(obs.coordinate != "libs.jackson.databind" for obs in picture.observations)
    assert {citation.path for citation in databind.evidence} == {
        "build.gradle",
        "gradle/libs.versions.toml",
    }


def test_a_catalog_entry_no_script_uses_is_policy_not_an_optional_declaration() -> None:
    # An unconsumed catalog entry still tells a reviewer what version the
    # project intends, so it stays visible — as a version policy, which is what
    # `managed` already means here. Nothing about a catalog is optional.
    picture = _picture({"gradle/libs.versions.toml": VERSION_CATALOG})

    okhttp = _observation(picture, "com.squareup.okhttp3:okhttp")
    assert okhttp.shipment_observation == "unverified_shipment_undetermined"
    assert "unverified_optional_declaration" not in okhttp.qualifiers


def test_an_alias_with_no_catalog_in_the_tree_is_not_resolved_to_a_guess() -> None:
    picture = _picture({"build.gradle": BUILD_GRADLE})

    alias = _observation(picture, "libs.jackson.databind")
    assert alias.version == ""
    assert "version_catalog_alias" in alias.declaration_notes


# --------------------------------------------------------------------------- #
# Build output present in the tree with nothing declaring it
# --------------------------------------------------------------------------- #


def test_a_vendored_tree_with_no_declaration_is_reported_from_build_output() -> None:
    picture = _picture(
        {"go.mod": GO_MOD},
        present_paths=[
            "go.mod",
            "main.go",
            "vendor/github.com/gorilla/mux/mux.go",
            "vendor/github.com/acme/undeclared/thing.go",
        ],
    )

    undeclared = _observation(picture, "github.com/acme/undeclared")
    assert undeclared.observation_origin == "build_output"
    assert undeclared.shipment_observation == "unverified_present_without_declaration"
    assert undeclared.evidence[0].path.startswith("vendor/github.com/acme/undeclared")


@pytest.mark.parametrize(
    ("paths", "module"),
    [
        (
            ["vendor/gopkg.in/yaml.v2/LICENSE", "vendor/gopkg.in/yaml.v2/apic.go"],
            "gopkg.in/yaml.v2",
        ),
        (
            ["vendor/go.uber.org/zap/logger.go", "vendor/go.uber.org/zap/zapcore/core.go"],
            "go.uber.org/zap",
        ),
        (["vendor/k8s.io/api/LICENSE", "vendor/k8s.io/api/core/v1/types.go"], "k8s.io/api"),
        (["vendor/sigs.k8s.io/yaml/yaml.go"], "sigs.k8s.io/yaml"),
        (
            ["vendor/github.com/acme/undeclared/thing.go",
             "vendor/github.com/acme/undeclared/sub/other.go"],
            "github.com/acme/undeclared",
        ),
    ],
)
def test_an_undeclared_vendored_module_is_one_lead_not_one_row_per_file(
    paths: list[str], module: str
) -> None:
    # A module path is not three segments by decree: `gopkg.in/yaml.v2` is two,
    # and taking the third segment from the path turns every vendored FILE into
    # its own component. That is N rows of noise where the reader exists to
    # produce one lead, and reachability can never match any of them against
    # the real import.
    picture = _picture({"go.mod": GO_MOD}, present_paths=["go.mod", *paths])

    vendored = [obs for obs in picture.observations if obs.observation_origin == "build_output"]
    assert [obs.coordinate for obs in vendored] == [module]


def test_a_vendor_directory_under_a_similarly_named_one_is_still_read() -> None:
    # Only a whole path segment named `vendor` opens a vendor tree. Finding the
    # first occurrence of the text and rejecting it when it is not one drops the
    # real vendor directory that follows, and the modules in it disappear.
    picture = _picture(
        {"go.mod": GO_MOD},
        present_paths=[
            "go.mod",
            "myvendor/vendor/github.com/acme/undeclared/thing.go",
        ],
    )

    vendored = [
        obs for obs in picture.observations if obs.observation_origin == "build_output"
    ]
    assert [obs.coordinate for obs in vendored] == ["github.com/acme/undeclared"]


def test_a_packaged_jar_under_web_inf_lib_is_read_as_shipped_output() -> None:
    picture = _picture(
        {"services/api/pom.xml": SERVICE_POM},
        present_paths=[
            "services/api/pom.xml",
            "services/api/src/main/webapp/WEB-INF/lib/log4j-core-2.14.1.jar",
        ],
    )

    log4j = _observation(picture, "log4j-core")
    assert log4j.observation_origin == "build_output"
    assert log4j.version == "2.14.1"
    assert log4j.shipment_observation == "unverified_present_without_declaration"


def test_a_vendored_path_that_matches_a_declaration_is_not_reported_twice() -> None:
    picture = _picture(
        {"go.mod": GO_MOD},
        present_paths=["go.mod", "vendor/github.com/gorilla/mux/mux.go"],
    )

    mux = [obs for obs in picture.observations if obs.coordinate == "github.com/gorilla/mux"]
    assert len(mux) == 1
    assert mux[0].observation_origin == "source_manifest"


# --------------------------------------------------------------------------- #
# Monorepo
# --------------------------------------------------------------------------- #


def test_a_multi_ecosystem_monorepo_keeps_every_module_separate() -> None:
    picture = _picture(
        {
            "pom.xml": AGGREGATOR_POM,
            "services/api/pom.xml": SERVICE_POM,
            "web/package.json": PACKAGE_JSON,
            "gateway/go.mod": GO_MOD,
        }
    )

    assert set(picture.ecosystems) == {"maven", "npm", "go"}
    assert {"", "services/api", "web", "gateway"} <= set(picture.modules)
    assert _observation(picture, "lodash").module_path == "web"
    assert _observation(picture, "github.com/gorilla/mux").module_path == "gateway"


def test_an_aggregator_pom_is_marked_and_ships_nothing_of_its_own() -> None:
    picture = _picture({"pom.xml": AGGREGATOR_POM})

    managed = _observation(picture, "org.apache.commons:commons-text")
    assert "unverified_aggregator_module" in managed.qualifiers
    assert managed.shipment_observation == "unverified_shipment_undetermined"


# --------------------------------------------------------------------------- #
# Reachability
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("ecosystem", "coordinate", "expected"),
    [
        ("maven", "org.apache.commons:commons-text", "org.apache.commons.text"),
        ("npm", "@scope/widget", "@scope/widget"),
        ("go", "github.com/gorilla/mux", "github.com/gorilla/mux"),
        ("python", "PyYAML", "pyyaml"),
    ],
)
def test_candidate_module_prefixes_cover_the_conventional_import_root(
    ecosystem: str, coordinate: str, expected: str
) -> None:
    assert expected in dp.candidate_module_prefixes(ecosystem, coordinate)


@pytest.mark.parametrize(
    ("language", "raw", "expected"),
    [
        ("java", "org.apache.commons.text.StringSubstitutor;", "org.apache.commons.text.StringSubstitutor"),
        ("python", "from django.db import models", "django.db"),
        ("python", "import requests", "requests"),
        ("javascript", "const _ = require('lodash/fp')", "lodash/fp"),
        ("typescript", "import x from '@scope/widget'", "@scope/widget"),
        ("go", "github.com/gorilla/mux", "github.com/gorilla/mux"),
    ],
)
def test_normalize_import_extracts_the_module_path(
    language: str, raw: str, expected: str
) -> None:
    assert expected in dp.normalize_import(language, raw)


def test_an_imported_component_is_reported_with_its_reference_sites() -> None:
    picture = _picture(
        {"services/api/pom.xml": SERVICE_POM, "pom.xml": AGGREGATOR_POM},
        indexed_files=[
            dp.IndexedFile(
                path="services/api/src/main/java/Api.java",
                language="java",
                analysis_status="complete",
                imports=("org.apache.commons.text.StringSubstitutor",),
            )
        ],
    )

    commons = _observation(picture, "org.apache.commons:commons-text", version="1.9")
    assert commons.reachability_observation == "unverified_import_site_observed"
    assert commons.reference_sites[0].path == "services/api/src/main/java/Api.java"
    assert commons.reference_sites[0].raw_import == "org.apache.commons.text.StringSubstitutor"


def test_a_component_no_complete_file_names_is_reported_as_looked_at_not_absent() -> None:
    picture = _picture(
        {"services/api/pom.xml": SERVICE_POM},
        indexed_files=[
            dp.IndexedFile(
                path="services/api/src/main/java/Api.java",
                language="java",
                analysis_status="complete",
                imports=("java.util.List",),
            )
        ],
    )

    guava = _observation(picture, "com.google.guava:guava")
    assert guava.reachability_observation == "unverified_no_reference_observed"
    assert guava.reference_sites == ()


def test_a_degraded_index_cannot_produce_a_no_reference_observation() -> None:
    # A file whose parse degraded has no trustworthy import list. Counting it as
    # "looked at" would manufacture a clean result out of a parser failure.
    picture = _picture(
        {"services/api/pom.xml": SERVICE_POM},
        indexed_files=[
            dp.IndexedFile(
                path="services/api/src/main/java/Api.java",
                language="java",
                analysis_status="degraded",
                imports=(),
            )
        ],
    )

    assert {obs.reachability_observation for obs in picture.observations} == {
        "unverified_reachability_unindexed"
    }


def test_an_index_without_the_components_language_is_not_a_negative_result() -> None:
    # A Java component cannot be excluded by an index that only covers Python.
    picture = _picture(
        {"services/api/pom.xml": SERVICE_POM},
        indexed_files=[
            dp.IndexedFile(
                path="tools/build.py",
                language="python",
                analysis_status="complete",
                imports=("import os",),
            )
        ],
    )

    assert (
        _observation(picture, "com.google.guava:guava").reachability_observation
        == "unverified_reachability_unindexed"
    )


# --------------------------------------------------------------------------- #
# One import is one component's import
# --------------------------------------------------------------------------- #


def _jvm_pom(*artifacts: str, group: str = "org.springframework") -> str:
    declarations = "".join(
        "<dependency>"
        f"<groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        "<version>5.3.30</version></dependency>"
        for artifact in artifacts
    )
    return (
        '<?xml version="1.0"?>'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<groupId>com.example</groupId><artifactId>api</artifactId>"
        f"<dependencies>{declarations}</dependencies></project>"
    )


def _java_index(*imports: str) -> list[dp.IndexedFile]:
    return [
        dp.IndexedFile(
            path="src/main/java/Api.java",
            language="java",
            analysis_status="complete",
            imports=imports,
        )
    ]


def test_an_import_credits_the_artifact_that_explains_it_not_its_whole_group() -> None:
    # A groupId is the package root of every artifact published under it, so one
    # `org.springframework.core` import matched on the group alone becomes a
    # lead for spring-core, spring-web AND spring-beans. The lead tier is the
    # report's argument and is rendered uncapped; three guesses where one import
    # exists is exactly what it must not contain.
    picture = _picture(
        {"pom.xml": _jvm_pom("spring-core", "spring-web", "spring-beans")},
        indexed_files=_java_index("org.springframework.core.io.Resource"),
    )

    reached = {
        obs.coordinate
        for obs in picture.observations
        if obs.reachability_observation == "unverified_import_site_observed"
    }
    assert reached == {"org.springframework:spring-core"}
    assert (
        _observation(picture, "org.springframework:spring-web").reachability_observation
        == "unverified_no_reference_observed"
    )


def test_each_import_of_one_group_lands_on_the_artifact_that_publishes_it() -> None:
    # The three jackson artifacts share a groupId that IS one of their package
    # roots. Each import must reach its own artifact, and the one nothing
    # imports must stay out of the lead tier.
    picture = _picture(
        {
            "pom.xml": _jvm_pom(
                "jackson-core",
                "jackson-databind",
                "jackson-annotations",
                group="com.fasterxml.jackson.core",
            )
        },
        indexed_files=_java_index(
            "com.fasterxml.jackson.core.JsonParser",
            "com.fasterxml.jackson.databind.ObjectMapper",
        ),
    )

    reached = {
        obs.coordinate: [site.raw_import for site in obs.reference_sites]
        for obs in picture.observations
        if obs.reachability_observation == "unverified_import_site_observed"
    }
    assert reached == {
        "com.fasterxml.jackson.core:jackson-core": [
            "com.fasterxml.jackson.core.JsonParser"
        ],
        "com.fasterxml.jackson.core:jackson-databind": [
            "com.fasterxml.jackson.databind.ObjectMapper"
        ],
    }


def test_an_import_no_artifact_id_explains_is_credited_to_every_candidate() -> None:
    # `org.springframework.util` is not named by any artifact id in the group.
    # With nothing to tell the candidates apart, reporting none of them would be
    # a false clean on a component the code demonstrably reaches — so all of
    # them keep the observation.
    picture = _picture(
        {"pom.xml": _jvm_pom("spring-core", "spring-web")},
        indexed_files=_java_index("org.springframework.util.StringUtils"),
    )

    assert {obs.reachability_observation for obs in picture.observations} == {
        "unverified_import_site_observed"
    }


def test_an_artifact_whose_package_root_is_its_group_is_still_reached() -> None:
    # slf4j-api's package IS `org.slf4j`; nothing in the artifact id says so.
    # Dropping the group as a candidate to cure the ambiguity above would report
    # the most widely imported library in Java as unreferenced.
    picture = _picture(
        {"pom.xml": _jvm_pom("slf4j-api", group="org.slf4j")},
        indexed_files=_java_index("org.slf4j.Logger"),
    )

    assert _observation(picture, "org.slf4j:slf4j-api").reachability_observation == (
        "unverified_import_site_observed"
    )


@pytest.mark.parametrize(
    ("coordinate", "expected"),
    [
        # An artifact id conventionally repeats a group segment, and the segment
        # it repeats is not always the last one.
        ("com.fasterxml.jackson.core:jackson-databind", "com.fasterxml.jackson.databind"),
        ("org.apache.commons:commons-text", "org.apache.commons.text"),
        # ... and it is sometimes an abbreviation of it.
        ("org.springframework:spring-core", "org.springframework.core"),
    ],
)
def test_the_artifact_id_names_the_package_the_group_alone_cannot(
    coordinate: str, expected: str
) -> None:
    assert expected in dp.candidate_module_prefixes("maven", coordinate)


# --------------------------------------------------------------------------- #
# Reachability is scoped to the module that declared the dependency
# --------------------------------------------------------------------------- #


ADMIN_PACKAGE_JSON = '{"name": "admin", "dependencies": {"axios": "1.6.0"}}'


def test_a_module_with_no_index_of_its_own_is_never_read_as_unreferenced() -> None:
    # `admin` is indexed and `web` is not. Counting a sibling's files as a look
    # at this module turns "we could not look" into "we looked and saw nothing",
    # which is the substitution this vocabulary exists to prevent.
    picture = _picture(
        {"web/package.json": PACKAGE_JSON, "admin/package.json": ADMIN_PACKAGE_JSON},
        indexed_files=[
            dp.IndexedFile(
                path="admin/src/app.js",
                language="javascript",
                analysis_status="complete",
                imports=("const axios = require('axios')",),
            )
        ],
    )

    assert _observation(picture, "axios").reachability_observation == (
        "unverified_import_site_observed"
    )
    lodash = _observation(picture, "lodash")
    assert lodash.module_path == "web"
    assert lodash.reachability_observation == "unverified_reachability_unindexed"


def test_a_sibling_modules_import_is_not_a_reference_to_this_declaration() -> None:
    # `web` declares lodash and only `admin` imports it. Attributing the
    # sibling's import site to `web`'s declaration reports a lead in a module
    # whose own code never names the component.
    picture = _picture(
        {"web/package.json": PACKAGE_JSON, "admin/package.json": ADMIN_PACKAGE_JSON},
        indexed_files=[
            dp.IndexedFile(
                path="web/src/app.js",
                language="javascript",
                analysis_status="complete",
                imports=("import './local'",),
            ),
            dp.IndexedFile(
                path="admin/src/app.js",
                language="javascript",
                analysis_status="complete",
                imports=("import _ from 'lodash'",),
            ),
        ],
    )

    lodash = _observation(picture, "lodash")
    assert lodash.reachability_observation == "unverified_no_reference_observed"
    assert lodash.reference_sites == ()


def test_a_declaration_in_an_ancestor_module_covers_its_descendants() -> None:
    # A workspace root `package.json`, like an aggregator POM, governs every
    # package beneath it, so a descendant's import really does reach it.
    picture = _picture(
        {"package.json": '{"name": "workspace", "dependencies": {"lodash": "4.17.21"}}'},
        indexed_files=[
            dp.IndexedFile(
                path="packages/app/src/index.js",
                language="javascript",
                analysis_status="complete",
                imports=("import _ from 'lodash'",),
            )
        ],
    )

    lodash = _observation(picture, "lodash")
    assert lodash.module_path == ""
    assert lodash.reachability_observation == "unverified_import_site_observed"
    assert lodash.reference_sites[0].path == "packages/app/src/index.js"


def test_a_vendored_component_is_searched_for_across_the_whole_tree() -> None:
    # Build output has no declaring module: its bytes are in the artifact, so
    # every indexed file is a candidate importer of it.
    picture = _picture(
        {"gateway/go.mod": GO_MOD},
        present_paths=["gateway/go.mod", "vendor/github.com/acme/undeclared/thing.go"],
        indexed_files=[
            dp.IndexedFile(
                path="cmd/server/main.go",
                language="go",
                analysis_status="complete",
                imports=("github.com/acme/undeclared/thing",),
            )
        ],
    )

    undeclared = _observation(picture, "github.com/acme/undeclared")
    assert undeclared.module_path == ""
    assert undeclared.reachability_observation == "unverified_import_site_observed"


# --------------------------------------------------------------------------- #
# Scanner report: an optional secondary input, never the premise
# --------------------------------------------------------------------------- #


def test_a_matching_scanner_row_annotates_but_never_changes_shipment() -> None:
    rows = [{"ecosystem": "maven", "component": "jakarta.servlet:jakarta.servlet-api", "version": "6.0.0"}]
    picture = _picture({"services/api/pom.xml": SERVICE_POM}, scan_rows=rows)

    servlet = _observation(picture, "jakarta.servlet:jakarta.servlet-api")
    assert "unverified_scanner_row_correlated" in servlet.qualifiers
    assert servlet.shipment_observation == "unverified_expected_from_runtime"


def test_a_gradle_build_correlates_against_the_jvm_rows_a_scanner_reports() -> None:
    # Trivy calls the ecosystem `gradle` and Maven and Gradle share one
    # coordinate space. Comparing the two ecosystem names as strings makes every
    # row of a correctly scanned Gradle project unmatched — and an unmatched row
    # is taught to mean the scan covered a different artifact than the build.
    rows = [
        {"ecosystem": "maven", "component": "org.apache.commons:commons-text", "version": "1.9"}
    ]
    picture = _picture({"build.gradle": BUILD_GRADLE}, scan_rows=rows)

    commons = _observation(picture, "org.apache.commons:commons-text")
    assert commons.ecosystem == "gradle"
    assert "unverified_scanner_row_correlated" in commons.qualifiers
    assert not [gap for gap in picture.gaps if gap.gap == "unmatched_scanner_row"]


def test_a_python_scanner_row_correlates_across_pep_503_spellings() -> None:
    # The readers normalize (`PyYAML` -> `pyyaml`, `zope.interface` ->
    # `zope-interface`); a scanner reports the distribution's own spelling.
    # Comparing them raw makes every Python row unmatched.
    rows = [
        {"ecosystem": "python", "component": "PyYAML", "version": "6.0.1"},
        {"ecosystem": "python", "component": "zope.interface", "version": "5.4.0"},
    ]
    picture = _picture(
        {"requirements.txt": "PyYAML==6.0.1\nzope-interface==5.4.0\n"}, scan_rows=rows
    )

    assert "unverified_scanner_row_correlated" in _observation(picture, "pyyaml").qualifiers
    assert (
        "unverified_scanner_row_correlated"
        in _observation(picture, "zope-interface").qualifiers
    )
    assert not [gap for gap in picture.gaps if gap.gap == "unmatched_scanner_row"]


def test_a_jvm_row_naming_only_the_artifact_id_correlates_with_its_coordinate() -> None:
    # Grype names a java-archive `commons-text`; the POM names
    # `org.apache.commons:commons-text`. One component, two spellings.
    rows = [{"ecosystem": "maven", "component": "commons-text", "version": "1.9"}]
    picture = _picture({"services/api/pom.xml": SERVICE_POM}, scan_rows=rows)

    commons = _observation(picture, "org.apache.commons:commons-text")
    assert "unverified_scanner_row_correlated" in commons.qualifiers
    assert not [gap for gap in picture.gaps if gap.gap == "unmatched_scanner_row"]


def test_a_scanner_row_naming_nothing_this_build_declares_is_a_gap_not_a_component() -> None:
    rows = [{"ecosystem": "maven", "component": "org.example:ghost", "version": "1.0"}]
    picture = _picture({"services/api/pom.xml": SERVICE_POM}, scan_rows=rows)

    assert all(obs.coordinate != "org.example:ghost" for obs in picture.observations)
    assert any(
        gap.gap == "unmatched_scanner_row" and "org.example:ghost" in gap.detail
        for gap in picture.gaps
    )


# --------------------------------------------------------------------------- #
# Gaps and determinism
# --------------------------------------------------------------------------- #


def test_an_unparsed_ecosystem_is_reported_as_a_hole_in_the_picture() -> None:
    parses = [
        dm.parse_manifest("composer_manifest", "composer.json", '{"require": {"a/b": "1"}}')
    ]
    picture = dp.build_dependency_picture(parses=parses)

    assert picture.observations == ()
    assert [gap.gap for gap in picture.gaps] == ["unparsed_ecosystem"]


def test_the_picture_is_deterministic() -> None:
    files = {
        "pom.xml": AGGREGATOR_POM,
        "services/api/pom.xml": SERVICE_POM,
        "web/package.json": PACKAGE_JSON,
        "web/package-lock.json": PACKAGE_LOCK_V3,
        "gateway/go.mod": GO_MOD,
    }
    paths = sorted(files) + ["vendor/github.com/acme/undeclared/thing.go"]

    first = _picture(files, present_paths=paths)
    second = _picture(files, present_paths=paths)

    assert first == second
