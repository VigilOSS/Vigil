"""`vigil assess code-dependencies` — the I/O shell around the derivation libs.

The command owns no decisions. These pin that it walks a real tree, reads only
rostered files, renders the lead set first, and never renders a negative
observation without the evidence and the detection marker beside it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dependencies
from assess.lib.dependency_manifests import Evidence
from assess.lib.dependency_picture import DependencyObservation, ReferenceSite


def _args(repo: Path, **overrides) -> SimpleNamespace:
    base = dict(
        repo_path=str(repo),
        structural_index=None,
        scan_report=None,
        as_json=False,
        engagement_dir=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


POM = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>api</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
    </dependency>
    <dependency>
      <groupId>jakarta.servlet</groupId>
      <artifactId>jakarta.servlet-api</artifactId>
      <version>6.0.0</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>
"""


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _write(root, "pom.xml", POM)
    _write(root, "src/main/java/Api.java", "import org.apache.commons.text.StringSubstitutor;\n")
    _write(root, "web/package.json", '{"name": "ui", "dependencies": {"lodash": "4.17.21"}}')
    _write(root, "README.md", "# api\n")
    return root


def test_command_registers_on_the_assess_parser() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    code_dependencies.register(sub)

    args = parser.parse_args(["code-dependencies", "/tmp/repo", "--json"])
    assert args.repo_path == "/tmp/repo"
    assert args.as_json is True


def test_json_output_carries_the_schema_and_every_observation(repo: Path, capsys) -> None:
    code_dependencies.run(_args(repo, as_json=True))
    payload = json.loads(capsys.readouterr().out)

    assert payload["schema"] == "code-dependency-picture/v1"
    coordinates = {obs["coordinate"] for obs in payload["observations"]}
    assert coordinates == {
        "org.apache.commons:commons-text",
        "jakarta.servlet:jakarta.servlet-api",
        "lodash",
    }
    assert sorted(payload["ecosystems"]) == ["maven", "npm"]


def test_json_output_is_byte_identical_across_runs(repo: Path, capsys) -> None:
    code_dependencies.run(_args(repo, as_json=True))
    first = capsys.readouterr().out
    code_dependencies.run(_args(repo, as_json=True))
    second = capsys.readouterr().out

    assert first == second


def test_text_output_leads_with_the_shipped_and_reachable_set(repo: Path, capsys) -> None:
    index = repo.parent / "index.json"
    index.write_text(
        json.dumps(
            {
                "files": {
                    "src/main/java/Api.java": {
                        "language": "java",
                        "analysis_status": "complete",
                        "index_path": "files/api.json",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (repo.parent / "files").mkdir(exist_ok=True)
    (repo.parent / "files" / "api.json").write_text(
        json.dumps({"imports": ["org.apache.commons.text.StringSubstitutor"]}),
        encoding="utf-8",
    )

    code_dependencies.run(_args(repo, structural_index=str(index)))
    out = capsys.readouterr().out

    lead_at = out.index("org.apache.commons:commons-text")
    other_at = out.index("jakarta.servlet:jakarta.servlet-api")
    assert lead_at < other_at
    assert "unverified_import_site_observed" in out
    assert "unverified_expected_from_runtime" in out


def test_text_output_states_that_nothing_here_is_a_verdict(repo: Path, capsys) -> None:
    code_dependencies.run(_args(repo))
    out = capsys.readouterr().out

    # Every rendered observation name is an `unverified_` one, so a reader
    # cannot lift a line out of this report and quote it as a clearance.
    assert "unverified_" in out
    assert "not shipped" not in out.lower()
    assert "unused" not in out.lower()


def test_a_missing_repository_path_fails_closed(tmp_path: Path, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        code_dependencies.run(_args(tmp_path / "absent"))

    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


def test_an_unreadable_structural_index_is_refused_not_silently_skipped(
    repo: Path, tmp_path: Path, capsys
) -> None:
    # Silently continuing would downgrade every component to
    # `unverified_reachability_unindexed` while the operator believes an index
    # was consulted.
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        code_dependencies.run(_args(repo, structural_index=str(broken)))

    assert exc.value.code == 1
    assert "structural index" in capsys.readouterr().err


def test_scan_report_rows_are_correlated_as_a_secondary_input(
    repo: Path, tmp_path: Path, capsys
) -> None:
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Type": "pom",
                        "Vulnerabilities": [
                            {
                                "PkgName": "org.apache.commons:commons-text",
                                "InstalledVersion": "1.9",
                                "VulnerabilityID": "CVE-2022-42889",
                            },
                            {
                                "PkgName": "org.example:ghost",
                                "InstalledVersion": "1.0",
                                "VulnerabilityID": "CVE-2000-0001",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    code_dependencies.run(_args(repo, scan_report=str(report), as_json=True))
    payload = json.loads(capsys.readouterr().out)

    commons = next(
        obs
        for obs in payload["observations"]
        if obs["coordinate"] == "org.apache.commons:commons-text"
    )
    assert "unverified_scanner_row_correlated" in commons["qualifiers"]
    assert any(
        gap["gap"] == "unmatched_scanner_row" and "org.example:ghost" in gap["detail"]
        for gap in payload["gaps"]
    )


def _scan_report(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_a_trivy_gradle_report_correlates_against_the_gradle_build_it_scanned(
    tmp_path: Path, capsys
) -> None:
    # Trivy names this ecosystem `gradle` and the reader that produced the
    # component names it `gradle` too — but they are one JVM coordinate space
    # with Maven, and a correctly scanned Gradle project must not report every
    # one of its own rows as belonging to some other artifact.
    root = tmp_path / "gradle-app"
    _write(
        root,
        "build.gradle",
        "dependencies {\n    implementation 'org.apache.commons:commons-text:1.9'\n}\n",
    )
    report = _scan_report(
        tmp_path / "trivy.json",
        {
            "Results": [
                {
                    "Type": "gradle",
                    "Target": "build.gradle",
                    "Vulnerabilities": [
                        {
                            "PkgName": "org.apache.commons:commons-text",
                            "InstalledVersion": "1.9",
                            "VulnerabilityID": "CVE-2022-42889",
                        }
                    ],
                }
            ]
        },
    )

    code_dependencies.run(_args(root, scan_report=str(report), as_json=True))
    payload = json.loads(capsys.readouterr().out)

    commons = next(
        obs
        for obs in payload["observations"]
        if obs["coordinate"] == "org.apache.commons:commons-text"
    )
    assert "unverified_scanner_row_correlated" in commons["qualifiers"]
    assert not [gap for gap in payload["gaps"] if gap["gap"] == "unmatched_scanner_row"]


def test_a_grype_report_is_read_with_grypes_own_ecosystem_names(
    tmp_path: Path, capsys
) -> None:
    root = tmp_path / "py-app"
    _write(root, "requirements.txt", "PyYAML==6.0.1\n")
    report = _scan_report(
        tmp_path / "grype.json",
        {
            "source": {"target": "py-app"},
            "matches": [
                {"artifact": {"name": "PyYAML", "version": "6.0.1", "type": "python"}}
            ],
        },
    )

    code_dependencies.run(_args(root, scan_report=str(report), as_json=True))
    payload = json.loads(capsys.readouterr().out)

    pyyaml = next(obs for obs in payload["observations"] if obs["coordinate"] == "pyyaml")
    assert "unverified_scanner_row_correlated" in pyyaml["qualifiers"]
    assert not [gap for gap in payload["gaps"] if gap["gap"] == "unmatched_scanner_row"]


def test_a_capped_section_says_how_much_it_elided(tmp_path: Path, capsys) -> None:
    # A section that silently renders 25 of 1470 rows reads as a small section.
    # The count and the elision line are what keep the report honest.
    root = tmp_path / "big"
    entries = {f"pkg{index:03d}": f"^1.0.{index}" for index in range(60)}
    _write(root, "package.json", json.dumps({"name": "big", "dependencies": entries}))

    code_dependencies.run(_args(root))
    out = capsys.readouterr().out

    assert f"shipped, reachability never indexed ({len(entries)})" in out
    assert (
        f"... {len(entries) - code_dependencies.SECTION_TEXT_LIMIT} more in this section"
        in out
    )


def _long_specifier() -> str:
    return "git+https://example.test/" + "a" * 600 + ".git#v2"


def test_json_carries_the_whole_evidence_line(tmp_path: Path, capsys) -> None:
    # The cap belongs to the renderer. Cutting the RECORD truncates `--json`
    # too, with no marker and no way to recover the rest of the line.
    root = tmp_path / "long"
    _write(
        root,
        "package.json",
        json.dumps({"name": "long", "dependencies": {"widget": _long_specifier()}}, indent=2),
    )

    code_dependencies.run(_args(root, as_json=True))
    payload = json.loads(capsys.readouterr().out)

    widget = next(obs for obs in payload["observations"] if obs["coordinate"] == "widget")
    assert _long_specifier() in widget["evidence"][0]["text"]


def test_the_text_render_bounds_evidence_width_and_says_what_it_elided(
    tmp_path: Path, capsys
) -> None:
    root = tmp_path / "long"
    _write(
        root,
        "package.json",
        json.dumps({"name": "long", "dependencies": {"widget": _long_specifier()}}, indent=2),
    )

    code_dependencies.run(_args(root))
    cited = [line for line in capsys.readouterr().out.splitlines() if "evidence:" in line]

    assert cited, "an observation rendered without its evidence cannot be audited"
    assert _long_specifier() not in cited[0]
    assert "more character(s)" in cited[0]
    assert "--json" in cited[0]


def test_a_capped_reference_and_evidence_list_says_how_much_it_elided(capsys) -> None:
    # A row that renders 5 of 40 reference sites and 3 of 9 citations reads as a
    # row with 5 references and 3 citations. The counts are the honest part.
    sites = tuple(
        ReferenceSite(path=f"src/file{index}.js", language="javascript", raw_import="lodash")
        for index in range(8)
    )
    evidence = tuple(
        Evidence(path="package.json", line=index, text=f"line {index}")
        for index in range(1, 6)
    )
    code_dependencies._print_observation(
        DependencyObservation(
            ecosystem="npm",
            coordinate="lodash",
            version="4.17.21",
            version_source="manifest",
            declared_scope="dependencies",
            declaration="direct",
            module_path="",
            manifest_path="package.json",
            observation_origin="source_manifest",
            shipment_observation="unverified_ships_by_default_scope",
            reachability_observation="unverified_import_site_observed",
            detection="npm_manifest_parse",
            reference_sites=sites,
            evidence=evidence,
        )
    )
    out = capsys.readouterr().out

    assert f"{len(sites) - code_dependencies.REFERENCE_SITE_LIMIT} more reference" in out
    assert f"{len(evidence) - code_dependencies.EVIDENCE_LIMIT} more citation" in out
    assert "--json" in out


def test_every_observation_reaches_exactly_one_report_section(repo: Path, capsys) -> None:
    # An observation that matches no section, or two, is one the text report
    # either drops silently or double-counts. Both are how a picture starts
    # lying about its own size.
    code_dependencies.run(_args(repo, as_json=True))
    payload = json.loads(capsys.readouterr().out)

    assert sum(payload["counts"].values()) == len(payload["observations"])


def test_one_odd_manifest_does_not_discard_the_rest_of_the_picture(
    repo: Path, capsys
) -> None:
    # `tool = "setuptools"` is valid TOML and is not the table a pyproject
    # reader expects. Losing the run over it costs the operator every other
    # manifest, the build output and the index — the opposite of how the index
    # loader degrades one unreadable artifact.
    _write(repo, "tools/pyproject.toml", 'tool = "setuptools"\n[project]\nname = "t"\n')

    code_dependencies.run(_args(repo, as_json=True))
    payload = json.loads(capsys.readouterr().out)

    assert {obs["coordinate"] for obs in payload["observations"]} == {
        "org.apache.commons:commons-text",
        "jakarta.servlet:jakarta.servlet-api",
        "lodash",
    }
    unreadable = [
        gap for gap in payload["gaps"] if gap["gap"] == "unreadable_declaration_block"
    ]
    assert unreadable and unreadable[0]["path"] == "tools/pyproject.toml"


def test_a_named_but_unreadable_index_artifact_counts_as_unindexed(
    repo: Path, capsys
) -> None:
    # The manifest promises import evidence for this file and the artifact is
    # gone. Treating that as "read it, saw no imports" would manufacture
    # `unverified_no_reference_observed` out of a missing file.
    index = repo.parent / "index.json"
    index.write_text(
        json.dumps(
            {
                "files": {
                    "src/main/java/Api.java": {
                        "language": "java",
                        "analysis_status": "complete",
                        "index_path": "files/absent.json",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    code_dependencies.run(_args(repo, structural_index=str(index), as_json=True))
    payload = json.loads(capsys.readouterr().out)

    maven = [obs for obs in payload["observations"] if obs["ecosystem"] == "maven"]
    assert maven
    assert {obs["reachability_observation"] for obs in maven} == {
        "unverified_reachability_unindexed"
    }
    assert any(
        gap["gap"] == "structural_index_artifact_missing" for gap in payload["gaps"]
    )


def _index_naming(repo: Path, artifact_body: str | None) -> Path:
    """An index manifest for the fixture's one Java file, plus its artifact."""

    index = repo.parent / "index.json"
    index.write_text(
        json.dumps(
            {
                "files": {
                    "src/main/java/Api.java": {
                        "language": "java",
                        "analysis_status": "complete",
                        "index_path": "files/api.json",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    if artifact_body is not None:
        (repo.parent / "files").mkdir(exist_ok=True)
        (repo.parent / "files" / "api.json").write_text(artifact_body, encoding="utf-8")
    return index


def _maven_reachability(payload: dict) -> set[str]:
    maven = [obs for obs in payload["observations"] if obs["ecosystem"] == "maven"]
    assert maven
    return {obs["reachability_observation"] for obs in maven}


@pytest.mark.parametrize(
    ("body", "gap", "detail_fragment"),
    [
        ('{"file_path": "Api.java"}', "structural_index_artifact_malformed", "imports"),
        ("[]", "structural_index_artifact_malformed", "list"),
        (
            '{"imports": [{"raw": "org.apache.commons.text.StringSubstitutor"}]}',
            "structural_index_artifact_malformed",
            "dict",
        ),
        ("{truncated", "structural_index_artifact_unparseable", "JSON"),
    ],
)
def test_an_index_artifact_of_the_wrong_shape_counts_as_unindexed(
    repo: Path, capsys, body: str, gap: str, detail_fragment: str
) -> None:
    # Each of these parses far enough to leave `imports` empty while the
    # manifest still calls the file `complete`. Reading that as "we looked and
    # saw no imports" manufactures `unverified_no_reference_observed` out of an
    # artifact that never said anything, which is the same failure as the
    # missing-artifact case one test above.
    index = _index_naming(repo, body)

    code_dependencies.run(_args(repo, structural_index=str(index), as_json=True))
    payload = json.loads(capsys.readouterr().out)

    assert _maven_reachability(payload) == {"unverified_reachability_unindexed"}
    reported = [row for row in payload["gaps"] if row["gap"] == gap]
    assert reported, f"expected a {gap} gap, got {[row['gap'] for row in payload['gaps']]}"
    assert detail_fragment in reported[0]["detail"]
    assert reported[0]["path"] == "src/main/java/Api.java"


def test_one_unreadable_index_artifact_does_not_discard_the_whole_picture(
    repo: Path, capsys
) -> None:
    # A corrupt per-file artifact is a hole in the index, not a reason to lose
    # the manifests, the build output and every other file's import evidence.
    index = _index_naming(repo, "{truncated")

    code_dependencies.run(_args(repo, structural_index=str(index), as_json=True))
    payload = json.loads(capsys.readouterr().out)

    assert {obs["coordinate"] for obs in payload["observations"]} == {
        "org.apache.commons:commons-text",
        "jakarta.servlet:jakarta.servlet-api",
        "lodash",
    }


def test_a_readable_index_artifact_still_supplies_its_import_sites(
    repo: Path, capsys
) -> None:
    index = _index_naming(
        repo, json.dumps({"imports": ["org.apache.commons.text.StringSubstitutor"]})
    )

    code_dependencies.run(_args(repo, structural_index=str(index), as_json=True))
    payload = json.loads(capsys.readouterr().out)

    commons = next(
        obs
        for obs in payload["observations"]
        if obs["coordinate"] == "org.apache.commons:commons-text"
    )
    assert commons["reachability_observation"] == "unverified_import_site_observed"
    assert not [
        row for row in payload["gaps"] if row["gap"].startswith("structural_index_artifact")
    ]
