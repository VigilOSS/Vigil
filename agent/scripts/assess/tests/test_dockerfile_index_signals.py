"""Dockerfile source edges that show what code reaches an image."""

from assess.lib.treesitter_index import index_file


def test_docker_copy_local_source_is_a_navigation_target() -> None:
    source = b"""\
FROM alpine:3.20
COPY scripts/start.sh /usr/local/bin/start.sh
ENTRYPOINT ["/usr/local/bin/start.sh"]
"""
    indexed = index_file("Dockerfile", "dockerfile", source)

    assert indexed["analysis_status"] == "complete"
    assert {target["resolved"] for target in indexed["import_targets"]} >= {"scripts/start.sh"}


def test_docker_copy_from_named_stage_is_not_a_local_source() -> None:
    source = b"""\
FROM alpine AS builder
RUN echo built > /out.txt
FROM alpine
COPY --from=builder /out.txt /out.txt
"""
    indexed = index_file("Dockerfile", "dockerfile", source)

    assert not any(target["resolved"] == "/out.txt" for target in indexed["import_targets"])


def test_docker_copy_json_and_option_forms_keep_local_sources() -> None:
    source = b"""\
FROM alpine
COPY ["scripts/one.sh", "/one.sh"]
COPY --chown=root:root scripts/two.sh /two.sh
"""
    indexed = index_file("Dockerfile", "dockerfile", source)

    assert {target["resolved"] for target in indexed["import_targets"]} >= {
        "scripts/one.sh",
        "scripts/two.sh",
    }


def test_docker_copy_glob_preserves_source_hint_without_claiming_exact_target() -> None:
    indexed = index_file("Dockerfile", "dockerfile", b"FROM alpine\nCOPY scripts/*.sh /bin/\n")

    assert {"raw": "scripts/*.sh", "resolved": ""} in indexed["import_targets"]


def test_docker_secret_named_arg_without_default_is_only_an_input() -> None:
    indexed = index_file("Dockerfile", "dockerfile", b"FROM alpine\nARG API_KEY\n")

    assert any(source["kind"] == "build_argument" for source in indexed["security_sources"])
    assert not any(sink["kind"] == "embedded_secret_arg" for sink in indexed["security_sinks"])


def test_docker_secret_named_arg_with_default_retains_the_sink() -> None:
    indexed = index_file("Dockerfile", "dockerfile", b"FROM alpine\nARG API_KEY=not-secret\n")

    assert any(sink["kind"] == "embedded_secret_arg" for sink in indexed["security_sinks"])
