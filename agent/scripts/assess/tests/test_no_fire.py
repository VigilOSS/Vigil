from __future__ import annotations

import re

import pytest

from assess.lib import no_fire


def test_path_pattern_blocks_every_host_and_query_variant() -> None:
    scope_doc = {"off_limits_paths": ["/api/send-email", "/admin/*"]}

    assert no_fire.match_url(scope_doc, "https://a.example/api/send-email?dry=1")
    assert no_fire.match_url(scope_doc, "https://b.example/admin/delete")
    assert not no_fire.match_url(scope_doc, "https://a.example/api/send-email-preview")


def test_absolute_pattern_is_host_specific() -> None:
    scope_doc = {"off_limits_paths": ["https://api.example/reset/*"]}

    assert no_fire.match_url(scope_doc, "https://api.example/reset/alice")
    assert not no_fire.match_url(scope_doc, "https://www.example/reset/alice")


@pytest.mark.parametrize(
    "encoded",
    [
        "/admin%2Fdelete",
        "/admin%252Fdelete",
        "/safe/%2e%2e/admin/delete",
    ],
)
def test_encoded_and_normalized_paths_cannot_bypass_no_fire(encoded: str) -> None:
    scope_doc = {"off_limits_paths": ["/admin/delete"]}

    assert no_fire.match_url(scope_doc, f"https://example.test{encoded}")


@pytest.mark.parametrize("path", ["/admin%FFdelete", "/admin%ZZdelete"])
def test_invalid_percent_encoding_fails_closed(path: str) -> None:
    with pytest.raises(no_fire.NoFirePolicyError, match="percent encoding"):
        no_fire.match_url(
            {"off_limits_paths": ["/admin/delete"]},
            f"https://example.test{path}",
        )


def test_excessive_nested_encoding_fails_closed() -> None:
    scope_doc = {"off_limits_paths": ["/admin/delete"]}

    with pytest.raises(no_fire.NoFirePolicyError, match="encoding"):
        no_fire.match_url(
            scope_doc,
            "https://example.test/admin%2525252Fdelete",
        )


def test_crawl_exclusion_regex_covers_path_and_absolute_patterns() -> None:
    regex = no_fire.crawl_exclusion_regex(
        {"off_limits_paths": ["/notify", "https://api.example/reset/*"]}
    )

    assert regex
    assert "notify" in regex
    assert "api" in regex


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/admin/delete",
        "https://example.test/admin%2Fdelete",
        "https://example.test/admin%252Fdelete",
        "https://example.test/safe/%2e%2e/admin/delete",
    ],
)
def test_crawl_exclusion_regex_conservatively_blocks_encoded_paths(url: str) -> None:
    regex = no_fire.crawl_exclusion_regex(
        {"off_limits_paths": ["/admin/delete"]}
    )

    assert re.search(regex, url, flags=re.IGNORECASE)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test/files%2Fpublic",
        "https://example.test/assets/profile%2Ejson",
        "https://example.test/docs%5Cguide",
    ],
)
def test_crawl_exclusion_regex_keeps_unrelated_encoded_paths(url: str) -> None:
    regex = no_fire.crawl_exclusion_regex({"off_limits_paths": ["/logout"]})

    assert not re.search(regex, url, flags=re.IGNORECASE)


@pytest.mark.parametrize(
    "value",
    ["/not-a-list", ["/ok", 7], ["relative-without-leading-slash"]],
)
def test_malformed_policy_fails_closed(value) -> None:
    with pytest.raises(no_fire.NoFirePolicyError):
        no_fire.patterns({"off_limits_paths": value})
