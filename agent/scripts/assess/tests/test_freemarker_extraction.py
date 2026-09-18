"""FreeMarker template indexing: interpolation sites, output contexts, escaping.

The escape/context signal here is regex-derived and therefore advisory. These
tests pin the property that matters most: no shape the extractor emits can be
read as proof that a template is safely escaped.
"""
from __future__ import annotations

import json

import pytest

from assess.lib import treesitter_index
from assess.lib.code_languages import detect_language
from assess.lib.treesitter_index import index_file, language_for_file


TEMPLATE = """\
<#ftl output_format="HTML" auto_esc=false>
<#import "template.ftl" as layout>
<#include "common.ftl">
<html>
<head>
  <script src="https://cdn.example.com/login.js"></script>
  <script>
    var msg = "${message.summary}";
    var safe = "${message.summary?js_string}";
  </script>
  <style>body { color: ${theme.color}; }</style>
</head>
<body>
  <!-- rendered for ${realm.name} -->
  <h1>${realm.displayName}</h1>
  <p>${message.summary?html}</p>
  <a href="${url.loginAction}">continue</a>
  <div class="${cssClass}" data-raw=${rawValue} onclick="go('${target}')" style="width:${w}px">
  <form action="${url.loginAction}" method="post">
    <input type="text" name="username" value="${(login.username!'')}"/>
    <input type="hidden" name="execution" value="${execution}"/>
    <input type="password" name="password"/>
    <textarea name="comment"></textarea>
    <select name="locale"></select>
    <button name="submitAction" value="save">Save</button>
  </form>
  <#escape x as x?html>
    <span>${untrusted}</span>
    <#noescape>
      <span>${rawHtml}</span>
    </#noescape>
    <span>${alsoRaw?no_esc}</span>
  </#escape>
  <#macro alert kind message>
    <div class="alert-${kind}">${message}</div>
  </#macro>
  <#function upper value>
    <#return value?upper_case>
  </#function>
  <${dynamicTag}>text</${dynamicTag}>
  <p>${"literal " + user}</p>
  <p>${user?html + comment}</p>
  <p>${"outer ${inner?html} ${raw} tail"}</p>
  <p>#{counter}</p>
  <p>${evil?eval}</p>
</body>
</html>
"""


def _line_of(needle: str, template: str = TEMPLATE) -> int:
    """Return the 1-based line carrying *needle* (which must be unique)."""
    lines = template.splitlines()
    matches = [number for number, line in enumerate(lines, 1) if needle in line]
    assert len(matches) == 1, f"{needle!r} is not unique: {matches}"
    return matches[0]


def _index(source: str = TEMPLATE, file_path: str = "login.ftl") -> dict:
    return index_file(file_path, "freemarker", source=source.encode("utf-8"))


def _interpolations(result: dict) -> list[dict]:
    return [
        sink
        for sink in result["security_sinks"]
        if sink["kind"] == "template_interpolation"
    ]


def _at_line(result: dict, line: int) -> list[dict]:
    return [sink for sink in _interpolations(result) if sink["line"] == line]


def _only(records: list[dict]) -> dict:
    assert len(records) == 1, records
    return records[0]


# ---------------------------------------------------------------------------
# Language registration
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "filename",
    ["login.ftl", "themes/base/login/register.FTL", "page.ftlh", "feed.ftlx"],
)
def test_freemarker_templates_resolve_to_a_structural_language(filename: str) -> None:
    assert detect_language(filename) == "freemarker"
    assert language_for_file(filename) == "freemarker"
    assert "freemarker" in treesitter_index.SUPPORTED_LANGUAGES
    assert "freemarker" in treesitter_index.LIGHTWEIGHT_LANGUAGES


def test_freemarker_template_indexes_as_a_complete_lightweight_artifact() -> None:
    result = _index()

    assert result["language"] == "freemarker"
    assert result["analysis_mode"] == "lightweight_regex"
    assert result["analysis_status"] == "complete"
    assert result["structural_index_available"] is True
    assert result["unavailable_dimensions"] == []
    assert result["security_sources"], "bounded security-source scan must cover .ftl"


# ---------------------------------------------------------------------------
# Escaping is an observation, never a verdict
# ---------------------------------------------------------------------------

def test_escape_observation_vocabulary_never_asserts_safety() -> None:
    vocabulary = treesitter_index.FREEMARKER_ESCAPE_OBSERVATIONS

    assert set(vocabulary) == {
        "unverified_escape_observed",
        "unverified_partial_escape_observed",
        "unverified_escape_suppressed",
        "unverified_no_escape_observed",
    }
    assert all(value.startswith("unverified_") for value in vocabulary)


def test_every_interpolation_is_an_xss_sink_whatever_escaping_was_observed() -> None:
    result = _index()
    interpolations = _interpolations(result)

    assert len(interpolations) >= 18
    observed = {sink["escape_observation"] for sink in interpolations}
    assert "unverified_escape_observed" in observed, "fixture must exercise the escaped path"
    for sink in interpolations:
        assert "xss" in sink["vuln_classes"]
        assert sink["escape_observation"] in treesitter_index.FREEMARKER_ESCAPE_OBSERVATIONS
        assert sink["output_context"] in treesitter_index.FREEMARKER_OUTPUT_CONTEXTS
        assert sink["detection"] == "heuristic_template_regex"
        # No shape may present itself as a safety verdict.
        assert not {"escaped", "is_escaped", "safe", "is_safe", "sanitized"} & set(sink)


def test_ambient_escape_block_still_reports_every_interpolation_verbatim() -> None:
    result = _index()
    sink = _only(_at_line(result, _line_of("${untrusted}")))

    assert sink["escape_observation"] == "unverified_escape_observed"
    assert sink["expression"] == "untrusted"
    assert [scope["directive"] for scope in sink["ambient_escape_scopes"]] == [
        "<#escape x as x?html>"
    ]
    assert sink["ambient_escape_scopes"][0]["line"] == _line_of("<#escape x as x?html>")


def test_nested_noescape_defeats_the_enclosing_escape_block() -> None:
    result = _index()
    sink = _only(_at_line(result, _line_of("${rawHtml}")))

    assert sink["escape_observation"] == "unverified_no_escape_observed"
    assert [scope["directive"] for scope in sink["ambient_escape_scopes"]] == [
        "<#escape x as x?html>",
        "<#noescape>",
    ]


def test_no_esc_builtin_suppresses_an_ambient_escape() -> None:
    result = _index()
    sink = _only(_at_line(result, _line_of("${alsoRaw?no_esc}")))

    assert sink["escape_observation"] == "unverified_escape_suppressed"
    assert sink["observed_escapers"] == ["?no_esc"]


def test_escaping_only_part_of_an_expression_is_not_reported_as_escaped() -> None:
    result = _index()
    partial = _only(_at_line(result, _line_of("${user?html + comment}")))
    literal_concat = _only(_at_line(result, _line_of('${"literal " + user}')))

    assert partial["escape_observation"] == "unverified_partial_escape_observed"
    assert partial["observed_escapers"] == ["?html"]
    assert literal_concat["escape_observation"] == "unverified_no_escape_observed"


def test_identity_escape_directive_is_not_treated_as_escaping() -> None:
    source = "<#escape x as x>\n<p>${value}</p>\n</#escape>\n"
    sink = _only(_interpolations(_index(source, "identity.ftl")))

    assert sink["escape_observation"] == "unverified_no_escape_observed"
    assert sink["ambient_escape_scopes"][0]["directive"] == "<#escape x as x>"


def test_ftl_header_auto_esc_false_overrides_a_markup_output_format() -> None:
    result = _index()
    sink = _only(_at_line(result, _line_of("${realm.displayName}")))

    assert sink["escape_observation"] == "unverified_no_escape_observed"
    assert sink["ambient_escape_scopes"] == []


def test_ftl_header_output_format_enables_ambient_escaping() -> None:
    source = '<#ftl output_format="HTML">\n<p>${value}</p>\n'
    sink = _only(_interpolations(_index(source, "header.ftl")))

    assert sink["escape_observation"] == "unverified_escape_observed"


_NO_HEADER = "<p>${value}</p>\n"


@pytest.mark.parametrize("file_path", ["page.ftlh", "themes/base/feed.FTLX"])
def test_escaping_extension_supplies_the_ambient_no_directive_declares(file_path: str) -> None:
    """`.ftlh`/`.ftlx` carry an escaping output format in the filename itself.

    FreeMarker's "recognize output format by file extension" feature makes these
    HTML and XML, and auto-escaping is on for an escaping output format. Reading
    only the bytes would report every interpolation in a Keycloak-style theme as
    unescaped, which is not what the template engine does.
    """
    sink = _only(_interpolations(_index(_NO_HEADER, file_path)))

    assert sink["escape_observation"] == "unverified_escape_observed"


def test_a_bare_ftl_still_reports_unescaped_without_a_directive() -> None:
    """A plain `.ftl` inherits the application's configured default output format.

    That configuration is not in this file and not in this repository, so the
    extractor keeps the reporting-heavy reading rather than assuming an ambient
    it cannot see.
    """
    sink = _only(_interpolations(_index(_NO_HEADER, "login.ftl")))

    assert sink["escape_observation"] == "unverified_no_escape_observed"


def test_an_explicit_header_still_beats_the_extension() -> None:
    source = "<#ftl auto_esc=false>\n<p>${value}</p>\n"
    sink = _only(_interpolations(_index(source, "page.ftlh")))

    assert sink["escape_observation"] == "unverified_no_escape_observed"


def test_no_esc_still_suppresses_an_extension_supplied_ambient() -> None:
    sink = _only(_interpolations(_index("<p>${value?no_esc}</p>\n", "page.ftlh")))

    assert sink["escape_observation"] == "unverified_escape_suppressed"


def test_an_unknown_extension_is_read_as_a_bare_template() -> None:
    sink = _only(_interpolations(_index(_NO_HEADER, "generated_template")))

    assert sink["escape_observation"] == "unverified_no_escape_observed"


# ---------------------------------------------------------------------------
# Output context
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("needle", "context", "attribute", "quote"),
    [
        ("${realm.displayName}", "html_text", "", ""),
        ('var msg = "${message.summary}"', "script", "", ""),
        ("color: ${theme.color}", "style", "", ""),
        ("<!-- rendered for ${realm.name} -->", "html_comment", "", ""),
        ('<a href="${url.loginAction}">', "url_attribute", "href", '"'),
        ("<${dynamicTag}>text", "html_tag", "", ""),
    ],
)
def test_output_context_is_recorded_per_interpolation(
    needle: str, context: str, attribute: str, quote: str
) -> None:
    result = _index()
    sink = _at_line(result, _line_of(needle))[0]

    assert sink["output_context"] == context
    assert sink["attribute"] == attribute
    assert sink["attribute_quote"] == quote
    assert sink["output_context"] in treesitter_index.FREEMARKER_OUTPUT_CONTEXTS


def test_one_tag_separates_class_unquoted_handler_and_style_contexts() -> None:
    result = _index()
    line = _line_of('data-raw=${rawValue}')
    by_expression = {sink["expression"]: sink for sink in _at_line(result, line)}

    assert by_expression["cssClass"]["output_context"] == "html_attribute"
    assert by_expression["cssClass"]["attribute_quote"] == '"'
    assert by_expression["rawValue"]["output_context"] == "html_attribute"
    assert by_expression["rawValue"]["attribute_quote"] == ""
    assert by_expression["target"]["output_context"] == "event_handler_attribute"
    assert by_expression["target"]["attribute"] == "onclick"
    assert by_expression["w"]["output_context"] == "style_attribute"


def test_url_attribute_interpolation_also_carries_open_redirect() -> None:
    result = _index()
    sink = _at_line(result, _line_of('<a href="${url.loginAction}">'))[0]

    assert sink["vuln_classes"] == ["xss", "open-redirect"]


def test_numeric_interpolation_is_indexed_as_an_interpolation_site() -> None:
    result = _index()
    sink = _only(_at_line(result, _line_of("#{counter}")))

    assert sink["interpolation_syntax"] == "numeric"
    assert sink["expression"] == "counter"


# ---------------------------------------------------------------------------
# Structure: macros, functions, imports, form fields
# ---------------------------------------------------------------------------

def test_macros_and_functions_become_callables_entry_points_and_exports() -> None:
    result = _index()
    callables = {func["name"]: func for func in result["functions"]}

    assert callables["alert"]["params"] == ["kind", "message"]
    assert callables["alert"]["line_start"] == _line_of("<#macro alert kind message>")
    assert callables["alert"]["line_end"] == _line_of("</#macro>")
    assert callables["upper"]["params"] == ["value"]
    assert {"alert", "upper"}.issubset(
        {export["name"] for export in result["exports"]}
    )
    assert {
        (entry["name"], entry["kind"])
        for entry in result["entry_points"]
    } >= {("alert", "freemarker_macro"), ("upper", "freemarker_function")}


def test_interpolations_inside_a_macro_are_attributed_to_that_macro() -> None:
    result = _index()
    sink = _at_line(result, _line_of('<div class="alert-${kind}">'))[0]

    assert sink["function"] == "alert"


def test_template_includes_and_imports_are_indexed_as_imports() -> None:
    result = _index()

    assert "template.ftl" in result["imports"]
    assert "common.ftl" in result["imports"]


def test_form_fields_are_recorded_as_entry_points() -> None:
    result = _index()
    fields = {
        entry["name"]: entry["annotation"]
        for entry in result["entry_points"]
        if entry["kind"] == "html_form_field"
    }

    assert fields == {
        "username": "text",
        "execution": "hidden",
        "password": "password",
        "comment": "",
        "locale": "",
        "submitAction": "",
    }


def test_dynamic_evaluation_builtins_are_flagged_as_template_injection() -> None:
    result = _index()
    evaluations = [
        sink
        for sink in result["security_sinks"]
        if sink["kind"] == "freemarker_dynamic_evaluation"
    ]

    assert [sink["line"] for sink in evaluations] == [_line_of("${evil?eval}")]
    assert evaluations[0]["vuln_classes"] == ["ssti", "injection"]


# ---------------------------------------------------------------------------
# Adversarial shapes
# ---------------------------------------------------------------------------

def test_nested_interpolation_is_captured_as_one_site_with_the_whole_expression() -> None:
    result = _index()
    sink = _only(_at_line(result, _line_of('${"outer ${inner?html} ${raw} tail"}')))

    assert sink["expression"] == '"outer ${inner?html} ${raw} tail"'
    assert sink["escape_observation"] == "unverified_partial_escape_observed"


def test_unterminated_interpolation_is_reported_and_scanning_continues() -> None:
    source = '<p>${broken</p>\n<p>${after}</p>\n'
    result = _index(source, "broken.ftl")
    malformed = [
        sink
        for sink in result["security_sinks"]
        if sink["kind"] == "malformed_template_interpolation"
    ]

    assert [sink["line"] for sink in malformed] == [1]
    assert [sink["expression"] for sink in _interpolations(result)] == ["after"]


def test_unterminated_escape_block_is_reported_at_its_opening_line() -> None:
    source = "<#escape x as x?html>\n<p>${value}</p>\n"
    result = _index(source, "unclosed.ftl")
    malformed = [
        sink
        for sink in result["security_sinks"]
        if sink["kind"] == "malformed_template_directive"
    ]

    assert [sink["line"] for sink in malformed] == [1]
    assert _only(_interpolations(result))["escape_observation"] == (
        "unverified_escape_observed"
    )


def test_unbalanced_escape_close_is_reported_without_losing_the_scan() -> None:
    source = "<p>${a}</p>\n</#escape>\n<p>${b}</p>\n"
    result = _index(source, "stray.ftl")
    malformed = [
        sink
        for sink in result["security_sinks"]
        if sink["kind"] == "malformed_template_directive"
    ]

    assert [sink["line"] for sink in malformed] == [2]
    assert [sink["expression"] for sink in _interpolations(result)] == ["a", "b"]


def test_interpolation_escaping_an_attribute_quote_is_not_read_as_html_text() -> None:
    source = '<a title="${a}" href=${b}>x</a>\n'
    result = _index(source, "attrs.ftl")
    contexts = {
        sink["expression"]: sink["output_context"] for sink in _interpolations(result)
    }

    assert contexts == {"a": "html_attribute", "b": "url_attribute"}


def test_large_template_degrades_at_the_structural_signal_limit() -> None:
    limit = treesitter_index.STRUCTURAL_SIGNAL_LIMIT
    source = "".join(f"<p>${{value{number}}}</p>\n" for number in range(limit + 100))

    result = _index(source, "huge.ftl")

    assert result["analysis_status"] == "degraded"
    assert result["degradation_reason"] == "artifact_signal_limit"
    assert result["structural_index_available"] is True
    assert "security_sinks" in result["truncated_dimensions"]
    assert len(result["security_sinks"]) == limit
    assert result["signal_counts"]["security_sinks"] == limit + 100


def test_extraction_is_deterministic_for_identical_bytes() -> None:
    first = json.dumps(_index(), sort_keys=True)
    second = json.dumps(_index(), sort_keys=True)

    assert first == second


def test_streaming_fallback_retains_freemarker_signal() -> None:
    fallback = treesitter_index._fallback_from_bytes(
        "huge.ftl",
        "freemarker",
        TEMPLATE.encode("utf-8"),
        degradation_reason="exact_parser_source_limit",
    )

    assert fallback["analysis_mode"] == "streaming_security_fallback"
    for dimension in ("entry_points", "imports", "security_sinks", "security_sources"):
        assert dimension not in fallback["unavailable_dimensions"]
        assert fallback["signal_counts"].get(dimension, 0) > 0


def test_html_indexing_is_unchanged_by_freemarker_support() -> None:
    """`.ftl` support is additive: the HTML extractor still ignores `${...}`."""
    source = '<p>${value}</p>\n<p>{{mustache}}</p>\n'
    result = index_file("page.html", "html", source=source.encode("utf-8"))

    assert [sink["line"] for sink in result["security_sinks"]] == [2]
    assert result["security_sinks"][0]["kind"] == "template_interpolation"


def test_freemarker_artifacts_satisfy_the_index_and_sync_contracts() -> None:
    """The extra per-interpolation fields must not break the artifact gates.

    `code-index build` and `code-index sync` are what turn an artifact into a
    manifest row, a coverage status and a backend record, so a `.ftl` artifact
    has to clear both in the complete and the truncated shape.
    """
    from assess.commands.code_index import _validate_analysis_artifact
    from assess.commands.code_index_sync import _validated_structural_metadata

    limit = treesitter_index.STRUCTURAL_SIGNAL_LIMIT
    truncating = "".join(f"<p>${{value{number}}}</p>\n" for number in range(limit + 1))
    for label, source in (("complete", TEMPLATE), ("degraded", truncating)):
        raw = source.encode("utf-8")
        result = _index(source, f"{label}.ftl")

        assert result["analysis_status"] == label
        _validate_analysis_artifact(result, rel_path=f"{label}.ftl", source_size=len(raw))
        metadata = _validated_structural_metadata(
            result, rel_path=f"{label}.ftl", source_size=len(raw)
        )
        assert metadata["structural_analysis_status"] == label
        assert metadata["structural_analysis_mode"] == "lightweight_regex"
