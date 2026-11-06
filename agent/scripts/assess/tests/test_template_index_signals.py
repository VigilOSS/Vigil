"""Signals from HTML, CSS, Blade, Twig and FreeMarker as rendered source."""

from __future__ import annotations

import json
import time

import pytest

from assess.commands import code_ingest
from assess.lib import treesitter_index
from assess.lib.code_languages import detect_language
from assess.lib.treesitter_index import StreamingSecurityScanner, index_file
from test_code_ingest_vendored_minified import _args, _offline_ingest, _write
from test_php_shared_extensions import _PreviewClient


def test_multiline_html_form_and_script_attributes_are_indexed() -> None:
    source = b"""\
<form
  action="/upload" method="post">
</form>
<script
  src="https://cdn.example/app.js"></script>
"""

    indexed = index_file("page.html", "html", source)

    assert any(item["kind"] == "html_form" and item["annotation"] == "/upload"
               for item in indexed["entry_points"])
    assert "https://cdn.example/app.js" in indexed["imports"]
    assert any(item["kind"] == "external_script_load"
               for item in indexed["security_sinks"])


def test_html_data_attributes_do_not_register_forms_or_scripts() -> None:
    source = b"""\
<form data-action="/tracking"></form>
<script data-src="http://example.test/tracking.js"></script>
<script src="http://cdn.example/live.js"></script>
"""

    indexed = index_file("page.html", "html", source)

    # The form is an entry whose action is unknown, not an entry to
    # `/tracking`; the live `src` on line 3 is what a read `src` looks like.
    assert [(item["kind"], item["annotation"]) for item in indexed["entry_points"]] == [
        ("html_form", "")
    ]
    assert indexed["imports"] == ["http://cdn.example/live.js"]
    assert [(item["kind"], item["line"]) for item in indexed["security_sinks"]] == [
        ("external_script_load", 3)
    ]


def test_html_form_without_action_is_still_input_entry() -> None:
    source = b'<form method="post"><input name="name"></form>\n'

    indexed = index_file("page.html", "html", source)

    assert any(item["kind"] == "html_form" and item["line"] == 1
               for item in indexed["entry_points"])


@pytest.mark.parametrize("language,path", [
    ("html", "view.html"),
    ("blade", "view.blade.php"),
    ("freemarker", "view.ftl"),
])
def test_streaming_fallback_keeps_actionless_form_entry(language: str, path: str) -> None:
    scanner = StreamingSecurityScanner(path, language)
    scanner.feed(b'<form method="post"><input name="name"></form>\n')

    assert any(item["kind"] == "html_form" for item in scanner.finish(
        degradation_reason="source_too_large"
    )["entry_points"])


@pytest.mark.parametrize("language", ["blade", "freemarker"])
def test_template_comment_does_not_create_html_surface(language: str) -> None:
    comment = "{{--" if language == "blade" else "<#--"
    close = "--}}" if language == "blade" else "-->"
    path = "view.blade.php" if language == "blade" else "view.ftl"
    source = (f'{comment} <script src="http://example.test/a.js"></script> '
              f'<form action="/login"> {close}\n'
              '<form action="/live"></form>\n'
              '<script src="http://cdn.example/live.js"></script>\n').encode()

    indexed = index_file(path, language, source)

    # Only the live half of each dimension survives, which is the reading a
    # masked comment has to produce: not silence, the live markup alone.
    assert [(item["kind"], item["line"], item["annotation"])
            for item in indexed["entry_points"]] == [("html_form", 2, "/live")]
    assert indexed["imports"] == ["http://cdn.example/live.js"]
    assert [(item["kind"], item["line"]) for item in indexed["security_sinks"]] == [
        ("external_script_load", 3)
    ]


def test_blade_comment_does_not_add_template_import() -> None:
    source = b"{{-- @include('admin.secret') --}}\n@include('layouts.app')\n{{ $name }}\n"

    indexed = index_file("view.blade.php", "blade", source)

    assert indexed["imports"] == ["layouts.app"]
    assert [(item["kind"], item["line"]) for item in indexed["security_sinks"]] == [
        ("template_interpolation", 3)
    ]


def test_template_comment_closure_preserves_live_markup_and_line() -> None:
    source = b"{{-- <form action='/dead'> --}}<form action='/live'>\n"

    indexed = index_file("view.blade.php", "blade", source)

    assert [(item["annotation"], item["line"]) for item in indexed["entry_points"]] == [
        ("/live", 1)
    ]


@pytest.mark.parametrize("language,path,opening", [
    ("html", "page.html", "<!--"),
    ("twig", "templates/page.html.twig", "{#"),
    ("blade", "view.blade.php", "{{--"),
    ("freemarker", "view.ftl", "<#--"),
])
def test_a_comment_the_file_never_closes_hides_no_signal(
    language: str, path: str, opening: str,
) -> None:
    """An opener with no closer is a construct the file got wrong.

    Masking from it to the end of the file deletes every signal after it and
    hides the inline code that would have declared the debt, so the file
    reports a clean complete read and owes no review span. A closed comment
    still masks: `test_template_comment_closure_preserves_live_markup_and_line`
    is the other half of this pair.
    """
    source = (f"{opening} unterminated\n"
              '<form action="/login"></form>\n'
              '<iframe src="/x"></iframe>\n').encode()

    indexed = index_file(path, language, source)

    assert [(item["kind"], item["line"], item["annotation"])
            for item in indexed["entry_points"]] == [("html_form", 2, "/login")]
    assert [(item["kind"], item["line"]) for item in indexed["security_sinks"]] == [
        ("iframe_embed", 3)
    ]


def test_css_block_comments_do_not_emit_import_or_behavior_signals() -> None:
    source = b"""\
body { color: red; /* behavior: url(evil.htc); */ }
/*
@import url(http://example.test/evil.css);
*/
@import url("http://cdn.example/live.css");
body { behavior: url(live.htc); }
"""

    indexed = index_file("style.css", "css", source)

    assert [(item["kind"], item["line"]) for item in indexed["security_sinks"]] == [
        ("external_css_import", 5),
        ("css_behavior", 6),
    ]
    assert "http://cdn.example/live.css" in indexed["imports"]
    assert "http://example.test/evil.css" not in indexed["imports"]


def test_css_comment_closure_preserves_live_behavior_signal() -> None:
    source = b"/* behavior: url(dead.htc) */ body { behavior: url(live.htc); }\n"

    indexed = index_file("style.css", "css", source)

    assert [(item["kind"], item["line"]) for item in indexed["security_sinks"]] == [
        ("css_behavior", 1)
    ]


def test_multiline_css_import_retains_external_dependency_signal() -> None:
    source = b'@import\n url("http://cdn.example/theme.css");\n'

    indexed = index_file("style.css", "css", source)

    assert "http://cdn.example/theme.css" in indexed["imports"]
    assert any(item["kind"] == "external_css_import" for item in indexed["security_sinks"])


@pytest.mark.parametrize("language,path", [("html", "view.html"), ("freemarker", "view.ftl")])
def test_multiline_form_is_entry_in_html_compatible_templates(language: str, path: str) -> None:
    source = b"<form\n action=\"/search\">\n</form>\n"

    indexed = index_file(path, language, source)

    assert any(item["kind"] == "html_form" and item["annotation"] == "/search"
               for item in indexed["entry_points"])


def _twig_sinks(source: str) -> list[tuple[str, int]]:
    indexed = index_file("templates/page.html.twig", "twig", source.encode())
    assert indexed["analysis_status"] == "complete"
    return [(sink["kind"], sink["line"]) for sink in indexed["security_sinks"]]


@pytest.mark.parametrize("path,header,language", [
    ("templates/base.html.twig", None, "twig"),
    ("templates/mail.twig", None, "twig"),
    ("themes/acme/card.tpl", None, "html"),
    ("themes/acme/card.tpl", "{% extends 'base.tpl' %}\n", "twig"),
    ("themes/acme/card.tpl", "<p>{{ name }}</p>\n", "twig"),
    ("themes/acme/card.tpl", "<p>{$name|escape}</p>\n{if $admin}x{/if}\n", "html"),
    ("themes/acme/card.tpl", "<p>Acme</p>\n", "html"),
])
def test_twig_language_detection(path: str, header: str | None, language: str) -> None:
    assert detect_language(path, header=header) == language
    assert "twig" in treesitter_index.SUPPORTED_LANGUAGES
    assert "twig" in treesitter_index.LIGHTWEIGHT_LANGUAGES


def test_ingest_reads_a_tpl_file_as_twig_only_when_it_opens_a_twig_delimiter(
    monkeypatch, tmp_path, capsys,
) -> None:
    repo, engagement = _offline_ingest(monkeypatch, tmp_path)
    _write(repo, "themes/acme/twig.tpl", "{% block body %}{{ name }}{% endblock %}\n")
    _write(repo, "themes/acme/smarty.tpl", "<p>{$name}</p>\n")
    _PreviewClient.payloads = []
    monkeypatch.setattr(code_ingest, "AssessmentClient", _PreviewClient)

    code_ingest.run(_args(repo, name="acme-themes", dry_run=True, engagement_dir=str(engagement)))
    assert json.loads(capsys.readouterr().out)["files"] == 3

    languages = {
        str(record["file_path"]): str(record["language"])
        for record in _PreviewClient.payloads[0]["files"]
    }
    assert languages["themes/acme/twig.tpl"] == "twig"
    assert languages["themes/acme/smarty.tpl"] == "html"


def test_a_handlebars_block_in_a_tpl_is_not_a_twig_comment() -> None:
    """A `.tpl` written in Handlebars is HTML with mustache interpolation.

    Read as Twig instead, the `{#` of `{{#each}}` opens a comment the file
    never closes, every signal below that line is masked away, and the index
    still reports a complete read -- a file silently removed from review.
    """
    source = """\
<h1>Acme</h1>
{{#each items}}
  <li>{{this.name}}</li>
{{/each}}
<script>eval(decodeURIComponent(location.hash.slice(1)))</script>
<script src="http://cdn.example/a.js"></script>
<form action="/login" method="post"></form>
"""

    assert detect_language("themes/acme/page.tpl", header=source) == "html"

    indexed = index_file("themes/acme/page.tpl", "html", source.encode())

    assert [(item["kind"], item["annotation"]) for item in indexed["entry_points"]] == [
        ("html_form", "/login")
    ]
    assert indexed["imports"] == ["http://cdn.example/a.js"]
    assert ("external_script_load", 6) in [
        (sink["kind"], sink["line"]) for sink in indexed["security_sinks"]
    ]
    # The inline script body no lightweight reader reads is the file's declared
    # debt, so it owes a review span instead of reporting a clean read.
    assert indexed["analysis_status"] == "degraded"
    assert indexed["unavailable_dimensions"] == ["call_sites", "dataflow"]


def test_escaped_twig_output_in_body_text_is_not_a_raw_sink() -> None:
    indexed = index_file(
        "templates/page.html.twig", "twig",
        b"<p>Hello {{ user.name }}</p>\n<p title=\"{{ user.title }}\">{{ user.bio|e }}</p>\n",
    )

    sinks = indexed["security_sinks"]
    assert [(sink["kind"], sink["line"]) for sink in sinks] == [
        ("template_interpolation", 1),
        ("template_interpolation", 2),
        ("template_interpolation", 2),
    ]
    assert all(sink["vuln_classes"] == ["xss", "ssti"] for sink in sinks)
    assert all(set(sink) == {"kind", "line", "function", "snippet", "vuln_classes"} for sink in sinks)


def test_twig_raw_filter_is_unescaped_output() -> None:
    source = "<h1>{{ user.name }}</h1>\n<div>{{ user.bio|raw }}</div>\n<div>{{- note | striptags | raw -}}</div>\n"

    assert _twig_sinks(source) == [
        ("template_interpolation", 1),
        ("unescaped_output", 2),
        ("unescaped_output", 3),
    ]


def test_twig_autoescape_false_tag_is_unescaped_output() -> None:
    source = """\
<p>{{ before }}</p>
{% autoescape false %}
  <p>{{ inside }}</p>
  {% autoescape 'html' %}<p>{{ nested }}</p>{% endautoescape %}
  <p>{{
    multiline }}</p>
{% endautoescape %}
<p>{{ after }}</p>
"""

    assert _twig_sinks(source) == [
        ("template_interpolation", 1),
        ("unescaped_output", 2),
        ("template_interpolation", 3),
        ("template_interpolation", 4),
        ("template_interpolation", 5),
        ("template_interpolation", 8),
    ]
    scanner = StreamingSecurityScanner("templates/page.html.twig", "twig")
    scanner.feed(source.encode())
    assert ("unescaped_output", 2) in {
        (sink["kind"], sink["line"])
        for sink in scanner.finish(degradation_reason="source_too_large")["security_sinks"]
    }


@pytest.mark.parametrize("construct", [
    "{{ template_from_string(page.body) }}",
    "{% include page.template %}",
    "{% extends layout %}",
    "{% embed 'partials/' ~ name %}{% endembed %}",
    "{% include ['partials/a.html.twig', page.template] %}",
    "{% include [page.template, 'partials/a.html.twig'] %}",
    "{% import macros as forms %}",
    "{{ include(name) }}",
    "{{ source(page.path) }}",
])
def test_twig_template_chosen_at_render_time_is_dynamic_evaluation(construct: str) -> None:
    indexed = index_file("templates/page.html.twig", "twig", f"<p>Acme</p>\n{construct}\n".encode())

    dynamic = [sink for sink in indexed["security_sinks"] if sink["kind"] == "twig_dynamic_evaluation"]
    assert [(sink["line"], sink["vuln_classes"]) for sink in dynamic] == [(2, ["ssti", "injection"])]


@pytest.mark.parametrize("construct,imports,sinks", [
    ("{% include 'partials/header.html.twig' %}",
     ["partials/header.html.twig"], []),
    ("{% include ['partials/a.html.twig', 'partials/b.html.twig'] with {'x': 1} %}",
     ["partials/a.html.twig"], []),
    ("{{ include('partials/header.html.twig', {'x': 1}) }}",
     [], [("template_interpolation", 1)]),
    ("{{ source('partials/logo.svg') }}",
     [], [("template_interpolation", 1)]),
])
def test_twig_template_named_by_a_literal_is_not_dynamic_evaluation(
    construct: str, imports: list[str], sinks: list[tuple[str, int]],
) -> None:
    indexed = index_file("templates/page.html.twig", "twig", f"{construct}\n".encode())

    # What the construct did read is the claim: a literal composition names its
    # template in `imports`, and an `include()`/`source()` output is the one
    # escaped interpolation of its line. Absence of `twig_dynamic_evaluation`
    # on its own would hold just as well with the reader switched off.
    assert indexed["imports"] == imports
    assert [(sink["kind"], sink["line"]) for sink in indexed["security_sinks"]] == sinks


def test_twig_comments_and_verbatim_blocks_are_not_outputs() -> None:
    source = """\
{# <p>{{ user.bio|raw }}</p> {% include 'dead.twig' %} #}
{% verbatim %}<p>{{ user.bio|raw }}</p>{% endverbatim %}
{% include 'live.twig' %}
<p>{{ user.name }}</p>
"""

    indexed = index_file("templates/page.html.twig", "twig", source.encode())

    assert indexed["analysis_status"] == "complete"
    assert [(sink["kind"], sink["line"]) for sink in indexed["security_sinks"]] == [
        ("template_interpolation", 4)
    ]
    assert indexed["imports"] == ["live.twig"]


def test_a_verbatim_block_the_file_never_closes_hides_no_output() -> None:
    """An unclosed `verbatim` skips nothing, for the same reason a comment does.

    Skipping to the end of the file on a missing `endverbatim` drops every
    output below it while the index still reports a complete read.
    """
    source = """\
{% verbatim %}<p>{{ handlebars }}</p>
<div>{{ user.bio|raw }}</div>
{% include page.template %}
"""

    assert _twig_sinks(source) == [
        ("template_interpolation", 1),
        ("unescaped_output", 2),
        ("twig_dynamic_evaluation", 3),
    ]


@pytest.mark.parametrize("language,path,unit", [
    ("html", "page.html", "{{ "),
    ("twig", "templates/page.html.twig", "{{ "),
    ("twig", "templates/page.html.twig", "{% "),
    ("twig", "templates/page.html.twig", "{# "),
    ("twig", "templates/page.html.twig", "<a "),
    ("blade", "view.blade.php", "{{ "),
    ("blade", "view.blade.php", "{!! "),
    ("blade", "view.blade.php", "{{-- "),
])
def test_unterminated_template_openers_index_in_linear_time(
    language: str, path: str, unit: str,
) -> None:
    """Cost per byte must not grow with the file.

    An absolute second-count cannot tell linear from quadratic; it only moves
    the size at which a quadratic reader stalls `code-index build`, which reads
    every file in a repository. Four times the bytes buys about four times the
    work from a linear reader and sixteen from a quadratic one, so the growth
    factor is the assertion and the midpoint between the two is the bound. The
    fastest of several runs is the estimate, because load only ever adds time.

    The status is asserted with it, because the cheapest way to read an opener
    in linear time is to stop reading at it -- and an artifact that answers
    `degraded` for every unterminated opener would satisfy the growth bound
    while owing a review span for source the reader simply skipped.
    """

    def elapsed(repeat: int) -> float:
        source = (unit * repeat).encode()
        best = float("inf")
        for _ in range(3):
            started = time.monotonic()
            indexed = index_file(path, language, source)
            best = min(best, time.monotonic() - started)
            # Linear because every byte was read, not because none was.
            assert indexed["bytes_scanned"] == len(source)
            assert indexed["analysis_status"] == "complete"
        return best

    growth = elapsed(16_000) / elapsed(4_000)

    assert growth < 8, f"{growth:.1f}x the work for 4x the bytes"


def test_twig_template_composition_is_recorded_as_imports() -> None:
    source = """\
{% extends 'layouts/base.html.twig' %}
{% import "macros/forms.html.twig" as forms %}
{% from 'macros/ui.html.twig' import button %}
{% block body %}
  {%- include ['partials/a.html.twig', 'partials/b.html.twig'] -%}
  {% embed "partials/card.html.twig" %}{% endembed %}
  <script src="/js/app.js"></script>
{% endblock %}
"""

    indexed = index_file("templates/page.html.twig", "twig", source.encode())

    assert indexed["imports"] == [
        "/js/app.js",
        "layouts/base.html.twig",
        "macros/forms.html.twig",
        "macros/ui.html.twig",
        "partials/a.html.twig",
        "partials/card.html.twig",
    ]


def test_twig_template_keeps_html_entry_points() -> None:
    indexed = index_file(
        "templates/login.html.twig", "twig",
        b'<form action="{{ path(\'login\') }}" method="post"></form>\n',
    )

    assert [item["kind"] for item in indexed["entry_points"]] == ["html_form"]
