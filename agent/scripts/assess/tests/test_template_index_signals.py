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
"""

    indexed = index_file("page.html", "html", source)

    assert any(item["kind"] == "html_form" for item in indexed["entry_points"])
    assert all(item["annotation"] != "/tracking" for item in indexed["entry_points"])
    assert not indexed["imports"]
    assert not indexed["security_sinks"]


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
              f'<form action="/login"> {close}\n').encode()

    indexed = index_file(path, language, source)

    assert not indexed["entry_points"]
    assert not indexed["imports"]
    assert not indexed["security_sinks"]


def test_blade_comment_does_not_add_template_import() -> None:
    source = b"{{-- @include('admin.secret') --}}\n{{ $name }}\n"

    indexed = index_file("view.blade.php", "blade", source)

    assert not indexed["imports"]
    assert any(item["kind"] == "template_interpolation"
               for item in indexed["security_sinks"])


def test_template_comment_closure_preserves_live_markup_and_line() -> None:
    source = b"{{-- <form action='/dead'> --}}<form action='/live'>\n"

    indexed = index_file("view.blade.php", "blade", source)

    assert [(item["annotation"], item["line"]) for item in indexed["entry_points"]] == [
        ("/live", 1)
    ]


def test_css_block_comments_do_not_emit_import_or_behavior_signals() -> None:
    source = b"""\
body { color: red; /* behavior: url(evil.htc); */ }
/*
@import url(http://example.test/evil.css);
*/
"""

    indexed = index_file("style.css", "css", source)

    assert not indexed["imports"]
    assert not indexed["security_sinks"]


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


@pytest.mark.parametrize("construct", [
    "{% include 'partials/header.html.twig' %}",
    "{% include ['partials/a.html.twig', 'partials/b.html.twig'] with {'x': 1} %}",
    "{{ include('partials/header.html.twig', {'x': 1}) }}",
    "{{ source('partials/logo.svg') }}",
])
def test_twig_template_named_by_a_literal_is_not_dynamic_evaluation(construct: str) -> None:
    indexed = index_file("templates/page.html.twig", "twig", f"{construct}\n".encode())

    assert not any(sink["kind"] == "twig_dynamic_evaluation" for sink in indexed["security_sinks"])


def test_twig_comments_and_verbatim_blocks_are_not_outputs() -> None:
    source = """\
{# <p>{{ user.bio|raw }}</p> {% include 'dead.twig' %} #}
{% verbatim %}<p>{{ user.bio|raw }}</p>{% endverbatim %}
<p>{{ user.name }}</p>
"""

    indexed = index_file("templates/page.html.twig", "twig", source.encode())

    assert indexed["analysis_status"] == "complete"
    assert [(sink["kind"], sink["line"]) for sink in indexed["security_sinks"]] == [
        ("template_interpolation", 3)
    ]
    assert not indexed["imports"]


@pytest.mark.parametrize("unit,repeat", [("<a ", 30_000), ("{{ ", 16_000), ("{% ", 16_000), ("{# ", 16_000)])
def test_unterminated_twig_constructs_index_in_linear_time(unit: str, repeat: int) -> None:
    started = time.monotonic()
    indexed = index_file("templates/page.html.twig", "twig", (unit * repeat).encode())

    assert time.monotonic() - started < 5
    assert indexed["analysis_status"] == "complete"


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
