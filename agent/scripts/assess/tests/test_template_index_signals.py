"""Signals from HTML, CSS, Blade and FreeMarker as rendered source."""

from __future__ import annotations

import pytest

from assess.lib.treesitter_index import StreamingSecurityScanner, index_file


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
