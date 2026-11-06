"""An index never reports complete over code its readers did not look at.

The HTML pass, which Blade, Twig and FreeMarker templates also run, takes
tags and attributes, not the script an inline `<script>` element runs; the PHP
readers blank inline HTML, script included; the Blade readers take echoes and
directives, not an `@php` block or raw PHP. Each such body leaves the
function-scoped dimensions unmeasured, so the file is degraded and owes a
whole-file read, while every record the readers did find is kept.
"""
from __future__ import annotations

import pytest

from assess.lib.treesitter_index import FUNCTION_SCOPED_DIMENSIONS, index_file

_INLINE_SCRIPT_PAGE = b"""<!doctype html>
<html>
<body>
<script>
  document.write(location.hash);
</script>
</body>
</html>
"""
_TEMPLATE_SCRIPT = b"<script>\n  document.write(location.hash);\n</script>\n"
_PHP_PAGE_WITH_SCRIPT = b"""<?php $title = 'Acme'; ?>
<html><body>
<script>
  document.write(location.hash);
</script>
</body></html>
"""


@pytest.mark.parametrize(
    ("file_path", "language", "source"),
    [
        ("web/page.html", "html", _INLINE_SCRIPT_PAGE),
        ("public/page.php", "php", _PHP_PAGE_WITH_SCRIPT),
        ("resources/views/page.blade.php", "blade", b"<div></div>\n" + _TEMPLATE_SCRIPT),
        ("templates/page.html.twig", "twig", b"<div></div>\n" + _TEMPLATE_SCRIPT),
        ("templates/page.ftlh", "freemarker", b"<div></div>\n" + _TEMPLATE_SCRIPT),
        (
            "resources/views/page.blade.php",
            "blade",
            b"<div>\n@php\n    $rows = DB::select($request->input('q'));\n@endphp\n</div>\n",
        ),
        (
            "resources/views/raw.blade.php",
            "blade",
            b"<div>\n<?php system($_GET['c']); ?>\n</div>\n",
        ),
        (
            "web/app.html",
            "html",
            b"<script type=\"module\">\n  document.write(location.hash);\n</script>\n",
        ),
        (
            "templates/app.html.twig",
            "twig",
            b"<script type=\"text/babel\">\n  document.write(location.hash);\n</script>\n",
        ),
    ],
)
def test_an_unread_code_body_leaves_function_scope_unmeasured(
    file_path: str, language: str, source: bytes
) -> None:
    indexed = index_file(file_path, language, source)

    assert indexed["analysis_status"] == "degraded"
    assert indexed["degradation_reason"] == "unscanned_function_scope"
    assert set(indexed["unavailable_dimensions"]) == set(FUNCTION_SCOPED_DIMENSIONS)
    assert indexed["security_sinks"] == []


def test_records_found_beside_an_unread_script_are_kept() -> None:
    source = b"""<!doctype html>
<html>
<body>
<button onclick="go()">Go</button>
<script>
  function go() { eval(location.hash.slice(1)); }
</script>
</body>
</html>
"""
    indexed = index_file("web/page.html", "html", source)

    assert indexed["analysis_status"] == "degraded"
    assert [sink["kind"] for sink in indexed["security_sinks"]] == ["inline_event_handler"]
    assert "security_sinks" not in indexed["unavailable_dimensions"]
    assert "dataflow" in indexed["unavailable_dimensions"]


@pytest.mark.parametrize(
    ("file_path", "language", "source"),
    [
        (
            "web/page.html",
            "html",
            b"<html>\n<script src=\"/static/app.js\"></script>\n<script>\n</script>\n"
            b"<!-- <script>eval(x)</script> -->\n</html>\n",
        ),
        ("public/page.php", "php", b"<?php $title = 'Acme'; ?>\n<html><body><p>Acme</p></body></html>\n"),
        (
            "public/data.php",
            "php",
            b"<?php $rows = [1]; ?>\n<script><?php echo json_encode($rows); ?></script>\n",
        ),
        (
            "resources/views/page.blade.php",
            "blade",
            b"<div>{{ $name }}</div>\n{{-- @php <script>eval(x)</script> --}}\n",
        ),
        ("templates/page.html.twig", "twig", b"<div></div>\n{# <script>eval(x)</script> #}\n"),
        (
            "web/data.html",
            "html",
            b"<script type=\"application/ld+json\">{\"@type\": \"Organization\"}</script>\n"
            b"<script type='importmap'>{\"imports\": {}}</script>\n"
            b"<script type=speculationrules>{\"prerender\": []}</script>\n",
        ),
        (
            "templates/data.html.twig",
            "twig",
            b"<script type=\"application/json\">{{ payload|json_encode|raw }}</script>\n",
        ),
        (
            "web/loader.html",
            "html",
            b"<script src=\"/app.js\" data-x=\"a>b\"></script>\n"
            b"<script-loader>load()</script-loader>\n",
        ),
        (
            "templates/loader.html.twig",
            "twig",
            b"<script src=\"/app.js\" data-x='a>b'></script>\n<script-loader>load()</script-loader>\n",
        ),
        ("templates/page.ftlh", "freemarker", b"<div></div>\n<#-- <script>eval(x)</script> -->\n"),
    ],
)
def test_a_page_whose_code_the_readers_saw_stays_complete(
    file_path: str, language: str, source: bytes
) -> None:
    assert index_file(file_path, language, source)["analysis_status"] == "complete"

