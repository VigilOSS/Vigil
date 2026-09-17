"""What the structural indexer's scanners can see, and what they call it.

Every test here pins a *scan scope* — the span of source a reader accepts, and
the vocabulary it reports over that span. Each one covers a boundary that was
silently wrong in the miss direction, which is the direction that costs a
finding: an attribute value truncated mid-interpolation, an unregistered output
format read as escaping, a `#` line eaten as a comment in languages where `#`
is code, a call site hidden behind a per-function dedupe, a vuln class no
taxonomy has ever heard of, and a language claimed as analyzed with nothing
behind the claim.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from assess.lib import treesitter_index, vuln_taxonomy
from assess.lib.code_languages import (
    STRUCTURAL_SUPPORTED_LANGUAGES,
    structural_language_for_file,
)
from assess.lib.treesitter_index import index_file


def _line_carrying(needle: str, source: str | bytes) -> int:
    """Return the 1-based line holding *needle*, which must be unique."""
    text = source.decode() if isinstance(source, bytes) else source
    matches = [n for n, line in enumerate(text.splitlines(), 1) if needle in line]
    assert len(matches) == 1, f"{needle!r} is not unique in fixture: {matches}"
    return matches[0]


def _freemarker_sinks(source: str, *, file_path: str = "login.ftl") -> list[dict]:
    _funcs, _entries, sinks, _exports, _imports = treesitter_index._extract_freemarker(
        source.splitlines(), file_path=file_path
    )
    return sinks


def _only_interpolation(source: str, *, file_path: str = "login.ftl") -> dict:
    interpolations = [
        sink
        for sink in _freemarker_sinks(source, file_path=file_path)
        if sink["kind"] == "template_interpolation"
    ]
    assert len(interpolations) == 1, interpolations
    return interpolations[0]


def _streaming(file_path: str, language: str, source: bytes) -> dict:
    return treesitter_index._fallback_from_bytes(
        file_path, language, source, degradation_reason="test"
    )


# --- 1. FreeMarker attribute values ----------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        '${url!""}',            # default-to-empty, the Keycloak-theme staple
        '${msg("key")}',        # double quotes inside a double-quoted attribute
        "${msg('key')}",        # the idiom that already worked
        '${(url.x)!""}',
        '${msg("a") + "/" + id}',
    ],
)
def test_a_quote_inside_an_interpolation_does_not_end_the_attribute(value: str) -> None:
    """A URL-context interpolation must survive quotes inside its expression.

    Ending the attribute at the first matching quote truncates the value
    mid-`${`, and the site degrades from a `url_attribute` interpolation
    carrying `open-redirect` to undifferentiated `malformed` noise.
    """
    sink = _only_interpolation(f'<a href="{value}">go</a>')

    assert sink["output_context"] == "url_attribute"
    assert sink["attribute"] == "href"
    assert "open-redirect" in sink["vuln_classes"]


def test_a_truly_unterminated_interpolation_is_still_reported_malformed() -> None:
    kinds = {sink["kind"] for sink in _freemarker_sinks('<a href="${url">go</a>')}

    assert "malformed_template_interpolation" in kinds


# --- 2. FreeMarker output formats ------------------------------------------


@pytest.mark.parametrize("output_format", ["HTML", "XHTML", "XML", "RTF", "html"])
def test_a_markup_output_format_is_read_as_escaping(output_format: str) -> None:
    header = _only_interpolation(f'<#ftl output_format="{output_format}">\n<p>${{v}}</p>')
    scoped = _only_interpolation(
        f'<#outputformat "{output_format}">\n<p>${{v}}</p>\n</#outputformat>'
    )

    assert header["escape_observation"] == "unverified_escape_observed"
    assert scoped["escape_observation"] == "unverified_escape_observed"


@pytest.mark.parametrize(
    "output_format",
    ["JavaScript", "JSON", "CSS", "plainText", "undefined", "MyAppRegisteredFormat"],
)
def test_a_non_markup_output_format_is_never_read_as_escaping(output_format: str) -> None:
    """Unknown must mean "nobody escaped this", not "escaped".

    A denylist of non-escaping formats gives every format nobody enumerated —
    FreeMarker's own `JavaScript`/`JSON`/`CSS`, and every app-registered name —
    a clean bill of health on an interpolation that nothing escapes.
    """
    header = _only_interpolation(f'<#ftl output_format="{output_format}">\n<p>${{v}}</p>')
    scoped = _only_interpolation(
        f'<#outputformat "{output_format}">\n<p>${{v}}</p>\n</#outputformat>'
    )

    assert header["escape_observation"] == "unverified_no_escape_observed"
    assert scoped["escape_observation"] == "unverified_no_escape_observed"


# --- 3. `#` is not a comment in every language -----------------------------


PHP_CONTROLLER = b"""<?php
namespace App;

class HomeController
{
    #[Route('/admin', name: 'admin')]
    public function admin(string $slug)
    {
        return $slug;
    }
}
"""


def test_a_php_attribute_makes_its_method_an_entry_point() -> None:
    """`_ENTRY_ANNOTATIONS["php"]` matches `#[Route`, against `annotations`.

    The PHP branch never populated `annotations`, so the matcher had nothing to
    read and every attribute-routed controller action was a plain method.
    """
    indexed = index_file("HomeController.php", "php", PHP_CONTROLLER)

    assert [entry["kind"] for entry in indexed["entry_points"]] == ["symfony_route"]
    assert indexed["entry_points"][0]["name"] == "admin"
    annotations = [ann for func in indexed["functions"] for ann in func["annotations"]]
    assert any(ann.startswith("#[Route") for ann in annotations), annotations


def test_a_php_attribute_line_is_not_eaten_by_the_streaming_comment_rule() -> None:
    observed = _streaming("HomeController.php", "php", PHP_CONTROLLER)

    assert [entry["kind"] for entry in observed["entry_points"]] == ["symfony_route"]


def test_a_freemarker_interpolation_at_line_start_is_not_eaten_as_a_comment() -> None:
    """`#{...}` is FreeMarker's numeric interpolation, not a comment."""
    observed = _streaming("total.ftl", "freemarker", b"#{order.total}\n")

    assert [sink["kind"] for sink in observed["security_sinks"]] == [
        "template_interpolation"
    ]


def test_a_php_hash_comment_is_still_skipped() -> None:
    observed = _streaming("legacy.php", "php", b"# system($_GET['cmd']);\n")

    assert observed["security_sinks"] == []
    assert observed["security_sources"] == []


def test_a_python_hash_comment_is_still_skipped() -> None:
    observed = _streaming("job.py", "python", b"# os.system(request.args['cmd'])\n")

    assert observed["security_sinks"] == []


def test_a_powershell_line_comment_is_skipped_on_both_paths() -> None:
    """`#` opens a comment in PowerShell, unlike the other `#{`/`#[` languages."""
    source = b"# Invoke-Expression $Payload\n"

    assert _streaming("deploy.ps1", "powershell", source)["security_sinks"] == []
    assert index_file("deploy.ps1", "powershell", source)["security_sinks"] == []


def test_a_shell_shebang_is_still_an_entry_point() -> None:
    observed = _streaming("deploy.sh", "shell", b"#!/bin/bash\n")

    assert [entry["kind"] for entry in observed["entry_points"]] == ["shell_script"]


# --- 4. Sink vocabulary drift ----------------------------------------------


def test_every_sink_vuln_class_is_canonical() -> None:
    """`_SINK_DEFINITIONS` speaks the one cross-track vocabulary, or nothing.

    A class that is not in `vuln_taxonomy.VULN_CLASSES` reaches coverage
    accounting, skill routing and the depth gate as an unknown string: it
    matches no skill, satisfies no expectation, and silently drops the whole
    family it was supposed to name.
    """
    declared = {
        vuln_class
        for definition in treesitter_index._SINK_DEFINITIONS
        for vuln_class in definition["vuln_classes"]
    }

    assert sorted(declared - set(vuln_taxonomy.VULN_CLASSES)) == []


STAX_JAVA = b"""\
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;

public class FeedImporter {
    public void importFeed(InputStream body) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(body);
        while (reader.hasNext()) {
            reader.next();
        }
    }
}
"""


def test_the_stax_parser_is_an_xml_parse_sink_like_its_siblings() -> None:
    """StAX is a first-class JAXP parser, and defaults to entities enabled.

    `xml_parse` already carries DOM (`DocumentBuilderFactory`), SAX
    (`SAXParserFactory`) and the SAX reader (`XMLReader`); without
    `XMLInputFactory` the fourth standard Java XML entry point produces no
    sink at all, so an XXE reached through `createXMLStreamReader` is invisible
    to the family that exists to find it. `XMLInputFactory` is also where the
    hardening lives (`IS_SUPPORTING_EXTERNAL_ENTITIES`, `SUPPORT_DTD`), so it
    is the line a reviewer needs to see.

    The pattern is written the way the API is really called — a bare type
    name, matching both the declaration and the `newInstance()` — not as a
    fully-qualified spelling no source line carries.
    """
    indexed = index_file("FeedImporter.java", "java", STAX_JAVA)
    xml_sinks = [
        sink for sink in indexed["security_sinks"] if sink["kind"] == "xml_parse"
    ]

    factory_line = _line_carrying("XMLInputFactory.newInstance()", STAX_JAVA)

    assert xml_sinks, indexed["security_sinks"]
    assert [sink["vuln_classes"] for sink in xml_sinks] == [["xxe"]] * len(xml_sinks)
    assert factory_line in {sink["line"] for sink in xml_sinks}, (
        "the XMLInputFactory line itself must be reported, not just its reader"
    )


# --- 5. Call-site scope -----------------------------------------------------


REPEATED_CALLS = b"""<?php
function handler($cmd)
{
    exec("ls -la");
    $x = 1;
    exec($cmd);
    exec($cmd); exec($cmd);
}
"""


def test_each_call_to_one_callee_is_recorded_once_per_line() -> None:
    """A safe call must not hide an unsafe one further down the same function.

    Deduplicating per function keeps only the first `exec(...)`, so the literal
    call on line 4 hid the tainted call on line 6 — the one the taint
    scheduler exists to find. Repeats on a single line stay one site.
    """
    indexed = index_file("handler.php", "php", REPEATED_CALLS)
    exec_lines = [
        site["line"] for site in indexed["call_sites"] if site["callee"] == "exec"
    ]

    assert exec_lines == [4, 6, 7]
    assert [site["passes_caller_params"] for site in indexed["call_sites"]
            if site["callee"] == "exec"] == [False, True, True]


# --- 6. A language claimed as analyzed has an extractor ---------------------


def test_powershell_resolves_to_a_structural_language() -> None:
    for name in ("deploy.ps1", "Utils.psm1", "Module.psd1"):
        assert structural_language_for_file(name) == "powershell"
    assert "powershell" in STRUCTURAL_SUPPORTED_LANGUAGES
    assert "powershell" in treesitter_index.LIGHTWEIGHT_LANGUAGES


POWERSHELL_SCRIPT = """\
param(
    [Parameter(Mandatory)][string]$Target,
    [string]$Payload
)

Import-Module WebAdministration
. .\\lib\\helpers.ps1

function Invoke-Deploy {
    param([string]$Command)
    Invoke-Expression $Command
    Start-Process -FilePath $env:COMSPEC -ArgumentList $Command
}

# Invoke-Expression $Payload   <- a comment, not a sink
$response = Invoke-WebRequest -Uri $Target
$secret = ConvertTo-SecureString "hunter2" -AsPlainText -Force
Import-Clixml -Path $Payload
"""


def test_a_powershell_script_is_structurally_indexed() -> None:
    indexed = index_file("deploy.ps1", "powershell", POWERSHELL_SCRIPT.encode())

    assert indexed["structural_index_available"] is True
    assert indexed["analysis_mode"] == "lightweight_regex"
    assert [func["name"] for func in indexed["functions"]] == ["Invoke-Deploy"]
    assert [export["kind"] for export in indexed["exports"]] == ["powershell_function"]
    assert "WebAdministration" in indexed["imports"]

    by_kind = {sink["kind"] for sink in indexed["security_sinks"]}
    assert {"dynamic_code_evaluation", "process_exec", "url_fetch",
            "plaintext_secret", "deserialization"} <= by_kind

    evaluation = next(
        sink for sink in indexed["security_sinks"]
        if sink["kind"] == "dynamic_code_evaluation"
    )
    assert evaluation["function"] == "Invoke-Deploy"
    assert evaluation["vuln_classes"] == ["injection"]
    # The commented-out `Invoke-Expression` is the only other occurrence.
    assert sum(
        sink["kind"] == "dynamic_code_evaluation" for sink in indexed["security_sinks"]
    ) == 1

    assert {entry["kind"] for entry in indexed["entry_points"]} == {"script_parameters"}
    assert {source["kind"] for source in indexed["security_sources"]} == {
        "environment_input"
    }


def test_the_powershell_streaming_fallback_covers_every_signal_dimension() -> None:
    """The bounded scanner is what runs on a file too large to parse whole.

    `_attach_bounded_security_sources` also routes the structural path's
    sources through it, so a language with no streaming patterns cannot be
    indexed at all.
    """
    observed = _streaming("deploy.ps1", "powershell", POWERSHELL_SCRIPT.encode())

    assert set(observed["unavailable_dimensions"]) == set(
        treesitter_index.STREAMING_FALLBACK_BASELINE_UNAVAILABLE
    )
    assert observed["security_sinks"]
    assert observed["security_sources"]
    assert observed["entry_points"]
    assert observed["imports"]


# --- 7. Declarator and lookback scope --------------------------------------


POINTER_RETURN_SOURCE = """\
#include <string.h>
#include <stdlib.h>

char *copy_name(const char *name) {
    char buf[16];
    strcpy(buf, name);
    return strdup(buf);
}

char **make_grid(int width) {
    return malloc(width);
}

void (*get_callback(int slot))(int) {
    return 0;
}

int plain(const char *name) {
    char buf[8];
    strcpy(buf, name);
    return 0;
}
"""


def test_a_pointer_return_type_does_not_hide_a_c_function() -> None:
    """The same bytes must index the same whether the file is `.c` or `.cpp`.

    `char *copy_name(...)` parses as `pointer_declarator(function_declarator)`,
    and reading only the declarator's direct children finds neither the name nor
    the parameters, so the function is dropped. `_detect_sinks` scans function
    bodies, so its `strcpy` goes with it — in the most memory-unsafe language
    Vigil supports, for the commonest shape of allocation helper.
    """
    source = POINTER_RETURN_SOURCE.encode()
    c_index = index_file("alloc.c", "c", source)
    cpp_index = index_file("alloc.cpp", "cpp", source)

    assert [func["name"] for func in c_index["functions"]] == [
        "copy_name",
        "make_grid",
        "get_callback",
        "plain",
    ]
    assert [func["name"] for func in c_index["functions"]] == [
        func["name"] for func in cpp_index["functions"]
    ]
    assert sorted(sink["function"] for sink in c_index["security_sinks"]) == sorted(
        sink["function"] for sink in cpp_index["security_sinks"]
    )
    assert {"copy_name", "plain"} <= {
        sink["function"] for sink in c_index["security_sinks"]
    }


def test_a_pointer_returning_c_function_keeps_its_parameters() -> None:
    indexed = index_file("alloc.c", "c", POINTER_RETURN_SOURCE.encode())
    by_name = {func["name"]: func for func in indexed["functions"]}

    assert by_name["copy_name"]["params"] == ["const char *name"]
    assert by_name["make_grid"]["params"] == ["int width"]
    # A function returning a function pointer nests a second `function_declarator`.
    assert by_name["get_callback"]["params"] == ["int slot"]


STACKED_ROUTES = b"""const express = require("express");
const app = express();
app.get("/admin", handleAdmin);
function helper(x) {
  return x + 1;
}
function handleAdmin(req, res) {
  res.send(helper(1));
}
"""


def test_a_stacked_function_never_inherits_a_neighbours_registration() -> None:
    """A registration belongs to the callable it actually registers.

    `helper` and `handleAdmin` merely sit near `app.get("/admin", ...)`; neither
    is passed to it. Proximity is not registration, so neither may be reported.
    Attribution is structural — an enclosing call, not a line window — so there
    is no distance at which a neighbour starts inheriting the match.
    """
    indexed = index_file("routes.js", "javascript", STACKED_ROUTES)

    assert indexed["entry_points"] == []
    assert not [func for func in indexed["functions"] if func["is_entry_point"]]


# The span a registration can be written in has two parts, and this is the
# second: `app.get(` sits on a line the callback does not span as soon as the
# path plus the handler exceeds 80 columns, which is what Prettier's default
# emits for most real routes. The catalogue suite owns the shape corpus
# (arrow / named expression / trailing middleware / async adapter); what is
# pinned here is the span itself.
WRAPPED_ROUTE = b"""const app = require("express")();

app.get(
  "/reports/:id",
  async (req, res) => {
    res.send("ok");
  }
);
"""


def test_the_entry_point_span_reaches_the_call_that_registers_a_callback() -> None:
    """A registration belongs to the callback, however far above it is written.

    Reading only the callback's own lines loses the route entirely — and the
    route is what schedules the function as a request surface, so losing it
    means the hunter is never sent. The call is reached structurally, so no
    reformatting and no argument count can move it out of the span.
    """
    indexed = index_file("reports.js", "javascript", WRAPPED_ROUTE)
    callback_line = _line_carrying("  async (req, res) => {", WRAPPED_ROUTE)

    assert [
        (entry["kind"], entry["line"]) for entry in indexed["entry_points"]
    ] == [("express_route", callback_line)]


def test_a_callback_nested_inside_a_registered_callback_is_not_the_route() -> None:
    """The walk to the enclosing call stops at the first callable it crosses.

    An inner helper closure is registered by nothing; only the callback the
    route call actually receives is the request surface. Without the callable
    boundary the walk would reach `app.get(` from arbitrary depth and hand the
    hunter a closure that no request ever enters directly.
    """
    source = b"""const app = require("express")();

app.get(
  "/reports/:id",
  (req, res) => {
    const format = (row) => row.id;
    res.send(format(req.params));
  }
);
"""
    indexed = index_file("reports.js", "javascript", source)
    handler_line = _line_carrying("  (req, res) => {", source)

    assert [entry["line"] for entry in indexed["entry_points"]] == [handler_line]
    assert "format" in {func["name"] for func in indexed["functions"]}, (
        "fixture must still extract the nested closure"
    )


# --- 8. PHP file inclusion is `lfi`/`rfi`, not `path-traversal` -------------


def test_php_file_inclusion_reports_the_inclusion_classes() -> None:
    """`include $view;` is file inclusion; `fopen($p)` is traversal.

    `lfi`/`rfi` are the canonical classes for inclusion
    (`vuln_taxonomy.py`), and they route to a different skill than
    `path-traversal`. Folding them into the `file_path` family gave every PHP
    `include` the wrong family and hid `rfi` entirely.
    """
    source = b"""<?php
function render($view, $path)
{
    include $view;
    require_once $view;
    $handle = fopen($path, "r");
    return $handle;
}
"""
    indexed = index_file("render.php", "php", source)
    by_kind: dict[str, list[str]] = {}
    for sink in indexed["security_sinks"]:
        by_kind.setdefault(sink["kind"], sink["vuln_classes"])

    assert by_kind["file_inclusion"] == ["lfi", "rfi"]
    assert by_kind["file_path"] == ["path-traversal"]


# --- 9. Emitted vuln classes across every table ----------------------------


# Classes the code track emits that the canonical taxonomy has no home for.
# Each is a real finding family (`vuln_taxonomy.py` has no container-hardening,
# build-supply-chain, or exposed-surface class), so remapping one onto an
# existing class would misroute the hunter rather than fix anything. They are
# named here so the invariant is enforced for everything else and this
# exception is visible in CI instead of silent.
UNHOMED_VULN_CLASSES = {"network-exposure", "privilege-escalation", "supply-chain"}


def _emitted_vuln_classes() -> set[str]:
    """Every vuln class the indexer can put on a record.

    Read from the module source rather than from a roster: the pattern tables
    are only half of it, and the lightweight extractors spell their classes
    inline at each `sinks.append(...)`. An AST sweep of every
    ``"vuln_classes": [...]`` literal plus the three pattern tables is the only
    way to cover both without a second list to keep in sync.
    """
    module = ast.parse(Path(treesitter_index.__file__).read_text(encoding="utf-8"))
    emitted = {
        element.value
        for node in ast.walk(module)
        if isinstance(node, ast.Dict)
        for key, value in zip(node.keys, node.values)
        if isinstance(key, ast.Constant) and key.value == "vuln_classes"
        for element in getattr(value, "elts", ())
        if isinstance(element, ast.Constant) and isinstance(element.value, str)
    }
    for entries in treesitter_index._STREAM_EXTRA_SINK_PATTERNS.values():
        for _kind, _pattern, vuln_classes in entries:
            emitted.update(vuln_classes)
    return emitted


def test_no_indexer_table_invents_a_vuln_class() -> None:
    invented = sorted(_emitted_vuln_classes() - set(vuln_taxonomy.VULN_CLASSES))

    assert invented == sorted(UNHOMED_VULN_CLASSES), (
        "a vuln class outside the canonical taxonomy reaches the hunter as an "
        "unknown string: it matches no skill and satisfies no coverage "
        f"expectation. New offenders: {sorted(set(invented) - UNHOMED_VULN_CLASSES)}"
    )


def test_a_security_source_carries_no_vuln_class() -> None:
    """A source is where a value came from, not a vulnerability.

    Every source record labelled itself `tainted-input`, which is not a class in
    any taxonomy — a `vuln_classes` field that can only hold a non-class makes
    the invariant above unenforceable while claiming to carry a family.
    """
    observed = _streaming("job.py", "python", b"x = request.args['q']\n")

    assert [source["kind"] for source in observed["security_sources"]] == [
        "http_request_input"
    ]
    assert all(
        "vuln_classes" not in source for source in observed["security_sources"]
    ), observed["security_sources"]
