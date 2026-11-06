"""PHP `file_inclusion` sinks come from the parse tree and name their argument.

An inclusion construct loads and runs the file it names, so every one is a
sink -- a literal one included, because a hunter decides whether it matters,
not the indexer. What a line merely spells like an inclusion (a comment, a
string, an array key, a `$include` variable, `$this->include()` view
rendering) is not one. Whether the argument is static is the import target's
status to say.
"""
from __future__ import annotations

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file


def _inclusions(indexed: dict) -> list[dict]:
    return [sink for sink in indexed["security_sinks"] if sink["kind"] == "file_inclusion"]


def test_every_inclusion_construct_is_a_sink_naming_its_argument() -> None:
    source = b"""<?php
require_once __DIR__ . '/bootstrap.php';
include 'acme/header.php';
require ACME_ROOT . '/config.php';
include $_GET['page'] . '.php';
require_once $CFG->dirroot . '/lib/setup.php';
include dirname(__FILE__) . '/footer.php';
require self::TEMPLATES . 'page.php';
"""
    indexed = index_file("public/index.php", "php", source)

    assert {sink["line"]: sink["argument"] for sink in _inclusions(indexed)} == {
        2: "__DIR__ . '/bootstrap.php'",
        3: "'acme/header.php'",
        4: "ACME_ROOT . '/config.php'",
        5: "$_GET['page'] . '.php'",
        6: "$CFG->dirroot . '/lib/setup.php'",
        7: "dirname(__FILE__) . '/footer.php'",
        8: "self::TEMPLATES . 'page.php'",
    }


def test_an_include_sink_names_its_argument() -> None:
    source = b"""<?php
include $CFG->dirroot . '/theme/' . $theme . '/layout.php';
"""
    (sink,) = _inclusions(index_file("public/index.php", "php", source))

    assert sink["argument"] == "$CFG->dirroot . '/theme/' . $theme . '/layout.php'"
    assert sink["vuln_classes"] == ["lfi", "rfi"]
    assert sink["function"] == "<top-level>"


def test_an_include_is_attributed_to_its_innermost_callable() -> None:
    source = b"""<?php
class AcmeView
{
    public function render($name)
    {
        $load = function () use ($name) {
            include $name;
        };
        require __DIR__ . '/helpers.php';
    }
}
"""
    indexed = index_file("src/AcmeView.php", "php", source)

    assert [(sink["line"], sink["function"]) for sink in _inclusions(indexed)] == [
        (7, "$load"),
        (9, "render"),
    ]


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("// include $page;", id="comment"),
        pytest.param("/* require 'legacy.php'; */", id="block-comment"),
        pytest.param("$hint = 'please include the header';", id="string"),
        pytest.param("$opts['require'] = true;", id="array-key"),
        pytest.param("$include = $request->get('tpl');", id="variable"),
        pytest.param("return $this->include('acme/view');", id="view-rendering"),
        pytest.param("Acme::require_once($x);", id="static-call"),
    ],
)
def test_php_non_inclusion_constructs_are_not_file_inclusion(statement: str) -> None:
    source = ("<?php\nfunction acme_handler($x, $request) {\n    " + statement + "\n}\n").encode()
    indexed = index_file("src/acme.php", "php", source)

    assert _inclusions(indexed) == []


def test_streaming_reports_include_sinks_by_line() -> None:
    source = b"""<?php
require_once __DIR__ . '/bootstrap.php';
include $_GET['page'];
$this->include('acme/view');
"""
    streamed = treesitter_index._fallback_from_bytes(
        "public/index.php", "php", source, degradation_reason="test"
    )

    assert [sink["line"] for sink in _inclusions(streamed)] == [2, 3]
