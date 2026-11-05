"""`<top-level>` segments cover executable file-scope code, and only that.

A segment is a review obligation, so declarations never open one: namespace
and package lines, imports, `declare(...)`, PHP tags, comments, attributes,
decorators, and class, interface, trait, enum and function declarations
including their headers. Statements that run when the file is loaded or
requested do: calls, output, control flow, inclusions, a `define()` of a
computed value, and bindings whose value is not a literal. A line inside one
that holds only closing punctuation owes nothing of its own. A file-scope line that carries a sink
or a source always counts, so a reported `<top-level>` sink is never left
without an obligation. The file-scope readers themselves are unchanged.
"""
from __future__ import annotations

import pytest

from assess.lib.treesitter_index import index_file


def _segments(indexed: dict) -> list[tuple[int, int]]:
    return [(segment["line_start"], segment["line_end"]) for segment in indexed["top_level_segments"]]


PHP_CLASS = b"""<?php
declare(strict_types=1);

namespace Acme\\Billing;

use Acme\\Support\\Money;
use function Acme\\Support\\format;

/** An invoice. */
#[Entity]
final class Invoice implements \\JsonSerializable
{
    public const STATUS = 'open';
    private array $lines = [];

    public function total(): Money
    {
        return new Money(1);
    }
}
?>
"""

PHP_INTERFACE_ENUM = b"""<?php
namespace Acme;

interface Payable
{
    public function pay(): void;
}

enum Status: string
{
    case Open = 'open';

    public function label(): string { return 'x'; }
}
"""

JAVA_CLASS = b"""package acme;

import java.util.List;

public class Report {
    private static final int LIMIT = 10;
    private List<String> rows;

    public int size() { return rows.size(); }
}
"""

PYTHON_MODULE = b'''"""Acme reports."""
from __future__ import annotations

import os
from acme import base

__all__ = ["Report"]
LIMIT = 10


class Report(base.Base):
    rows = []

    def size(self):
        return len(self.rows)
'''

GO_PACKAGE = b"""package acme

import "fmt"

const Limit = 10

type Report struct{ rows []string }

func (r Report) Size() int { return len(r.rows) }
"""

TS_MODULE = b"""import { Base } from "./base";

export interface Row { id: string }
export type Rows = Row[];
export const LIMIT = 10;

export class Report extends Base {
  size(): number { return 1; }
}

export function build(): Report { return new Report(); }
export { Base };
"""

C_UNIT = b"""#include <stdio.h>
#define LIMIT 10

struct report { int rows; };
static const int limit = LIMIT;
int report_size(struct report *r);

int report_size(struct report *r) { return r->rows; }
"""

CSHARP_CLASS = b"""using System;

namespace Acme;

public class Report
{
    private const int Limit = 10;

    public int Size() { return 1; }
}
"""


@pytest.mark.parametrize(
    ("path", "language", "source"),
    [
        pytest.param("src/Invoice.php", "php", PHP_CLASS, id="php-class"),
        pytest.param("src/Status.php", "php", PHP_INTERFACE_ENUM, id="php-interface-enum"),
        pytest.param("acme/Report.java", "java", JAVA_CLASS, id="java-class"),
        pytest.param("acme/report.py", "python", PYTHON_MODULE, id="python-module"),
        pytest.param("acme/report.go", "go", GO_PACKAGE, id="go-package"),
        pytest.param("src/report.ts", "typescript", TS_MODULE, id="ts-module"),
        pytest.param("src/report.c", "c", C_UNIT, id="c-unit"),
        pytest.param("src/Report.cs", "csharp", CSHARP_CLASS, id="csharp-class"),
    ],
)
def test_declarations_open_no_segment(path: str, language: str, source: bytes) -> None:
    indexed = index_file(path, language, source)

    assert indexed["analysis_mode"] == "tree_sitter"
    assert indexed["total_functions"] >= 1
    assert _segments(indexed) == []


PHP_FRONT_CONTROLLER = b"""<?php
namespace Acme;

use Acme\\Kernel;

define('ACME_ROOT', __DIR__);
$kernel = new Kernel();

function boot() { return 1; }

if (PHP_SAPI !== 'cli') {
    echo $kernel->handle();
}
"""

PHP_INLINE_OUTPUT = b"""<?php
function title() { return 'Acme'; }
?>
<h1><?= title() ?></h1>
"""

PYTHON_SIDE_EFFECTS = b"""import os

DB_HOST = os.environ.get("DB_HOST")


def handler():
    return DB_HOST


if __name__ == "__main__":
    handler()
"""

GO_VAR = b"""package acme

import "os"

var target = os.Getenv("ACME_TARGET")

func Run() string { return target }
"""

JS_SERVER = b"""import express from "express";

const app = express();

function health(req, res) { res.send("ok"); }

app.get("/health", health);
export default app;
"""

JAVA_STATIC_INITIALIZER = b"""class Runner {
  static {
    Runtime.getRuntime().exec(System.getenv("CMD"));
  }

  void run() {}
}
"""

C_MACRO_SINK = b"""#include <stdlib.h>
#define RUN(cmd) system(cmd)

int run(const char *cmd) { return RUN(cmd); }
"""

PHP_CONSTANTS = b"""<?php
const ACME_NAME = 'acme';
const ACME_LABEL = ACME_NAME . ' billing';
const ACME_CLOCK = new \\Acme\\Clock();

function now() { return ACME_CLOCK; }
"""



@pytest.mark.parametrize(
    ("path", "language", "source", "segments"),
    [
        pytest.param("public/index.php", "php", PHP_FRONT_CONTROLLER, [(7, 7), (11, 12)], id="php-front-controller"),
        pytest.param("views/page.php", "php", PHP_INLINE_OUTPUT, [(4, 4)], id="php-inline-output"),
        pytest.param("acme/app.py", "python", PYTHON_SIDE_EFFECTS, [(3, 3), (10, 11)], id="python-side-effects"),
        pytest.param("acme/state.go", "go", GO_VAR, [(5, 5)], id="go-var-initializer"),
        pytest.param("src/server.js", "javascript", JS_SERVER, [(3, 3), (7, 8)], id="js-module-side-effects"),
        pytest.param("Runner.java", "java", JAVA_STATIC_INITIALIZER, [(2, 3)], id="java-static-initializer"),
        pytest.param("acme/macros.c", "c", C_MACRO_SINK, [(2, 2)], id="c-macro-sink"),
        pytest.param("config/app.php", "php", PHP_CONSTANTS, [(4, 4)], id="php-const-constructs-object"),
    ],
)
def test_executable_file_scope_opens_segments(
    path: str, language: str, source: bytes, segments: list[tuple[int, int]]
) -> None:
    assert _segments(index_file(path, language, source)) == segments


def test_narrowing_leaves_the_file_scope_readers_unchanged() -> None:
    source = b"""<?php
namespace Acme;

class Shell
{
    public function run($cmd) { return 1; }
}

system($_GET['cmd']);
"""
    indexed = index_file("bin/shell.php", "php", source)

    assert ("process_exec", "<top-level>", 9) in {
        (sink["kind"], sink["function"], sink["line"]) for sink in indexed["security_sinks"]
    }
    assert _segments(indexed) == [(9, 9)]


def test_a_zero_callable_declarations_file_has_no_segment() -> None:
    """With no callable and no executable file scope, the backend's whole-file
    span rule is what applies, as it did before segments existed."""
    source = b"""<?php
namespace Acme;

final class Money
{
    public const CURRENCY = 'USD';
    private int $cents = 0;
}
"""
    indexed = index_file("src/Money.php", "php", source)

    assert indexed["total_functions"] == 0
    assert _segments(indexed) == []


PHP_DOCUMENTED_CLASS = b"""<?php
namespace Acme\\Render;

use DOMDocument;

/**
 * Renders a page. Reads `$_GET['page']` and calls `$request->process()`;
 * see shell_exec() and unserialize() for what this class never does.
 */
final class Page
{
    public const BANNED = 'unserialize() is banned';
    protected array $formats = ['print' => 'print.css'];
    protected DOMDocument $document;

    public function title(): string
    {
        return 'Acme';
    }
}
"""

PYTHON_DOCUMENTED_CLASS = b'''class Report:
    """Never call eval(input()) or os.system(cmd) here."""

    def size(self):
        return 1
'''


@pytest.mark.parametrize(
    ("path", "language", "source"),
    [
        pytest.param("src/Page.php", "php", PHP_DOCUMENTED_CLASS, id="php-docblock-import-members"),
        pytest.param("acme/report.py", "python", PYTHON_DOCUMENTED_CLASS, id="python-docstring"),
    ],
)
def test_reader_signals_in_declarations_open_no_segment(path: str, language: str, source: bytes) -> None:
    """A reader matching text in a comment, an import or a constant member
    still reports its `<top-level>` signal, but nothing there runs."""
    indexed = index_file(path, language, source)

    assert [sink for sink in indexed["security_sinks"] if sink["function"] == "<top-level>"] or (
        indexed["security_sources"]
    )
    assert _segments(indexed) == []


def test_a_php_property_hook_body_is_reviewed_code() -> None:
    source = b"""<?php
final class Terminal
{
    public string $mode = 'raw';
    public array $position {
        get {
            return [shell_exec('stty -g')];
        }
    }

    public function reset(): void {}
}
"""
    indexed = index_file("src/Terminal.php", "php", source)

    assert ("process_exec", "<top-level>", 7) in {
        (sink["kind"], sink["function"], sink["line"]) for sink in indexed["security_sinks"]
    }
    assert _segments(indexed) == [(6, 7)]


@pytest.mark.parametrize(
    ("path", "language", "source", "segments"),
    [
        pytest.param(
            "src/registry.js", "javascript",
            b"class Registry {\n  static {\n    register(Registry);\n  }\n\n  size() { return 1; }\n}\n",
            [(2, 3)], id="js-static-block",
        ),
        pytest.param(
            "acme/runner.py", "python",
            b"import os\n\nclass Runner:\n    os.system('make')\n\n    def run(self):\n        return 1\n",
            [(4, 4)], id="python-class-body-sink",
        ),
    ],
)
def test_class_bodies_open_segments_for_code_that_runs(
    path: str, language: str, source: bytes, segments: list[tuple[int, int]]
) -> None:
    assert _segments(index_file(path, language, source)) == segments
