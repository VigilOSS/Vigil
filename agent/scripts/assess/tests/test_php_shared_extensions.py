"""Extensions PHP shares with other formats read as PHP only when the file is.

`.inc`, `.module`, `.install` and `.theme` name PHP include fragments and
Drupal module, install and theme files, but the same names are C, C++ and
assembler fragments, packaging install lists and desktop theme files. Indexed
as PHP, those gain a rendered-page entry point and a `<top-level>` segment that
owe review for code that never runs as PHP, so ingest reads them as PHP only
when they open a PHP tag.
"""
from __future__ import annotations

import json

import pytest

from assess.commands import code_ingest
from assess.lib.code_languages import detect_language
from test_code_ingest_vendored_minified import _args, _offline_ingest, _write

PHP_FRAGMENTS = {
    "includes/common.inc": "<?php\nfunction acme_common() {}\n",
    "modules/acme/acme.module": "<?php\n\n/**\n * Implements hook_help().\n */\n",
    "modules/acme/acme.install": "<?php\nfunction acme_install() {}\n",
    "themes/acme/acme.theme": "<?PHP\nfunction acme_preprocess_page(&$variables) {}\n",
    "views/header.inc": "<html>\n<title><?= $title ?></title>\n",
    "legacy/acme.inc": "<?\nfunction acme_legacy() { return $_GET['x']; }\n",
}
OTHER_FORMATS = {
    "lib/Support/Unix/Path.inc": "//===- Unix/Path.inc - Acme Unix Path Implementation -*- C++ -*-===//\n"
    "#include <limits.h>\n",
    "debian/acme.install": "usr/bin/acme\nusr/share/acme/\n",
    "share/themes/Acme/index.theme": "[Desktop Entry]\nName=Acme\n",
    "src/acme.module": "MODULE acme\n",
    "share/acme/acme.theme": '<?xml version="1.0"?>\n<theme name="acme"/>\n',
}


@pytest.mark.parametrize(("path", "header"), sorted(PHP_FRAGMENTS.items()))
def test_a_shared_extension_that_opens_a_php_tag_is_php(path: str, header: str) -> None:
    assert detect_language(path, header=header) == "php"


@pytest.mark.parametrize(("path", "header"), sorted(OTHER_FORMATS.items()))
def test_a_shared_extension_without_a_php_tag_is_not_php(path: str, header: str) -> None:
    assert detect_language(path, header=header) is None


class _PreviewClient:
    payloads: list[dict] = []

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post(self, endpoint: str, payload: dict, **_options):
        assert endpoint == "code/repos/refresh/preview"
        type(self).payloads.append(payload)
        return {"repo_key": payload["repo_key"], "files": len(payload["files"])}


def test_ingest_reads_each_shared_extension_by_its_content(monkeypatch, tmp_path, capsys) -> None:
    repo, engagement = _offline_ingest(monkeypatch, tmp_path)
    for path, content in {**PHP_FRAGMENTS, **OTHER_FORMATS}.items():
        _write(repo, path, content)
    _PreviewClient.payloads = []
    monkeypatch.setattr(code_ingest, "AssessmentClient", _PreviewClient)

    code_ingest.run(_args(repo, name="acme-reports", dry_run=True, engagement_dir=str(engagement)))

    assert json.loads(capsys.readouterr().out)["files"] == len(PHP_FRAGMENTS) + len(OTHER_FORMATS) + 1
    languages = {
        str(record["file_path"]): str(record["language"])
        for record in _PreviewClient.payloads[0]["files"]
    }
    assert {path: languages[path] for path in PHP_FRAGMENTS} == dict.fromkeys(PHP_FRAGMENTS, "php")
    assert {path: languages[path] for path in OTHER_FORMATS} == dict.fromkeys(OTHER_FORMATS, "")
