"""Empirical audit of `_SINK_DEFINITIONS`' file_path / file_inclusion /
sql_exec / process_exec families -- 108 regex patterns across 10 languages.

Every pattern below is exercised against an idiomatic, current-era (2026)
fixture through the real tree-sitter indexer. Only patterns that fire on
realistic code get a case in ``CASES`` -- DEAD / REDUNDANT / MISROUTED
patterns are named, with the file:line evidence, in ``_EXCLUDED`` instead,
and ``test_case_table_covers_every_live_pattern_in_the_assigned_slice``
proves the two lists together account for all 108 patterns, so the catalogue
cannot silently regain a dead pattern or lose a live one.

Taxonomy note. Three defects this audit recorded have since been fixed in the
catalogue, and the tests below now pin the corrected values so a regression
fails loudly rather than being re-documented:

* ``sql_exec`` emitted the non-canonical ``"sql-injection"`` and now emits
  ``["sqli"]``, the canonical class (vuln_taxonomy.py:73).
* PHP's four inclusion constructs (``include``/``require``/``include_once``/
  ``require_once``) were classed as ``file_path`` -> ``path-traversal``.
  They are now their own ``file_inclusion`` kind carrying ``["lfi", "rfi"]``
  (vuln_taxonomy.py:92-93). The patterns moved verbatim, so the slice is
  kept that redistribution: ``file_path`` is 35 and ``file_inclusion`` is 4.

* Ruby's command-substitution pattern was ``\b`[^`]*` ``. ``\b`` holds only at
  a word/non-word transition and a backtick is never a word character, so the
  anchor demanded a word character immediately to its left -- which idiomatic
  Ruby (``out = `ssh ...` ``) never writes. It was pinned DEAD; the anchor is
  gone and it has a real case in ``CASES`` instead.

* Java's valid ``Runtime.getRuntime().exec(...)`` form and Python's four
  commonly used subprocess convenience APIs are live process-execution sinks,
  bringing this slice to 93 patterns (87 live, 6 excluded) at that point.

* C# was then added as a tree-sitter language, contributing 14 patterns to
  this slice (5 ``file_path``, 7 ``sql_exec``, 2 ``process_exec``). All 14
  fire LIVE on idiomatic C# and get real cases in ``CASES``; none is excluded,
  bringing the slice to 107 patterns (101 live, 6 excluded). C++ stream
  construction adds one live ``file_path`` pattern.

``file_path`` keeps the constructs that really are traversal
(``fopen``/``file_get_contents``/``file_put_contents``).
"""
from __future__ import annotations

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file
from assess.lib.vuln_taxonomy import is_valid_class


# ---------------------------------------------------------------------------
# Fixtures -- one idiomatic, current-era (2026) source file per language.
#
# Each LIVE pattern gets its own line (never sharing a line with another
# pattern in the same family) so a sink at that exact line can only be
# produced by that one pattern -- removing the pattern from the catalogue
# makes the corresponding assertion fail with nothing left to find.
# ---------------------------------------------------------------------------

JAVA_SOURCE = """\
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.commons.io.FileUtils;
import java.sql.Connection;
import java.sql.Statement;

class FileController {
    void readUpload(String filename) throws Exception {
        File target = new File(uploadDir, filename);
        FileInputStream in = new FileInputStream(target);
        in.close();
    }

    void writeReport(String path) throws Exception {
        FileOutputStream out = new FileOutputStream(path);
        out.close();
    }

    void resolvePath(String name) {
        Path resolved = Paths.get(baseDir, name);
    }

    void copyAttachment(File src, File dest) throws Exception {
        FileUtils.copyFile(src, dest);
    }
}

class ReportDao {
    Connection connection;

    void runSelect(String sql) throws Exception {
        Statement selectStmt = connection.createStatement();
        selectStmt.executeQuery(sql);
    }

    void runUpdate(String sql) throws Exception {
        Statement updateStmt = connection.createStatement();
        updateStmt.executeUpdate(sql);
    }
}

class Shell {
    void runCommand(String cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.start();
    }

    void runRuntime(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
"""

C_SOURCE = """\
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sqlite3.h>

void read_config(const char *path) {
    FILE *f = fopen(path, "r");
    fclose(f);
}

int open_upload(const char *path) {
    int fd = open(path, O_RDONLY);
    return fd;
}

int check_access(const char *path) {
    return access(path, R_OK);
}

int check_stat(const char *path, struct stat *out) {
    return stat(path, out);
}

void run_query(sqlite3 *db, const char *sql) {
    sqlite3_exec(db, sql, NULL, NULL, NULL);
}

void run_command(const char *cmd) {
    system(cmd);
}

void run_pipe(const char *cmd) {
    FILE *p = popen(cmd, "r");
    pclose(p);
}

void run_execve(char *path, char *const argv[], char *const envp[]) {
    execve(path, argv, envp);
}
"""

CPP_SOURCE = """\
#include <fstream>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sqlite3.h>

class ConfigReader {
public:
    FILE* openLegacy(const char* path) {
        return fopen(path, "r");
    }

    void readStreamCtor(const std::string& path) {
        std::ifstream input(path);
    }

    void readConfig(const std::string& path) {
        std::ifstream in;
        in.open(path);
    }

    int openUpload(const char* path) {
        return open(path, O_RDONLY);
    }

    int checkAccess(const char* path) {
        return access(path, R_OK);
    }

    int checkStat(const char* path, struct stat* out) {
        return stat(path, out);
    }
};

void runQuery(sqlite3* db, const char* sql) {
    sqlite3_exec(db, sql, NULL, NULL, NULL);
}

void runCommand(const char* cmd) {
    system(cmd);
}

void runPipe(const char* cmd) {
    FILE* p = popen(cmd, "r");
    pclose(p);
}

void runExecve(char* path, char* const argv[], char* const envp[]) {
    execve(path, argv, envp);
}
"""

PYTHON_SOURCE = """\
import os
import subprocess
from pathlib import Path


def read_upload(filename):
    target = os.path.join(UPLOAD_DIR, filename)
    return open(target, "rb")


def resolve_path(name):
    return Path(BASE_DIR) / name


def run_generic(conn, sql):
    cur = conn.cursor()
    cur.execute(sql)


def run_shell(cmd):
    os.system(cmd)


def run_subprocess(cmd):
    subprocess.run(cmd, shell=True)


def run_popen(cmd):
    subprocess.Popen(cmd, shell=True)


def run_call(cmd):
    subprocess.call(cmd, shell=True)


def run_check_output(cmd):
    return subprocess.check_output(cmd, shell=True)


def run_check_call(cmd):
    return subprocess.check_call(cmd, shell=True)


def run_getoutput(cmd):
    return subprocess.getoutput(cmd)


def run_getstatusoutput(cmd):
    return subprocess.getstatusoutput(cmd)
"""

JAVASCRIPT_SOURCE = """\
const fs = require("fs");
const path = require("path");
const child_process = require("node:child_process");

function readUpload(filename) {
  const full = path.join(UPLOAD_DIR, filename);
  fs.readFile(full, (err, data) => {
    console.log(data);
  });
}

function writeReport(name, body) {
  fs.writeFileSync(name, body);
}

function runSelect(pool, name) {
  pool.query("SELECT * FROM users WHERE name = ?", [name]);
}

function runPrepared(client, sql, params) {
  client.execute(sql, params);
}

function runLegacyExec(cmd) {
  child_process.exec(cmd);
}

function runSpawn(cmd, args) {
  child_process.spawn(cmd, args);
}
"""

TYPESCRIPT_SOURCE = """\
import * as fs from "fs";
import * as path from "path";
import * as child_process from "node:child_process";

function readUpload(filename: string): void {
  const full: string = path.join(UPLOAD_DIR, filename);
  fs.readFile(full, (err, data) => {
    console.log(data);
  });
}

function writeReport(name: string, body: string): void {
  fs.writeFileSync(name, body);
}

function runSelect(pool: Pool, name: string): void {
  pool.query("SELECT * FROM users WHERE name = ?", [name]);
}

function runPrepared(client: Client, sql: string, params: unknown[]): void {
  client.execute(sql, params);
}

function runLegacyExec(cmd: string): void {
  child_process.exec(cmd);
}

function runSpawn(cmd: string, args: string[]): void {
  child_process.spawn(cmd, args);
}
"""

GO_SOURCE = """\
package main

import (
	"database/sql"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
)

func openUpload(name string) (*os.File, error) {
	return os.Open(name)
}

func createReport(name string) (*os.File, error) {
	return os.Create(name)
}

func joinPath(base, name string) string {
	return filepath.Join(base, name)
}

func readAllLegacy(name string) ([]byte, error) {
	return ioutil.ReadFile(name)
}

func readAllModern(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func runQueryRow(db *sql.DB, id int) *sql.Row {
	return db.QueryRow("SELECT * FROM users WHERE id = ?", id)
}

func runExec(db *sql.DB, name string) (sql.Result, error) {
	return db.Exec("DELETE FROM users WHERE name = ?", name)
}

func runCommand(cmd string, args []string) error {
	command := exec.Command(cmd, args...)
	return command.Run()
}

func startProcess(path string, argv []string) (*os.Process, error) {
	return os.StartProcess(path, argv, &os.ProcAttr{})
}
"""

RUBY_SOURCE = """\
require "fileutils"

class ReportController
  def read_upload(filename)
    File.open(File.join(upload_dir, filename))
  end

  def read_whole(filename)
    File.read(filename)
  end

  def read_io(filename)
    IO.read(filename)
  end

  def copy_attachment(src, dest)
    FileUtils.cp(src, dest)
  end

  def run_select(conn, sql)
    conn.execute(sql)
  end

  def run_system(cmd)
    system(cmd)
  end

  def run_exec(cmd)
    exec(cmd)
  end

  def run_open3(cmd)
    Open3.capture2(cmd)
  end

  def run_popen(cmd)
    IO.popen(cmd)
  end

  def run_remote(host)
    out = `ssh #{host} uptime`
    out
  end
end
"""

PHP_SOURCE = """\
<?php

class FileController {
    public function readUpload($filename) {
        $handle = fopen($filename, "r");
        fclose($handle);
    }

    public function readWhole($filename) {
        return file_get_contents($filename);
    }

    public function writeReport($filename, $body) {
        file_put_contents($filename, $body);
    }
}

// The classic output-buffered PHP view renderer: `include` of a path built
// from a caller-supplied view name is the canonical LFI shape, and it is what
// `file_inclusion` exists to see. All four inclusion constructs appear here in
// their own methods, because _detect_sinks records one hit per pattern per
// function (treesitter_index.py:1606).
class ViewRenderer {
    private $viewRoot = "resources/views";

    public function render(string $view, array $data): string {
        extract($data);
        ob_start();
        include $this->viewRoot . "/" . $view . ".php";
        return ob_get_clean();
    }

    public function renderOrFail(string $view): string {
        ob_start();
        require $this->viewRoot . "/" . $view . ".php";
        return ob_get_clean();
    }

    public function loadHelpers(string $helper): void {
        include_once $this->viewRoot . "/helpers/" . $helper . ".php";
    }

    public function loadConfig(string $name): void {
        require_once "config/" . $name . ".php";
    }
}

class ReportDao {
    public function runMysqli($mysqli, $sql) {
        return mysqli_query($mysqli, $sql);
    }

    public function runDirectQuery($pdo, $sql) {
        return $pdo->query($sql);
    }

    public function runPrepare($pdo, $sql) {
        return $pdo->prepare($sql);
    }
}

class Shell {
    public function runExec($cmd) {
        exec($cmd);
    }

    public function runSystem($cmd) {
        system($cmd);
    }

    public function runShellExec($cmd) {
        return shell_exec($cmd);
    }

    public function runPassthru($cmd) {
        passthru($cmd);
    }

    public function runProcOpen($cmd) {
        return proc_open($cmd, [], $pipes);
    }

    public function runPopen($cmd) {
        return popen($cmd, "r");
    }
}
"""

CSHARP_SOURCE = """\
using System;
using System.Data.SqlClient;
using System.Data.OleDb;
using System.Diagnostics;
using System.IO;
using Microsoft.EntityFrameworkCore;

namespace Vigil.Data
{
    public class UserRepository
    {
        private readonly string _root;

        public UserRepository(string root)
        {
            _root = root;
        }

        public string ReadProfile(string name)
        {
            string full = Path.Combine(_root, name);
            return File.ReadAllText(full);
        }

        public void WriteProfile(string name, string body)
        {
            File.WriteAllText(name, body);
        }

        public Stream OpenUpload(string name)
        {
            return File.OpenRead(name);
        }

        public string ReadStream(string name)
        {
            using (var reader = new StreamReader(name))
            {
                return reader.ReadToEnd();
            }
        }

        public void RunSqlCommand(SqlConnection conn, string sql)
        {
            var command = new SqlCommand(sql, conn);
            command.ExecuteReader();
        }

        public void RunOleDbCommand(OleDbConnection conn, string sql)
        {
            var legacy = new OleDbCommand(sql, conn);
            legacy.ExecuteNonQuery();
        }

        public object RunScalar(SqlCommand scalarCommand)
        {
            return scalarCommand.ExecuteScalar();
        }

        public void RunRawQuery(AppDbContext context, string sql)
        {
            context.Users.FromSqlRaw(sql);
        }

        public void RunRawNonQuery(AppDbContext context, string sql)
        {
            context.Database.ExecuteSqlRaw(sql);
        }

        public void RunProcess(string cmd)
        {
            Process.Start(cmd);
        }

        public void RunProcessInfo(string cmd)
        {
            var info = new ProcessStartInfo("cmd.exe", cmd);
            info.UseShellExecute = true;
        }
    }
}
"""

_SOURCES: dict[str, str] = {
    "java": JAVA_SOURCE,
    "c": C_SOURCE,
    "cpp": CPP_SOURCE,
    "python": PYTHON_SOURCE,
    "javascript": JAVASCRIPT_SOURCE,
    "typescript": TYPESCRIPT_SOURCE,
    "go": GO_SOURCE,
    "ruby": RUBY_SOURCE,
    "php": PHP_SOURCE,
    "csharp": CSHARP_SOURCE,
}

_PATHS: dict[str, str] = {
    "java": "ReportDao.java",
    "c": "file_ops.c",
    "cpp": "config_reader.cpp",
    "python": "uploads.py",
    "javascript": "uploads.js",
    "typescript": "uploads.ts",
    "go": "main.go",
    "ruby": "report_controller.rb",
    "php": "controller.php",
    "csharp": "UserRepository.cs",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RESULTS_CACHE: dict[str, dict] = {}


def _result(language: str) -> dict:
    """Index (and cache) the fixture for *language* through the real indexer."""
    if language not in _RESULTS_CACHE:
        source = _SOURCES[language]
        _RESULTS_CACHE[language] = index_file(
            _PATHS[language], language, source=source.encode("utf-8")
        )
    return _RESULTS_CACHE[language]


def _line_of(text: str, source: str) -> int:
    """Return the 1-based line carrying *text* (which must be unique)."""
    lines = source.splitlines()
    matches = [number for number, line in enumerate(lines, 1) if text in line]
    assert len(matches) == 1, f"{text!r} is not unique in fixture: lines {matches}"
    return matches[0]


def _sinks_at(result: dict, line: int, kind: str) -> list[dict]:
    return [
        sink
        for sink in result["security_sinks"]
        if sink["line"] == line and sink["kind"] == kind
    ]


# ---------------------------------------------------------------------------
# All LIVE patterns are exercised structurally, never via the streaming
# fallback -- confirm every fixture actually took the tree_sitter path.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("language", sorted(_SOURCES))
def test_every_fixture_indexes_on_the_structural_path(language: str) -> None:
    result = _result(language)
    assert result["analysis_mode"] == "tree_sitter", (
        f"{language} fixture fell back to {result['analysis_mode']!r} "
        f"(reason={result.get('degradation_reason')!r}); a syntax error anywhere "
        "demotes the whole file to the streaming scanner (treesitter_index.py:3874)"
    )


# ---------------------------------------------------------------------------
# The LIVE catalogue sweep: (family, language, pattern verbatim, needle,
# expected vuln_classes). ``expected_vuln_classes`` is ``None`` for every
# sql_exec case -- see the module docstring and the dedicated defect test
# below for why the emitted value is never asserted as correct.
# ---------------------------------------------------------------------------

CASES: list[tuple[str, str, str, str, list[str] | None]] = [
    # ---- file_path : java (treesitter_index.py:249-250) ----
    ("file_path", "java", r"\bnew\s+File\s*\(", "new File(uploadDir, filename)", ["path-traversal"]),
    ("file_path", "java", r"\bFileInputStream\s*\(", "new FileInputStream(target)", ["path-traversal"]),
    ("file_path", "java", r"\bFileOutputStream\s*\(", "new FileOutputStream(path)", ["path-traversal"]),
    ("file_path", "java", r"\bPaths\.get\s*\(", "Paths.get(baseDir, name)", ["path-traversal"]),
    ("file_path", "java", r"\bFileUtils\.copy", "FileUtils.copyFile(src, dest)", ["path-traversal"]),
    # ---- file_path : c (treesitter_index.py:251) ----
    ("file_path", "c", r"\bfopen\s*\(", 'fopen(path, "r")', ["path-traversal"]),
    ("file_path", "c", r"\bopen\s*\(", "open(path, O_RDONLY)", ["path-traversal"]),
    ("file_path", "c", r"\baccess\s*\(", "access(path, R_OK)", ["path-traversal"]),
    ("file_path", "c", r"\bstat\s*\(", "stat(path, out)", ["path-traversal"]),
    # ---- file_path : cpp (treesitter_index.py:252) ----
    ("file_path", "cpp", r"\bfopen\s*\(", 'return fopen(path, "r")', ["path-traversal"]),
    ("file_path", "cpp", r"\bopen\s*\(", "in.open(path)", ["path-traversal"]),
    ("file_path", "cpp", r"\baccess\s*\(", "access(path, R_OK)", ["path-traversal"]),
    ("file_path", "cpp", r"\bstat\s*\(", "stat(path, out)", ["path-traversal"]),
    ("file_path", "cpp", r"\b(?:std::)?(?:i|o|f)fstream\s+(?:[A-Za-z_]\w*)\s*[({]", "std::ifstream input(path)", ["path-traversal"]),
    # ---- file_path : python (treesitter_index.py:253) ----
    ("file_path", "python", r"\bopen\s*\(", 'open(target, "rb")', ["path-traversal"]),
    ("file_path", "python", r"\bos\.path\.join\s*\(", "os.path.join(UPLOAD_DIR, filename)", ["path-traversal"]),
    ("file_path", "python", r"\bPath\s*\(", "Path(BASE_DIR) / name", ["path-traversal"]),
    # ---- file_path : javascript (treesitter_index.py:254) ----
    ("file_path", "javascript", r"\bfs\.readFile\w*\s*\(", "fs.readFile(full, (err, data)", ["path-traversal"]),
    ("file_path", "javascript", r"\bfs\.writeFile\w*\s*\(", "fs.writeFileSync(name, body)", ["path-traversal"]),
    ("file_path", "javascript", r"\bpath\.join\s*\(", "path.join(UPLOAD_DIR, filename)", ["path-traversal"]),
    # ---- file_path : typescript (treesitter_index.py:255) ----
    ("file_path", "typescript", r"\bfs\.readFile\w*\s*\(", "fs.readFile(full, (err, data)", ["path-traversal"]),
    ("file_path", "typescript", r"\bfs\.writeFile\w*\s*\(", "fs.writeFileSync(name, body)", ["path-traversal"]),
    ("file_path", "typescript", r"\bpath\.join\s*\(", "path.join(UPLOAD_DIR, filename)", ["path-traversal"]),
    # ---- file_path : go (treesitter_index.py:256-257) ----
    ("file_path", "go", r"\bos\.Open\w*\s*\(", "return os.Open(name)", ["path-traversal"]),
    ("file_path", "go", r"\bos\.Create\s*\(", "return os.Create(name)", ["path-traversal"]),
    ("file_path", "go", r"\bfilepath\.Join\s*\(", "filepath.Join(base, name)", ["path-traversal"]),
    ("file_path", "go", r"\bioutil\.ReadFile\s*\(", "ioutil.ReadFile(name)", ["path-traversal"]),
    ("file_path", "go", r"\bos\.ReadFile\s*\(", "return os.ReadFile(name)", ["path-traversal"]),
    # ---- file_path : ruby (treesitter_index.py:258-259) ----
    ("file_path", "ruby", r"\bFile\.open\s*\(", "File.open(File.join(upload_dir, filename))", ["path-traversal"]),
    ("file_path", "ruby", r"\bFile\.read\s*\(", "File.read(filename)", ["path-traversal"]),
    ("file_path", "ruby", r"\bIO\.read\s*\(", "IO.read(filename)", ["path-traversal"]),
    ("file_path", "ruby", r"\bFileUtils\.\w+\s*\(", "FileUtils.cp(src, dest)", ["path-traversal"]),
    # ---- file_path : php (treesitter_index.py:260-261) ----
    ("file_path", "php", r"\bfopen\s*\(", 'fopen($filename, "r")', ["path-traversal"]),
    ("file_path", "php", r"\bfile_get_contents\s*\(", "file_get_contents($filename)", ["path-traversal"]),
    ("file_path", "php", r"\bfile_put_contents\s*\(", "file_put_contents($filename, $body)", ["path-traversal"]),
    # ---- file_path : csharp (treesitter_index.py:276-278) ----
    ("file_path", "csharp", r"\bFile\.ReadAllText\s*\(", "File.ReadAllText(full)", ["path-traversal"]),
    ("file_path", "csharp", r"\bFile\.WriteAllText\s*\(", "File.WriteAllText(name, body)", ["path-traversal"]),
    ("file_path", "csharp", r"\bFile\.Open\w*\s*\(", "File.OpenRead(name)", ["path-traversal"]),
    ("file_path", "csharp", r"\bnew\s+StreamReader\s*\(", "new StreamReader(name)", ["path-traversal"]),
    ("file_path", "csharp", r"\bPath\.Combine\s*\(", "Path.Combine(_root, name)", ["path-traversal"]),
    # ---- file_inclusion : php ----
    # Its own sink kind, carrying the canonical file-inclusion classes rather
    # than borrowing file_path's `path-traversal`. The four constructs are
    # independent, not redundant: `_` is a `\w` char, so `\binclude\b` cannot
    # match inside `include_once` (nor `\brequire\b` inside `require_once`).
    ("file_inclusion", "php", r"\binclude\b", 'include $this->viewRoot . "/" . $view', ["lfi", "rfi"]),
    ("file_inclusion", "php", r"\brequire\b", 'require $this->viewRoot . "/" . $view', ["lfi", "rfi"]),
    ("file_inclusion", "php", r"\binclude_once\b", 'include_once $this->viewRoot . "/helpers/"', ["lfi", "rfi"]),
    ("file_inclusion", "php", r"\brequire_once\b", 'require_once "config/"', ["lfi", "rfi"]),

    # ---- sql_exec : java (treesitter_index.py:268-269) ----
    ("sql_exec", "java", r"\bcreateStatement\s*\(", "selectStmt = connection.createStatement()", ["sqli"]),
    ("sql_exec", "java", r"\.executeQuery\s*\(", "selectStmt.executeQuery(sql)", ["sqli"]),
    ("sql_exec", "java", r"\.executeUpdate\s*\(", "updateStmt.executeUpdate(sql)", ["sqli"]),
    # ---- sql_exec : c / cpp (treesitter_index.py:270-271) ----
    ("sql_exec", "c", r"\bsqlite3_exec\s*\(", "sqlite3_exec(db, sql, NULL, NULL, NULL)", ["sqli"]),
    ("sql_exec", "cpp", r"\bsqlite3_exec\s*\(", "sqlite3_exec(db, sql, NULL, NULL, NULL)", ["sqli"]),
    # ---- sql_exec : python (treesitter_index.py:272) ----
    ("sql_exec", "python", r"\.execute\s*\(", "cur.execute(sql)", ["sqli"]),
    # ---- sql_exec : javascript / typescript (treesitter_index.py:273-274) ----
    ("sql_exec", "javascript", r"\.query\s*\(", 'pool.query("SELECT * FROM users WHERE name = ?", [name])', ["sqli"]),
    ("sql_exec", "javascript", r"\.execute\s*\(", "client.execute(sql, params)", ["sqli"]),
    ("sql_exec", "typescript", r"\.query\s*\(", 'pool.query("SELECT * FROM users WHERE name = ?", [name])', ["sqli"]),
    ("sql_exec", "typescript", r"\.execute\s*\(", "client.execute(sql, params)", ["sqli"]),
    # ---- sql_exec : go (treesitter_index.py:275) ----
    ("sql_exec", "go", r"\b\w+\.QueryRow\s*\(", 'db.QueryRow("SELECT * FROM users WHERE id = ?", id)', ["sqli"]),
    ("sql_exec", "go", r"\b\w+\.Exec\s*\(", 'db.Exec("DELETE FROM users WHERE name = ?", name)', ["sqli"]),
    # ---- sql_exec : ruby (treesitter_index.py:276-277) ----
    ("sql_exec", "ruby", r"\b\w+\.execute\s*\(", "conn.execute(sql)", ["sqli"]),
    # ---- sql_exec : php (treesitter_index.py:278-279) ----
    ("sql_exec", "php", r"\bmysqli_query\s*\(", "mysqli_query($mysqli, $sql)", ["sqli"]),
    ("sql_exec", "php", r"\$\w+->query\s*\(", "$pdo->query($sql)", ["sqli"]),
    ("sql_exec", "php", r"\$\w+->prepare\s*\(", "$pdo->prepare($sql)", ["sqli"]),
    # ---- sql_exec : csharp (treesitter_index.py:310-313) ----
    ("sql_exec", "csharp", r"\bnew\s+SqlCommand\s*\(", "new SqlCommand(sql, conn)", ["sqli"]),
    ("sql_exec", "csharp", r"\bnew\s+OleDbCommand\s*\(", "new OleDbCommand(sql, conn)", ["sqli"]),
    ("sql_exec", "csharp", r"\.ExecuteReader\s*\(", "command.ExecuteReader()", ["sqli"]),
    ("sql_exec", "csharp", r"\.ExecuteNonQuery\s*\(", "legacy.ExecuteNonQuery()", ["sqli"]),
    ("sql_exec", "csharp", r"\.ExecuteScalar\s*\(", "scalarCommand.ExecuteScalar()", ["sqli"]),
    ("sql_exec", "csharp", r"\bFromSqlRaw\s*\(", "context.Users.FromSqlRaw(sql)", ["sqli"]),
    ("sql_exec", "csharp", r"\bExecuteSqlRaw\s*\(", "context.Database.ExecuteSqlRaw(sql)", ["sqli"]),

    # ---- process_exec : java (treesitter_index.py:286) ----
    ("process_exec", "java", r"\bRuntime\.getRuntime\s*\(\s*\)\.exec\s*\(", "Runtime.getRuntime().exec(cmd)", ["injection"]),
    ("process_exec", "java", r"\bProcessBuilder\s*\(", "new ProcessBuilder(cmd)", ["injection"]),
    # ---- process_exec : c (treesitter_index.py:287) ----
    ("process_exec", "c", r"\bsystem\s*\(", "system(cmd)", ["injection"]),
    ("process_exec", "c", r"\bpopen\s*\(", 'popen(cmd, "r")', ["injection"]),
    ("process_exec", "c", r"\bexecve\s*\(", "execve(path, argv, envp)", ["injection"]),
    # ---- process_exec : cpp (treesitter_index.py:288) ----
    ("process_exec", "cpp", r"\bsystem\s*\(", "system(cmd)", ["injection"]),
    ("process_exec", "cpp", r"\bpopen\s*\(", 'popen(cmd, "r")', ["injection"]),
    ("process_exec", "cpp", r"\bexecve\s*\(", "execve(path, argv, envp)", ["injection"]),
    # ---- process_exec : python (treesitter_index.py:289-290) ----
    ("process_exec", "python", r"\bos\.system\s*\(", "os.system(cmd)", ["injection"]),
    ("process_exec", "python", r"\bsubprocess\.run\s*\(", "subprocess.run(cmd, shell=True)", ["injection"]),
    ("process_exec", "python", r"\bsubprocess\.Popen\s*\(", "subprocess.Popen(cmd, shell=True)", ["injection"]),
    ("process_exec", "python", r"\bsubprocess\.call\s*\(", "subprocess.call(cmd, shell=True)", ["injection"]),
    ("process_exec", "python", r"\bsubprocess\.check_output\s*\(", "subprocess.check_output(cmd, shell=True)", ["injection"]),
    ("process_exec", "python", r"\bsubprocess\.check_call\s*\(", "subprocess.check_call(cmd, shell=True)", ["injection"]),
    ("process_exec", "python", r"\bsubprocess\.getoutput\s*\(", "subprocess.getoutput(cmd)", ["injection"]),
    ("process_exec", "python", r"\bsubprocess\.getstatusoutput\s*\(", "subprocess.getstatusoutput(cmd)", ["injection"]),
    # ---- process_exec : javascript / typescript (treesitter_index.py:291-292) ----
    ("process_exec", "javascript", r"\bchild_process\.exec\s*\(", "child_process.exec(cmd)", ["injection"]),
    ("process_exec", "javascript", r"\bchild_process\.spawn\s*\(", "child_process.spawn(cmd, args)", ["injection"]),
    ("process_exec", "typescript", r"\bchild_process\.exec\s*\(", "child_process.exec(cmd)", ["injection"]),
    ("process_exec", "typescript", r"\bchild_process\.spawn\s*\(", "child_process.spawn(cmd, args)", ["injection"]),
    # ---- process_exec : go (treesitter_index.py:293) ----
    ("process_exec", "go", r"\bexec\.Command\s*\(", "exec.Command(cmd, args...)", ["injection"]),
    ("process_exec", "go", r"\bos\.StartProcess\s*\(", "os.StartProcess(path, argv, &os.ProcAttr{})", ["injection"]),
    # ---- process_exec : ruby (treesitter_index.py:294-295) ----
    ("process_exec", "ruby", r"\bsystem\s*\(", "    system(cmd)", ["injection"]),
    ("process_exec", "ruby", r"\bexec\s*\(", "    exec(cmd)", ["injection"]),
    ("process_exec", "ruby", r"\bOpen3\.\w+\s*\(", "Open3.capture2(cmd)", ["injection"]),
    ("process_exec", "ruby", r"\bIO\.popen\s*\(", "IO.popen(cmd)", ["injection"]),
    ("process_exec", "ruby", r"`[^`]*`", "`ssh #{host} uptime`", ["injection"]),
    # ---- process_exec : php (treesitter_index.py:296-297) ----
    ("process_exec", "php", r"\bexec\s*\(", "        exec($cmd);", ["injection"]),
    ("process_exec", "php", r"\bsystem\s*\(", "system($cmd)", ["injection"]),
    ("process_exec", "php", r"\bshell_exec\s*\(", "shell_exec($cmd)", ["injection"]),
    ("process_exec", "php", r"\bpassthru\s*\(", "passthru($cmd)", ["injection"]),
    ("process_exec", "php", r"\bproc_open\s*\(", "proc_open($cmd, [], $pipes)", ["injection"]),
    ("process_exec", "php", r"\bpopen\s*\(", 'popen($cmd, "r")', ["injection"]),
    # ---- process_exec : csharp (treesitter_index.py:340) ----
    ("process_exec", "csharp", r"\bProcess\.Start\s*\(", "Process.Start(cmd)", ["injection"]),
    ("process_exec", "csharp", r"\bnew\s+ProcessStartInfo\s*\(", 'new ProcessStartInfo("cmd.exe", cmd)', ["injection"]),
]


@pytest.mark.parametrize(
    ("family", "language", "pattern", "needle", "expected_classes"),
    CASES,
    ids=[f"{family}/{language}/{pattern}" for family, language, pattern, _, _ in CASES],
)
def test_live_pattern_fires_on_idiomatic_code(
    family: str, language: str, pattern: str, needle: str, expected_classes: list[str] | None
) -> None:
    result = _result(language)
    line = _line_of(needle, _SOURCES[language])
    sinks = _sinks_at(result, line, family)

    assert sinks, (
        f"{pattern!r} ({family}/{language}) produced no {family} sink at line {line} "
        f"({needle!r}) -- removed or renamed in _SINK_DEFINITIONS?"
    )
    if expected_classes is not None:
        assert all(sink["vuln_classes"] == expected_classes for sink in sinks)


# ---------------------------------------------------------------------------
# Canonical-class pins. Both of these were recorded as taxonomy defects by
# this audit and have since been corrected in the catalogue; the tests hold
# the corrected values so the old, non-canonical strings cannot come back.
# ---------------------------------------------------------------------------

def test_php_inclusion_is_its_own_kind_carrying_the_canonical_lfi_rfi_classes() -> None:
    """PHP file inclusion is `file_inclusion` -> ``["lfi", "rfi"]``.

    ``lfi`` and ``rfi`` are the canonical classes for file inclusion
    (vuln_taxonomy.py:92-93). Reusing ``file_path``/``path-traversal`` --
    which is what these four patterns used to emit -- understated an RFI as a
    traversal and routed the hunter to the wrong reference material.

    The separation is also asserted in the other direction: ``file_path``
    must keep the PHP constructs that genuinely are traversal, so this cannot
    be "fixed" by moving the whole PHP family across.
    """
    result = _result("php")

    for needle in (
        'include $this->viewRoot . "/" . $view',
        'require $this->viewRoot . "/" . $view',
        'include_once $this->viewRoot . "/helpers/"',
        'require_once "config/"',
    ):
        line = _line_of(needle, PHP_SOURCE)
        sink = _sinks_at(result, line, "file_inclusion")[0]
        assert sink["vuln_classes"] == ["lfi", "rfi"], needle
        assert not _sinks_at(result, line, "file_path"), (
            f"{needle!r} must no longer double-report as file_path"
        )

    assert is_valid_class("lfi") and is_valid_class("rfi")

    traversal_line = _line_of("file_get_contents($filename)", PHP_SOURCE)
    assert _sinks_at(result, traversal_line, "file_path"), (
        "file_path must keep the PHP constructs that really are traversal"
    )


def test_sql_exec_emits_the_canonical_sqli_class() -> None:
    """treesitter_index.py:266 emits ``vuln_classes=["sqli"]``.

    ``sqli`` is the canonical class for SQL injection (vuln_taxonomy.py:73).
    This pins the corrected value and guards against a regression back to the
    non-canonical ``"sql-injection"`` string this line used to emit.
    """
    result = _result("python")
    line = _line_of("cur.execute(sql)", PYTHON_SOURCE)
    sink = _sinks_at(result, line, "sql_exec")[0]

    assert sink["vuln_classes"] == ["sqli"]
    assert is_valid_class("sqli")
    assert not is_valid_class("sql-injection")


# ---------------------------------------------------------------------------
# Meta-test: the case table above, plus this allow-list, must account for
# every one of the 107 patterns in the four assigned families. This is what
# stops the catalogue drifting back to silent zero recall -- add a pattern
# to _SINK_DEFINITIONS without touching this file and the test below fails.
# ---------------------------------------------------------------------------

_IN_SCOPE_FAMILIES = {"file_path", "file_inclusion", "sql_exec", "process_exec"}

# (family, language, pattern verbatim) -> why it is NOT in CASES above.
# Every entry was verified empirically (see the agent's report); none of
# these is "maybe" -- each was driven through the real indexer with an
# idiomatic fixture attempting to trigger it correctly, and either could
# not be made to fire on realistic code, or fires but is provably covered
# by (or worse than) another pattern in the same family.
_EXCLUDED: dict[tuple[str, str, str], str] = {
    # NOTE: the four PHP inclusion constructs used to live here as MISROUTED
    # (`file_path` -> `path-traversal`). They now have their own
    # `file_inclusion` sink kind carrying `["lfi", "rfi"]`, so they are LIVE
    # and correctly classed, and have real cases in CASES above instead.

    # --- sql_exec / java: fires, but the dominant realistic match is a
    # false positive. Verified: `pool.execute(job)` on a
    # java.util.concurrent.ExecutorService (JDK stdlib, ubiquitous in any
    # concurrent Java code) produces a sql_exec/sql-injection sink with
    # nothing SQL-related on the line. executeQuery/executeUpdate already
    # cover the precise JDBC cases.
    ("sql_exec", "java", r"\.execute\s*\("):
        "misrouted: false positive verified on ExecutorService.execute(Runnable) (JDK stdlib, java.util.concurrent)",

    # --- sql_exec / go: fires, but collides with the single most common
    # line shape in any Go HTTP handler. Verified: `r.URL.Query().Get("name")`
    # (net/http stdlib -- reading a query-string parameter) produces a
    # sql_exec/sql-injection sink with zero SQL involved. QueryRow/Exec are
    # unaffected (verified) and remain the precise patterns for this family.
    ("sql_exec", "go", r"\b\w+\.Query\s*\("):
        "misrouted: false positive verified on r.URL.Query() (net/http stdlib) -- fires in nearly every Go HTTP handler",

    # --- sql_exec / ruby: requires the literal receiver "ActiveRecord",
    # which no idiomatic Rails code writes. Verified: `User.find_by_sql(...)`
    # (the actual idiom -- called on the model subclass) does NOT match;
    # only the never-written `ActiveRecord::Base.find_by_sql(...)` does.
    ("sql_exec", "ruby", r"\bActiveRecord.*\.find_by_sql\s*\("):
        "dead: requires literal 'ActiveRecord' receiver; real code calls find_by_sql on the model subclass (User.find_by_sql), never on ActiveRecord::Base directly",

    # --- sql_exec / ruby: requires the standalone word "raw" (word-bounded,
    # so "raw_sql"/"rawValue" never match -- underscore and case are both
    # \w). Verified: `User.where("name = '#{name}'")` (the real vulnerable
    # idiom, string interpolation) does not match; only a variable literally
    # named `raw` does, which is not an established Rails idiom.
    ("sql_exec", "ruby", r"\b\w+\.where\s*\(.*\braw\b"):
        "dead: requires a variable/method literally named 'raw' (word-bounded); the real vulnerable idiom (string interpolation in .where(...)) has no 'raw' token and is not caught",

    # --- sql_exec / php: PDO::query() is an instance method; the pattern
    # requires the static call form PDO::query(...), which is invalid PHP
    # (fatal error calling a non-static method statically since PHP 8).
    # Verified mechanically matches the literal text, but no valid PHP
    # program can contain it.
    ("sql_exec", "php", r"\bPDO::query\s*\("):
        "dead: PDO::query() is an instance-only method; PDO::query(...) as a static call is invalid PHP (fatal error since PHP 8)",

    # --- sql_exec / python: redundant. Verified: `cur.execute(sql)`
    # produces TWO sql_exec rows on the same line when the receiver is named
    # "cursor" (cursor.execute + generic .execute both fire); every string
    # \bcursor\.execute\s*\( can match, \.execute\s*\( also matches (it is
    # a strict textual superset), so \.execute\s*\( already covers every
    # case this pattern covers.
    ("sql_exec", "python", r"\bcursor\.execute\s*\("):
        "redundant: any cursor.execute(...) call also matches the generic \\.execute\\s*\\( pattern in the same family (verified both fire on the same line)",

}


def test_case_table_covers_every_live_pattern_in_the_assigned_slice() -> None:
    tested = {(family, language, pattern) for family, language, pattern, _, _ in CASES}
    excluded = set(_EXCLUDED)

    all_patterns: set[tuple[str, str, str]] = set()
    for sink_def in treesitter_index._SINK_DEFINITIONS:
        if sink_def["kind"] not in _IN_SCOPE_FAMILIES:
            continue
        for language, patterns in sink_def["patterns"].items():
            for pattern in patterns:
                all_patterns.add((sink_def["kind"], language, pattern))

    assert tested.isdisjoint(excluded), tested & excluded
    assert tested | excluded == all_patterns, (
        f"catalogue drift: in catalogue but neither tested nor excluded: "
        f"{all_patterns - tested - excluded}; "
        f"tested/excluded but no longer in catalogue: "
        f"{(tested | excluded) - all_patterns}"
    )

    # Hard counts. The slice is now 108 patterns. C# was added as a
    # tree-sitter language, contributing 14 new patterns to this slice
    # (5 file_path, 7 sql_exec, 2 process_exec), all of which fire LIVE on
    # idiomatic C# -- so the case table gains 14 rows and _EXCLUDED gains
    # nothing. PHP's four inclusion constructs still account for the
    # file_path (34) / file_inclusion (4) split described above.
    # file_path=39, file_inclusion=4, sql_exec=29, process_exec=35 -> 107.
    assert len(all_patterns) == 108
    assert len(tested) == 102
    assert len(excluded) == 6


def test_case_table_has_no_duplicate_rows() -> None:
    keys = [(family, language, pattern) for family, language, pattern, _, _ in CASES]
    assert len(keys) == len(set(keys)), "duplicate (family, language, pattern) row in CASES"
