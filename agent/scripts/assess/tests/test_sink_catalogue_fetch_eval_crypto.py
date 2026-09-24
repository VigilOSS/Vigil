"""Empirical catalogue audit: `url_fetch`, `deserialization`, `eval_exec`, `crypto`.

Scope is exactly these four `_SINK_DEFINITIONS` families in
`assess.lib.treesitter_index` (107 patterns total: 33 `url_fetch`, 20
`deserialization`, 23 `eval_exec`, 31 `crypto`). Every pattern was probed with
an idiomatic, current-era (2026) fixture through the real structural indexer.
Only the patterns that actually fire on idiomatic code get a test here; the
rest (`DEAD` / `OBSOLETE` / `MISROUTED`) are recorded in the exclusion
allow-list on the meta-test at the bottom, each with the empirical reason.

Each fixture below is deliberately minimal and was chosen so that the target
line matches exactly one pattern in its family -- so a case here fails if (and
only if) its specific pattern is removed or broken, not because some other
pattern in the family happens to cover the same line.
"""
from __future__ import annotations

import re
from functools import lru_cache

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _line_of(source: str, needle: str) -> int:
    """Return the 1-based line carrying *needle* (which must be unique)."""
    lines = source.splitlines()
    matches = [number for number, line in enumerate(lines, 1) if needle in line]
    assert len(matches) == 1, f"{needle!r} is not unique in fixture: {matches}"
    return matches[0]


@lru_cache(maxsize=None)
def _index_fixture(family: str, language: str) -> dict:
    file_name, source = FIXTURES[(family, language)]
    return index_file(file_name, language, source=source.encode("utf-8"))


def _sinks_at(result: dict, kind: str, line: int) -> list[dict]:
    return [
        sink
        for sink in result["security_sinks"]
        if sink["kind"] == kind and sink["line"] == line
    ]


# Every pattern in these four families maps to exactly these vuln_classes
# (agent/scripts/assess/lib/treesitter_index.py:301-364).
EXPECTED_VULN_CLASSES = {
    "url_fetch": ["ssrf"],
    "deserialization": ["deserialization"],
    "eval_exec": ["injection"],
    "crypto": ["crypto-misuse"],
}


# ---------------------------------------------------------------------------
# Fixtures -- one idiomatic 2026-era source per (family, language).
#
# Each was run through the real indexer via the probe harness before being
# pinned here; every one indexes as analysis_mode == "tree_sitter" with no
# tree-sitter has_error demotion.
# ---------------------------------------------------------------------------

# ---- url_fetch (33 patterns; LIVE: java x2, python x9, js x3, ts x3, go x4,
#      ruby x3, php x3, csharp x4 = 31) ---------------------------------------

_JAVA_URL_FETCH = """
import java.net.URL;
import java.net.HttpURLConnection;

public class Fetcher {
    public String fetchOld(String target) throws Exception {
        URL url = new URL(target);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        return conn.getResponseCode() + "";
    }
}
"""

_PYTHON_URL_FETCH = """
import requests
import urllib.request

def fetch_a(url):
    return requests.get(url, timeout=5).json()

def fetch_post(url):
    return requests.post(url, json={"probe": True})

def fetch_put(url):
    return requests.put(url, data=b"probe")

def fetch_patch(url):
    return requests.patch(url, json={"enabled": True})

def fetch_delete(url):
    return requests.delete(url)

def fetch_head(url):
    return requests.head(url)

def fetch_options(url):
    return requests.options(url)

def fetch_request(url):
    return requests.request("TRACE", url)

def fetch_b(url):
    with urllib.request.urlopen(url) as resp:
        return resp.read()
"""

_JS_URL_FETCH = """
const axios = require("axios");
const http = require("http");

async function fetchA(url) {
  const res = await fetch(url);
  return res.json();
}

function fetchB(target, cb) {
  http.request(target, cb).end();
}

async function fetchC(url) {
  const res = await axios.get(url);
  return res.data;
}
"""

_TS_URL_FETCH = """
import axios from "axios";
import http from "http";

async function fetchA(url: string): Promise<any> {
  const res = await fetch(url);
  return res.json();
}

function fetchB(target: string, cb: () => void): void {
  http.request(target, cb).end();
}

async function fetchC(url: string): Promise<any> {
  const res = await axios.get(url);
  return res.data;
}
"""

_GO_URL_FETCH = """
package main

import "net/http"

func fetchA(url string) {
	http.Get(url)
}

func fetchB(url string) {
	http.Post(url, "application/json", nil)
}

func fetchC(url string) {
	req, _ := http.NewRequest("GET", url, nil)
	http.DefaultClient.Do(req)
}
"""

_RUBY_URL_FETCH = """
require "net/http"
require "httparty"

def fetch_a(url)
  Net::HTTP.get(URI(url))
end

def fetch_b(url)
  HTTParty.get(url)
end

def fetch_c(url)
  URI.open(url).read
end
"""

# PHP `file_get_contents(.*http` / `fopen(.*http` require the literal text
# "http" on the same source line -- true for a hardcoded base URL (below),
# false for the far more common `file_get_contents($url)` where the scheme
# lives only inside the variable (see coverage-gap note in the final report).
_PHP_URL_FETCH = """<?php
function fetchA($url) {
    $ch = curl_init($url);
    return curl_exec($ch);
}

function fetchBHttp($target) {
    return file_get_contents("http://" . $target);
}

function fetchCHttp($target) {
    return fopen("http://" . $target, "r");
}
"""

_CSHARP_URL_FETCH = """
using System;
using System.Net;
using System.Net.Http;

namespace Probe
{
    public class Fetcher
    {
        public void FetchWithHttpClient(string url)
        {
            var client = new HttpClient();
            client.GetStringAsync(url);
        }

        public void FetchWithWebRequest(string url)
        {
            var req = WebRequest.Create(url);
            req.GetResponse();
        }

        public void FetchWithWebClient(string url)
        {
            var wc = new WebClient();
            wc.DownloadString(url);
        }

        public void FetchWithHttpWebRequest(string url)
        {
            HttpWebRequest hwr = WebRequest.CreateHttp(url);
            hwr.GetResponse();
        }
    }
}
"""

# ---- deserialization (20 patterns; LIVE: java x3, python x3, go x2,
#      ruby x2, php x1, csharp x6 = 17) ----------------------------------------

_JAVA_DESER = """
import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.beans.XMLDecoder;

public class Deser {
    public Object load(String path) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(path))) {
            return in.readObject();
        }
    }

    public Object loadXml(java.io.InputStream is) {
        XMLDecoder decoder = new XMLDecoder(is);
        return decoder.readObject();
    }
}
"""

_PYTHON_DESER = """
import pickle
import yaml
import marshal

def load_pickle(data):
    return pickle.loads(data)

def load_yaml(data):
    return yaml.load(data)

def load_marshal(data):
    return marshal.loads(data)
"""

_GO_DESER = """
package main

import (
	"encoding/gob"
	"encoding/xml"
)

func loadGob(r *bytesReader, v interface{}) error {
	dec := gob.NewDecoder(r)
	return dec.Decode(v)
}

func loadXML(data []byte, v interface{}) error {
	return xml.Unmarshal(data, v)
}
"""

_RUBY_DESER = """
def load_marshal(data)
  Marshal.load(data)
end

def load_yaml(data)
  YAML.load(data)
end
"""

_PHP_DESER = """<?php
function loadSerialized($data) {
    return unserialize($data);
}
"""

_CSHARP_DESER = """
using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Web.Script.Serialization;
using System.Web.UI;
using System.Xml.Serialization;
using Newtonsoft.Json;

namespace Probe
{
    public class Deserializer
    {
        public object LoadBinary(Stream stream)
        {
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);
        }

        public object LoadJavaScript(string json)
        {
            var serializer = new JavaScriptSerializer();
            return serializer.DeserializeObject(json);
        }

        public object LoadNetDataContract(Stream stream)
        {
            var contract = new NetDataContractSerializer();
            return contract.ReadObject(stream);
        }

        public object LoadViewState(string data)
        {
            var formatter = new LosFormatter();
            return formatter.Deserialize(data);
        }

        public T LoadTyped<T>(string json)
        {
            var settings = new JsonSerializerSettings();
            settings.TypeNameHandling = TypeNameHandling.All;
            return JsonConvert.DeserializeObject<T>(json, settings);
        }

        public object LoadXml(Stream stream)
        {
            var xml = new XmlSerializer(typeof(object));
            return xml.Deserialize(stream);
        }
    }
}
"""

# ---- eval_exec (23 patterns; LIVE: python x2, js x3, ts x3, ruby x5,
#      php x1, csharp x4 = 18) ------------------------------------------------

_PYTHON_EVAL = """
def run_eval(expr, ctx):
    return eval(expr, ctx)

def run_exec(code, ctx):
    exec(code, ctx)
"""

_JS_EVAL = """
function runEval(code) {
  return eval(code);
}

function makeFn(body) {
  return new Function("x", body);
}

function scheduleLiteral() {
  setTimeout("doWork()", 100);
}
"""

_TS_EVAL = """
function runEval(code: string): unknown {
  return eval(code);
}

function makeFn(body: string): Function {
  return new Function("x", body);
}

function scheduleLiteral(): void {
  setTimeout("doWork()", 100);
}
"""

# Rails-idiomatic `send`/`public_send` (dynamic method dispatch) alongside
# raw `eval`/`instance_eval`/`class_eval` -- all five patterns fire on
# completely ordinary metaprogramming, with a high false-positive rate noted
# in the final report for send/public_send specifically.
_RUBY_EVAL = """
def run_eval(code)
  eval(code)
end

class Model
  def run_in_context(code)
    instance_eval(code)
  end

  def define_accessor(name)
    class_eval("def #{name}; @#{name}; end")
  end
end

class ApplicationController
  def process_action(action_name)
    send(action_name)
  end
end

class UserSerializer
  def as_json(attr)
    public_send(attr)
  end
end
"""

_PHP_EVAL = """<?php
function runEval($code) {
    eval($code);
}
"""

_CSHARP_EVAL = """
using System;
using System.Reflection;
using System.CodeDom.Compiler;
using Microsoft.CSharp;

namespace Probe
{
    public class Loader
    {
        public Assembly LoadFromBytes(byte[] raw)
        {
            var assembly = Assembly.Load(raw);
            return assembly;
        }

        public object Instantiate(Type type)
        {
            var instance = Activator.CreateInstance(type);
            return instance;
        }

        public Type Resolve(string typeName)
        {
            var resolved = Type.GetType(typeName);
            return resolved;
        }

        public void CompileSource(string code)
        {
            var provider = new CSharpCodeProvider();
            provider.CompileAssemblyFromSource(new CompilerParameters(), code);
        }
    }
}
"""

# ---- crypto (31 patterns; LIVE: java x2, c x2, cpp x2, python x0, js x2,
#      ts x2, go x2, ruby x2, php x3, csharp x6 = 23) --------------------------

_JAVA_CRYPTO = """
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
    public byte[] encrypt(byte[] key, byte[] data) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(data);
    }
}
"""

_C_CRYPTO = """
#include <openssl/evp.h>
#include <openssl/aes.h>

int encrypt_data(EVP_CIPHER_CTX *ctx, unsigned char *in, int inlen, unsigned char *out) {
    int outlen;
    EVP_CipherUpdate(ctx, out, &outlen, in, inlen);
    return outlen;
}

void legacy_encrypt(AES_KEY *key, const unsigned char *in, unsigned char *out) {
    AES_encrypt(in, out, key);
}
"""

_CPP_CRYPTO = """
#include <openssl/evp.h>
#include <openssl/aes.h>

class Encryptor {
public:
    int encryptData(EVP_CIPHER_CTX *ctx, unsigned char *in, int inlen, unsigned char *out) {
        int outlen = 0;
        EVP_CipherUpdate(ctx, out, &outlen, in, inlen);
        return outlen;
    }

    void encryptBlock(AES_KEY *key, const unsigned char *in, unsigned char *out) {
        AES_encrypt(in, out, key);
    }
};
"""

_JS_CRYPTO = """
const crypto = require("crypto");

function encryptModern(key, iv, data) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function hash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}
"""

_TS_CRYPTO = """
import crypto from "crypto";

function encryptModern(key: Buffer, iv: Buffer, data: Buffer): Buffer {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

function hash(data: Buffer): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}
"""

_GO_CRYPTO = """
package main

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/hmac"
)

func newCipher(key []byte) {
	aes.NewCipher(key)
}

func newHmac(key []byte) {
	hmac.New(sha256.New, key)
}
"""

_RUBY_CRYPTO = """
require "openssl"

def encrypt(key, iv, data)
  cipher = OpenSSL::Cipher.new("aes-256-gcm")
  cipher.encrypt
  cipher.key = key
  cipher.iv = iv
  cipher.update(data) + cipher.final
end

def hmac_it(key, data)
  OpenSSL::HMAC.hexdigest("SHA256", key, data)
end
"""

_PHP_CRYPTO = """<?php
function encryptData($key, $iv, $data) {
    return openssl_encrypt($data, "aes-256-gcm", $key, 0, $iv);
}

function legacyMd5($data) {
    return md5($data);
}

function legacySha1($data) {
    return sha1($data);
}
"""

_CSHARP_CRYPTO = """
using System;
using System.Security.Cryptography;

namespace Probe
{
    public class Cryptor
    {
        public byte[] HashWithMd5(byte[] data)
        {
            var hasher = MD5.Create();
            return hasher.ComputeHash(data);
        }

        public byte[] HashWithSha1(byte[] data)
        {
            var digest = SHA1.Create();
            return digest.ComputeHash(data);
        }

        public void EncryptWithDes()
        {
            var provider = new DESCryptoServiceProvider();
            provider.GenerateKey();
        }

        public void EncryptWithTripleDes()
        {
            var triple = TripleDES.Create();
            triple.GenerateKey();
        }

        public void EncryptWithRijndael()
        {
            var rijndael = new RijndaelManaged();
            rijndael.GenerateKey();
        }

        public int WeakToken()
        {
            var random = new Random();
            return random.Next();
        }
    }
}
"""


FIXTURES: dict[tuple[str, str], tuple[str, str]] = {
    ("url_fetch", "java"): ("Fetcher.java", _JAVA_URL_FETCH),
    ("url_fetch", "python"): ("fetcher.py", _PYTHON_URL_FETCH),
    ("url_fetch", "javascript"): ("fetcher.js", _JS_URL_FETCH),
    ("url_fetch", "typescript"): ("fetcher.ts", _TS_URL_FETCH),
    ("url_fetch", "go"): ("fetcher.go", _GO_URL_FETCH),
    ("url_fetch", "ruby"): ("fetcher.rb", _RUBY_URL_FETCH),
    ("url_fetch", "php"): ("fetcher.php", _PHP_URL_FETCH),
    ("url_fetch", "csharp"): ("Fetcher.cs", _CSHARP_URL_FETCH),
    ("deserialization", "java"): ("Deser.java", _JAVA_DESER),
    ("deserialization", "python"): ("deser.py", _PYTHON_DESER),
    ("deserialization", "go"): ("deser.go", _GO_DESER),
    ("deserialization", "ruby"): ("deser.rb", _RUBY_DESER),
    ("deserialization", "php"): ("deser.php", _PHP_DESER),
    ("deserialization", "csharp"): ("Deserializer.cs", _CSHARP_DESER),
    ("eval_exec", "python"): ("evalpy.py", _PYTHON_EVAL),
    ("eval_exec", "javascript"): ("evaljs.js", _JS_EVAL),
    ("eval_exec", "typescript"): ("evalts.ts", _TS_EVAL),
    ("eval_exec", "ruby"): ("evalrb.rb", _RUBY_EVAL),
    ("eval_exec", "php"): ("evalphp.php", _PHP_EVAL),
    ("eval_exec", "csharp"): ("Loader.cs", _CSHARP_EVAL),
    ("crypto", "java"): ("Crypto.java", _JAVA_CRYPTO),
    ("crypto", "c"): ("crypto.c", _C_CRYPTO),
    ("crypto", "cpp"): ("crypto.cpp", _CPP_CRYPTO),
    ("crypto", "javascript"): ("crypto.js", _JS_CRYPTO),
    ("crypto", "typescript"): ("crypto.ts", _TS_CRYPTO),
    ("crypto", "go"): ("crypto.go", _GO_CRYPTO),
    ("crypto", "ruby"): ("crypto.rb", _RUBY_CRYPTO),
    ("crypto", "php"): ("crypto.php", _PHP_CRYPTO),
    ("crypto", "csharp"): ("Cryptor.cs", _CSHARP_CRYPTO),
}


# ---------------------------------------------------------------------------
# Case table: (family, language, pattern verbatim, needle that locates the
# line in its fixture). One row per LIVE pattern -- 89 total.
# ---------------------------------------------------------------------------

CASES: list[tuple[str, str, str, str]] = [
    # -- url_fetch: java (2) --
    ("url_fetch", "java", r"\bnew\s+URL\s*\(", "URL url = new URL(target);"),
    ("url_fetch", "java", r"\bHttpURLConnection\b", "HttpURLConnection conn ="),
    # -- url_fetch: python (9) --
    ("url_fetch", "python", r"\brequests\.get\s*\(", "requests.get(url, timeout=5)"),
    ("url_fetch", "python", r"\brequests\.post\s*\(", "requests.post(url, json="),
    ("url_fetch", "python", r"\brequests\.put\s*\(", "requests.put(url, data="),
    ("url_fetch", "python", r"\brequests\.patch\s*\(", "requests.patch(url, json="),
    ("url_fetch", "python", r"\brequests\.delete\s*\(", "requests.delete(url)"),
    ("url_fetch", "python", r"\brequests\.head\s*\(", "requests.head(url)"),
    ("url_fetch", "python", r"\brequests\.options\s*\(", "requests.options(url)"),
    ("url_fetch", "python", r"\brequests\.request\s*\(", 'requests.request("TRACE", url)'),
    ("url_fetch", "python", r"\burllib\.request\.urlopen\s*\(", "urllib.request.urlopen(url)"),
    # -- url_fetch: javascript (3) --
    ("url_fetch", "javascript", r"\bfetch\s*\(", "const res = await fetch(url);"),
    ("url_fetch", "javascript", r"\bhttp\.request\s*\(", "http.request(target, cb).end();"),
    ("url_fetch", "javascript", r"\baxios\.", "const res = await axios.get(url);"),
    # -- url_fetch: typescript (3) --
    ("url_fetch", "typescript", r"\bfetch\s*\(", "const res = await fetch(url);"),
    ("url_fetch", "typescript", r"\bhttp\.request\s*\(", "http.request(target, cb).end();"),
    ("url_fetch", "typescript", r"\baxios\.", "const res = await axios.get(url);"),
    # -- url_fetch: go (4) --
    ("url_fetch", "go", r"\bhttp\.Get\s*\(", "http.Get(url)"),
    ("url_fetch", "go", r"\bhttp\.Post\s*\(", "http.Post(url,"),
    ("url_fetch", "go", r"\bhttp\.NewRequest\s*\(", "http.NewRequest("),
    ("url_fetch", "go", r"\bhttp\.DefaultClient\.Do\s*\(", "http.DefaultClient.Do(req)"),
    # -- url_fetch: ruby (3) --
    ("url_fetch", "ruby", r"\bNet::HTTP\.\w+\s*\(", "Net::HTTP.get(URI(url))"),
    ("url_fetch", "ruby", r"\bHTTParty\.\w+\s*\(", "HTTParty.get(url)"),
    ("url_fetch", "ruby", r"\bURI\.open\s*\(", "URI.open(url).read"),
    # -- url_fetch: php (3) --
    ("url_fetch", "php", r"\bcurl_exec\s*\(", "curl_exec($ch)"),
    ("url_fetch", "php", r"\bfile_get_contents\s*\(.*http", 'file_get_contents("http://" . $target)'),
    ("url_fetch", "php", r"\bfopen\s*\(.*http", 'fopen("http://" . $target, "r")'),
    # -- url_fetch: csharp (4) --
    ("url_fetch", "csharp", r"\bnew\s+HttpClient\s*\(", "var client = new HttpClient();"),
    ("url_fetch", "csharp", r"\bWebRequest\.Create\s*\(", "var req = WebRequest.Create(url);"),
    ("url_fetch", "csharp", r"\bnew\s+WebClient\s*\(", "var wc = new WebClient();"),
    ("url_fetch", "csharp", r"\bHttpWebRequest\b", "HttpWebRequest hwr = WebRequest.CreateHttp(url);"),

    # -- deserialization: java (3) --
    ("deserialization", "java", r"\bObjectInputStream\b", "ObjectInputStream in = new ObjectInputStream"),
    ("deserialization", "java", r"\breadObject\s*\(", "return in.readObject();"),
    ("deserialization", "java", r"\bXMLDecoder\b", "XMLDecoder decoder = new XMLDecoder(is);"),
    # -- deserialization: python (3) --
    ("deserialization", "python", r"\bpickle\.loads?\s*\(", "pickle.loads(data)"),
    ("deserialization", "python", r"\byaml\.load\s*\(", "yaml.load(data)"),
    ("deserialization", "python", r"\bmarshal\.loads?\s*\(", "marshal.loads(data)"),
    # -- deserialization: go (2, json.Unmarshal excluded as MISROUTED) --
    ("deserialization", "go", r"\bgob\.NewDecoder\s*\(", "dec := gob.NewDecoder(r)"),
    ("deserialization", "go", r"\bxml\.Unmarshal\s*\(", "return xml.Unmarshal(data, v)"),
    # -- deserialization: ruby (2, JSON.parse excluded as MISROUTED) --
    ("deserialization", "ruby", r"\bMarshal\.load\s*\(", "Marshal.load(data)"),
    ("deserialization", "ruby", r"\bYAML\.load\s*\(", "YAML.load(data)"),
    # -- deserialization: php (1, json_decode excluded as MISROUTED) --
    ("deserialization", "php", r"\bunserialize\s*\(", "unserialize($data)"),
    # -- deserialization: csharp (6) --
    ("deserialization", "csharp", r"\bBinaryFormatter\b", "var formatter = new BinaryFormatter();"),
    ("deserialization", "csharp", r"\bJavaScriptSerializer\b", "var serializer = new JavaScriptSerializer();"),
    ("deserialization", "csharp", r"\bNetDataContractSerializer\b", "var contract = new NetDataContractSerializer();"),
    ("deserialization", "csharp", r"\bLosFormatter\b", "var formatter = new LosFormatter();"),
    ("deserialization", "csharp", r"\bTypeNameHandling\b", "settings.TypeNameHandling = TypeNameHandling.All;"),
    ("deserialization", "csharp", r"\bnew\s+XmlSerializer\s*\(", "var xml = new XmlSerializer(typeof(object));"),

    # -- eval_exec: python (2, compile excluded as MISROUTED) --
    ("eval_exec", "python", r"\beval\s*\(", "return eval(expr, ctx)"),
    ("eval_exec", "python", r"\bexec\s*\(", "    exec(code, ctx)"),
    # -- eval_exec: javascript (3) --
    ("eval_exec", "javascript", r"\beval\s*\(", "return eval(code);"),
    ("eval_exec", "javascript", r"\bFunction\s*\(", 'return new Function("x", body);'),
    ("eval_exec", "javascript", r"""\bset(?:Timeout|Interval)\s*\(\s*["'`]""", 'setTimeout("doWork()", 100);'),
    # -- eval_exec: typescript (3) --
    ("eval_exec", "typescript", r"\beval\s*\(", "return eval(code);"),
    ("eval_exec", "typescript", r"\bFunction\s*\(", 'return new Function("x", body);'),
    ("eval_exec", "typescript", r"""\bset(?:Timeout|Interval)\s*\(\s*["'`]""", 'setTimeout("doWork()", 100);'),
    # -- eval_exec: ruby (5) --
    ("eval_exec", "ruby", r"\beval\s*\(", "  eval(code)"),
    ("eval_exec", "ruby", r"\binstance_eval\s*\(", "instance_eval(code)"),
    ("eval_exec", "ruby", r"\bclass_eval\s*\(", 'class_eval("def #{name}; @#{name}; end")'),
    ("eval_exec", "ruby", r"\bsend\s*\(", "send(action_name)"),
    ("eval_exec", "ruby", r"\bpublic_send\s*\(", "public_send(attr)"),
    # -- eval_exec: php (1) --
    ("eval_exec", "php", r"\beval\s*\(", "eval($code);"),
    # -- eval_exec: csharp (4) --
    ("eval_exec", "csharp", r"\bAssembly\.Load\w*\s*\(", "var assembly = Assembly.Load(raw);"),
    ("eval_exec", "csharp", r"\bActivator\.CreateInstance\s*\(", "var instance = Activator.CreateInstance(type);"),
    ("eval_exec", "csharp", r"\bType\.GetType\s*\(", "var resolved = Type.GetType(typeName);"),
    ("eval_exec", "csharp", r"\bCSharpCodeProvider\b", "var provider = new CSharpCodeProvider();"),

    # -- crypto: java (2, MessageDigest( excluded as DEAD) --
    ("crypto", "java", r"\bCipher\.getInstance\s*\(", 'Cipher.getInstance("AES/GCM/NoPadding")'),
    ("crypto", "java", r"\bSecretKeySpec\s*\(", 'SecretKeySpec spec = new SecretKeySpec(key, "AES");'),
    # -- crypto: c (2) --
    ("crypto", "c", r"\bEVP_Cipher\w*\s*\(", "EVP_CipherUpdate(ctx, out, &outlen, in, inlen);"),
    ("crypto", "c", r"\bAES_encrypt\s*\(", "AES_encrypt(in, out, key);"),
    # -- crypto: cpp (2) --
    ("crypto", "cpp", r"\bEVP_Cipher\w*\s*\(", "EVP_CipherUpdate(ctx, out, &outlen, in, inlen);"),
    ("crypto", "cpp", r"\bAES_encrypt\s*\(", "AES_encrypt(in, out, key);"),
    # -- crypto: javascript (2) --
    ("crypto", "javascript", r"\bcrypto\.createCipher\w*\s*\(", 'crypto.createCipheriv("aes-256-gcm", key, iv);'),
    ("crypto", "javascript", r"\bcrypto\.createHash\s*\(", 'crypto.createHash("sha256")'),
    # -- crypto: typescript (2) --
    ("crypto", "typescript", r"\bcrypto\.createCipher\w*\s*\(", 'crypto.createCipheriv("aes-256-gcm", key, iv);'),
    ("crypto", "typescript", r"\bcrypto\.createHash\s*\(", 'crypto.createHash("sha256")'),
    # -- crypto: go (2, crypto/\w+ excluded as DEAD, sha256.New( excluded as MISROUTED) --
    ("crypto", "go", r"\baes\.NewCipher\s*\(", "aes.NewCipher(key)"),
    ("crypto", "go", r"\bhmac\.New\s*\(", "hmac.New(sha256.New, key)"),
    # -- crypto: ruby (2, Digest::\w+ excluded as MISROUTED) --
    ("crypto", "ruby", r"\bOpenSSL::Cipher\b", 'OpenSSL::Cipher.new("aes-256-gcm")'),
    ("crypto", "ruby", r"\bOpenSSL::HMAC\b", 'OpenSSL::HMAC.hexdigest("SHA256", key, data)'),
    # -- crypto: php (3, hash( excluded as MISROUTED, mcrypt_encrypt( excluded as OBSOLETE) --
    ("crypto", "php", r"\bopenssl_encrypt\s*\(", "openssl_encrypt($data,"),
    ("crypto", "php", r"\bmd5\s*\(", "return md5($data);"),
    ("crypto", "php", r"\bsha1\s*\(", "return sha1($data);"),
    # -- crypto: csharp (6) --
    ("crypto", "csharp", r"\bMD5\b", "var hasher = MD5.Create();"),
    ("crypto", "csharp", r"\bSHA1\b", "var digest = SHA1.Create();"),
    ("crypto", "csharp", r"\bDESCryptoServiceProvider\b", "var provider = new DESCryptoServiceProvider();"),
    ("crypto", "csharp", r"\bTripleDES\b", "var triple = TripleDES.Create();"),
    ("crypto", "csharp", r"\bRijndaelManaged\b", "var rijndael = new RijndaelManaged();"),
    ("crypto", "csharp", r"\bnew\s+Random\s*\(", "var random = new Random();"),
]


# ---------------------------------------------------------------------------
# The catalogue sweep
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("family", "language", "pattern", "needle"),
    CASES,
    ids=[f"{family}:{language}:{pattern!r}" for family, language, pattern, needle in CASES],
)
def test_live_sink_pattern_fires_on_idiomatic_2026_code(
    family: str, language: str, pattern: str, needle: str
) -> None:
    """Every LIVE pattern must find its sink at the fixture line it targets.

    This fails if the pattern is deleted from `_SINK_DEFINITIONS` (no sink of
    this kind would be recorded at the line), if it's rewritten to no longer
    match the idiom (same), or if the vuln_classes mapping regresses.
    """
    result = _index_fixture(family, language)
    assert result["analysis_mode"] == "tree_sitter", (
        f"{family}/{language} fixture demoted to {result['analysis_mode']} "
        f"(reason={result.get('degradation_reason')}) -- has_error trap hit"
    )

    _, source = FIXTURES[(family, language)]
    line = _line_of(source, needle)
    sinks = _sinks_at(result, family, line)

    assert sinks, (
        f"no {family!r} sink recorded at {language} line {line} "
        f"(pattern {pattern!r}, needle {needle!r})"
    )
    assert any(re.search(pattern, sink["snippet"]) for sink in sinks), (
        f"pattern {pattern!r} does not actually match the recorded snippet(s): "
        f"{[s['snippet'] for s in sinks]}"
    )
    for sink in sinks:
        assert sink["vuln_classes"] == EXPECTED_VULN_CLASSES[family]
        assert sink["function"], "sink must be attributed to a containing function"


# ---------------------------------------------------------------------------
# Meta-test: the case table must cover every LIVE pattern in these four
# families, and only those. This is what stops the catalogue drifting back
# to silent zero recall (a pattern added, renamed, or reworded here with no
# corresponding case) while also stopping a removed/dead pattern from being
# silently re-added to CASES without re-justifying it.
# ---------------------------------------------------------------------------

_TARGET_KINDS = {"url_fetch", "deserialization", "eval_exec", "crypto"}

# Patterns verified NOT LIVE (DEAD / OBSOLETE / MISROUTED), each with the
# empirical reason. kind, language, pattern (verbatim from _SINK_DEFINITIONS).
_EXCLUDED: dict[tuple[str, str, str], str] = {
    # -- url_fetch (2 excluded) --
    ("url_fetch", "java", r"\bHttpClient\.send\s*\("):
        "DEAD -- written as a static call on the type name; HttpClient.send "
        "is an instance method (client.send(...)). Verified: idiomatic "
        "java.net.http.HttpClient code produces zero sinks; only a "
        "non-compiling literal `HttpClient.send(...)` call fires.",
    ("url_fetch", "ruby", r"\bopen-uri\b"):
        "DEAD -- matches a `require \"open-uri\"` line, but sinks are only "
        "scanned inside function bodies (treesitter_index.py:1568/1535) and "
        "idiomatic Ruby always requires at file top level (a top-level "
        "require is invisible to the structural sink pass). Verified: moving "
        "the require inside a method makes it fire, but that is not how "
        "anyone requires a stdlib gem. Also REDUNDANT with URI.open( in the "
        "same family, which already covers the real call site.",

    # -- deserialization (3 excluded) --
    ("deserialization", "go", r"\bjson\.Unmarshal\s*\("):
        "MISROUTED -- fires on ordinary typed JSON unmarshalling "
        "(json.Unmarshal(data, &v)), which is safe, ubiquitous Go and not a "
        "deserialization vulnerability class (no arbitrary type/code "
        "execution on decode, unlike gob/pickle/Marshal.load).",
    ("deserialization", "ruby", r"\bJSON\.parse\s*\("):
        "MISROUTED -- JSON.parse is Ruby's safe, default JSON parser (unlike "
        "Marshal.load/YAML.load it never instantiates arbitrary objects or "
        "calls arbitrary code); flagging it as deserialization noise is a "
        "false positive on correct code.",
    ("deserialization", "php", r"\bjson_decode\s*\("):
        "MISROUTED -- same reasoning as Ruby JSON.parse/Go json.Unmarshal in "
        "this family: json_decode() only produces arrays/stdClass, never "
        "invokes __wakeup/__destruct the way unserialize() does. Not an "
        "explicit brief lead but the identical structural issue, verified "
        "the same way.",

    # -- eval_exec (5 excluded) --
    ("eval_exec", "java", r"\bScriptEngine\.eval\s*\("):
        "DEAD -- static-call-on-type-name form again; real code is "
        "`engine.eval(...)` on an instance obtained from "
        "ScriptEngineManager. Verified: idiomatic instance-based scripting "
        "code produces zero sinks; only a non-compiling literal "
        "`ScriptEngine.eval(...)` fires.",
    ("eval_exec", "python", r"\bcompile\s*\("):
        "MISROUTED -- `\\bcompile\\s*\\(` has no owner prefix, so it matches "
        "`re.compile(pattern)`, one of the most common calls in idiomatic "
        "Python and completely unrelated to code execution. Verified by "
        "execution: `re.compile(pattern)` inside a function produces an "
        "eval_exec/injection sink.",
    ("eval_exec", "php", r"\bassert\s*\("):
        "MISROUTED -- the vulnerable capability this pattern is presumably "
        "for (assert() implicitly eval()'ing a string argument) was removed "
        "in PHP 8.0 (RFC \"Saner string to number comparisons\"-era cleanup; "
        "assert() no longer evaluates string assertions from PHP 8.0 "
        "onward). Idiomatic PHP 8.x invariant checks like "
        "`assert($cond, 'msg')` are ordinary boolean assertions, not an "
        "injection sink, in 2026-era code.",
    ("eval_exec", "php", r"\bpreg_replace\s*\(.*/e"):
        "OBSOLETE -- the `/e` (eval) modifier to preg_replace() was removed "
        "in PHP 7.0.0 (2015); calling preg_replace with `/e` on PHP 7+ is a "
        "fatal error (\"preg_replace(): Unknown modifier 'e'\" -> since 7.0 "
        "actually raises a warning and returns null, having been deprecated "
        "since 5.5.0), not something a current codebase can run.",
    ("eval_exec", "php", r"\bcreate_function\s*\("):
        "OBSOLETE -- create_function() was deprecated in PHP 7.2.0 and "
        "removed entirely in PHP 8.0.0; calling it now is a fatal "
        "\"Call to undefined function\" error.",

    # -- crypto (8 excluded) --
    ("crypto", "java", r"\bMessageDigest\s*\("):
        "DEAD -- MessageDigest has no public constructor; the only way to "
        "obtain one is the static factory MessageDigest.getInstance(...), "
        "which this pattern does not match (no '(' immediately after "
        "'MessageDigest'). Verified: idiomatic "
        "`MessageDigest.getInstance(\"SHA-256\")` produces zero sinks; only "
        "a non-compiling literal `MessageDigest(...)` call fires. Same "
        "static/instance-form bug class as HttpClient.send and "
        "ScriptEngine.eval above.",
    ("crypto", "python", r"\bCrypto\.Cipher\."):
        "DEAD -- PyCryptodome is idiomatically imported as "
        "`from Crypto.Cipher import AES` and called as `AES.new(...)`, "
        "never through the fully-qualified `Crypto.Cipher.AES` path. "
        "Verified: idiomatic import+call produces zero sinks; only the "
        "fully-qualified form (`Crypto.Cipher.AES.new(...)`), which no real "
        "PyCryptodome code writes, fires.",
    ("crypto", "python", r"\bhashlib\."):
        "MISROUTED -- fires on every hashlib call including fully correct "
        "usage (hashlib.sha256(data).hexdigest() for a checksum/cache key). "
        "Verified by execution. Unlike Cipher/OpenSSL::Cipher, a bare digest "
        "call has no separate mode/IV/padding argument to misuse -- the "
        "algorithm choice IS the entire signal, and hashlib. does not "
        "distinguish weak (md5/sha1) from strong (sha256/sha3/blake2).",
    ("crypto", "go", r"\bcrypto/\w+\b"):
        "DEAD -- this is an import-path pattern (e.g. `crypto/sha256`), but "
        "import statements are top-level and sinks are only scanned inside "
        "function bodies. Verified: a file that only imports crypto/sha256 "
        "produces zero sinks; the pattern only fires if the import-path text "
        "is written as a string literal inside a function body, which no "
        "real Go code does. Also REDUNDANT with aes.NewCipher(/sha256.New(/"
        "hmac.New( in the same family, which already cover the reachable "
        "call sites.",
    ("crypto", "go", r"\bsha256\.New\s*\("):
        "MISROUTED -- targets SHA-256 specifically (never a weak algorithm), "
        "so unlike hashlib./Digest::\\w+ it cannot even incidentally catch a "
        "weak-hash case; it fires only on code that has already made the "
        "currently-recommended choice. Verified: idiomatic "
        "`sha256.New()` fires and is indistinguishable from misuse.",
    ("crypto", "ruby", r"\bDigest::\w+\b"):
        "MISROUTED -- same overbreadth as Python hashlib.: fires equally on "
        "Digest::SHA256 (correct) and Digest::MD5 (weak), verified by "
        "execution on both; the pattern cannot distinguish them, so it is "
        "algorithm-blind noise rather than a misuse signal.",
    ("crypto", "php", r"\bhash\s*\("):
        "MISROUTED -- same overbreadth as hashlib./Digest::\\w+: "
        "`hash(\"sha256\", $data)` is correct, idiomatic PHP (cache keys, "
        "ETags) and fires identically to `hash(\"md5\", $data)`. Verified by "
        "execution. md5()/sha1() in this same family already give "
        "algorithm-specific, always-weak signal; this generic form adds "
        "only noise.",
    ("crypto", "php", r"\bmcrypt_encrypt\s*\("):
        "OBSOLETE -- the mcrypt extension was removed from PHP core in "
        "PHP 7.2.0 (2018); mcrypt_encrypt() is undefined on any PHP version "
        "a 2026 target would run without a long-unmaintained PECL package.",
}


def test_case_table_covers_every_live_pattern_and_no_dead_ones() -> None:
    """The table above must track `_SINK_DEFINITIONS` exactly for our 4 families.

    Every (kind, language, pattern) triple in the real catalogue must be
    either covered by a CASES row or named in `_EXCLUDED` with a reason --
    never both, never neither. This is what prevents the catalogue drifting
    back to silent zero recall (a new/renamed pattern with no test) and
    prevents a dead pattern from being silently reintroduced into CASES.
    """
    catalogue: set[tuple[str, str, str]] = set()
    for sink_def in treesitter_index._SINK_DEFINITIONS:
        if sink_def["kind"] not in _TARGET_KINDS:
            continue
        for language, patterns in sink_def["patterns"].items():
            for pattern in patterns:
                catalogue.add((sink_def["kind"], language, pattern))

    tested = {(family, language, pattern) for family, language, pattern, _ in CASES}
    excluded = set(_EXCLUDED)

    # No triple is both tested and excluded.
    assert tested & excluded == set(), tested & excluded

    # Every triple in the real catalogue is accounted for exactly once.
    assert tested | excluded == catalogue, (
        f"untracked patterns (new/renamed, need a case or an exclusion): "
        f"{catalogue - (tested | excluded)}; "
        f"stale entries (no longer in the catalogue): "
        f"{(tested | excluded) - catalogue}"
    )

    # 33 + 20 + 23 + 31 = 107 (csharp added 4/6/4/6, all LIVE).
    assert len(catalogue) == 107
    assert len(tested) == 89
    assert len(excluded) == 18
