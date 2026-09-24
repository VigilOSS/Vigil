"""Empirical catalogue audit: auth, xss_output, redirect, xml_parse, memory,
and format_string sinks in ``_SINK_DEFINITIONS`` (treesitter_index.py:244).

Every pattern in these six families was executed against an idiomatic,
current-era (2026) fixture in its own language through the real indexer.
Only patterns that actually fire on realistic code (LIVE) get a case in
``CASES`` below; DEAD/MISROUTED patterns are named, with the reason and the
execution that proved it, in ``_EXCLUDED_PATTERNS`` -- the meta-test at the
bottom cross-checks ``CASES`` and ``_EXCLUDED_PATTERNS`` against the real
``_SINK_DEFINITIONS`` at runtime, so a pattern silently added or removed from
the catalogue breaks this file instead of drifting unnoticed.

Two additional sections pin properties that are not "does the pattern fire"
but are still load-bearing:

* known cross-family duplication (C ``sprintf`` lands in both ``memory`` and
  ``format_string``; Go ``xml.Unmarshal`` lands in both ``xml_parse`` and the
  ``deserialization`` family owned elsewhere), and
* known reachability/precision gaps on patterns that ARE live but miss the
  dominant real-world idiom (Java's two-statement ``getWriter()``/``write()``
  split, Go's non-``w`` writer names, PHP's top-level template style, Ruby's
  parenthesis-free ``redirect_to``).

These gap-pin tests assert *current* behaviour (a documented miss), not that
the miss is correct -- see the report accompanying this file for the fix
list.
"""
from __future__ import annotations

import re
from typing import NamedTuple

import pytest

from assess.lib import treesitter_index
from assess.lib.treesitter_index import index_file


# ---------------------------------------------------------------------------
# Helpers (matching the test_freemarker_extraction.py idiom)
# ---------------------------------------------------------------------------

def _index(path: str, language: str, source: str) -> dict:
    return index_file(path, language, source=source.encode("utf-8"))


def _line_of(source: str, needle: str) -> int:
    """Return the 1-based line carrying *needle* (which must be unique)."""
    lines = source.splitlines()
    matches = [number for number, line in enumerate(lines, 1) if needle in line]
    assert len(matches) == 1, f"{needle!r} is not unique in fixture: {matches}"
    return matches[0]


def _sinks_of_kind(result: dict, kind: str) -> list[dict]:
    return [sink for sink in result["security_sinks"] if sink["kind"] == kind]


def _only(records: list[dict]) -> dict:
    assert len(records) == 1, records
    return records[0]


# ---------------------------------------------------------------------------
# Table-driven catalogue sweep
# ---------------------------------------------------------------------------

class Case(NamedTuple):
    id: str
    kind: str  # the sink "kind" field, which is also the family name here
    language: str
    pattern: str  # regex verbatim, copied from _SINK_DEFINITIONS
    path: str
    source: str
    needle: str  # unique substring on the line the sink must be reported at
    vuln_classes: list[str]


# ---- auth fixtures (vuln_classes: ["auth-bypass", "web-app-auth"]) --------

_AUTH_VULN_CLASSES = ["auth-bypass", "web-app-auth"]

AUTH_JAVA = """\
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        HttpSession session = req.getSession();
        session.setAttribute("user", username);
        if (req.isUserInRole("ADMIN")) {
            authenticate(username, password);
        }
    }
}
"""

AUTH_PYTHON = """\
from flask import session
from flask_login import login_required
from django.contrib.auth import login


@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    return render_template("dashboard.html", user_id=user_id)


def do_login(request, username, password):
    user = authenticate(request, username=username, password=password)
    login(request, user)
    return user
"""

AUTH_JS = """\
function requireAuth(req, res, next) {
  passport.authenticate("jwt", { session: false })(req, res, next);
}

function afterLogin(req, res) {
  req.session.userId = req.user.id;
}
"""

AUTH_TS = """\
function requireAuth(req: Request, res: Response, next: NextFunction): void {
  passport.authenticate("jwt", { session: false })(req, res, next);
}

function afterLogin(req: Request, res: Response): void {
  req.session.userId = req.user.id;
}
"""

AUTH_GO = """\
package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func loginHandler(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")
	tok, _ := jwt.Parse(tokenString, keyFunc)
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_ = userID
	_ = tok
	_ = hash
}
"""

AUTH_RUBY = """\
class SessionsController < ApplicationController
  devise :database_authenticatable, :registerable

  def create
    authenticate_user!
    user = User.find_by(email: params[:email])
    session[:user_id] = user.id
    redirect_to current_user.admin? ? admin_path : root_path
  end
end
"""

AUTH_PHP = """\
<?php
class SessionController {
    public function login(Request $request) {
        session_start();
        if (password_verify($request->password, $user->password)) {
            if (Auth::check()) {
                $_SESSION["user"] = $user->id;
                return response()->json(["ok" => true]);
            }
        }
    }
}
"""

# ---- xss_output fixtures (vuln_classes: ["web-app-injection"]) ------------

_XSS_VULN_CLASSES = ["web-app-injection"]

XSS_JAVA = """\
public class GreetingServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().write("<p>" + req.getParameter("name") + "</p>");
    }
}
"""

XSS_JS = """\
function renderGreeting(name) {
  document.getElementById("greeting").innerHTML = "Hello " + name;
  document.getElementById("legacy").outerHTML = "<div>" + name + "</div>";
  document.write("<p>" + name + "</p>");
}
"""

XSS_TS = """\
function renderGreeting(name: string): void {
  document.getElementById("greeting")!.innerHTML = "Hello " + name;
  document.getElementById("legacy")!.outerHTML = "<div>" + name + "</div>";
  document.write("<p>" + name + "</p>");
}
"""

XSS_GO = """\
package main

func renderHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	unsafe := template.HTML("<b>" + name + "</b>")
	fmt.Fprintf(w, "<p>%s</p>", unsafe)
}
"""

XSS_RUBY = """\
class PagesController < ApplicationController
  def show
    @content = raw(params[:body])
    @trusted = params[:note].html_safe
    render inline: @content
  end
end
"""

XSS_PHP = """\
<?php
class PageController {
    public function show($name) {
        echo "<h1>" . $name . "</h1>";
        print $name;
        printf("<p>%s</p>", $name);
    }
}
"""

# ---- redirect fixtures (vuln_classes: ["open-redirect"]) ------------------

_REDIRECT_VULN_CLASSES = ["open-redirect"]

REDIRECT_JAVA = """\
public class RedirectServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String target = req.getParameter("next");
        resp.sendRedirect(target);
        resp.setHeader("Location", target);
    }
}
"""

REDIRECT_PYTHON = """\
from django.http import HttpResponseRedirect
from flask import redirect


def go_flask(request):
    return redirect(request.args.get("next"))


def go_django(request):
    return HttpResponseRedirect(request.GET.get("next"))
"""

REDIRECT_JS = """\
function goToNext(req, res) {
  res.redirect(req.query.next);
}
"""

REDIRECT_TS = """\
function goToNext(req: Request, res: Response): void {
  res.redirect(req.query.next as string);
}
"""

REDIRECT_GO = """\
package main

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}
"""

# Rails idiom is parens-free (`redirect_to params[:next]`), which this
# pattern cannot see -- see the gap-pin test below. This fixture uses the
# (less common, but real) parenthesised form to demonstrate the LIVE path.
REDIRECT_RUBY = """\
class SessionsController < ApplicationController
  def create
    redirect_to(params[:next])
  end
end
"""

REDIRECT_PHP = """\
<?php
class RedirController {
    public function go($next) {
        header("Location: " . $next);
        redirect($next);
    }
}
"""

# ---- xml_parse fixtures (vuln_classes: ["xxe"]) ----------------------------

_XML_VULN_CLASSES = ["xxe"]

XML_JAVA = """\
public class XmlParser {
    public Document parseDom(InputStream input) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(input);
    }

    public void parseSax(InputStream input) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        XMLReader reader = parser.getXMLReader();
        reader.parse(new InputSource(input));
    }

    public void parseStax(InputStream input) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(input);
        while (reader.hasNext()) {
            reader.next();
        }
    }
}
"""

XML_C = """\
#include <libxml/parser.h>

int load_config(const char *path) {
    xmlDocPtr doc = xmlParseFile(path);
    if (doc == NULL) {
        return -1;
    }
    xmlFreeDoc(doc);
    return 0;
}
"""

XML_GO = """\
package main

import "encoding/xml"

func decodeStream(r io.Reader) (*Config, error) {
	var cfg Config
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func decodeBytes(data []byte) (*Config, error) {
	var cfg Config
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
"""

XML_RUBY = """\
class FeedParser
  def parse_nokogiri(data)
    doc = Nokogiri::XML(data)
    doc.root
  end

  def parse_rexml(data)
    doc = REXML::Document.new(data)
    doc.root
  end
end
"""

XML_PHP = """\
<?php
class FeedParser {
    public function parseSimple($xmlString) {
        $obj = simplexml_load_string($xmlString);
        return $obj;
    }

    public function parseDom($xmlString) {
        $dom = new DOMDocument();
        $dom->loadXML($xmlString);
        return $dom;
    }

    public function parseLegacy($xmlString) {
        $parser = xml_parser_create();
        xml_parse($parser, $xmlString);
        return $parser;
    }
}
"""

# ---- memory fixtures (vuln_classes: ["buffer-overflow", "use-after-free"]) -

_MEMORY_VULN_CLASSES = ["buffer-overflow", "use-after-free"]

# `malloc`/`free`/`realloc` are deliberately present (realistic C) but are
# NOT asserted on: they are MISROUTED, see _EXCLUDED_PATTERNS.
MEMORY_C = """\
#include <stdlib.h>
#include <string.h>

void copy_name(char *dest, size_t destlen, const char *name) {
    char *buf = malloc(64);
    strcpy(buf, name);
    memcpy(dest, buf, destlen);
    sprintf(dest, "%.*s", (int)destlen, buf);
    free(buf);
}
"""

# ---- format_string fixtures (vuln_classes: ["format-string"]) -------------

_FORMAT_STRING_VULN_CLASSES = ["format-string"]

# `snprintf` is deliberately present (the *safe* replacement, used
# correctly) but is NOT asserted on: it is MISROUTED, see _EXCLUDED_PATTERNS.
FORMAT_STRING_C = """\
#include <stdio.h>

void log_msg(char *scratch, const char *user_input) {
    printf(user_input);
    fprintf(stderr, "%s\\n", user_input);
    sprintf(scratch, "%s", user_input);
}
"""

# ---- csharp fixture (one file spanning all four in-scope C# families) ------
#
# C# was added as a tree-sitter language after the per-family fixtures above.
# Rather than one fixture per (family, language), a single controller carries
# every LIVE C# needle on its own line inside a method body. Two deliberate
# properties:
#
# * `[Authorize]` sits on the method DECLARATION -- outside every scanned
#   function body and not top-level -- so `_detect_sinks` never reads it and
#   it does not fire (verified). It is listed in _EXCLUDED_PATTERNS.
# * The two redirect needles share `GoTo`. `\bRedirect\s*\(` also matches the
#   `.Redirect(` inside `Response.Redirect(`, and `_detect_sinks` keeps only
#   the first line a pattern hits per function, so the bare `Redirect(` line
#   is placed BEFORE `Response.Redirect(`: the bare-form pattern breaks on the
#   earlier line and each line then carries exactly one redirect sink.
CSHARP_SOURCE = """\
using System.Web;
using System.Web.Security;
using System.Security.Claims;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace Vigil.Web
{
    public class AccountController : Controller
    {
        public void SignIn(string user)
        {
            FormsAuthentication.SetAuthCookie(user, false);
            var principal = HttpContext.User;
            var claims = new ClaimsPrincipal();
        }

        [Authorize]
        public string Protected()
        {
            return "secret";
        }

        public IActionResult Render(string content)
        {
            return Content(Html.Raw(content).ToString());
        }

        public IActionResult GoTo(string next)
        {
            var fallback = Redirect(next);
            Response.Redirect(next);
            return fallback;
        }

        public void ParseXml(string path, System.IO.Stream stream)
        {
            var doc = new XmlDocument();
            var legacy = new XmlTextReader(path);
            var reader = XmlReader.Create(stream);
        }
    }
}
"""


CASES: tuple[Case, ...] = (
    # -- auth --
    Case("auth-java-getSession", "auth", "java", r"\bgetSession\s*\(",
         "LoginServlet.java", AUTH_JAVA,
         "HttpSession session = req.getSession();", _AUTH_VULN_CLASSES),
    Case("auth-java-setAttribute", "auth", "java", r"\bsetAttribute\s*\(",
         "LoginServlet.java", AUTH_JAVA,
         'session.setAttribute("user", username);', _AUTH_VULN_CLASSES),
    Case("auth-java-isUserInRole", "auth", "java", r"\bisUserInRole\s*\(",
         "LoginServlet.java", AUTH_JAVA,
         'if (req.isUserInRole("ADMIN")) {', _AUTH_VULN_CLASSES),
    Case("auth-java-authenticate", "auth", "java", r"\bauthenticate\s*\(",
         "LoginServlet.java", AUTH_JAVA,
         "authenticate(username, password);", _AUTH_VULN_CLASSES),
    Case("auth-python-session-subscript", "auth", "python", r"\bsession\s*\[",
         "views.py", AUTH_PYTHON,
         'user_id = session["user_id"]', _AUTH_VULN_CLASSES),
    Case("auth-python-login-call", "auth", "python", r"\blogin\s*\(",
         "views.py", AUTH_PYTHON,
         "login(request, user)", _AUTH_VULN_CLASSES),
    Case("auth-python-login-required", "auth", "python", r"@login_required\b",
         "views.py", AUTH_PYTHON,
         "@login_required", _AUTH_VULN_CLASSES),
    Case("auth-js-req-session", "auth", "javascript", r"\breq\.session\b",
         "auth.js", AUTH_JS,
         "req.session.userId = req.user.id;", _AUTH_VULN_CLASSES),
    Case("auth-js-passport-authenticate", "auth", "javascript",
         r"\bpassport\.authenticate\s*\(", "auth.js", AUTH_JS,
         'passport.authenticate("jwt", { session: false })(req, res, next);',
         _AUTH_VULN_CLASSES),
    Case("auth-ts-req-session", "auth", "typescript", r"\breq\.session\b",
         "auth.ts", AUTH_TS,
         "req.session.userId = req.user.id;", _AUTH_VULN_CLASSES),
    Case("auth-ts-passport-authenticate", "auth", "typescript",
         r"\bpassport\.authenticate\s*\(", "auth.ts", AUTH_TS,
         'passport.authenticate("jwt", { session: false })(req, res, next);',
         _AUTH_VULN_CLASSES),
    Case("auth-go-jwt", "auth", "go", r"\bjwt\.\w+\s*\(",
         "auth.go", AUTH_GO,
         "tok, _ := jwt.Parse(tokenString, keyFunc)", _AUTH_VULN_CLASSES),
    Case("auth-go-session-get", "auth", "go", r"\bsession\.Get\s*\(",
         "auth.go", AUTH_GO,
         'userID := session.Get("user_id")', _AUTH_VULN_CLASSES),
    Case("auth-go-bcrypt", "auth", "go", r"\bbcrypt\.\w+\s*\(",
         "auth.go", AUTH_GO,
         "hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)",
         _AUTH_VULN_CLASSES),
    Case("auth-ruby-authenticate-user", "auth", "ruby", r"\bauthenticate_user\b",
         "auth.rb", AUTH_RUBY,
         "authenticate_user!", _AUTH_VULN_CLASSES),
    Case("auth-ruby-current-user", "auth", "ruby", r"\bcurrent_user\b",
         "auth.rb", AUTH_RUBY,
         "redirect_to current_user.admin? ? admin_path : root_path",
         _AUTH_VULN_CLASSES),
    Case("auth-ruby-session-subscript", "auth", "ruby", r"\bsession\s*\[",
         "auth.rb", AUTH_RUBY,
         "session[:user_id] = user.id", _AUTH_VULN_CLASSES),
    Case("auth-ruby-devise", "auth", "ruby", r"\bdevise\b",
         "auth.rb", AUTH_RUBY,
         "devise :database_authenticatable", _AUTH_VULN_CLASSES),
    Case("auth-php-auth-facade", "auth", "php", r"\bAuth::\w+\s*\(",
         "auth.php", AUTH_PHP,
         "if (Auth::check()) {", _AUTH_VULN_CLASSES),
    Case("auth-php-password-verify", "auth", "php", r"\bpassword_verify\s*\(",
         "auth.php", AUTH_PHP,
         "if (password_verify($request->password, $user->password)) {",
         _AUTH_VULN_CLASSES),
    Case("auth-php-session-start", "auth", "php", r"\bsession_start\s*\(",
         "auth.php", AUTH_PHP,
         "session_start();", _AUTH_VULN_CLASSES),
    Case("auth-php-session-superglobal", "auth", "php", r"\$_SESSION\b",
         "auth.php", AUTH_PHP,
         '$_SESSION["user"] = $user->id;', _AUTH_VULN_CLASSES),
    Case("auth-csharp-formsauthentication", "auth", "csharp",
         r"\bFormsAuthentication\b", "AccountController.cs", CSHARP_SOURCE,
         "FormsAuthentication.SetAuthCookie(user, false);", _AUTH_VULN_CLASSES),
    Case("auth-csharp-httpcontext-user", "auth", "csharp",
         r"\bHttpContext\.User\b", "AccountController.cs", CSHARP_SOURCE,
         "var principal = HttpContext.User;", _AUTH_VULN_CLASSES),
    Case("auth-csharp-claimsprincipal", "auth", "csharp",
         r"\bClaimsPrincipal\b", "AccountController.cs", CSHARP_SOURCE,
         "var claims = new ClaimsPrincipal();", _AUTH_VULN_CLASSES),

    # -- xss_output --
    Case("xss-java-getwriter-write", "xss_output", "java",
         r"\bgetWriter\s*\(\s*\)\.write\s*\(", "GreetingServlet.java", XSS_JAVA,
         'resp.getWriter().write("<p>" + req.getParameter("name") + "</p>");',
         _XSS_VULN_CLASSES),
    Case("xss-js-innerHTML", "xss_output", "javascript", r"\.innerHTML\b",
         "render.js", XSS_JS,
         'document.getElementById("greeting").innerHTML = "Hello " + name;',
         _XSS_VULN_CLASSES),
    Case("xss-js-outerHTML", "xss_output", "javascript", r"\.outerHTML\b",
         "render.js", XSS_JS,
         'document.getElementById("legacy").outerHTML = "<div>" + name + "</div>";',
         _XSS_VULN_CLASSES),
    Case("xss-js-document-write", "xss_output", "javascript",
         r"\bdocument\.write\s*\(", "render.js", XSS_JS,
         'document.write("<p>" + name + "</p>");', _XSS_VULN_CLASSES),
    Case("xss-ts-innerHTML", "xss_output", "typescript", r"\.innerHTML\b",
         "render.ts", XSS_TS,
         'document.getElementById("greeting")!.innerHTML = "Hello " + name;',
         _XSS_VULN_CLASSES),
    Case("xss-ts-outerHTML", "xss_output", "typescript", r"\.outerHTML\b",
         "render.ts", XSS_TS,
         'document.getElementById("legacy")!.outerHTML = "<div>" + name + "</div>";',
         _XSS_VULN_CLASSES),
    Case("xss-ts-document-write", "xss_output", "typescript",
         r"\bdocument\.write\s*\(", "render.ts", XSS_TS,
         'document.write("<p>" + name + "</p>");', _XSS_VULN_CLASSES),
    Case("xss-go-template-html", "xss_output", "go", r"\btemplate\.HTML\s*\(",
         "render.go", XSS_GO,
         'unsafe := template.HTML("<b>" + name + "</b>")', _XSS_VULN_CLASSES),
    Case("xss-go-fprintf-w", "xss_output", "go", r"\bfmt\.Fprintf\s*\(\s*w\b",
         "render.go", XSS_GO,
         'fmt.Fprintf(w, "<p>%s</p>", unsafe)', _XSS_VULN_CLASSES),
    Case("xss-ruby-raw", "xss_output", "ruby", r"\braw\s*\(",
         "pages_controller.rb", XSS_RUBY,
         "@content = raw(params[:body])", _XSS_VULN_CLASSES),
    Case("xss-ruby-html-safe", "xss_output", "ruby", r"\.html_safe\b",
         "pages_controller.rb", XSS_RUBY,
         "@trusted = params[:note].html_safe", _XSS_VULN_CLASSES),
    Case("xss-php-echo", "xss_output", "php", r"\becho\b",
         "PageController.php", XSS_PHP,
         'echo "<h1>" . $name . "</h1>";', _XSS_VULN_CLASSES),
    Case("xss-php-print", "xss_output", "php", r"\bprint\b",
         "PageController.php", XSS_PHP,
         "print $name;", _XSS_VULN_CLASSES),
    Case("xss-php-printf", "xss_output", "php", r"\bprintf\s*\(",
         "PageController.php", XSS_PHP,
         'printf("<p>%s</p>", $name);', _XSS_VULN_CLASSES),
    Case("xss-csharp-html-raw", "xss_output", "csharp", r"\bHtml\.Raw\s*\(",
         "AccountController.cs", CSHARP_SOURCE,
         "return Content(Html.Raw(content).ToString());", _XSS_VULN_CLASSES),

    # -- redirect --
    Case("redirect-java-sendRedirect", "redirect", "java", r"\bsendRedirect\s*\(",
         "RedirectServlet.java", REDIRECT_JAVA,
         "resp.sendRedirect(target);", _REDIRECT_VULN_CLASSES),
    Case("redirect-java-setHeader-location", "redirect", "java",
         r'\bsetHeader\s*\(\s*"Location"', "RedirectServlet.java", REDIRECT_JAVA,
         'resp.setHeader("Location", target);', _REDIRECT_VULN_CLASSES),
    Case("redirect-python-redirect", "redirect", "python", r"\bredirect\s*\(",
         "views.py", REDIRECT_PYTHON,
         'return redirect(request.args.get("next"))', _REDIRECT_VULN_CLASSES),
    Case("redirect-python-httpresponseredirect", "redirect", "python",
         r"\bHttpResponseRedirect\s*\(", "views.py", REDIRECT_PYTHON,
         'return HttpResponseRedirect(request.GET.get("next"))',
         _REDIRECT_VULN_CLASSES),
    Case("redirect-js-res-redirect", "redirect", "javascript",
         r"\bres\.redirect\s*\(", "r.js", REDIRECT_JS,
         "res.redirect(req.query.next);", _REDIRECT_VULN_CLASSES),
    Case("redirect-ts-res-redirect", "redirect", "typescript",
         r"\bres\.redirect\s*\(", "r.ts", REDIRECT_TS,
         "res.redirect(req.query.next as string);", _REDIRECT_VULN_CLASSES),
    Case("redirect-go-http-redirect", "redirect", "go", r"\bhttp\.Redirect\s*\(",
         "r.go", REDIRECT_GO,
         "http.Redirect(w, r, next, http.StatusFound)", _REDIRECT_VULN_CLASSES),
    Case("redirect-ruby-redirect-to", "redirect", "ruby", r"\bredirect_to\s*\(",
         "sessions_controller.rb", REDIRECT_RUBY,
         "redirect_to(params[:next])", _REDIRECT_VULN_CLASSES),
    Case("redirect-php-header-location", "redirect", "php",
         r"""\bheader\s*\(\s*['\"]Location""", "RedirController.php", REDIRECT_PHP,
         'header("Location: " . $next);', _REDIRECT_VULN_CLASSES),
    Case("redirect-php-redirect-call", "redirect", "php", r"\bredirect\s*\(",
         "RedirController.php", REDIRECT_PHP,
         "redirect($next);", _REDIRECT_VULN_CLASSES),
    # Bare `Redirect(` sits on its own line ABOVE `Response.Redirect(` in the
    # fixture so each carries exactly one redirect sink -- see CSHARP_SOURCE.
    Case("redirect-csharp-redirect", "redirect", "csharp", r"\bRedirect\s*\(",
         "AccountController.cs", CSHARP_SOURCE,
         "var fallback = Redirect(next);", _REDIRECT_VULN_CLASSES),
    Case("redirect-csharp-response-redirect", "redirect", "csharp",
         r"\bResponse\.Redirect\s*\(", "AccountController.cs", CSHARP_SOURCE,
         "Response.Redirect(next);", _REDIRECT_VULN_CLASSES),

    # -- xml_parse --
    Case("xml-java-documentbuilderfactory", "xml_parse", "java",
         r"\bDocumentBuilderFactory\b", "XmlParser.java", XML_JAVA,
         "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();",
         _XML_VULN_CLASSES),
    Case("xml-java-saxparserfactory", "xml_parse", "java",
         r"\bSAXParserFactory\b", "XmlParser.java", XML_JAVA,
         "SAXParserFactory factory = SAXParserFactory.newInstance();",
         _XML_VULN_CLASSES),
    Case("xml-java-xmlreader", "xml_parse", "java", r"\bXMLReader\b",
         "XmlParser.java", XML_JAVA,
         "XMLReader reader = parser.getXMLReader();", _XML_VULN_CLASSES),
    # StAX -- the fourth Java XML entry point, and the one the family used to
    # miss while DOM, SAX and XMLReader were all covered. The bare type name
    # matches both the declaration and `XMLInputFactory.newInstance()`, which
    # is the line that also carries the `SUPPORT_DTD`/`IS_SUPPORTING_EXTERNAL_
    # ENTITIES` hardening a reviewer is looking for. Distinct from the row
    # above: `\bXMLReader\b` does not match `XMLStreamReader` (verified), so
    # parseStax reports exactly one xml_parse sink, at the factory line.
    Case("xml-java-xmlinputfactory", "xml_parse", "java",
         r"\bXMLInputFactory\b", "XmlParser.java", XML_JAVA,
         "XMLInputFactory factory = XMLInputFactory.newInstance();",
         _XML_VULN_CLASSES),
    Case("xml-c-xmlparsefile", "xml_parse", "c", r"\bxmlParseFile\s*\(",
         "load_config.c", XML_C,
         "xmlDocPtr doc = xmlParseFile(path);", _XML_VULN_CLASSES),
    Case("xml-cpp-xmlparsefile", "xml_parse", "cpp", r"\bxmlParseFile\s*\(",
         "load_config.cpp", XML_C,
         "xmlDocPtr doc = xmlParseFile(path);", _XML_VULN_CLASSES),
    Case("xml-go-newdecoder", "xml_parse", "go", r"\bxml\.NewDecoder\s*\(",
         "feed.go", XML_GO,
         "dec := xml.NewDecoder(r)", _XML_VULN_CLASSES),
    Case("xml-go-unmarshal", "xml_parse", "go", r"\bxml\.Unmarshal\s*\(",
         "feed.go", XML_GO,
         "if err := xml.Unmarshal(data, &cfg); err != nil {", _XML_VULN_CLASSES),
    Case("xml-ruby-nokogiri", "xml_parse", "ruby", r"\bNokogiri::XML\s*\(",
         "feed_parser.rb", XML_RUBY,
         "doc = Nokogiri::XML(data)", _XML_VULN_CLASSES),
    Case("xml-ruby-rexml", "xml_parse", "ruby", r"\bREXML::Document\.new\s*\(",
         "feed_parser.rb", XML_RUBY,
         "doc = REXML::Document.new(data)", _XML_VULN_CLASSES),
    Case("xml-php-simplexml", "xml_parse", "php", r"\bsimplexml_load_string\s*\(",
         "FeedParser.php", XML_PHP,
         "$obj = simplexml_load_string($xmlString);", _XML_VULN_CLASSES),
    Case("xml-php-domdocument", "xml_parse", "php", r"\bDOMDocument\b",
         "FeedParser.php", XML_PHP,
         "$dom = new DOMDocument();", _XML_VULN_CLASSES),
    Case("xml-php-xml-parse", "xml_parse", "php", r"\bxml_parse\s*\(",
         "FeedParser.php", XML_PHP,
         "xml_parse($parser, $xmlString);", _XML_VULN_CLASSES),
    Case("xml-csharp-xmldocument", "xml_parse", "csharp",
         r"\bnew\s+XmlDocument\s*\(", "AccountController.cs", CSHARP_SOURCE,
         "var doc = new XmlDocument();", _XML_VULN_CLASSES),
    Case("xml-csharp-xmltextreader", "xml_parse", "csharp", r"\bXmlTextReader\b",
         "AccountController.cs", CSHARP_SOURCE,
         "var legacy = new XmlTextReader(path);", _XML_VULN_CLASSES),
    Case("xml-csharp-xmlreader-create", "xml_parse", "csharp",
         r"\bXmlReader\.Create\s*\(", "AccountController.cs", CSHARP_SOURCE,
         "var reader = XmlReader.Create(stream);", _XML_VULN_CLASSES),

    # -- memory (malloc/free/realloc excluded -- MISROUTED, see below) --
    Case("memory-c-memcpy", "memory", "c", r"\bmemcpy\s*\(",
         "copy_name.c", MEMORY_C,
         "memcpy(dest, buf, destlen);", _MEMORY_VULN_CLASSES),
    Case("memory-c-strcpy", "memory", "c", r"\bstrcpy\s*\(",
         "copy_name.c", MEMORY_C,
         "strcpy(buf, name);", _MEMORY_VULN_CLASSES),
    Case("memory-c-sprintf", "memory", "c", r"\bsprintf\s*\(",
         "copy_name.c", MEMORY_C,
         'sprintf(dest, "%.*s", (int)destlen, buf);', _MEMORY_VULN_CLASSES),
    Case("memory-cpp-memcpy", "memory", "cpp", r"\bmemcpy\s*\(",
         "copy_name.cpp", MEMORY_C,
         "memcpy(dest, buf, destlen);", _MEMORY_VULN_CLASSES),
    Case("memory-cpp-strcpy", "memory", "cpp", r"\bstrcpy\s*\(",
         "copy_name.cpp", MEMORY_C,
         "strcpy(buf, name);", _MEMORY_VULN_CLASSES),
    Case("memory-cpp-sprintf", "memory", "cpp", r"\bsprintf\s*\(",
         "copy_name.cpp", MEMORY_C,
         'sprintf(dest, "%.*s", (int)destlen, buf);', _MEMORY_VULN_CLASSES),

    # -- format_string (snprintf excluded -- MISROUTED, see below) --
    Case("format-string-c-printf", "format_string", "c", r"\bprintf\s*\(",
         "log_msg.c", FORMAT_STRING_C,
         "printf(user_input);", _FORMAT_STRING_VULN_CLASSES),
    Case("format-string-c-fprintf", "format_string", "c", r"\bfprintf\s*\(",
         "log_msg.c", FORMAT_STRING_C,
         'fprintf(stderr, "%s\\n", user_input);', _FORMAT_STRING_VULN_CLASSES),
    Case("format-string-c-sprintf", "format_string", "c", r"\bsprintf\s*\(",
         "log_msg.c", FORMAT_STRING_C,
         'sprintf(scratch, "%s", user_input);', _FORMAT_STRING_VULN_CLASSES),
    Case("format-string-cpp-printf", "format_string", "cpp", r"\bprintf\s*\(",
         "log_msg.cpp", FORMAT_STRING_C,
         "printf(user_input);", _FORMAT_STRING_VULN_CLASSES),
    Case("format-string-cpp-fprintf", "format_string", "cpp", r"\bfprintf\s*\(",
         "log_msg.cpp", FORMAT_STRING_C,
         'fprintf(stderr, "%s\\n", user_input);', _FORMAT_STRING_VULN_CLASSES),
    Case("format-string-cpp-sprintf", "format_string", "cpp", r"\bsprintf\s*\(",
         "log_msg.cpp", FORMAT_STRING_C,
         'sprintf(scratch, "%s", user_input);', _FORMAT_STRING_VULN_CLASSES),
)


@pytest.mark.parametrize("case", CASES, ids=[case.id for case in CASES])
def test_live_sink_pattern_fires_on_idiomatic_code(case: Case) -> None:
    """Every LIVE pattern must fire, at the right line, with the right
    vuln_classes, on a realistic fixture -- and the match must genuinely come
    from the cataloged regex (not from a coincidental sibling pattern in the
    same family), so removing the pattern from `_SINK_DEFINITIONS` fails this
    test.
    """
    result = _index(case.path, case.language, case.source)
    assert result["analysis_mode"] == "tree_sitter", (
        f"{case.id}: fixture fell back off the structural path "
        f"({result['analysis_mode']}) -- a syntax error demoted it to the "
        f"streaming scanner, which uses different (IGNORECASE) matching."
    )

    line = _line_of(case.source, case.needle)
    hits = [sink for sink in _sinks_of_kind(result, case.kind) if sink["line"] == line]
    assert len(hits) == 1, (
        f"{case.id}: expected exactly one {case.kind!r} sink at line {line}, "
        f"got {hits}"
    )
    sink = _only(hits)
    assert sink["vuln_classes"] == case.vuln_classes
    assert re.search(case.pattern, sink["snippet"]), (
        f"{case.id}: snippet {sink['snippet']!r} does not contain a match "
        f"for {case.pattern!r} -- the sink came from a different pattern"
    )


# ---------------------------------------------------------------------------
# Cross-family duplication, verified by execution
# ---------------------------------------------------------------------------

def test_c_sprintf_produces_both_memory_and_format_string_sinks() -> None:
    """`sprintf` is listed in both `memory` (treesitter_index.py:427) and
    `format_string` (treesitter_index.py:437). One call site legitimately
    yields two sink records with two different `vuln_classes` lists -- this
    pins that both actually appear, and that they disagree on classification
    (buffer-overflow risk is real here; the call has a literal format string,
    so treating it as attacker-controlled-format is the weaker of the two).
    """
    result = _index("log_msg.c", "c", FORMAT_STRING_C)
    line = _line_of(FORMAT_STRING_C, 'sprintf(scratch, "%s", user_input);')

    memory_hit = _only([s for s in _sinks_of_kind(result, "memory") if s["line"] == line])
    format_hit = _only(
        [s for s in _sinks_of_kind(result, "format_string") if s["line"] == line]
    )
    assert memory_hit["vuln_classes"] == ["buffer-overflow", "use-after-free"]
    assert format_hit["vuln_classes"] == ["format-string"]


def test_go_xml_unmarshal_duplicates_the_deserialization_family() -> None:
    """`xml.Unmarshal` is listed in `xml_parse` (treesitter_index.py:417,
    this slice) AND in `deserialization` (treesitter_index.py:323, owned by
    another agent). Both records must appear on the same line -- this pins
    the duplication empirically without asserting anything about whether the
    `deserialization` entry itself is correct.
    """
    result = _index("feed.go", "go", XML_GO)
    line = _line_of(XML_GO, "if err := xml.Unmarshal(data, &cfg); err != nil {")

    xml_hit = _only([s for s in _sinks_of_kind(result, "xml_parse") if s["line"] == line])
    deser_hit = _only(
        [s for s in _sinks_of_kind(result, "deserialization") if s["line"] == line]
    )
    assert xml_hit["vuln_classes"] == ["xxe"]
    assert deser_hit["vuln_classes"] == ["deserialization"]


# ---------------------------------------------------------------------------
# Known reachability/precision gaps on LIVE patterns, pinned by execution
#
# These patterns DO fire (they are in CASES above) but miss the dominant
# real-world idiom for their language/framework. Each test below proves the
# gap currently exists; it is not an assertion that the gap is acceptable.
# ---------------------------------------------------------------------------

def test_java_getwriter_write_split_across_two_statements_is_invisible() -> None:
    """`\\bgetWriter\\s*\\(\\s*\\)\\.write\\s*\\(` (treesitter_index.py:388)
    requires both calls chained on one line. The dominant real Servlet idiom
    -- `PrintWriter out = resp.getWriter(); out.write(...)` -- never produces
    that substring, so it is invisible to this sink.
    """
    source = """\
public class SplitWriterServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();
        out.write("<html>" + req.getParameter("name") + "</html>");
    }
}
"""
    result = _index("SplitWriterServlet.java", "java", source)
    assert result["analysis_mode"] == "tree_sitter"
    assert _sinks_of_kind(result, "xss_output") == []


def test_go_fprintf_writer_named_anything_but_w_is_invisible() -> None:
    """`\\bfmt\\.Fprintf\\s*\\(\\s*w\\b` (treesitter_index.py:391) requires
    the writer argument to be the literal identifier `w`. A handler using
    `resp` (also idiomatic Go) is invisible to this sink even though the
    call is identical in every way that matters.
    """
    source = """\
package main

func renderHandler(resp http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(resp, "<p>%s</p>", name)
}
"""
    result = _index("render_resp.go", "go", source)
    assert result["analysis_mode"] == "tree_sitter"
    assert _sinks_of_kind(result, "xss_output") == []


def test_php_top_level_template_echo_is_indexed() -> None:
    """Plain PHP views expose their top-level output sinks."""
    source = """\
<?php
$name = $_GET["name"];
?>
<html>
<body>
<h1><?php echo $name; ?></h1>
<p><?= $name ?></p>
</body>
</html>
"""
    result = _index("template.php", "php", source)
    assert result["analysis_mode"] == "tree_sitter"
    assert result["functions"] == []
    assert _sinks_of_kind(result, "xss_output")


def test_ruby_redirect_to_without_parentheses_is_invisible() -> None:
    """`\\bredirect_to\\s*\\(` (treesitter_index.py:405) requires literal
    parentheses. The Ruby/Rails style guide (and Rubocop's defaults) prefer
    the parenthesis-free command form for exactly this kind of DSL call --
    `redirect_to params[:next]` -- which this sink never sees.
    """
    source = """\
class SessionsController < ApplicationController
  def create
    redirect_to params[:next]
  end
end
"""
    result = _index("sessions_controller_no_parens.rb", "ruby", source)
    assert result["analysis_mode"] == "tree_sitter"
    assert _sinks_of_kind(result, "redirect") == []


def test_php_session_superglobal_matches_the_sigil_it_is_written_for() -> None:
    """Regression for a leading `\\b` that could never be satisfied.

    `\\b` holds only at a `\\w`/non-`\\w` transition, and `$` is never `\\w`,
    so `\\b\\$_SESSION\\b` required a word character immediately to the left of
    the sigil -- which valid PHP never writes. The pattern matched `a$_SESSION`
    and nothing else. The anchor is gone; both halves are asserted here so the
    fix cannot silently revert to the unmatchable form.
    """
    source = """\
<?php
class SessionReader {
    public function read() {
        return $_SESSION["user"];
    }
}
"""
    result = _index("SessionReader.php", "php", source)
    assert result["analysis_mode"] == "tree_sitter"
    assert [sink["line"] for sink in _sinks_of_kind(result, "auth")] == [
        _line_of(source, '$_SESSION["user"]')
    ]
    assert not _unmatchable_word_anchors()


# `\w`-style classes and the zero-width assertions: an escape that is not a
# literal character, so a `\b` in front of one is perfectly satisfiable.
_NON_LITERAL_ESCAPES = frozenset("wdsWDSbBAZzGN")
# Likewise for regex syntax: a group, a class or another anchor is not the
# literal this test reasons about.
_REGEX_SYNTAX_STARTS = frozenset("[(^$.*+?{|")


def _literal_required_after_word_boundary(pattern: str) -> str | None:
    """The single literal character *pattern* demands right after a leading `\b`."""
    if not pattern.startswith("\\b"):
        return None
    rest = pattern[2:]
    if not rest:
        return None
    if rest[0] == "\\":
        if len(rest) < 2 or rest[1] in _NON_LITERAL_ESCAPES:
            return None
        return rest[1]
    if rest[0] in _REGEX_SYNTAX_STARTS:
        return None
    return rest[0]


def _unmatchable_word_anchors() -> list[tuple[str, str, str]]:
    """Every sink pattern whose leading `\b` can never hold.

    `\b` matches only at a word/non-word transition, so a `\b` immediately in
    front of a non-word literal demands a word character to that literal's
    left. Valid PHP never writes one before the `$` sigil and idiomatic Ruby
    never writes one before a command-substitution backtick; both patterns
    shipped anchored and matched nothing at all. What is pinned here is the
    shape rather than those two instances, so the next one fails on arrival.
    """
    return [
        (str(definition["kind"]), language, pattern)
        for definition in treesitter_index._SINK_DEFINITIONS
        for language, patterns in definition["patterns"].items()
        for pattern in patterns
        if (literal := _literal_required_after_word_boundary(pattern)) is not None
        and not literal.isalnum()
        and literal != "_"
    ]


def test_ruby_devise_macro_is_attributed_to_top_level_scope() -> None:
    source = """\
class User < ApplicationRecord
  devise :database_authenticatable, :registerable, :recoverable, :validatable

  def to_s
    email
  end
end
"""
    result = _index("user.rb", "ruby", source)
    assert result["analysis_mode"] == "tree_sitter"
    assert result["functions"] == [
        func for func in result["functions"] if func["name"] != "devise"
    ]
    assert [
        (sink["function"], sink["line"])
        for sink in _sinks_of_kind(result, "auth")
    ] == [("<top-level>", 2)]


def test_python_login_required_decorator_is_attributed_to_top_level_scope() -> None:
    source = """\
from flask_login import login_required


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")
"""
    result = _index("views_decorator_only.py", "python", source)
    assert result["analysis_mode"] == "tree_sitter"
    assert [
        (sink["function"], sink["line"])
        for sink in _sinks_of_kind(result, "auth")
    ] == [("<top-level>", 5)]


def test_python_xml_etree_fully_qualified_call_needs_an_unaliased_import() -> None:
    """`\\bxml\\.etree\\.ElementTree\\.parse\\s*\\(` and
    `\\blxml\\.etree\\.parse\\s*\\(` (treesitter_index.py:416) only match the
    literal fully-qualified spelling. Idiomatic 2026 Python aliases the
    import -- `import xml.etree.ElementTree as ET` (the stdlib docs' own
    example) or `from lxml import etree` -- after which the fully-qualified
    string never appears again in the file, so the pattern never fires on
    the code a real target actually contains.
    """
    source = """\
import xml.etree.ElementTree as ET
from lxml import etree


def load_stdlib(path):
    tree = ET.parse(path)
    return tree.getroot()


def load_lxml(path):
    tree = etree.parse(path)
    return tree.getroot()
"""
    result = _index("xml_aliased.py", "python", source)
    assert result["analysis_mode"] == "tree_sitter"
    assert _sinks_of_kind(result, "xml_parse") == []


def test_memory_family_malloc_free_realloc_fire_on_correct_safe_code() -> None:
    """`\\bmalloc\\s*\\(`, `\\bfree\\s*\\(`, `\\brealloc\\s*\\(`
    (treesitter_index.py:427-428) carry `["buffer-overflow",
    "use-after-free"]` unconditionally. This pins that they fire on a
    completely correct, bounds-safe, single free -- i.e. they are a
    zero-signal allocation-lifecycle marker, not evidence of either listed
    vuln class. (They are excluded from the LIVE case table as MISROUTED;
    this test documents why by construction rather than assertion.)
    """
    result = _index("copy_name.c", "c", MEMORY_C)

    malloc_hit = _only(
        [s for s in _sinks_of_kind(result, "memory") if "malloc(64)" in s["snippet"]]
    )
    free_hit = _only(
        [s for s in _sinks_of_kind(result, "memory") if s["snippet"] == "free(buf);"]
    )
    # Both fire, and both are tagged with a vuln class that this specific,
    # correct, non-vulnerable call cannot actually exhibit.
    assert malloc_hit["vuln_classes"] == ["buffer-overflow", "use-after-free"]
    assert free_hit["vuln_classes"] == ["buffer-overflow", "use-after-free"]


def test_format_string_family_snprintf_fires_on_the_safe_replacement() -> None:
    """`\\bsnprintf\\s*\\(` (treesitter_index.py:437) fires identically to
    `printf(user_input)` even when `snprintf` is used exactly as CERT/MISRA
    recommend -- a literal format string and an explicit `sizeof` bound.
    That is the *fix* for the sprintf/printf bugs this family exists to
    catch, not an instance of them. (Excluded from the LIVE case table as
    MISROUTED.)
    """
    source = """\
#include <stdio.h>

void log_safe(const char *user_input) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", user_input);
}
"""
    result = _index("log_safe.c", "c", source)
    hit = _only(_sinks_of_kind(result, "format_string"))
    assert "snprintf(buf, sizeof(buf)" in hit["snippet"]
    assert hit["vuln_classes"] == ["format-string"]


# ---------------------------------------------------------------------------
# Meta-test: the case table must track the real catalogue
# ---------------------------------------------------------------------------

_FAMILIES = frozenset(
    {"auth", "xss_output", "redirect", "xml_parse", "memory", "format_string"}
)

# Patterns deliberately NOT in CASES, with the verdict and the execution that
# established it. Every entry here is exercised by a dedicated test above
# (or, for the two Ruby/PHP "cannot fire" cases, by re.search directly)
# rather than by a CASES row, per the brief: never assert broken/misrouted
# output as if it were a passing, correct test.
_EXCLUDED_PATTERNS: dict[tuple[str, str, str], str] = {
    ("xml_parse", "python", r"\bxml\.etree\.ElementTree\.parse\s*\("):
        "DEAD in practice -- only matches the unaliased fully-qualified "
        "spelling; idiomatic code aliases the import. "
        "See test_python_xml_etree_fully_qualified_call_needs_an_unaliased_import.",
    ("xml_parse", "python", r"\blxml\.etree\.parse\s*\("):
        "DEAD in practice -- same aliasing mismatch (`from lxml import etree`). "
        "See test_python_xml_etree_fully_qualified_call_needs_an_unaliased_import.",
    ("memory", "c", r"\bmalloc\s*\("):
        "MISROUTED -- fires on every allocation, safe or not; "
        "buffer-overflow/use-after-free describe what happens later, not "
        "the allocation call. See test_memory_family_malloc_free_realloc_fire_on_correct_safe_code.",
    ("memory", "cpp", r"\bmalloc\s*\("):
        "MISROUTED -- see memory/c/malloc.",
    ("memory", "c", r"\bfree\s*\("):
        "MISROUTED -- fires on every correct, safe deallocation; "
        "buffer-overflow never applies to free(), and use-after-free "
        "requires a later use this sink cannot see. "
        "See test_memory_family_malloc_free_realloc_fire_on_correct_safe_code.",
    ("memory", "cpp", r"\bfree\s*\("):
        "MISROUTED -- see memory/c/free.",
    ("memory", "c", r"\brealloc\s*\("):
        "MISROUTED -- same reasoning as malloc/free: fires on every correct "
        "realloc call.",
    ("memory", "cpp", r"\brealloc\s*\("):
        "MISROUTED -- see memory/c/realloc.",
    ("format_string", "c", r"\bsnprintf\s*\("):
        "MISROUTED -- snprintf is the CERT/MISRA-recommended *safe* "
        "replacement for sprintf; fires identically on correctly "
        "bounds-checked, literal-format calls. "
        "See test_format_string_family_snprintf_fires_on_the_safe_replacement.",
    ("format_string", "cpp", r"\bsnprintf\s*\("):
        "MISROUTED -- see format_string/c/snprintf.",
    ("auth", "csharp", r"\[Authorize\b"):
        "DEAD in structural scan -- `[Authorize]` is a declaration-level "
        "attribute that sits on the method/class declaration, outside every "
        "scanned function body and not at top-level, so `_detect_sinks` never "
        "reads it. Verified: it produces no auth sink on the AccountController "
        "fixture even though the attribute is present on `Protected()`.",
    ("xss_output", "csharp", r"@Html\.Raw\b"):
        "DEAD/redundant for .cs -- `@Html.Raw(...)` is Razor `.cshtml` view "
        "syntax, not idiomatic (or even parseable) C# in a `.cs` source file; "
        "the C# source form `Html.Raw(...)` is already covered LIVE by "
        r"\bHtml\.Raw\s*\(.",
}


def test_case_table_covers_every_live_pattern_in_the_assigned_families() -> None:
    """Prove CASES has no silent gaps against the real `_SINK_DEFINITIONS`.

    This is the drift guard: if a pattern is added to, removed from, or
    changed in the auth/xss_output/redirect/xml_parse/memory/format_string
    families, this test fails until the case table (or the commented
    exclusion allow-list, with a reason) is updated to match.
    """
    catalogue: set[tuple[str, str, str]] = set()
    for sink_def in treesitter_index._SINK_DEFINITIONS:
        if sink_def["kind"] not in _FAMILIES:
            continue
        for language, patterns in sink_def["patterns"].items():
            for pattern in patterns:
                catalogue.add((sink_def["kind"], language, pattern))

    covered = {(case.kind, case.language, case.pattern) for case in CASES}
    excluded = set(_EXCLUDED_PATTERNS)

    assert covered.isdisjoint(excluded), (
        "a pattern is both tested as LIVE and listed as excluded: "
        f"{covered & excluded}"
    )
    missing = catalogue - covered - excluded
    stale = (covered | excluded) - catalogue
    assert not missing, f"pattern(s) in the catalogue but untracked here: {missing}"
    assert not stale, f"tracked pattern(s) no longer in the catalogue: {stale}"

    # Hard counts: exactly six families, 92 patterns. The audit started at 80;
    # java `xml_parse` then gained `\bXMLInputFactory\b` (StAX), closing the
    # one Java XML entry point the family had no pattern for (81). C# was then
    # added as a tree-sitter language, contributing 11 patterns across auth (4),
    # xss_output (2), redirect (2) and xml_parse (3) -- 9 LIVE (covered) and 2
    # dead (`[Authorize` declaration attribute, `@Html.Raw` Razor syntax).
    assert len(catalogue) == 92
    assert len(covered) == 80
    assert len(excluded) == 12
