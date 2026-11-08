"""Tree-sitter structural indexing for code analysis.

Parses source files using tree-sitter to extract function/method definitions,
class structures, import statements, entry points, security sinks, and call
sites.  All tree-sitter imports are guarded so the module remains importable
(returning empty/degraded results) when tree-sitter packages are absent.
"""
from __future__ import annotations

import posixpath
import re
import threading
import warnings
from bisect import bisect_left, bisect_right
from collections.abc import Callable, Iterable
from functools import lru_cache
from typing import Any, NamedTuple

from assess.lib.code_languages import (
    STRUCTURAL_SUPPORTED_LANGUAGES,
    structural_language_for_file,
)

from assess.lib.treesitter_catalogues import (
    _CLASS_QUERIES,
    _C_DECLARATION_QUERY,
    _CPP_DECLARATION_QUERY,
    _ENTRY_ANNOTATIONS,
    _ENTRY_LINE_PATTERNS,
    _ENTRY_METHOD_NAMES,
    _FUNCTION_QUERIES,
    _GLOBAL_ENTRY_LINE_PATTERNS,
    _IMPORT_QUERIES,
    _PHP_CLI_ENTRY_EVIDENCE,
    _PHP_FILE_INCLUSION_VULN_CLASSES,
    _PHP_SERVER_ARGV,
    _SINK_DEFINITIONS,
)
from assess.lib.treesitter_common import (
    _gate_literals,
    _php_import_record,
    _snippet,
)
from assess.lib.treesitter_lightweight import (
    _blade_template_sources,
    _extract_blade,
    _extract_css,
    _extract_dockerfile,
    _extract_freemarker,
    _extract_html,
    _extract_lua,
    _extract_powershell,
    _extract_shell,
    _extract_twig,
    _holds_inline_script,
    _holds_unread_code,
)
from assess.lib.treesitter_streaming import (
    _SIGNAL_DIMENSIONS,
    _UNSUPPORTED_UNAVAILABLE_DIMENSIONS,
    _attach_bounded_security_sources,
    _complete_index_metadata,
    _fallback_from_bytes,
)

# Compatibility names for existing callers and catalogue tests. Their owning
# modules are imported directly above, so this façade creates no reverse import.
from assess.lib.treesitter_lightweight import (  # noqa: F401
    FREEMARKER_ESCAPE_OBSERVATIONS,
    FREEMARKER_OUTPUT_CONTEXTS,
    _LUA_DYNAMIC_REDIS_COMMAND_RE,
)
from assess.lib.treesitter_streaming import (  # noqa: F401
    STREAMING_FALLBACK_BASELINE_UNAVAILABLE,
    STREAMING_SCAN_OVERLAP_BYTES,
    STREAMING_SCAN_WINDOW_BYTES,
    STRUCTURAL_SIGNAL_LIMIT,
    StreamingSecurityScanner,
    _CAPPED_INDEX_LISTS,
    _STREAM_EXTRA_ENTRY_PATTERNS,
    _STREAM_EXTRA_SINK_PATTERNS,
    _STREAM_IMPORT_PATTERNS,
    _STREAM_SOURCE_PATTERNS,
    streaming_security_fallback,
)

# ---------------------------------------------------------------------------
# Guarded tree-sitter imports
# ---------------------------------------------------------------------------

_TS_AVAILABLE = False

try:
    import tree_sitter  # type: ignore[import-untyped]
    _TS_AVAILABLE = True
except ImportError:
    tree_sitter = None  # type: ignore[assignment]

# Per-language grammar loaders (also guarded)
_GRAMMAR_MODULES: dict[str, Any] = {}

def _try_import_grammar(mod_name: str, key: str) -> None:
    try:
        import importlib
        _GRAMMAR_MODULES[key] = importlib.import_module(mod_name)
    except ImportError:
        pass

_try_import_grammar("tree_sitter_java", "java")
_try_import_grammar("tree_sitter_c", "c")
_try_import_grammar("tree_sitter_cpp", "cpp")
_try_import_grammar("tree_sitter_python", "python")
_try_import_grammar("tree_sitter_javascript", "javascript")
_try_import_grammar("tree_sitter_typescript", "typescript")
_try_import_grammar("tree_sitter_go", "go")
_try_import_grammar("tree_sitter_ruby", "ruby")
_try_import_grammar("tree_sitter_php", "php")
_try_import_grammar("tree_sitter_c_sharp", "csharp")


# ---------------------------------------------------------------------------
# tree-sitter API compat: 0.23 had Language.query() + Query.captures(node)
# returning {name: [nodes]}.  0.25 removed both — use Query() constructor +
# QueryCursor.matches() instead.  This helper provides a single call site.
# ---------------------------------------------------------------------------

@lru_cache(maxsize=128)
def _compiled_ts_query(lang_obj: Any, query_str: str) -> Any:
    """Reuse immutable query plans across files; cursors remain per scan."""
    if hasattr(tree_sitter, "QueryCursor"):
        return tree_sitter.Query(lang_obj, query_str)
    return lang_obj.query(query_str)


class _SharedTreeQueries(threading.local):
    """One cursor pass answering every whole-tree query the extractors run.

    A cursor walks the whole tree whatever its pattern count, and each
    extractor asks for its own query over the same tree. So the queries of the
    tree's family are matched together the first time one is asked, and each
    answer is the matches of its own patterns in the order its own cursor
    returns them. `index_file` opens the pass for the tree it parsed and closes
    it when it is done; any other query runs on its own. Each thread has its
    own pass, so concurrent indexing never reads another file's matches.
    """

    def __init__(self) -> None:
        self._root: Any = None
        self._lang_obj: Any = None
        self._queries: tuple[str, ...] = ()
        self._results: dict[str, dict[str, list[Any]]] | None = None

    def open(self, root: Any, lang_obj: Any, queries: tuple[str, ...]) -> None:
        self._root, self._lang_obj, self._queries, self._results = root, lang_obj, queries, None

    def close(self) -> None:
        self.open(None, None, ())

    def captures(self, lang_obj: Any, query_str: str, root: Any) -> dict[str, list[Any]] | None:
        if (
            self._root is None
            or lang_obj is not self._lang_obj
            or query_str not in self._queries
            or root != self._root
        ):
            return None
        if self._results is None:
            self._results = self._match_all()
            if self._results is None:
                self._queries = ()
                return None
        return {name: list(nodes) for name, nodes in self._results[query_str].items()}

    def _match_all(self) -> dict[str, dict[str, list[Any]]] | None:
        try:
            combined = _compiled_ts_query(self._lang_obj, "\n".join(self._queries))
            owners = [
                query_str
                for query_str in self._queries
                for _pattern in range(_compiled_ts_query(self._lang_obj, query_str).pattern_count)
            ]
        except Exception:  # noqa: BLE001 - each query then reports its own failure
            return None
        if len(owners) != combined.pattern_count:
            return None
        results: dict[str, dict[str, list[Any]]] = {query_str: {} for query_str in self._queries}
        for pattern_index, match_dict in tree_sitter.QueryCursor(combined).matches(self._root):
            result = results[owners[pattern_index]]
            for name, nodes in match_dict.items():
                result.setdefault(name, []).extend(nodes)
        return results


_SHARED_TREE_QUERIES = _SharedTreeQueries()


def _ts_query_captures(lang_obj: Any, query_str: str, root_node: Any) -> dict[str, list[Any]]:
    """Run a tree-sitter query and return ``{capture_name: [nodes]}``."""
    if tree_sitter is None:
        return {}
    # 0.25+: Query() constructor + QueryCursor
    if hasattr(tree_sitter, "QueryCursor"):
        shared = _SHARED_TREE_QUERIES.captures(lang_obj, query_str, root_node)
        if shared is not None:
            return shared
        try:
            query = _compiled_ts_query(lang_obj, query_str)
        except Exception as exc:
            warnings.warn(
                f"tree-sitter query compilation failed; captures are degraded: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )
            return {}
        cursor = tree_sitter.QueryCursor(query)
        result: dict[str, list[Any]] = {}
        for _pattern_idx, match_dict in cursor.matches(root_node):
            for name, nodes in match_dict.items():
                result.setdefault(name, []).extend(nodes)
        return result
    # 0.23.x: Language.query() + Query.captures()
    try:
        query = _compiled_ts_query(lang_obj, query_str)
    except Exception as exc:
        warnings.warn(
            f"tree-sitter query compilation failed; captures are degraded: {exc}",
            RuntimeWarning,
            stacklevel=2,
        )
        return {}
    return query.captures(root_node)  # type: ignore[return-value]


# Tree-sitter backed languages (full structural parsing)
_TS_SUPPORTED_LANGUAGES = frozenset({
    "java", "c", "cpp", "python", "javascript", "typescript",
    "go", "ruby", "php", "csharp",
})

# Lightweight regex/line-based extractors (pure-python, no tree-sitter grammar)
LIGHTWEIGHT_LANGUAGES = frozenset({
    "blade", "dockerfile", "shell", "powershell", "lua", "html", "css",
    "freemarker", "twig",
})

# Combined set used by consumers (code_index.py / code_index_sync.py / assess
# backend) to gate which files are indexed. Anything not in this set is
# skipped silently with skipped_unsupported++.
SUPPORTED_LANGUAGES = STRUCTURAL_SUPPORTED_LANGUAGES


# ---------------------------------------------------------------------------
# Lazy grammar / parser cache
# ---------------------------------------------------------------------------

_PARSERS: dict[str, Any] = {}  # lang -> tree_sitter.Parser


def _get_parser(language: str) -> Any | None:
    """Return a tree-sitter Parser for *language*, loading the grammar lazily."""
    if not _TS_AVAILABLE:
        return None

    if language in _PARSERS:
        return _PARSERS[language]

    # TypeScript needs special handling: the grammar module exposes
    # language_typescript() and language_tsx() as separate entry points.
    if language == "typescript":
        gram = _GRAMMAR_MODULES.get("typescript")
        if gram is None:
            return None
        # Prefer language_typescript(); fall back to language()
        lang_fn = getattr(gram, "language_typescript", None) or getattr(gram, "language", None)
        if lang_fn is None:
            return None
        lang_obj = tree_sitter.Language(lang_fn())
    elif language == "tsx":
        gram = _GRAMMAR_MODULES.get("typescript")
        if gram is None:
            return None
        lang_fn = getattr(gram, "language_tsx", None)
        if lang_fn is None:
            return None
        lang_obj = tree_sitter.Language(lang_fn())
    elif language == "php":
        gram = _GRAMMAR_MODULES.get("php")
        if gram is None:
            return None
        lang_fn = getattr(gram, "language_php", None) or getattr(gram, "language", None)
        if lang_fn is None:
            return None
        lang_obj = tree_sitter.Language(lang_fn())
    else:
        gram = _GRAMMAR_MODULES.get(language)
        if gram is None:
            return None
        lang_fn = getattr(gram, "language", None)
        if lang_fn is None:
            return None
        lang_obj = tree_sitter.Language(lang_fn())

    parser = tree_sitter.Parser(lang_obj)
    _PARSERS[language] = parser
    return parser


# ---------------------------------------------------------------------------
# Tree-sitter query strings per language (functions, classes, imports)
# ---------------------------------------------------------------------------

_C_HTTP_CALLBACK_ARGUMENTS = {
    "evhttp_set_cb": 2,
    "evhttp_set_gencb": 1,
    "MHD_start_daemon": 4,
}

_CPP_HTTP_ROUTE_METHODS = frozenset({"Get", "Post", "Put", "Patch", "Delete", "Options"})
_CPP_HTTP_SCAN_TYPES = frozenset({
    "call_expression", "declaration", "field_declaration", "parameter_declaration",
    "using_declaration",
})
_CALL_EXPRESSION_TYPES = frozenset({"call_expression"})


def _cpp_http_route_callbacks(tree: Any, source: bytes) -> list[Any]:
    """Find cpp-httplib server handlers, which occupy a route call's second argument."""
    callbacks: list[Any] = []
    aliases: set[tuple[int, int, str]] = set()
    server_bindings: set[tuple[int, int, str]] = set()
    declarations: list[Any] = []
    route_calls: list[Any] = []
    for node in _named_nodes_of_types(tree, _CPP_HTTP_SCAN_TYPES):
        if node.type == "using_declaration":
            match = re.fullmatch(
                r"\s*using\s+httplib::(Server|SSLServer)\s*;",
                _node_text(node, source),
            )
            if match:
                scope = _cpp_binding_scopes(node, tree.root_node)[0]
                aliases.add((*scope, match.group(1)))
        elif node.type in {"declaration", "parameter_declaration", "field_declaration"}:
            declarations.append(node)
        elif node.type == "call_expression":
            route_calls.append(node)

    for node in declarations:
        type_node = node.child_by_field_name("type")
        declarator = node.child_by_field_name("declarator")
        if type_node is None or declarator is None:
            continue
        type_name = _node_text(type_node, source)
        scopes = _cpp_binding_scopes(node, tree.root_node)
        is_server = type_name in {"httplib::Server", "httplib::SSLServer"}
        if not is_server and type_name in {"Server", "SSLServer"}:
            is_server = any((*scope, type_name) in aliases for scope in scopes)
        if not is_server and type_name == "auto":
            initializer = declarator.child_by_field_name("value")
            is_server = initializer is not None and re.match(
                r"httplib::(?:Server|SSLServer)\s*[({]",
                _node_text(initializer, source),
            ) is not None
        if not is_server:
            continue
        path = _cpp_declarator_path(declarator)
        if path:
            server_bindings.add((*scopes[0], _node_text(path[-1], source)))

    for node in route_calls:
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "field_expression":
            continue
        receiver = callee.child_by_field_name("argument")
        if receiver is None or receiver.type != "identifier":
            continue
        receiver_name = _node_text(receiver, source)
        if not any(
            (*scope, receiver_name) in server_bindings
            for scope in _cpp_binding_scopes(node, tree.root_node)
        ):
            continue
        method = callee.child_by_field_name("field")
        if method is None or _node_text(method, source) not in _CPP_HTTP_ROUTE_METHODS:
            continue
        arguments = node.child_by_field_name("arguments")
        if arguments is None or len(arguments.named_children) < 2:
            continue
        route, callback = arguments.named_children[:2]
        if route.type not in {"string_literal", "raw_string_literal"}:
            continue
        if callback.type in {"lambda_expression", "identifier", "qualified_identifier"}:
            callbacks.append(callback)
    return callbacks


def _cpp_binding_scopes(node: Any, root: Any) -> list[tuple[int, int]]:
    """Return lexical function/class scopes followed by file scope."""
    scopes: list[tuple[int, int]] = []
    current = node.parent
    while current is not None:
        if current.type in {"function_definition", "class_specifier", "struct_specifier"}:
            scopes.append((current.start_byte, current.end_byte))
        current = current.parent
    scopes.append((root.start_byte, root.end_byte))
    return scopes


def _c_http_callback_names(tree: Any, source: bytes) -> set[str]:
    """Find direct function references in known C HTTP registration calls."""
    names: set[str] = set()
    for node in _named_nodes_of_types(tree, _CALL_EXPRESSION_TYPES):
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "identifier":
            continue
        argument_index = _C_HTTP_CALLBACK_ARGUMENTS.get(_node_text(callee, source))
        if argument_index is None:
            continue
        arguments = node.child_by_field_name("arguments")
        if arguments is None or len(arguments.named_children) <= argument_index:
            continue
        callback = arguments.named_children[argument_index]
        if callback.type == "pointer_expression" and _node_text(callback, source).lstrip().startswith("&"):
            children = callback.named_children
            if len(children) == 1:
                callback = children[0]
        if callback.type == "identifier":
            names.add(_node_text(callback, source))
    return names


# ---------------------------------------------------------------------------
# Call-site detection regex (simple heuristic)
# ---------------------------------------------------------------------------

_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*)\s*\(")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _node_text(node: Any, source: bytes) -> str:
    """Extract the source text of a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _node_lines(node: Any) -> tuple[int, int]:
    """Return 1-based (start_line, end_line) for a tree-sitter node."""
    return (node.start_point[0] + 1, node.end_point[0] + 1)


def _query_language_family(language: str) -> str:
    """Map parser-specific keys to the query family used in *_QUERIES."""
    if language == "tsx":
        return "typescript"
    return language


@lru_cache(maxsize=None)
def _whole_tree_queries(language: str, lang_obj: Any) -> tuple[str, ...]:
    """Every query the extractors run over a whole *language* tree.

    The node collections the readers take in document order -- every call,
    every closure, every comment -- are queries too, so the shared pass
    serves them instead of a Python walk of the tree per reader.
    """
    family = _query_language_family(language)
    queries = [
        _FUNCTION_QUERIES.get(family),
        _CLASS_QUERIES.get(family),
        _IMPORT_QUERIES.get(family),
    ]
    if family == "c":
        queries.append(_C_DECLARATION_QUERY)
    elif family == "cpp":
        queries.append(_CPP_DECLARATION_QUERY)
    elif family == "php":
        queries.extend((
            _PHP_INCLUDE_QUERY, _PHP_AST_SINK_QUERY, _PHP_CALL_QUERY,
        ))
    queries.extend(
        _node_type_query(lang_obj, types)
        for types in (
            *_WHOLE_TREE_NODE_TYPES.get(family, ()),
            _file_scope_candidate_types(family),
            _COMMENT_NODE_TYPES,
        )
    )
    return tuple(dict.fromkeys(query for query in queries if query))


@lru_cache(maxsize=None)
def _node_type_query(lang_obj: Any, types: frozenset[str]) -> str | None:
    """One pattern capturing, as ``node``, every named node of *types*.

    A type the grammar does not have would fail the query, and no node of it
    can occur, so it is left out; None when the grammar has none of them.
    """
    present = sorted(
        node_type for node_type in types if lang_obj.id_for_node_kind(node_type, True) is not None
    )
    if not present:
        return None
    return "[" + " ".join(f"({node_type})" for node_type in present) + "] @node"


def _named_nodes_of_types(tree: Any, types: frozenset[str]) -> list[Any]:
    """Every named node of *types* in *tree*, in document pre-order.

    The shared query pass answers when `index_file` registered *types* for the
    tree's family; otherwise this walks the tree, which returns the same nodes
    in the same order.
    """
    lang_obj = getattr(tree, "language", None)
    query = _node_type_query(lang_obj, types) if lang_obj is not None else None
    if query is not None:
        shared = _SHARED_TREE_QUERIES.captures(lang_obj, query, tree.root_node)
        if shared is not None:
            return shared.get("node", [])
    root = getattr(tree, "root_node", None)
    return [
        node
        for child in getattr(root, "named_children", ()) or ()
        for node in _walk_named_nodes(child)
        if node.type in types
    ]


_CPP_NAME_NODE_TYPES = frozenset({
    "conversion_operator",
    "destructor_name",
    "field_identifier",
    "identifier",
    "literal_operator_name",
    "operator_name",
    "qualified_identifier",
    "template_function",
})
_CPP_OBJECT_DECLARATOR_TYPES = frozenset({
    "abstract_array_declarator",
    "abstract_pointer_declarator",
    "abstract_reference_declarator",
    "array_declarator",
    "pointer_declarator",
    "reference_declarator",
})
_CPP_SIGNATURE_QUALIFIER_TYPES = frozenset({
    "noexcept",
    "ref_qualifier",
    "requires_clause",
    "type_qualifier",
})


def _field_children(node: Any, field_name: str) -> list[Any]:
    """Return direct children carrying *field_name* across tree-sitter APIs."""
    return [
        child
        for index, child in enumerate(node.children)
        if node.field_name_for_child(index) == field_name
    ]


def _cpp_declarator_child(node: Any) -> Any | None:
    child = node.child_by_field_name("declarator")
    if child is not None:
        return child
    if node.type in {
        "abstract_pointer_declarator",
        "abstract_reference_declarator",
        "parenthesized_declarator",
        "pointer_declarator",
        "reference_declarator",
    }:
        named_children = list(node.named_children)
        if len(named_children) == 1:
            return named_children[0]
    return None


def _cpp_declarator_path(declarator: Any) -> list[Any]:
    """Follow only the declared-name spine, excluding params and initializers."""
    path = [declarator]
    current = declarator
    while current.type not in _CPP_NAME_NODE_TYPES:
        current = _cpp_declarator_child(current)
        if current is None:
            return []
        path.append(current)
    return path


def _cpp_conversion_callable(
    declarator: Any,
    source: bytes,
) -> tuple[Any, str, str] | None:
    scope = ""
    conversion = declarator
    if declarator.type == "qualified_identifier":
        conversion = declarator.child_by_field_name("name")
        scope_node = declarator.child_by_field_name("scope")
        if scope_node is not None:
            scope = _node_text(scope_node, source)
    if conversion is None or conversion.type != "operator_cast":
        return None

    function_declarator = conversion.child_by_field_name("declarator")
    while function_declarator is not None and function_declarator.type not in {
        "abstract_function_declarator",
        "function_declarator",
    }:
        function_declarator = _cpp_declarator_child(function_declarator)
    operator_node = next(
        (child for child in conversion.children if child.type == "operator"),
        None,
    )
    if function_declarator is None or operator_node is None:
        return None
    target_type = source[operator_node.end_byte:function_declarator.start_byte].decode(
        "utf-8", errors="replace"
    ).strip()
    if not target_type:
        return None
    name = f"operator {target_type}"
    return function_declarator, name, scope


def _cpp_callable_declarator(
    declarator: Any,
    source: bytes,
) -> tuple[Any, str, str] | None:
    """Return the function declarator and name for an actual callable symbol.

    Walking from the declared name outward distinguishes a function returning
    a pointer from a pointer object whose pointee is a function: the nearest
    meaningful wrapper decides which one was declared.
    """
    conversion = _cpp_conversion_callable(declarator, source)
    if conversion is not None:
        return conversion

    path = _cpp_declarator_path(declarator)
    if not path:
        return None
    name_node = path[-1]
    for wrapper in reversed(path[:-1]):
        if wrapper.type == "function_declarator":
            scope = ""
            leaf_node = name_node
            if name_node.type == "qualified_identifier":
                scope_node = name_node.child_by_field_name("scope")
                qualified_leaf = name_node.child_by_field_name("name")
                if scope_node is not None:
                    scope = _node_text(scope_node, source)
                if qualified_leaf is not None:
                    leaf_node = qualified_leaf
            return wrapper, _node_text(leaf_node, source), scope
        if wrapper.type in _CPP_OBJECT_DECLARATOR_TYPES:
            return None
    return None


def _cpp_namespace_qualifier(node: Any, source: bytes) -> str:
    namespaces: list[str] = []
    current = node.parent
    while current is not None:
        if current.type == "namespace_definition":
            name_node = current.child_by_field_name("name")
            namespaces.append(
                _node_text(name_node, source) if name_node is not None else "<anonymous>"
            )
        current = current.parent
    return "::".join(reversed(namespaces))


def _cpp_has_ancestor(node: Any, node_type: str) -> bool:
    current = node.parent
    while current is not None:
        if current.type == node_type:
            return True
        current = current.parent
    return False


def _cpp_parameter_signature(params_node: Any, source: bytes) -> tuple[str, ...]:
    """Build a name-insensitive parameter signature for declaration dedup."""
    signatures: list[str] = []
    for parameter in params_node.named_children:
        if parameter.type == "comment":
            continue
        start = parameter.start_byte
        end = parameter.end_byte
        default_value = parameter.child_by_field_name("default_value")
        if default_value is not None:
            end = default_value.start_byte

        declarator = parameter.child_by_field_name("declarator")
        path = _cpp_declarator_path(declarator) if declarator is not None else []
        name_node = path[-1] if path else None
        if name_node is not None and name_node.start_byte < end:
            raw = source[start:name_node.start_byte] + source[name_node.end_byte:end]
        else:
            raw = source[start:end]
        canonical = re.sub(rb"\s+", b"", raw).rstrip(b"=").decode(
            "utf-8", errors="replace"
        )
        signatures.append(canonical)
    return tuple(signatures)


def _cpp_qualifier_signature(function_declarator: Any, source: bytes) -> tuple[str, ...]:
    return tuple(
        re.sub(r"\s+", "", _node_text(child, source))
        for child in function_declarator.named_children
        if child.type in _CPP_SIGNATURE_QUALIFIER_TYPES
    )


# The source last asked for a column and whether it is all ASCII, where a
# column in characters is the column in bytes. Decoding each line prefix
# instead is quadratic on a minified line that thousands of nodes share.
_ASCII_SOURCE: tuple[bytes | None, bool] = (None, False)


def _source_character_column(
    source: bytes, byte_offset: int, line_start: int | None = None
) -> int:
    global _ASCII_SOURCE
    if line_start is None:
        line_start = source.rfind(b"\n", 0, byte_offset) + 1
    cached_source, is_ascii = _ASCII_SOURCE
    if cached_source is not source:
        is_ascii = source.isascii()
        _ASCII_SOURCE = (source, is_ascii)
    if is_ascii:
        return byte_offset - line_start
    return len(source[line_start:byte_offset].decode("utf-8", errors="replace"))


def _node_character_range(node: Any, source: bytes) -> tuple[int, int, int, int]:
    # A tree-sitter point's column is the byte offset from its row's start,
    # and rows end only at `\n`: the line start needs no search.
    start_row, start_column = node.start_point
    end_row, end_column = node.end_point
    return (
        start_row + 1,
        _source_character_column(source, node.start_byte, node.start_byte - start_column),
        end_row + 1,
        _source_character_column(source, node.end_byte, node.end_byte - end_column),
    )


def _attach_callable_spans(
    parsed: dict[str, Any],
    *,
    callable_node: Any,
    source: bytes,
) -> None:
    body = callable_node.child_by_field_name("body")
    if body is None:
        return
    (
        parsed["_body_start_line"],
        parsed["_body_start_column"],
        parsed["_body_end_line"],
        parsed["_body_end_column"],
    ) = _node_character_range(body, source)


def _parse_cpp_callable(
    *,
    container: Any,
    declarator: Any,
    source: bytes,
    is_declaration: bool,
) -> dict[str, Any] | None:
    callable_parts = _cpp_callable_declarator(declarator, source)
    if callable_parts is None:
        return None
    function_declarator, name, declared_scope = callable_parts
    params_node = function_declarator.child_by_field_name("parameters")
    start_line, end_line = _node_lines(container)
    parsed = {
        "name": name,
        "qualified_name": name,
        "line_start": start_line,
        "line_end": end_line,
        "params": _extract_params(params_node, source) if params_node else [],
        "modifiers": [],
        "annotations": [],
        "is_entry_point": False,
        "is_declaration": is_declaration,
        "_start_byte": container.start_byte,
        "_end_byte": container.end_byte,
        "_cpp_is_friend": _cpp_has_ancestor(container, "friend_declaration"),
        "_cpp_declared_scope": declared_scope,
        "_cpp_namespace": _cpp_namespace_qualifier(container, source),
        "_cpp_parameter_signature": (
            _cpp_parameter_signature(params_node, source) if params_node else ()
        ),
        "_cpp_qualifier_signature": _cpp_qualifier_signature(
            function_declarator, source
        ),
    }
    body = container.child_by_field_name("body")
    if body is not None:
        (
            parsed["_body_start_line"],
            parsed["_body_start_column"],
            parsed["_body_end_line"],
            parsed["_body_end_column"],
        ) = _node_character_range(body, source)

    initializer_ranges: list[tuple[int, int, int, int]] = []
    for child in container.named_children:
        if child.type != "field_initializer_list":
            continue
        for initializer in child.named_children:
            if initializer.type != "field_initializer":
                continue
            initializer_children = list(initializer.named_children)
            if len(initializer_children) >= 2:
                initializer_ranges.append(
                    _node_character_range(initializer_children[-1], source)
                )
    if initializer_ranges:
        parsed["_initializer_ranges"] = initializer_ranges
    return parsed


_JAVASCRIPT_CALLABLE_TYPES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)


def _walk_named_nodes(node: Any):
    """Every named node under *node*, itself first, in document pre-order.

    An explicit stack rather than recursion, so a tree nested deeper than
    Python's call stack walks like any other.
    """
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.named_children))


def _normalized_javascript_target(value: str) -> str:
    return value.replace(".prototype.", ".").removesuffix(".prototype")


# An owner or key longer than this, or spanning lines, is code rather than a
# name a reader would search for, such as a bundler's namespace object.
_JAVASCRIPT_NAME_TEXT_LIMIT = 128


def _javascript_name_text(node: Any, source: bytes) -> str:
    text = _node_text(node, source)
    if len(text) <= _JAVASCRIPT_NAME_TEXT_LIMIT and "\n" not in text:
        return text
    line, column, _end_line, _end_column = _node_character_range(node, source)
    return f"<anonymous@{line}:{column}>"


def _javascript_define_property_name(node: Any, source: bytes) -> str | None:
    current = node.parent
    while current is not None:
        if current.type == "call_expression":
            callee = current.child_by_field_name("function")
            if callee is None or _node_text(callee, source) != "Object.defineProperty":
                return None
            arguments = current.child_by_field_name("arguments")
            values = list(arguments.named_children) if arguments is not None else []
            if len(values) < 3:
                return None
            descriptor = values[2]
            if not descriptor.start_byte <= node.start_byte < descriptor.end_byte:
                return None
            target = _normalized_javascript_target(_javascript_name_text(values[0], source))
            property_node = values[1]
            property_name = _javascript_name_text(property_node, source).strip("'\"`")
            if not target or not property_name:
                return None
            return f"{target}.{property_name}"
        current = current.parent
    return None


def _javascript_callable_name(node: Any, source: bytes) -> str:
    explicit_name = node.child_by_field_name("name")
    if explicit_name is not None:
        return _javascript_name_text(explicit_name, source)

    define_property_name = _javascript_define_property_name(node, source)
    if define_property_name:
        return define_property_name

    parent = node.parent
    if parent is not None and parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
        if name is not None:
            return _javascript_name_text(name, source)
    if parent is not None and parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left is not None:
            return _normalized_javascript_target(_javascript_name_text(left, source))
    if parent is not None and parent.type in {"pair", "public_field_definition"}:
        key = parent.child_by_field_name("key") or parent.child_by_field_name("name")
        if key is not None:
            return _javascript_name_text(key, source).strip("'\"`")

    line, column, _end_line, _end_column = _node_character_range(node, source)
    return f"<anonymous@{line}:{column}>"


def _parse_javascript_callable(node: Any, source: bytes) -> dict[str, Any]:
    name = _javascript_callable_name(node, source)
    parameters = node.child_by_field_name("parameters")
    single_parameter = node.child_by_field_name("parameter")
    parsed = {
        "name": name.rsplit(".", 1)[-1],
        "qualified_name": name,
        "line_start": node.start_point[0] + 1,
        "line_end": node.end_point[0] + 1,
        "params": (
            _extract_params(parameters, source)
            if parameters is not None
            else ([_node_text(single_parameter, source)] if single_parameter is not None else [])
        ),
        "modifiers": [],
        "annotations": [],
        "is_entry_point": False,
        "_start_byte": node.start_byte,
        "_end_byte": node.end_byte,
    }
    _attach_callable_spans(parsed, callable_node=node, source=source)
    return parsed


def _extract_javascript_callables(
    tree: Any,
    source: bytes,
) -> list[dict[str, Any]]:
    return [
        _parse_javascript_callable(node, source)
        for node in _named_nodes_of_types(tree, _JAVASCRIPT_CALLABLE_TYPES)
    ]


# PHP's two closure forms. `_CALLABLE_NODE_TYPES["php"]` already named them,
# but that table only bounds the registration walk; nothing extracted them, so
# a `Route::get('/x', function () { ... })` handler and every line of its body
# were read by no detector at all.
_PHP_CLOSURE_TYPES = frozenset({"anonymous_function", "arrow_function"})


# A bound name is an identifier a reader can search for, so it is normalized to
# one line and capped: the backend caps `name` at 512 characters and rejects an
# untrimmed one, and a multi-line array key or property path is not a name a
# reader would recognise anyway.
_PHP_CLOSURE_NAME_LIMIT = 200


def _php_closure_binding(node: Any, source: bytes) -> str:
    """Return the text of whatever binds *node*, or `""` when nothing does."""
    parent = node.parent
    if parent is None:
        return ""
    if parent.type in ("assignment_expression", "property_element"):
        target = parent.child_by_field_name("left") or parent.child_by_field_name("name")
        return _node_text(target, source) if target is not None else ""
    if parent.type == "array_element_initializer":
        # Exactly two children is `key => value`; one child is a positional
        # element, whose only child is the closure itself. Node objects are
        # recreated per access, so `child is node` never holds and identity
        # cannot be what tells the two apart.
        children = parent.named_children
        if len(children) == 2 and children[1].start_byte == node.start_byte:
            return _node_text(children[0], source).strip("'\"")
    return ""


def _php_closure_name(node: Any, source: bytes) -> str:
    """Name a PHP closure after whatever binds it, else after its position."""
    bound = " ".join(_php_closure_binding(node, source).split())
    if bound and len(bound) <= _PHP_CLOSURE_NAME_LIMIT:
        return bound
    line, column, _end_line, _end_column = _node_character_range(node, source)
    return f"<anonymous@{line}:{column}>"


def _parse_php_closure(node: Any, source: bytes) -> dict[str, Any]:
    parameters = node.child_by_field_name("parameters")
    name = _php_closure_name(node, source)
    parsed = {
        "name": name,
        "qualified_name": name,
        "line_start": node.start_point[0] + 1,
        "line_end": node.end_point[0] + 1,
        "params": _extract_params(parameters, source) if parameters is not None else [],
        "modifiers": [
            _node_text(child, source)
            for child in node.children
            if child.type == "static_modifier"
        ],
        "annotations": [],
        "is_entry_point": False,
        # A closure is a value, not a class member: `_detect_exports` treats a
        # modifier-less PHP callable as a public method, and `$formatter` is
        # not part of any file's public API.
        "is_closure": True,
        "_start_byte": node.start_byte,
        "_end_byte": node.end_byte,
    }
    _attach_callable_spans(parsed, callable_node=node, source=source)
    return parsed


def _php_namespace_scopes(tree: Any, source: bytes) -> list[tuple[int, int, str]]:
    """Byte ranges each PHP namespace declaration governs, in source order.

    A braced `namespace Acme\\Billing { ... }` governs its own block and the
    statement form `namespace Acme\\Billing;` governs everything up to the next
    declaration. The unnamed `namespace { ... }` block is the global namespace.
    PHP admits a declaration only as a top-level statement, so the program's
    own children are the whole inventory.
    """
    declarations = [
        node for node in tree.root_node.named_children if node.type == "namespace_definition"
    ]
    scopes: list[tuple[int, int, str]] = []
    for index, node in enumerate(declarations):
        name_node = node.child_by_field_name("name")
        name = "".join(_node_text(name_node, source).split()) if name_node is not None else ""
        body = node.child_by_field_name("body")
        if body is not None:
            scopes.append((body.start_byte, body.end_byte, name))
        else:
            end = declarations[index + 1].start_byte if index + 1 < len(declarations) else len(source)
            scopes.append((node.end_byte, end, name))
    return scopes


def _attach_php_namespaces(tree: Any, source: bytes, symbols: list[dict[str, Any]]) -> None:
    """Record on each PHP symbol the namespace its declaration sits in."""
    scopes = _php_namespace_scopes(tree, source)
    for symbol in symbols:
        symbol["_php_namespace"] = next(
            (name for start, end, name in scopes if start <= symbol["_start_byte"] < end),
            "",
        )


def _extract_php_closures(tree: Any, source: bytes) -> list[dict[str, Any]]:
    return [
        _parse_php_closure(node, source)
        for node in _named_nodes_of_types(tree, _PHP_CLOSURE_TYPES)
    ]


_RUBY_CALL_TYPES = frozenset({"call"})


def _extract_ruby_route_blocks(tree: Any, source: bytes) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for node in _named_nodes_of_types(tree, _RUBY_CALL_TYPES):
        if node.child_by_field_name("receiver") is not None:
            continue
        method = node.child_by_field_name("method")
        arguments = node.child_by_field_name("arguments")
        block = node.child_by_field_name("block")
        if method is None or arguments is None or block is None:
            continue
        verb = _node_text(method, source)
        if verb not in {"get", "post", "put", "patch", "delete", "options", "head"}:
            continue
        path = next((child for child in arguments.named_children if child.type == "string"), None)
        if path is None:
            continue
        line_start, line_end = _node_lines(node)
        name = f"{verb} {_node_text(path, source)}"
        parsed = {
            "name": name,
            "qualified_name": name,
            "line_start": line_start,
            "line_end": line_end,
            "params": [],
            "modifiers": [],
            "annotations": [],
            "is_entry_point": False,
            "_ruby_route": True,
            "_start_byte": node.start_byte,
            "_end_byte": node.end_byte,
        }
        (
            parsed["_body_start_line"],
            parsed["_body_start_column"],
            parsed["_body_end_line"],
            parsed["_body_end_column"],
        ) = _node_character_range(block, source)
        routes.append(parsed)
    return routes


def _extract_cpp_declarations(
    tree: Any,
    language: str,
    source: bytes,
) -> list[dict[str, Any]]:
    parser = _get_parser(language)
    if parser is None:
        return []
    captures = _ts_query_captures(
        parser.language,
        _CPP_DECLARATION_QUERY,
        tree.root_node,
    )
    declarations: list[dict[str, Any]] = []
    seen_declarators: set[tuple[int, int]] = set()
    for node in captures.get("decl", []):
        for declarator in _field_children(node, "declarator"):
            callable_parts = _cpp_callable_declarator(declarator, source)
            if callable_parts is None:
                continue
            function_declarator, _name, _scope = callable_parts
            source_range = (function_declarator.start_byte, function_declarator.end_byte)
            if source_range in seen_declarators:
                continue
            seen_declarators.add(source_range)
            parsed = _parse_cpp_callable(
                container=node,
                declarator=declarator,
                source=source,
                is_declaration=True,
            )
            if parsed is not None:
                declarations.append(parsed)
    return declarations


def _extract_c_declarations(tree: Any, language: str, source: bytes) -> list[dict[str, Any]]:
    parser = _get_parser(language)
    if parser is None:
        return []
    captures = _ts_query_captures(parser.language, _C_DECLARATION_QUERY, tree.root_node)
    declarations: list[dict[str, Any]] = []
    for node in captures.get("decl", []):
        for declarator in _field_children(node, "declarator"):
            callable_node = _c_function_declarator(declarator)
            if callable_node is None or callable_node.type != "function_declarator":
                continue
            name_node = callable_node.child_by_field_name("declarator")
            params_node = callable_node.child_by_field_name("parameters")
            if name_node is None or name_node.type != "identifier":
                continue
            name = _node_text(name_node, source)
            start_line, end_line = _node_lines(node)
            declarations.append({
                "name": name,
                "qualified_name": name,
                "line_start": start_line,
                "line_end": end_line,
                "params": _extract_params(params_node, source) if params_node else [],
                "modifiers": [
                    _node_text(child, source)
                    for child in node.children
                    if child.type == "storage_class_specifier"
                ],
                "annotations": [],
                "is_entry_point": False,
                "is_declaration": True,
                "_start_byte": node.start_byte,
                "_end_byte": node.end_byte,
            })
    return declarations


_CSHARP_LAMBDA_TYPES = frozenset({"lambda_expression"})
_CSHARP_CALLABLE_DECLARATION_TYPES = frozenset({"local_function_statement", "method_declaration"})
_CSHARP_INVOCATION_TYPES = frozenset({"invocation_expression"})


def _extract_functions_ts(tree: Any, language: str, source: bytes) -> list[dict[str, Any]]:
    """Extract function/method definitions and C++ declarations."""
    query_language = _query_language_family(language)
    query_str = _FUNCTION_QUERIES.get(query_language)
    if not query_str:
        return []

    parser = _get_parser(language)
    if parser is None:
        return []

    lang_obj = parser.language

    captures = _ts_query_captures(lang_obj, query_str, tree.root_node)
    functions: list[dict[str, Any]] = []
    seen_ranges: set[tuple[int, int]] = set()

    nodes = captures.get("func", [])

    for node in nodes:
        source_range = (node.start_byte, node.end_byte)
        if source_range in seen_ranges:
            continue
        seen_ranges.add(source_range)

        func_info = _parse_function_node(node, language, source)
        if func_info:
            functions.append(func_info)

    if query_language == "cpp":
        functions.extend(_extract_cpp_declarations(tree, language, source))
        by_start_byte = {function["_start_byte"]: function for function in functions}
        for callback in _cpp_http_route_callbacks(tree, source):
            if callback.type != "lambda_expression":
                continue
            declarator = callback.child_by_field_name("declarator")
            params_node = next(
                (child for child in _walk_named_nodes(declarator) if child.type == "parameter_list"),
                None,
            ) if declarator is not None else None
            if params_node is None or not re.search(r"\bRequest\b", _node_text(params_node, source)):
                continue
            line, column, _, _ = _node_character_range(callback, source)
            name = f"<route@{line}:{column}>"
            parsed = {
                "name": name,
                "qualified_name": name,
                "line_start": line,
                "line_end": callback.end_point[0] + 1,
                "params": _extract_params(params_node, source),
                "modifiers": [],
                "annotations": [],
                "is_entry_point": False,
                "is_closure": True,
                "is_declaration": False,
                "_start_byte": callback.start_byte,
                "_end_byte": callback.end_byte,
                "_cpp_parameter_signature": _cpp_parameter_signature(params_node, source),
                "_cpp_qualifier_signature": (),
            }
            _attach_callable_spans(parsed, callable_node=callback, source=source)
            ancestor = callback.parent
            while ancestor is not None:
                enclosing = by_start_byte.get(ancestor.start_byte)
                if enclosing is not None and enclosing["_end_byte"] == ancestor.end_byte:
                    enclosing.setdefault("_excluded_ranges", []).append(
                        _node_character_range(callback, source)
                    )
                    break
                ancestor = ancestor.parent
            functions.append(parsed)
            by_start_byte[callback.start_byte] = parsed
        functions.sort(key=lambda function: function["_start_byte"])
    elif query_language == "c":
        functions.extend(_extract_c_declarations(tree, language, source))
    elif query_language in {"javascript", "typescript"}:
        functions = _extract_javascript_callables(tree, source)
    elif query_language == "php":
        # Additive, unlike the javascript branch: the PHP query path reads
        # visibility modifiers and `#[Attribute]` groups that a generic
        # callable walk would drop, so closures join those records rather
        # than replacing them. Sorted so a nested closure follows the method
        # that encloses it, the order the query path already produces.
        functions = sorted(
            functions + _extract_php_closures(tree, source),
            key=lambda function: function["_start_byte"],
        )
        _attach_php_namespaces(tree, source, functions)
    elif query_language == "ruby":
        functions = sorted(
            functions + _extract_ruby_route_blocks(tree, source),
            key=lambda function: function["_start_byte"],
        )
    elif query_language == "csharp":
        for node in _named_nodes_of_types(tree, _CSHARP_LAMBDA_TYPES):
            parent = node.parent
            invocation = parent.parent if parent is not None and parent.type == "argument" else None
            if invocation is not None and invocation.type == "argument_list":
                invocation = invocation.parent
            if invocation is None or invocation.type != "invocation_expression":
                continue
            target = invocation.child_by_field_name("function")
            if target is None or not re.search(
                r"\.Map(?:Get|Post|Put|Patch|Delete|Methods|Fallback)\s*$",
                _node_text(target, source),
            ):
                continue
            line, column, _, _ = _node_character_range(node, source)
            name = f"<route@{line}:{column}>"
            parameters = node.child_by_field_name("parameters")
            single_parameter = node.child_by_field_name("parameter")
            parsed = {
                "name": name,
                "qualified_name": name,
                "line_start": line,
                "line_end": node.end_point[0] + 1,
                "params": (
                    _extract_params(parameters, source) if parameters is not None
                    else ([_node_text(single_parameter, source)] if single_parameter is not None else [])
                ),
                "modifiers": [],
                "annotations": [],
                "is_entry_point": False,
                "_minimal_api_route": True,
                "_start_byte": node.start_byte,
                "_end_byte": node.end_byte,
            }
            _attach_callable_spans(parsed, callable_node=node, source=source)
            functions.append(parsed)

        declaration_nodes = {
            node.start_byte: node
            for node in _named_nodes_of_types(tree, _CSHARP_CALLABLE_DECLARATION_TYPES)
        }
        for invocation in _named_nodes_of_types(tree, _CSHARP_INVOCATION_TYPES):
            target = invocation.child_by_field_name("function")
            if target is None or not re.search(
                r"\.Map(?:Get|Post|Put|Patch|Delete|Methods|Fallback)\s*$",
                _node_text(target, source),
            ):
                continue
            arguments = invocation.child_by_field_name("arguments")
            if arguments is None or not arguments.named_children:
                continue
            callback = arguments.named_children[-1]
            if callback.type != "argument" or len(callback.named_children) != 1:
                continue
            identifier = callback.named_children[0]
            if identifier.type != "identifier":
                continue
            name = _node_text(identifier, source)
            candidates: list[tuple[int, dict[str, Any]]] = []
            for func in functions:
                if func["name"] != name:
                    continue
                declaration = declaration_nodes.get(func["_start_byte"])
                if declaration is None:
                    continue
                scope_types = (
                    {"block", "compilation_unit"}
                    if declaration.type == "local_function_statement"
                    else {"class_declaration", "struct_declaration", "record_declaration"}
                )
                scope = declaration.parent
                while scope is not None and scope.type not in scope_types:
                    scope = scope.parent
                if scope is not None and scope.start_byte <= invocation.start_byte < scope.end_byte:
                    candidates.append((scope.end_byte - scope.start_byte, func))
            candidates.sort(key=lambda candidate: candidate[0])
            if candidates and (len(candidates) == 1 or candidates[0][0] < candidates[1][0]):
                candidates[0][1]["_minimal_api_route"] = True

    return functions


# Declarator nodes a C function definition can be wrapped in before its
# `function_declarator` is reached. A pointer return type is by far the
# commonest: `char *copy_name(...)` parses as
# `pointer_declarator(function_declarator(...))`.
_C_DECLARATOR_WRAPPERS = frozenset({
    "array_declarator",
    "parenthesized_declarator",
    "pointer_declarator",
})
_C_NAMED_DECLARATOR_PARENTS = _C_DECLARATOR_WRAPPERS | {"function_declarator"}


def _c_nested_declarator(node: Any) -> Any:
    """Return the declarator *node* wraps.

    `parenthesized_declarator` holds its child with no field name, so the field
    lookup every other wrapper answers to returns nothing there.
    """
    nested = node.child_by_field_name("declarator")
    if nested is not None:
        return nested
    return next(iter(node.named_children), None)


def _c_function_declarator(declarator: Any) -> Any:
    """Descend to the `function_declarator` a C definition's declarator wraps.

    Reading only the direct children of the declarator *field* finds neither the
    name nor the parameters of a pointer-returning function, so the function is
    dropped from the index entirely -- and because `_detect_sinks` scans function
    bodies, every sink inside it goes with it. The byte-identical `.cpp` keeps
    both, because the C++ branch already walks the declarator chain.
    """
    node = declarator
    while node is not None:
        if node.type in _C_DECLARATOR_WRAPPERS:
            node = _c_nested_declarator(node)
            continue
        # A function returning a function pointer nests a second
        # `function_declarator`; the named one is always the innermost.
        inner = (
            node.child_by_field_name("declarator")
            if node.type == "function_declarator"
            else None
        )
        if inner is None or inner.type not in _C_NAMED_DECLARATOR_PARENTS:
            return node
        node = inner
    return None


def _php_attributes(attribute_list: Any, source: bytes) -> list[str]:
    """Return each PHP 8 attribute under *attribute_list*, verbatim as `#[...]`.

    Attributes are the route and authorization table of every modern PHP
    framework, and `_ENTRY_ANNOTATIONS["php"]` is matched against a function's
    ``annotations``, so an attribute dropped here is a controller action that
    can never be an entry point.
    """
    return [
        f"#[{_node_text(attribute, source)}]"
        for group in attribute_list.children
        if group.type == "attribute_group"
        for attribute in group.children
        if attribute.type == "attribute"
    ]


def _parse_function_node(node: Any, language: str, source: bytes) -> dict[str, Any] | None:
    """Parse a single function/method tree-sitter node into a structured dict."""
    start_line, end_line = _node_lines(node)
    language = _query_language_family(language)
    name = ""
    params: list[str] = []
    modifiers: list[str] = []
    annotations: list[str] = []

    if language == "java":
        for child in node.children:
            if child.type == "identifier":
                name = _node_text(child, source)
            elif child.type == "formal_parameters":
                params = _extract_params(child, source)
            elif child.type == "modifiers":
                for mod in child.children:
                    txt = _node_text(mod, source)
                    if txt.startswith("@"):
                        annotations.append(txt.split("(")[0])
                    else:
                        modifiers.append(txt)
    elif language == "cpp":
        decl = node.child_by_field_name("declarator")
        if decl is not None:
            return _parse_cpp_callable(
                container=node,
                declarator=decl,
                source=source,
                is_declaration=False,
            )
    elif language == "c":
        modifiers = [
            _node_text(child, source)
            for child in node.children
            if child.type == "storage_class_specifier"
        ]
        decl = _c_function_declarator(node.child_by_field_name("declarator"))
        if decl:
            for child in decl.children:
                if child.type == "identifier":
                    name = _node_text(child, source)
                elif child.type == "parameter_list":
                    params = _extract_params(child, source)
                elif child.type == "field_identifier":
                    name = _node_text(child, source)
                elif child.type == "qualified_identifier":
                    name = _node_text(child, source)
    elif language == "python":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
        parent = node.parent
        if parent and parent.type == "decorated_definition":
            for child in parent.children:
                if child.type == "decorator":
                    annotations.append(_node_text(child, source).strip())
    elif language in ("javascript", "typescript"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
    elif language == "go":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
        receiver = node.child_by_field_name("receiver")
        if receiver:
            recv_text = _node_text(receiver, source).strip("() ")
            if recv_text:
                annotations.append(f"receiver:{recv_text}")
    elif language == "ruby":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
    elif language == "php":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
        for child in node.children:
            if child.type in ("visibility_modifier", "static_modifier", "abstract_modifier"):
                modifiers.append(_node_text(child, source))
            elif child.type == "attribute_list":
                annotations.extend(_php_attributes(child, source))
    elif language == "csharp":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        params_node = node.child_by_field_name("parameters")
        if params_node:
            params = _extract_params(params_node, source)
        for child in node.children:
            if child.type == "modifier":
                modifiers.append(_node_text(child, source))
            elif child.type == "attribute_list":
                annotations.extend(
                    f"[{_node_text(attribute, source)}]"
                    for attribute in child.named_children
                    if attribute.type == "attribute"
                )

    if not name:
        return None

    parsed = {
        "name": name,
        "qualified_name": name,
        "line_start": start_line,
        "line_end": end_line,
        "params": params,
        "modifiers": modifiers,
        "annotations": annotations,
        "is_entry_point": False,
    }
    parsed["_start_byte"] = node.start_byte
    parsed["_end_byte"] = node.end_byte
    _attach_callable_spans(parsed, callable_node=node, source=source)
    return parsed


def _extract_params(params_node: Any, source: bytes) -> list[str]:
    """Extract parameter text from a parameters node."""
    params: list[str] = []
    for child in params_node.children:
        if child.type in ("formal_parameter", "parameter", "spread_element",
                          "required_parameter", "optional_parameter",
                          "typed_parameter", "default_parameter",
                          "identifier", "typed_default_parameter",
                          "parameter_declaration", "optional_parameter_declaration",
                          "simple_parameter", "property_promotion_parameter",
                          "variadic_parameter", "optional_parameter",
                          "keyword_parameter", "block_parameter",
                          "splat_parameter", "hash_splat_parameter"):
            params.append(_node_text(child, source).strip())
    return params


def _extract_classes_ts(tree: Any, language: str, source: bytes) -> list[dict[str, Any]]:
    """Extract class/struct definitions using tree-sitter queries."""
    query_language = _query_language_family(language)
    query_str = _CLASS_QUERIES.get(query_language)
    if not query_str:
        return []

    parser = _get_parser(language)
    if parser is None:
        return []

    lang_obj = parser.language

    captures = _ts_query_captures(lang_obj, query_str, tree.root_node)
    classes: list[dict[str, Any]] = []

    nodes = captures.get("cls", [])

    for node in nodes:
        start_line, end_line = _node_lines(node)
        cls_info = _parse_class_node(node, language, source)
        if cls_info:
            classes.append(cls_info)

    if query_language == "php":
        _attach_php_namespaces(tree, source, classes)
    elif query_language == "csharp":
        local_interfaces = {
            _node_text(node.child_by_field_name("name"), source)
            for node in nodes
            if node.type == "interface_declaration"
            and node.child_by_field_name("name") is not None
        }
        local_classes = {
            _node_text(node.child_by_field_name("name"), source)
            for node in nodes
            if node.type in {"class_declaration", "record_declaration"}
            and node.child_by_field_name("name") is not None
        }
        for cls in classes:
            base_name = cls["extends"].rsplit("::", 1)[-1].rsplit(".", 1)[-1]
            if cls["extends"] and (
                cls["extends"] in local_interfaces
                or base_name in {"IDisposable", "IAsyncDisposable"} and base_name not in local_classes
            ):
                cls["implements"].insert(0, cls["extends"])
                cls["extends"] = ""

    return classes


def _parse_class_node(node: Any, language: str, source: bytes) -> dict[str, Any] | None:
    """Parse a class/struct tree-sitter node."""
    start_line, end_line = _node_lines(node)
    language = _query_language_family(language)
    name = ""
    extends: str = ""
    implements: list[str] = []
    java_public = False

    if language == "java":
        for child in node.children:
            if child.type == "identifier":
                name = _node_text(child, source)
            elif child.type == "modifiers":
                java_public = any(mod.type == "public" for mod in child.children)
            elif child.type == "superclass":
                for sc in child.children:
                    if sc.type in {"type_identifier", "scoped_type_identifier"}:
                        extends = _node_text(sc, source)
            elif child.type in {"super_interfaces", "extends_interfaces"}:
                for si in child.children:
                    if si.type == "type_list":
                        for ti in si.children:
                            if ti.type in {"type_identifier", "scoped_type_identifier"}:
                                if child.type == "extends_interfaces" and not extends:
                                    extends = _node_text(ti, source)
                                else:
                                    implements.append(_node_text(ti, source))
    elif language in ("c", "cpp"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        # Base classes (C++)
        for child in node.children:
            if child.type == "base_class_clause":
                for base in child.children:
                    if base.type == "type_identifier":
                        extends = _node_text(base, source)
    elif language == "python":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        superclasses = node.child_by_field_name("superclasses")
        if superclasses:
            for child in superclasses.children:
                if child.type == "identifier" or child.type == "attribute":
                    txt = _node_text(child, source)
                    if not extends:
                        extends = txt
                    else:
                        implements.append(txt)
    elif language in ("javascript", "typescript"):
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        for child in node.children:
            if child.type == "class_heritage":
                for hc in child.children:
                    if hc.type == "identifier" or hc.type == "member_expression":
                        extends = _node_text(hc, source)
    elif language == "go":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
    elif language == "ruby":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        superclass_node = node.child_by_field_name("superclass")
        if superclass_node:
            for child in superclass_node.children:
                if child.type in ("constant", "scope_resolution"):
                    extends = _node_text(child, source)
                    break
    elif language == "php":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        elif node.type == "anonymous_class":
            line, column, _end_line, _end_column = _node_character_range(node, source)
            name = f"<anonymous@{line}:{column}>"
        for child in node.children:
            if child.type == "base_clause":
                for gc in child.children:
                    if gc.type in ("name", "qualified_name"):
                        extends = _node_text(gc, source)
                        break
            elif child.type == "class_interface_clause":
                for gc in child.children:
                    if gc.type in ("name", "qualified_name"):
                        implements.append(_node_text(gc, source))
    elif language == "csharp":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = _node_text(name_node, source)
        # Only classes can inherit a base class. An interface/struct base list
        # consists entirely of interfaces; class first bases are resolved
        # against interfaces declared in this file after extraction.
        for child in node.children:
            if child.type == "base_list":
                for base in child.named_children:
                    if base.type in ("identifier", "qualified_name", "generic_name"):
                        txt = _node_text(base, source)
                        if node.type in ("interface_declaration", "struct_declaration"):
                            implements.append(txt)
                        elif not extends:
                            extends = txt
                        else:
                            implements.append(txt)

    if not name:
        return None

    parsed_class = {
        "name": name,
        "extends": extends,
        "implements": implements,
        "line_start": start_line,
        "line_end": end_line,
        "_start_byte": node.start_byte,
        "_end_byte": node.end_byte,
    }
    if language == "cpp":
        parsed_class["_cpp_namespace"] = _cpp_namespace_qualifier(node, source)
    elif language == "java":
        parsed_class["_java_public"] = java_public
    elif language == "csharp":
        parsed_class["_csharp_public"] = any(
            child.type == "modifier" and _node_text(child, source) == "public"
            for child in node.children
        )
    return parsed_class


_RUBY_REQUIRE_RE = re.compile(
    r"""(?:require|require_relative|load)\s*[\(]?\s*['"](.+?)['"]\s*[\)]?"""
)


def _extract_imports_ts(tree: Any, language: str, source: bytes) -> list[str]:
    """Extract import/include strings using tree-sitter queries."""
    query_language = _query_language_family(language)
    if query_language == "ruby":
        return _extract_ruby_imports(source)

    query_str = _IMPORT_QUERIES.get(query_language)
    if not query_str:
        return []

    parser = _get_parser(language)
    if parser is None:
        return []

    lang_obj = parser.language

    captures = _ts_query_captures(lang_obj, query_str, tree.root_node)
    imports: list[str] = []

    nodes = captures.get("imp", [])

    for node in nodes:
        text = _node_text(node, source).strip().rstrip(";")
        if query_language == "java":
            text = text.removeprefix("import").strip()
            text = text.removeprefix("static").strip()
        elif query_language in ("c", "cpp"):
            m = re.search(r'[<"](.+?)[>"]', text)
            if m:
                text = m.group(1)
        elif query_language == "go":
            # A Go `import_spec` may carry an alias, the blank `_`, or `.`
            # before its quoted path (`_ "github.com/lib/pq"`), so the path
            # comes from the spec's own `path` field -- trimming quotes off
            # the whole spec would leave the alias welded to the path.
            path_node = node.child_by_field_name("path")
            if path_node is not None:
                text = _node_text(path_node, source).strip('"`')
            if text.startswith("."):
                continue
        elif query_language == "csharp":
            # `using System.Data.SqlClient;` -> `System.Data.SqlClient`, and
            # `using static System.Math;` -> `System.Math`. A `using alias =
            # Ns.Type;` keeps its `alias = Ns.Type` body verbatim, the same way
            # the other languages leave an aliased import as authored.
            text = text.removeprefix("global").strip().removeprefix("using").strip()
            text = text.removeprefix("static").strip()
        elif query_language == "python":
            pass
        elif query_language in ("javascript", "typescript"):
            pass
        imports.append(text)

    return imports


def _php_use_kind(keyword: Any, source: bytes) -> str:
    return _node_text(keyword, source).lower() if keyword is not None else ""


def _extract_php_imports(tree: Any, source: bytes) -> list[dict[str, Any]]:
    """One normalised record per name each PHP `use` declaration imports.

    A declaration imports several names at once -- `use A, B as C;` and the
    grouped `use Acme\\Http\\{Request, function respond};` -- and its
    `function`/`const` keyword sits on the declaration, on its first clause, or
    on one member of a group. A trait `use` inside a class body and a closure's `use ($x)` are
    different nodes and import nothing.
    """
    parser = _get_parser("php")
    if parser is None:
        return []
    captures = _ts_query_captures(parser.language, _IMPORT_QUERIES["php"], tree.root_node)
    records: list[dict[str, Any]] = []
    for declaration in sorted(captures.get("imp", []), key=lambda node: node.start_byte):
        declared_kind = _php_use_kind(declaration.child_by_field_name("type"), source)
        group = declaration.child_by_field_name("body")
        prefix = ""
        if group is not None:
            prefix_node = next(
                (child for child in declaration.named_children if child.type == "namespace_name"),
                None,
            )
            prefix = _node_text(prefix_node, source) if prefix_node is not None else ""
        elif not declared_kind:
            # `use function A, B;` parses the keyword onto the first clause only,
            # yet it governs every name the declaration lists.
            first = next(
                (child for child in declaration.named_children if child.type == "namespace_use_clause"),
                None,
            )
            if first is not None:
                declared_kind = _php_use_kind(first.child_by_field_name("type"), source)
        for clause in (group or declaration).named_children:
            if clause.type != "namespace_use_clause":
                continue
            alias = clause.child_by_field_name("alias")
            name = next(
                (
                    child
                    for child in clause.named_children
                    if child.type in {"name", "qualified_name"}
                    and (alias is None or child.start_byte != alias.start_byte)
                ),
                None,
            )
            if name is None:
                continue
            text = _node_text(name, source)
            records.append(
                _php_import_record(
                    _php_use_kind(clause.child_by_field_name("type"), source)
                    or declared_kind
                    or "class",
                    f"{prefix}\\{text}" if prefix else text,
                    _node_text(alias, source) if alias is not None else "",
                    clause.start_point[0] + 1,
                )
            )
    return records


# --- PHP inclusion -----------------------------------------------------------
#
# `include`/`require` load and run another file, so each is an import edge.
# The argument is evaluated the way the interpreter would compute a fixed path:
# string literals, `__DIR__` and `__FILE__`, `dirname()` and `realpath()` of
# those, `.` concatenation, and constants the same file defines. Anything else
# -- a variable, a property, a call -- is `dynamic`, and a constant the file
# does not define names itself. The per-file reader never sees the repository,
# so a path it computes stays `unclassified` until `PhpIncludeResolver` checks
# it against the sealed snapshot.

_PHP_INCLUDE_CONSTRUCTS = {
    "include_expression": "include",
    "include_once_expression": "include_once",
    "require_expression": "require",
    "require_once_expression": "require_once",
}
_PHP_INCLUDE_QUERY = "\n".join((
    "[" + " ".join(f"({node_type})" for node_type in _PHP_INCLUDE_CONSTRUCTS) + "] @include",
    "(function_call_expression function: (name)) @call",
    "(const_element) @const",
))
_PHP_CLASS_LIKE_TYPES = frozenset(
    {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}
)
_PHP_STRING_TYPES = frozenset({"string", "encapsed_string", "heredoc", "nowdoc"})
_PHP_STRING_PART_TYPES = frozenset({
    "string_content", "string_value", "escape_sequence", "heredoc_start",
    "heredoc_body", "heredoc_end", "nowdoc_body", "nowdoc_string",
})
# The parts above that are a *container*: a heredoc or nowdoc keeps its text
# and its interpolations one level further down, under its body.
_PHP_STRING_BODY_TYPES = frozenset({"heredoc_body", "nowdoc_body"})
_PHP_STRING_ESCAPES = {"\\\\": "\\", "\\'": "'", '\\"': '"', "\\$": "$"}
# Paths are written with `/` on every platform the repository targets.
_PHP_PATH_CONSTANTS = {"DIRECTORY_SEPARATOR": "/"}
_PHP_URL_PATH = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_PHP_INCLUDE_CANDIDATE_LIMIT = 20
PHP_INCLUDE_STATUSES = frozenset({
    "resolved", "dynamic", "ambiguous", "target_absent", "target_excluded", "target_unindexed",
    "unclassified",
})


class _PhpPath(NamedTuple):
    """A statically known path: plain text, or text after the including file's
    directory raised *levels* times by `dirname()`."""

    anchored: bool
    levels: int
    text: str


class _PhpPathEvaluator:
    """Evaluate one include argument, recording why a value is not static."""

    def __init__(
        self,
        source: bytes,
        constants: dict[str, list[Any]],
        file_name: str,
    ) -> None:
        self.source = source
        self.constants = constants
        self.file_name = file_name
        self.dynamic = False
        self.unresolved: list[str] = []

    def value(self, node: Any, active: frozenset[str] = frozenset()) -> _PhpPath | None:
        node_type = node.type
        if node_type == "parenthesized_expression":
            inner = node.named_children[0] if node.named_children else None
            return self.value(inner, active) if inner is not None else None
        if node_type in _PHP_STRING_TYPES:
            return self._string(node)
        if node_type in {"name", "qualified_name"}:
            return self._constant(_node_text(node, self.source).lstrip("\\"), active)
        if node_type == "class_constant_access_expression":
            self.unresolved.append(_node_text(node, self.source))
            return None
        if node_type == "binary_expression":
            operator = node.child_by_field_name("operator")
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if operator is None or operator.type != "." or left is None or right is None:
                self.dynamic = True
                return None
            return self._concat(self.value(left, active), self.value(right, active))
        if node_type == "function_call_expression":
            return self._call(node, active)
        self.dynamic = True
        return None

    def _string(self, node: Any) -> _PhpPath | None:
        parts: list[str] = []
        stack = list(reversed(node.named_children))
        while stack:
            child = stack.pop()
            if child.type not in _PHP_STRING_PART_TYPES:
                self.dynamic = True
                return None
            if child.type == "escape_sequence":
                text = _node_text(child, self.source)
                parts.append(_PHP_STRING_ESCAPES.get(text, text))
            elif child.named_children:
                stack.extend(reversed(child.named_children))
            elif child.type in {"string_content", "string_value", "nowdoc_string"}:
                parts.append(_node_text(child, self.source))
        return _PhpPath(False, 0, "".join(parts))

    def _constant(self, name: str, active: frozenset[str]) -> _PhpPath | None:
        magic = name.upper()
        if magic == "__DIR__":
            return _PhpPath(True, 0, "")
        if magic == "__FILE__":
            return _PhpPath(True, 0, "/" + self.file_name)
        if name in _PHP_PATH_CONSTANTS:
            return _PhpPath(False, 0, _PHP_PATH_CONSTANTS[name])
        definitions = self.constants.get(name, [])
        if name not in active and definitions:
            values = {self.value(definition, active | {name}) for definition in definitions}
            if len(values) == 1 and None not in values:
                return values.pop()
            if None not in values:
                # Every definition is static but they differ, as on two
                # branches: which one runs is decided at run time.
                self.dynamic = True
                return None
        if not self.dynamic:
            self.unresolved.append(name)
        return None

    def _concat(self, left: _PhpPath | None, right: _PhpPath | None) -> _PhpPath | None:
        if left is None or right is None:
            return None
        if right.anchored:
            if left.anchored or left.text:
                self.dynamic = True
                return None
            return right
        return _PhpPath(left.anchored, left.levels, left.text + right.text)

    def _call(self, node: Any, active: frozenset[str]) -> _PhpPath | None:
        function = node.child_by_field_name("function")
        name = _node_text(function, self.source).lstrip("\\").lower() if function is not None else ""
        arguments = node.child_by_field_name("arguments")
        values = [
            argument.named_children[0]
            for argument in (arguments.named_children if arguments is not None else ())
            if argument.type == "argument" and argument.named_children
        ]
        if name == "realpath" and len(values) == 1:
            return self.value(values[0], active)
        if name == "dirname" and len(values) in {1, 2}:
            levels = 1
            if len(values) == 2:
                text = _node_text(values[1], self.source).replace("_", "")
                if values[1].type != "integer" or not text.isdigit():
                    self.dynamic = True
                    return None
                # A path never has more levels than this; the bound only keeps a
                # nonsense literal from costing a loop of its own size.
                levels = min(int(text), 256)
            path = self.value(values[0], active)
            for _level in range(levels):
                path = _php_dirname(path) if path is not None else None
            return path
        self.dynamic = True
        return None


def _php_dirname(path: _PhpPath) -> _PhpPath:
    """PHP's `dirname()`, which is string arithmetic and never touches a disk."""
    text = path.text.rstrip("/") if path.text not in {"", "/"} else path.text
    if not path.anchored:
        head = text.rsplit("/", 1)[0] if "/" in text else "."
        return _PhpPath(False, 0, head or "/")
    if not text:
        return _PhpPath(True, path.levels + 1, "")
    if "/" not in text:
        # `__DIR__ . 'x'` glued a name onto the directory itself.
        return _PhpPath(True, path.levels + 1, "")
    head = text.rsplit("/", 1)[0]
    return _PhpPath(True, path.levels, head)


def _php_defined_constants(captures: dict[str, list[Any]], source: bytes) -> dict[str, list[Any]]:
    """Value nodes of every global constant the file defines, by name."""
    constants: dict[str, list[Any]] = {}
    for call in captures.get("call", []):
        function = call.child_by_field_name("function")
        if function is None or _node_text(function, source).lower() != "define":
            continue
        arguments = call.child_by_field_name("arguments")
        values = [
            argument.named_children[0]
            for argument in (arguments.named_children if arguments is not None else ())
            if argument.type == "argument" and argument.named_children
        ]
        if len(values) < 2 or values[0].type not in {"string", "encapsed_string"}:
            continue
        name_parts = [child for child in values[0].named_children if child.type != "string_content"]
        if name_parts:
            continue
        constants.setdefault(
            "".join(_node_text(child, source) for child in values[0].named_children), []
        ).append(values[1])
    for element in captures.get("const", []):
        ancestor = element.parent
        while ancestor is not None and ancestor.type not in _PHP_CLASS_LIKE_TYPES:
            ancestor = ancestor.parent
        if ancestor is not None:
            continue
        children = element.named_children
        if len(children) == 2 and children[0].type == "name":
            constants.setdefault(_node_text(children[0], source), []).append(children[1])
    return constants


class _PhpIncludeSite(NamedTuple):
    node: Any
    construct: str
    argument: Any | None


def _php_include_sites(tree: Any, source: bytes) -> tuple[list[_PhpIncludeSite], dict[str, list[Any]]]:
    """Every inclusion construct in the file, in source order, and the file's constants."""
    parser = _get_parser("php")
    if parser is None:
        return [], {}
    captures = _ts_query_captures(parser.language, _PHP_INCLUDE_QUERY, tree.root_node)
    sites = [
        _PhpIncludeSite(
            node,
            _PHP_INCLUDE_CONSTRUCTS[node.type],
            next((child for child in node.named_children if not _is_comment_node(child)), None),
        )
        for node in sorted(captures.get("include", []), key=lambda item: item.start_byte)
    ]
    return sites, _php_defined_constants(captures, source)


class _PhpInclude(NamedTuple):
    """One inclusion read once: its import edge and its sink argument."""

    site: _PhpIncludeSite
    target: dict[str, Any]


def _php_include(
    site: _PhpIncludeSite,
    source: bytes,
    constants: dict[str, list[Any]],
    file_path: str,
) -> _PhpInclude:
    """Evaluate one inclusion: the `import_targets` record, before snapshot
    resolution, whose raw argument its sink carries."""
    record: dict[str, Any] = {
        "raw": _php_call_text(site.argument, source) if site.argument is not None else "",
        "resolved": "",
        "kind": "include",
        "construct": site.construct,
        "line": site.node.start_point[0] + 1,
    }
    evaluator = _PhpPathEvaluator(source, constants, file_path.replace("\\", "/").rsplit("/", 1)[-1])
    path = evaluator.value(site.argument) if site.argument is not None else None
    if evaluator.dynamic or site.argument is None:
        record["status"] = "dynamic"
    elif evaluator.unresolved:
        record["status"] = f"constant_unresolved:{evaluator.unresolved[0]}"
    elif path is not None:
        record.update(_php_static_include_target(path, file_path))
    else:
        record["status"] = "dynamic"
    return _PhpInclude(site, record)


def _php_static_include_target(path: _PhpPath, file_path: str) -> dict[str, str]:
    if path.anchored:
        segments = [".."] * path.levels
        text = path.text
        if text and not text.startswith("/"):
            # The name was glued onto a directory: `__DIR__ . 'x.php'` is a
            # sibling of that directory whose name starts with the directory's.
            directories = [part for part in file_path.replace("\\", "/").split("/")[:-1] if part]
            if path.levels >= len(directories):
                return {"status": "target_absent", "anchor": "file_dir", "path": text}
            segments.append("..")
            text = directories[len(directories) - 1 - path.levels] + text
        relative = posixpath.normpath("/".join([*segments, text.lstrip("/")]).strip("/") or ".")
        return {"status": "unclassified", "anchor": "file_dir", "path": relative}
    text = path.text
    if not text or _PHP_URL_PATH.match(text):
        return {"status": "target_absent", "anchor": "url" if text else "include_path", "path": text}
    if text.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", text):
        return {"status": "target_absent", "anchor": "absolute", "path": text}
    anchor = (
        "working_directory"
        if text in {".", ".."} or text.startswith(("./", "../"))
        else "include_path"
    )
    return {"status": "unclassified", "anchor": anchor, "path": posixpath.normpath(text)}


def _php_includes(tree: Any, source: bytes, file_path: str) -> list[_PhpInclude]:
    """Every inclusion in the file, evaluated once for its import edge and its sink."""
    sites, constants = _php_include_sites(tree, source)
    return [_php_include(site, source, constants, file_path) for site in sites]


def _php_include_sinks(
    includes: list[_PhpInclude],
    locator: _PhpCallableLocator,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """A `file_inclusion` sink per inclusion construct, read off the parse tree.

    Each is attributed to its innermost callable or `<top-level>` and names
    its argument. A literal inclusion stays a sink: whether a fixed
    path matters is the reviewer's call. What a line only spells like an
    inclusion -- a comment, a string, an array key, a `$include` variable,
    `$this->include()` -- has no inclusion node, so it is not one.
    """
    sinks: list[dict[str, Any]] = []
    for include in includes:
        node = include.site.node
        caller = locator.innermost(node.start_byte, node.end_byte)
        line_index = node.start_point[0]
        sinks.append({
            "kind": "file_inclusion",
            "line": line_index + 1,
            "function": caller["name"] if caller is not None else "<top-level>",
            "snippet": _snippet(source_lines[line_index]) if line_index < len(source_lines) else "",
            "vuln_classes": list(_PHP_FILE_INCLUSION_VULN_CLASSES),
            "argument": include.target["raw"],
        })
    return sinks


def _repo_join(directory: str, path: str) -> str | None:
    """`directory/path` as a repository path, or None when it leaves the root."""
    parts: list[str] = []
    for part in [*directory.split("/"), *path.split("/")]:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


class PhpIncludeResolver:
    """Resolve the static PHP include paths the per-file reader computed.

    A `__DIR__`-anchored path names one file: `resolved` when the snapshot
    holds it and the structural index reads its language, `target_unindexed`
    when it is in the snapshot under a language no extractor reads,
    `target_excluded` when it lies at or under an entry of the sealed exclusion
    inventory (*excluded_paths*, such as `vendor/`), and `target_absent` when it
    is not there or leaves the repository. A path the interpreter looks up
    through `include_path` or the working directory names no single file, so it
    is `ambiguous` and lists the snapshot files it could be, nearest first, and
    the exclusion entry holding the path from the including file's directory or
    the repository root when one does.
    """

    def __init__(
        self, snapshot_languages: dict[str, str], excluded_paths: Iterable[str] = ()
    ) -> None:
        self.snapshot_languages = snapshot_languages
        self.excluded_paths = frozenset(path for path in excluded_paths if path)
        self._by_basename: dict[str, list[str]] = {}
        for path in sorted(snapshot_languages):
            self._by_basename.setdefault(path.rsplit("/", 1)[-1], []).append(path)

    def resolve(self, indexed: dict[str, Any], *, rel_path: str) -> None:
        directory = posixpath.dirname(rel_path)
        for target in indexed.get("import_targets", []):
            if (
                target.get("kind") != "include"
                or target.get("status") != "unclassified"
                or "anchor" not in target
            ):
                continue
            if target["anchor"] == "file_dir":
                self._resolve_anchored(target, directory)
            else:
                self._resolve_ambiguous(target, directory)

    def _resolve_anchored(self, target: dict[str, Any], directory: str) -> None:
        repo_path = _repo_join(directory, target["path"])
        language = self.snapshot_languages.get(repo_path) if repo_path is not None else None
        if repo_path is None or language is None:
            excluded = self._excluded_entry(repo_path)
            target["status"] = "target_absent" if excluded is None else "target_excluded"
            if excluded is not None:
                target["excluded_entry"] = excluded
            return
        target["resolved"] = repo_path
        target["status"] = (
            "resolved" if language in STRUCTURAL_SUPPORTED_LANGUAGES else "target_unindexed"
        )

    def _resolve_ambiguous(self, target: dict[str, Any], directory: str) -> None:
        path = target["path"]
        ordered = [_repo_join(directory, path), _repo_join("", path)]
        if target["anchor"] == "include_path":
            suffix = "/" + path
            ordered.extend(
                candidate
                for candidate in self._by_basename.get(path.rsplit("/", 1)[-1], [])
                if candidate.endswith(suffix)
            )
        candidates: list[str] = []
        seen: set[str] = set()
        for candidate in ordered:
            if (
                candidate is not None
                and candidate in self.snapshot_languages
                and candidate not in seen
            ):
                candidates.append(candidate)
                seen.add(candidate)
        target["status"] = "ambiguous"
        target["candidates"] = candidates[:_PHP_INCLUDE_CANDIDATE_LIMIT]
        target["candidate_count"] = len(candidates)
        excluded = next(
            (entry for entry in map(self._excluded_entry, ordered[:2]) if entry is not None), None
        )
        if excluded is not None:
            target["excluded_entry"] = excluded

    def _excluded_entry(self, repo_path: str | None) -> str | None:
        """The outermost exclusion entry at or above *repo_path*, if any."""
        if repo_path is None or not self.excluded_paths:
            return None
        parts = repo_path.split("/")
        return next(
            (
                prefix
                for prefix in ("/".join(parts[:depth]) for depth in range(1, len(parts) + 1))
                if prefix in self.excluded_paths
            ),
            None,
        )


def _extract_import_records(
    tree: Any,
    language: str,
    source: bytes,
    php_includes: list[_PhpInclude],
) -> tuple[list[str], list[dict[str, Any]]]:
    """The `imports` strings and their `import_targets`, one entry per import."""
    query_language = _query_language_family(language)
    if query_language == "php":
        targets = sorted(
            [*_extract_php_imports(tree, source), *(include.target for include in php_includes)],
            key=lambda target: target["line"],
        )
        return [target["raw"] for target in targets], targets
    imports = _extract_imports_ts(tree, language, source)
    return imports, _resolve_import_targets(imports, query_language)


def _source_lines(source: bytes) -> list[str]:
    """Split lines where the snapshot counts them: at CR, LF and CRLF only."""
    lines = re.split(r"\r\n|\r|\n", source.decode("utf-8", errors="replace"))
    if not lines[-1]:
        lines.pop()
    return lines


def _extract_ruby_imports(source: bytes) -> list[str]:
    """Extract require/require_relative/load from Ruby source via regex."""
    imports: list[str] = []
    for line in _source_lines(source):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for m in _RUBY_REQUIRE_RE.finditer(line):
            imports.append(m.group(1))
    return imports


@lru_cache(maxsize=1024)
def _gated_line_pattern(pattern: str) -> tuple[re.Pattern[str], frozenset[str] | None]:
    compiled = re.compile(pattern)
    return compiled, _gate_literals(compiled)


def _line_pattern_matches(pattern: str, line: str) -> bool:
    """Whether `re.search(pattern, line)` matches; a line holding none of the
    literals every match requires is answered without running the pattern."""
    compiled, literals = _gated_line_pattern(pattern)
    if literals is not None and not any(literal in line for literal in literals):
        return False
    return compiled.search(line) is not None


def _detect_top_level_entry_points(
    tree: Any,
    language: str,
    source_lines: list[str],
    attributed: list[dict[str, Any]],
    file_scope_lines: list[tuple[int, str]],
) -> list[dict[str, Any]]:
    """Detect registrations and guards written as direct program children.

    *file_scope_lines* is the ``<top-level>`` scope. A route-table pattern
    reads every line of its statement, but only the lines that scope holds: a
    program child can be a function definition, and the table inside an app
    factory is the function-scoped pass's to attribute.

    *attributed* is what the function-scoped pass already found. A statement
    that registers a callable defined inline (`Route::get('/x', function () {
    ... })`) is reported there against the handler, which is the better record
    -- it carries the handler's name and bounds a scan scope -- so the same
    statement must not also yield a second, nameless entry point here.
    """
    entry_points: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    patterns = _GLOBAL_ENTRY_LINE_PATTERNS.get(language, [])
    if not patterns:
        return entry_points
    file_scope_text = {index + 1: text for index, text in file_scope_lines}

    for node in getattr(tree.root_node, "named_children", ()):
        # A comment is a named child in every shipped grammar, so an unanchored
        # body pattern (PHP registers its route table that way) reads a
        # commented-out registration as a live one. That inflates
        # `total_entry_points` and feeds `entry_point_proximity`, which puts a
        # reachability claim on code that does not run.
        if _is_comment_node(node):
            continue
        line_number = node.start_point[0] + 1
        if line_number > len(source_lines):
            continue
        statement_lines = range(line_number, node.end_point[0] + 2)
        for pattern in patterns:
            # A registration statement is read on its first line. A route table
            # is one statement whose every row registers a route, so its
            # patterns read each line the statement spans.
            candidate_lines = (
                [
                    (number, file_scope_text[number])
                    for number in statement_lines
                    if number in file_scope_text
                ]
                if pattern.get("statement_lines") == "all"
                else [(line_number, source_lines[line_number - 1])]
            )
            for candidate, text in candidate_lines:
                identity = (candidate, pattern["kind"])
                if identity in seen or not _line_pattern_matches(pattern["pattern"], text):
                    continue
                if any(
                    entry["kind"] == pattern["kind"] and entry["line"] in statement_lines
                    for entry in attributed
                ):
                    continue
                entry_points.append({
                    "name": "<top-level>",
                    "line": candidate,
                    "kind": pattern["kind"],
                    "annotation": "",
                })
                seen.add(identity)
    return entry_points


@lru_cache(maxsize=None)
def _php_request_input_patterns() -> tuple[re.Pattern[str], ...]:
    """The canonical PHP request-input table, compiled as the source scan reads
    it, less `$_SERVER['argv']`, which is command-line evidence first."""
    return tuple(
        re.compile(pattern, re.IGNORECASE)
        for kind, pattern in _STREAM_SOURCE_PATTERNS["php"]
        if kind == "http_request_input" and pattern != _PHP_SERVER_ARGV
    )


@lru_cache(maxsize=None)
def _php_cli_evidence_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple(
        (evidence, re.compile(pattern, re.IGNORECASE))
        for evidence, pattern in _PHP_CLI_ENTRY_EVIDENCE
    )


# A superglobal subscript followed by `=` is written, not read; `unset()` and
# `isset($_SERVER[...])` -- the probe a command-line script uses to refuse a
# web request -- read no request data.
_PHP_SUPERGLOBAL_WRITE = re.compile(r"\s*(?:\[[^\]\n]*\]\s*)*=(?![=>])")
_PHP_UNSET_ARGUMENTS = re.compile(r"\bunset\s*\([^)]*$", re.IGNORECASE)
_PHP_SERVER_ISSET = re.compile(r"\bisset\s*\(\s*$", re.IGNORECASE)
# Composer writes this marker into every file it generates. Its autoloader
# picks STDERR or echo by `PHP_SAPI` to report an unsupported PHP version, on
# the web and the command line alike.
_COMPOSER_GENERATED = re.compile(rb"@generated by Composer|\bComposerAutoloaderInit\w*::")
_PHP_DEFINED_PROBE = re.compile(r"\bdefined\s*\(", re.IGNORECASE)
_PHP_FILE_SCOPE_THIS = re.compile(r"(?-i:\$this)\b")


def _php_reads(pattern: re.Pattern[str], line: str) -> bool:
    """Whether *line* reads what *pattern* names, rather than writing or unsetting it."""
    for match in pattern.finditer(line):
        prefix = line[:match.start()]
        if _PHP_SUPERGLOBAL_WRITE.match(line, match.end()) or _PHP_UNSET_ARGUMENTS.search(prefix):
            continue
        if match.group().startswith("$_SERVER") and _PHP_SERVER_ISSET.search(prefix):
            continue
        return True
    return False


def _php_direct_access_guard(tree: Any, source: bytes) -> bool:
    """Whether the file refuses a direct request with a `defined()` guard.

    `defined('_JEXEC') or die;` and `if (!defined('X')) { exit; }` mark a file
    its framework includes -- a view, a layout, a partial -- and that answers
    a request for it by stopping.
    """
    stack = list(getattr(tree.root_node, "named_children", ()))
    while stack:
        node = stack.pop()
        if node.type == "namespace_definition":
            body = node.child_by_field_name("body")
            stack.extend(body.named_children if body is not None else ())
            continue
        if node.type == "expression_statement" and len(node.named_children) == 1:
            guard = node.named_children[0]
            if (
                guard.type == "binary_expression"
                and _php_declares_only(guard, source)
                and (right := guard.child_by_field_name("right")) is not None
                and _php_literal_exit(right, source)
            ):
                return True
        if node.type == "if_statement" and node.child_by_field_name("alternative") is None:
            condition = node.child_by_field_name("condition")
            body = node.child_by_field_name("body")
            statements = [
                statement
                for statement in (
                    (body.named_children if body.type in {"compound_statement", "colon_block"} else [body])
                    if body is not None else []
                )
                if not _is_comment_node(statement)
            ]
            if (
                condition is not None
                and _PHP_DEFINED_PROBE.search(_node_text(condition, source))
                and _php_existence_probe(condition, source)
                and statements
                and all(_php_literal_exit(statement, source) for statement in statements)
            ):
                return True
    return False


def _detect_php_file_scope_entry(
    file_scope: _FileScope,
    source: bytes,
    tree: Any,
    executable_lines: set[int],
) -> list[dict[str, Any]]:
    """A PHP file whose file scope runs on a request or a command is itself the entry point.

    Classic PHP has no router: the web server maps a URL to the file and runs
    its top-level statements, so a page reading `$_GET` at file scope is an
    HTTP entry point by definition. The evidence is the canonical request-input
    table read over the file-scope lines of statements that run
    (*executable_lines*), which already have commentary and inline HTML
    blanked, so a `$_GET` named in a comment, in page prose or in a class
    member is not a read, and neither is a write or an `unset()`. Inline HTML
    alone marks a rendered page: the server sends it back when the file is
    requested, but nothing in it proves request input reaches the file, so it
    carries its own, weaker kind. A file whose file scope uses `$this`, or
    that refuses a direct request with a `defined()` guard, is a view its
    framework renders, not a page a URL reaches. A script run from a shell is
    the same shape with another input: a shebang, a SAPI check, or a read of
    its arguments or standard input at file scope makes it a
    `php_cli_script`, whose annotation names that evidence. A dual-mode file
    is both. One record per kind -- the file is the entry, not each line that
    reads input.
    """
    entries: list[dict[str, Any]] = []
    patterns = _php_request_input_patterns()
    executable = [(index, line) for index, line in file_scope.scanned if index in executable_lines]
    request_line = next(
        (
            index + 1
            for index, line in executable
            if any(_php_reads(pattern, line) for pattern in patterns)
        ),
        None,
    )
    if request_line is not None:
        entries.append({
            "name": "<top-level>",
            "line": request_line,
            "kind": "php_script",
            "annotation": "request_input",
        })
    elif (
        file_scope.inline_text_lines
        and not any(_PHP_FILE_SCOPE_THIS.search(line) for _index, line in executable)
        and not _php_direct_access_guard(tree, source)
    ):
        entries.append({
            "name": "<top-level>",
            "line": file_scope.inline_text_lines[0],
            "kind": "php_rendered_page",
            "annotation": "inline_html",
        })
    cli_evidence: tuple[int, str] | None = (1, "shebang") if source.startswith(b"#!") else None
    if cli_evidence is None:
        cli_patterns = _php_cli_evidence_patterns()
        if _COMPOSER_GENERATED.search(source) is not None:
            cli_patterns = tuple(item for item in cli_patterns if item[0] != "sapi_check")
        cli_evidence = next(
            (
                (index + 1, evidence)
                for index, line in executable
                for evidence, pattern in cli_patterns
                if _php_reads(pattern, line)
            ),
            None,
        )
    if cli_evidence is not None:
        entries.append({
            "name": "<top-level>",
            "line": cli_evidence[0],
            "kind": "php_cli_script",
            "annotation": cli_evidence[1],
        })
    return entries


# Call nodes, per grammar family, for the walk from a callable to the call that
# registers it. Read off the shipped grammars rather than assumed: php names
# four distinct call nodes, and ruby folds commands into a single `call`.
_CALL_NODE_TYPES: dict[str, frozenset[str]] = {
    "c": frozenset({"call_expression"}),
    "cpp": frozenset({"call_expression"}),
    "go": frozenset({"call_expression"}),
    "javascript": frozenset({"call_expression"}),
    "typescript": frozenset({"call_expression"}),
    "php": frozenset({
        "function_call_expression",
        "member_call_expression",
        "nullsafe_member_call_expression",
        "scoped_call_expression",
    }),
    "ruby": frozenset({"call"}),
}

# The walk stops at the first callable it crosses. A closure nested inside a
# registered callback is registered by nothing; only the callback the route
# call itself receives is the request surface.
_CALLABLE_NODE_TYPES: dict[str, frozenset[str]] = {
    "c": frozenset({"function_definition"}),
    "cpp": frozenset({"function_definition", "lambda_expression"}),
    "go": frozenset({"func_literal", "function_declaration", "method_declaration"}),
    "javascript": _JAVASCRIPT_CALLABLE_TYPES,
    "typescript": _JAVASCRIPT_CALLABLE_TYPES,
    "php": frozenset({
        "anonymous_function",
        "arrow_function",
        "function_definition",
        "method_declaration",
    }),
    "ruby": frozenset({"block", "do_block", "lambda", "method", "singleton_method"}),
}


def _registering_call_lines(
    tree: Any,
    function: dict[str, Any],
    language: str,
    line_count: int,
) -> list[int]:
    """1-based first lines of the calls that receive *function* as an argument.

    A callback is registered by the call it is passed to, so that call's own
    first line is where the framework registration is written -- however many
    argument lines sit between the two. Prettier's 80-column wrap puts them on
    different lines for the majority of real Express/Koa/Fastify routes.

    Nested calls are walked through so an adapter (`asyncHandler(fn)`) does not
    hide the route call above it, and the walk stops at the first enclosing
    callable, which is what makes this structural rather than positional: a
    function merely stacked near a registration has no enclosing call at all.
    """
    call_types = _CALL_NODE_TYPES.get(language, frozenset())
    start_byte = function.get("_start_byte")
    end_byte = function.get("_end_byte")
    if not call_types or start_byte is None or end_byte is None:
        return []

    node = tree.root_node.descendant_for_byte_range(start_byte, end_byte)
    if node is None:
        return []

    callable_types = _CALLABLE_NODE_TYPES.get(language, frozenset())
    lines: list[int] = []
    current = node.parent
    while current is not None:
        if current.type in callable_types:
            break
        if current.type in call_types:
            line = current.start_point[0] + 1
            if 1 <= line <= line_count:
                lines.append(line)
        current = current.parent
    return lines


def _ruby_method_is_public(tree: Any, function: dict[str, Any], source: bytes) -> bool:
    node = tree.root_node.descendant_for_byte_range(
        function["_start_byte"], function["_end_byte"]
    )
    if node is None:
        return False
    body = node.parent
    if body is None or body.type != "body_statement":
        return False
    visibility = "public"
    for sibling in body.named_children:
        if sibling.start_byte >= node.start_byte:
            break
        if sibling.type == "identifier":
            token = _node_text(sibling, source)
            if token in {"public", "private", "protected"}:
                visibility = token
    return visibility == "public"


def _is_go_http_handler(function: dict[str, Any], http_aliases: set[str]) -> bool:
    """Whether a Go callable has exactly the `net/http` handler signature.

    `ServeMux`, every router built on it, and a hand-rolled route slice walked
    in a loop all dispatch to this shape, so the signature is the evidence the
    registration line cannot be: `mux.HandleFunc(rt.path, rt.handler)` names
    no handler at all. Exactly two parameters, because a helper that takes the
    pair and more (`writeJSON(w, r, v)`) is called by a handler, not routed to.
    """
    params = [param.strip() for param in function.get("params", [])]
    if len(params) != 2 or not http_aliases:
        return False
    alias = "|".join(re.escape(name) for name in sorted(http_aliases))
    return bool(
        re.fullmatch(rf"(?:\w+\s+)?(?:{alias})\.ResponseWriter", params[0])
        and re.fullmatch(rf"(?:\w+\s+)?\*\s*(?:{alias})\.Request", params[1])
    )


_TORNADO_VERB_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})


def _tornado_handler_classes(classes: list[dict[str, Any]]) -> set[str]:
    """Names of in-file classes that are, directly or through a base, Tornado handlers.

    Python's bases land in `extends` and `implements` by position, so a mixin
    written first (`class H(AuthMixin, RequestHandler)`) puts the handler base
    in `implements`; both are read, and in-file bases are followed to a fixed
    point so a `BaseHandler` chain resolves.
    """
    handlers: set[str] = set()
    changed = True
    while changed:
        changed = False
        for cls in classes:
            if cls["name"] in handlers:
                continue
            bases = {
                base.rsplit(".", 1)[-1]
                for base in [cls.get("extends") or "", *cls.get("implements", [])]
                if base
            }
            if "RequestHandler" in bases or bases & handlers:
                handlers.add(cls["name"])
                changed = True
    return handlers


_NODE_HTTP_MODULE_RE = r"['\"](?:node:)?https?2?['\"]"


def _node_http_module_names(source: bytes) -> tuple[set[str], bool, bool]:
    """Names bound to Node's http/https/http2 modules, whether a bare
    `createServer` was imported from one, and whether the file loads one at all."""
    text = source.decode("utf-8", errors="replace")
    loads_http = re.search(
        rf"\brequire\s*\(\s*{_NODE_HTTP_MODULE_RE}\s*\)|\bfrom\s+{_NODE_HTTP_MODULE_RE}", text
    ) is not None
    names = {"http", "https", "http2"}
    names.update(re.findall(
        rf"\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*{_NODE_HTTP_MODULE_RE}\s*\)", text
    ))
    names.update(re.findall(
        rf"\bimport\s+(?:\*\s+as\s+)?(\w+)\s+from\s+{_NODE_HTTP_MODULE_RE}", text
    ))
    bare = re.search(
        rf"\bcreateServer\b[^;\n]*(?:require\s*\(\s*|from\s+){_NODE_HTTP_MODULE_RE}", text
    ) is not None
    return names, bare, loads_http


def _node_server_handler_arguments(
    node: Any, source: bytes, modules: set[str], bare: bool, loads_http: bool
) -> list[Any] | None:
    """The arguments of a Node HTTP server registration that can be its handler.

    `http.createServer(handler)` and `https.createServer(options, handler)`
    take the request listener in either position; `server.on('request', fn)`
    attaches one afterwards, and is read only in a file that loads an HTTP
    module, because a browser-automation `page.on('request', fn)` has the same
    shape. `net.createServer` is a TCP server and is not read. None when *node*
    is not such a registration.
    """
    target = node.child_by_field_name("function")
    arguments = node.child_by_field_name("arguments")
    if target is None or arguments is None:
        return None
    actual = list(arguments.named_children)
    if target.type == "member_expression":
        receiver = target.child_by_field_name("object")
        prop = target.child_by_field_name("property")
        prop_text = _node_text(prop, source) if prop is not None else ""
        if prop_text == "on":
            if (
                loads_http
                and len(actual) >= 2
                and actual[0].type == "string"
                and _node_text(actual[0], source).strip("'\"`") == "request"
            ):
                return actual[1:]
            return None
        if prop_text != "createServer" or receiver is None:
            return None
        receiver_text = _node_text(receiver, source)
        if receiver_text not in modules and not re.fullmatch(
            rf"require\s*\(\s*{_NODE_HTTP_MODULE_RE}\s*\)", receiver_text
        ):
            return None
    elif not (target.type == "identifier" and bare and _node_text(target, source) == "createServer"):
        return None
    # The listener is the last argument; an options object or variable precedes it.
    return actual[-1:]


def _php_controller_classes(classes: list[dict[str, Any]], file_path: str) -> set[int]:
    """Ids of the classes whose public methods Laravel routes to.

    Under an `Http\\Controllers` namespace or path any named class may be
    routed, whatever it extends or is called.
    """
    in_controllers = "/http/controllers/" in f"/{file_path}".lower()
    return {
        id(cls)
        for cls in classes
        if not cls["name"].startswith("<anonymous@")
        and (
            in_controllers
            or re.search(r"(?:^|\\)http\\controllers(?:\\|$)", cls["_php_namespace"], re.IGNORECASE)
            or (cls["name"].endswith("Controller") and (cls.get("extends") or "").endswith("Controller"))
        )
    }


def _detect_entry_points(
    tree: Any,
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
    source: bytes,
    file_path: str = "",
) -> list[dict[str, Any]]:
    """Identify entry-point functions via annotations, names, and line patterns."""
    entry_points: list[dict[str, Any]] = []

    # Build class-membership lookup: line -> class name
    class_for_line: dict[int, dict[str, Any]] = {}
    for cls in classes:
        for line in range(cls["line_start"], cls["line_end"] + 1):
            class_for_line[line] = cls

    annotation_defs = _ENTRY_ANNOTATIONS.get(language, [])
    method_name_defs = _ENTRY_METHOD_NAMES.get(language, [])
    line_pattern_defs = _ENTRY_LINE_PATTERNS.get(language, [])
    c_http_callbacks = _c_http_callback_names(tree, source) if language == "c" else set()
    cpp_http_callbacks = _cpp_http_route_callbacks(tree, source) if language == "cpp" else []
    cpp_http_names = {
        _node_text(callback, source).rsplit("::", 1)[-1]
        for callback in cpp_http_callbacks
        if callback.type in {"identifier", "qualified_identifier"}
    }
    cpp_http_lambdas = {
        callback.start_byte
        for callback in cpp_http_callbacks
        if callback.type == "lambda_expression"
    }
    js_route_calls: list[tuple[Any, str]] = []
    if language in {"javascript", "typescript"}:
        for node in _named_nodes_of_types(tree, _CALL_EXPRESSION_TYPES):
            target = node.child_by_field_name("function")
            if target is None:
                continue
            match = re.fullmatch(
                r"(app|router)\.(?:get|post|put|delete)", _node_text(target, source)
            )
            if match is not None:
                js_route_calls.append((node, match.group(1)))
    js_server_calls: list[tuple[Any, list[Any]]] = []
    if language in {"javascript", "typescript"}:
        http_modules, bare_create_server, loads_http = _node_http_module_names(source)
        for node in _named_nodes_of_types(tree, _CALL_EXPRESSION_TYPES):
            handlers = _node_server_handler_arguments(
                node, source, http_modules, bare_create_server, loads_http
            )
            if handlers:
                js_server_calls.append((node, handlers))
    go_http_aliases = _go_http_aliases(source_lines) if language == "go" else set()
    tornado_handlers = _tornado_handler_classes(classes) if language == "python" else set()
    php_controllers = _php_controller_classes(classes, file_path) if language == "php" else set()
    # Nested callables share their lines -- a minified bundle is one line every
    # callable spans -- so each pattern reads each line once.
    line_pattern_hits: dict[tuple[str, int], bool] = {}

    for func in functions:
        if func.get("is_declaration", False):
            continue
        matched = False

        cls = class_for_line.get(func["line_start"])
        if (
            language == "ruby"
            and cls is not None
            and cls["name"].endswith("Controller")
            and cls.get("extends") in {"ApplicationController", "ActionController::Base", "ActionController::API"}
            and func["name"] != "initialize"
            and not func.get("_ruby_route")
            and _ruby_method_is_public(tree, func, source)
        ):
            entry_points.append({
                "name": func["name"],
                "line": func["line_start"],
                "kind": "rails_action",
                "annotation": "",
            })
            func["is_entry_point"] = True
            continue
        if (
            language == "php"
            and not any(modifier in {"private", "protected"} for modifier in func["modifiers"])
            and id(cls) in php_controllers
            and not func.get("is_closure")
            and (func["name"] == "__invoke" or not func["name"].startswith("__"))
            and not func["annotations"]
        ):
            entry_points.append({
                "name": func["name"],
                "line": func["line_start"],
                "kind": "laravel_action",
                "annotation": "",
            })
            func["is_entry_point"] = True
            continue

        if language == "c" and func["name"] in c_http_callbacks:
            entry_points.append({
                "name": func["name"],
                "line": func["line_start"],
                "kind": "http_handler",
                "annotation": "",
            })
            func["is_entry_point"] = True
            continue
        if language == "cpp" and (
            (func.get("is_closure", False) and func.get("_start_byte") in cpp_http_lambdas)
            or (
                func["name"] in cpp_http_names
                and any(re.search(r"\bRequest\b", param) for param in func["params"])
            )
        ):
            entry_points.append({
                "name": func["name"],
                "line": func["line_start"],
                "kind": "http_handler",
                "annotation": "",
            })
            func["is_entry_point"] = True
            continue

        if language == "csharp" and func.get("_minimal_api_route"):
            entry_points.append({
                "name": func["name"],
                "line": func["line_start"],
                "kind": "minimal_api_route",
                "annotation": "",
            })
            func["is_entry_point"] = True
            continue

        if language == "go" and _is_go_http_handler(func, go_http_aliases):
            entry_points.append({
                "name": func["name"],
                "line": func["line_start"],
                "kind": "go_http_handler",
                "annotation": "",
            })
            func["is_entry_point"] = True
            continue
        if (
            language == "python"
            and cls is not None
            and cls["name"] in tornado_handlers
            and func["name"] in _TORNADO_VERB_METHODS
            and func.get("params", [])[:1] == ["self"]
        ):
            entry_points.append({
                "name": func["name"],
                "line": func["line_start"],
                "kind": "tornado_handler",
                "annotation": "",
            })
            func["is_entry_point"] = True
            continue

        for ann_def in annotation_defs:
            for ann in func.get("annotations", []):
                if re.search(ann_def["pattern"], ann):
                    entry_points.append({
                        "name": func["name"],
                        "line": func["line_start"],
                        "kind": ann_def["kind"],
                        "annotation": ann.split("(")[0],
                    })
                    func["is_entry_point"] = True
                    matched = True
                    break
            if matched:
                break

        if matched:
            continue

        # Check method name patterns (Java servlet overrides, main, etc.)
        for mdef in method_name_defs:
            if func["name"] == mdef["name"]:
                if mdef["kind"] in ("servlet_override", "filter_override"):
                    cls = class_for_line.get(func["line_start"])
                    bases = [cls.get("extends", ""), *cls.get("implements", [])] if cls else []
                    base_names = {base.rsplit(".", 1)[-1] for base in bases}
                    valid_bases = (
                        {"Filter"} if mdef["kind"] == "filter_override"
                        else {"HttpServlet", "GenericServlet"}
                    )
                    if base_names & valid_bases:
                        entry_points.append({
                            "name": func["name"],
                            "line": func["line_start"],
                            "kind": mdef["kind"],
                            "annotation": "@Override",
                        })
                        func["is_entry_point"] = True
                        matched = True
                elif mdef["name"] == "main" and language == "java":
                    if "public" in func.get("modifiers", []) and "static" in func.get("modifiers", []):
                        entry_points.append({
                            "name": func["name"],
                            "line": func["line_start"],
                            "kind": "main_method",
                            "annotation": "",
                        })
                        func["is_entry_point"] = True
                        matched = True
                else:
                    entry_points.append({
                        "name": func["name"],
                        "line": func["line_start"],
                        "kind": mdef["kind"],
                        "annotation": "",
                    })
                    func["is_entry_point"] = True
                    matched = True
            if matched:
                break

        if matched:
            continue

        # Check source-line patterns across the function's own range plus the
        # first line of every call that registers it. Those two spans are where
        # a registration can be written: inside the body or on the signature
        # line (`func registerStdlib() {`, `void timer_callback(...) {`), or on
        # the `app.get(` a wrapped callback is an argument to. Attribution is
        # structural in both directions, so a function merely stacked under a
        # preceding registration -- which an earlier three-line lookback charged
        # for its neighbour's match -- is never reported for it.
        scan_indices = list(
            range(
                max(0, func["line_start"] - 1),
                min(len(source_lines), func["line_end"]),
            )
        )
        scan_indices.extend(
            line - 1
            for line in _registering_call_lines(
                tree, func, language, len(source_lines)
            )
        )
        for lp in line_pattern_defs:
            if language in {"c", "cpp"}:
                if re.search(lp["pattern"], f'{func["name"]}('):
                    entry_points.append({
                        "name": func["name"],
                        "line": func["line_start"],
                        "kind": lp["kind"],
                        "annotation": "",
                    })
                    func["is_entry_point"] = True
                    matched = True
                    break
                continue
            for line_no in scan_indices:
                if language in {"javascript", "typescript"} and lp["kind"] in {
                    "express_route", "express_router"
                } and any(
                    call.start_point[0] == line_no
                    and func["_start_byte"] < call.start_byte < func["_end_byte"]
                    for call, _ in js_route_calls
                ):
                    continue
                hit = line_pattern_hits.get((lp["pattern"], line_no))
                if hit is None:
                    hit = line_pattern_hits[(lp["pattern"], line_no)] = (
                        _line_pattern_matches(lp["pattern"], source_lines[line_no])
                    )
                if hit:
                    entry_points.append({
                        "name": func["name"],
                        "line": func["line_start"],
                        "kind": lp["kind"],
                        "annotation": "",
                    })
                    func["is_entry_point"] = True
                    matched = True
                    break
            if matched:
                break

    if language in {"javascript", "typescript"}:
        callable_nodes = {
            node.start_byte: node
            for node in _named_nodes_of_types(tree, _JAVASCRIPT_CALLABLE_TYPES)
        }
        bindings: dict[str, list[tuple[int, int, dict[str, Any]]]] = {}
        for func in functions:
            callable_node = callable_nodes.get(func["_start_byte"])
            if callable_node is None:
                continue
            if callable_node.type not in {"function_declaration", "generator_function_declaration"}:
                parent = callable_node.parent
                if parent is None or parent.type not in {"variable_declarator", "assignment_expression"}:
                    continue
                name = parent.child_by_field_name("name") or parent.child_by_field_name("left")
                if name is None or name.type != "identifier" or _node_text(name, source) != func["name"]:
                    continue
            scope = callable_node.parent
            while scope is not None and scope.type not in {"program", "statement_block"}:
                scope = scope.parent
            if scope is not None:
                bindings.setdefault(func["name"], []).append((scope.start_byte, scope.end_byte, func))
        for node, receiver in js_route_calls:
            arguments = node.child_by_field_name("arguments")
            if arguments is None:
                continue
            actual_args = arguments.named_children
            if not actual_args or actual_args[0].type not in {"string", "template_string"}:
                continue
            for argument in actual_args[1:]:
                if argument.type != "identifier":
                    continue
                candidates = [
                    binding for binding in bindings.get(_node_text(argument, source), [])
                    if binding[0] <= node.start_byte and node.end_byte <= binding[1]
                ]
                if not candidates:
                    continue
                func = min(candidates, key=lambda binding: (binding[1] - binding[0], -binding[2]["_start_byte"]))[2]
                if func["is_entry_point"]:
                    continue
                kind = "express_route" if receiver == "app" else "express_router"
                entry_points.append({
                    "name": func["name"],
                    "line": func["line_start"],
                    "kind": kind,
                    "annotation": "",
                })
                func["is_entry_point"] = True
        # The request listener a Node HTTP server dispatches every request to.
        # A hand-rolled router is exactly this function, path switch and all.
        # A listener this file does not define -- an imported app, a factory's
        # return value -- is still a registration, recorded at file scope.
        functions_by_start = {func["_start_byte"]: func for func in functions}
        for node, handlers in js_server_calls:
            unresolved = False
            for argument in handlers:
                func = None
                if argument.type in _JAVASCRIPT_CALLABLE_TYPES:
                    func = functions_by_start.get(argument.start_byte)
                elif argument.type == "identifier":
                    candidates = [
                        binding for binding in bindings.get(_node_text(argument, source), [])
                        if binding[0] <= node.start_byte and node.end_byte <= binding[1]
                    ]
                    if candidates:
                        func = min(
                            candidates,
                            key=lambda binding: (binding[1] - binding[0], -binding[2]["_start_byte"]),
                        )[2]
                if func is None:
                    unresolved = True
                    continue
                if func["is_entry_point"]:
                    continue
                entry_points.append({
                    "name": func["name"],
                    "line": func["line_start"],
                    "kind": "node_http_server",
                    "annotation": "",
                })
                func["is_entry_point"] = True
            if unresolved:
                entry_points.append({
                    "name": "<top-level>",
                    "line": node.start_point[0] + 1,
                    "kind": "node_http_server",
                    "annotation": "",
                })

    if language in ("c", "cpp", "go"):
        for func in functions:
            if func["name"] == "main" and not func["is_entry_point"] and not func.get("is_declaration", False):
                entry_points.append({
                    "name": "main",
                    "line": func["line_start"],
                    "kind": "main_function",
                    "annotation": "",
                })
                func["is_entry_point"] = True

    return entry_points


def _function_scan_lines(
    function: dict[str, Any],
    source_lines: list[str],
) -> list[tuple[int, str]]:
    """Return source segments that execute as part of a function definition."""
    body_start_line = function.get("_body_start_line")
    if body_start_line is None:
        start = max(0, function["line_start"] - 1)
        end = min(len(source_lines), function["line_end"])
        return [(line_index, source_lines[line_index]) for line_index in range(start, end)]

    lines: list[tuple[int, str]] = []
    excluded_by_line: dict[int, list[tuple[int, int]]] = {}
    for start_line, start_column, end_line, end_column in function.get("_excluded_ranges", []):
        for line_number in range(start_line, end_line + 1):
            line_index = line_number - 1
            if 0 <= line_index < len(source_lines):
                excluded_by_line.setdefault(line_number, []).append((
                    start_column if line_number == start_line else 0,
                    end_column if line_number == end_line else len(source_lines[line_index]),
                ))
    ranges = [
        *function.get("_initializer_ranges", []),
        (
            body_start_line,
            function["_body_start_column"],
            function["_body_end_line"],
            function["_body_end_column"],
        ),
    ]
    for start_line, start_column, end_line, end_column in ranges:
        for line_number in range(start_line, end_line + 1):
            line_index = line_number - 1
            if not 0 <= line_index < len(source_lines):
                continue
            line = source_lines[line_index]
            segment_start = start_column if line_number == start_line else 0
            segment_end = end_column if line_number == end_line else len(line)
            visible = [(segment_start, segment_end)]
            for excluded_start, excluded_end in sorted(excluded_by_line.get(line_number, [])):
                next_visible: list[tuple[int, int]] = []
                for visible_start, visible_end in visible:
                    if excluded_end <= visible_start or excluded_start >= visible_end:
                        next_visible.append((visible_start, visible_end))
                    else:
                        if visible_start < excluded_start:
                            next_visible.append((visible_start, excluded_start))
                        if excluded_end < visible_end:
                            next_visible.append((excluded_end, visible_end))
                visible = next_visible
            # Each fragment keeps its own columns, padded rather than cut to
            # column zero, so a reader that rejects a match by where it falls
            # -- PHP's string literals -- asks the question in the line's own
            # coordinates. `_file_scope_lines` answers in those coordinates
            # too, by blanking what it masks instead of cutting it out, and a
            # fragment stays its own string so no pattern can match across the
            # gap between two of them. Every snippet survives `.strip()`
            # unchanged.
            lines.extend(
                (line_index, " " * start + line[start:end])
                for start, end in visible
                if start < end
            )
    return lines


# Dimensions whose only readers are the callable spans `_function_scan_lines`
# returns and the file-scope complement `_file_scope_lines` returns:
# `_detect_sinks` and `_detect_call_sites` see nothing else, PHP's parse-tree
# call reader skips the same withheld lines, and the caller-parameter
# propagation signal rides on the call sites. Public because
# `code-coverage` reads the published list back and must ask the same question
# of it.
FUNCTION_SCOPED_DIMENSIONS = frozenset({"call_sites", "dataflow", "security_sinks"})

# Commentary as the grammars label it. `expression_statement` is here for the
# bare string Python and Ruby use as a docstring: the language evaluates it, so
# the parser cannot call it a comment, but it holds no call and no sink.
_COMMENT_NODE_TYPES = frozenset({"comment", "line_comment", "block_comment"})
_DOCSTRING_NODE_TYPES = frozenset({"string", "concatenated_string", "string_literal"})

UNSCANNED_SCOPE_DEGRADATION_REASON = "unscanned_function_scope"


def _is_comment_node(node: Any) -> bool:
    """Whether a grammar node is commentary rather than source."""
    node_type = getattr(node, "type", "")
    if node_type in _COMMENT_NODE_TYPES:
        return True
    if node_type != "expression_statement":
        return False
    children = list(getattr(node, "named_children", ()) or ())
    return len(children) == 1 and children[0].type in _DOCSTRING_NODE_TYPES


def _file_is_commentary_only(tree: Any, source_lines: list[str]) -> bool:
    """Whether the parsed file holds nothing a detector could ever have read.

    A file with no source is excluded from coverage debt: no line could have
    carried a signal, so the empty result *is* the measurement, and declaring
    one would put every placeholder module into the structural-debt surface
    alongside the files that really were never read.

    The prefix heuristic that used to answer this got both directions wrong --
    it read `#include <stdio.h>` as a comment and a `/* ... */` or docstring
    file as source. The grammar already labelled every comment node, so ask it.

    A root with no children at all is the one case the grammar cannot settle:
    it is an empty file, or a parser that returned nothing over bytes that do
    exist. The second is an anomaly, and ADR 0015 does not let an anomaly read
    as clean, so only genuinely blank source is excused there.
    """
    root = getattr(tree, "root_node", None)
    children = list(getattr(root, "named_children", ()) or ())
    if not children:
        return not any(line.strip() for line in source_lines)
    return all(_is_comment_node(node) for node in children)


_CASE_BLIND_SINK_LANGUAGES = frozenset({"php"})


@lru_cache(maxsize=None)
def _sink_line_readers(
    language: str,
) -> tuple[tuple[dict[str, Any], tuple[tuple[str, re.Pattern[str], tuple[str, ...]], ...]], ...]:
    """The sink catalogue `_detect_sinks` runs over a line, in catalogue order.

    Each pattern carries the literals it is gated on, one of which every match
    contains, so a line holding none -- or one the language's `_sink_line_gate`
    rejects -- cannot match it. An ungated pattern carries none. PHP names its
    functions case-blind, so its rows match ASCII case-blind and their literals,
    read off the case-sensitive pattern, are lowered for a lowered line.
    """
    case_blind = language in _CASE_BLIND_SINK_LANGUAGES
    return tuple(
        (
            definition,
            tuple(
                (
                    pattern,
                    re.compile(pattern, re.IGNORECASE | re.ASCII) if case_blind else exact,
                    tuple(sorted(
                        literal.lower() if case_blind else literal
                        for literal in _gate_literals(exact) or ()
                    )),
                )
                for pattern in definition["patterns"].get(language, [])
                for exact in (re.compile(pattern),)
            ),
        )
        for definition in _SINK_DEFINITIONS
    )


@lru_cache(maxsize=None)
def _function_scoped_reader_patterns(language: str) -> tuple[re.Pattern[str], ...]:
    """The sink catalogue `_detect_sinks` would have run over a line."""
    return tuple(
        compiled
        for _definition, patterns in _sink_line_readers(language)
        for _pattern, compiled, _literals in patterns
    )


@lru_cache(maxsize=None)
def _sink_line_gate(language: str) -> re.Pattern[str] | None:
    literals = sorted(
        {
            literal
            for _definition, patterns in _sink_line_readers(language)
            for _pattern, _compiled, pattern_literals in patterns
            for literal in pattern_literals
        },
        key=lambda literal: (-len(literal), literal),
    )
    return re.compile("|".join(map(re.escape, literals))) if literals else None


def _withheld_reader_signal(
    withheld: list[tuple[int, str]],
    language: str,
    *,
    withheld_call: bool = False,
) -> bool:
    """Whether a file-scope line the readers do not take carries signal.

    `_file_scope_lines` holds back declaration header lines -- `class Foo(Base):`,
    `package main` -- because the parenthesised list on one is a set of bases,
    not a call, and reading them would put a phantom call site on every class.
    A one-line `class Runner { static { exec(cmd); } }` is still source the
    sink catalogue would have matched, and it went unread, so it is a gap.
    For the line readers only the sink catalogue is asked: the call shape on
    these lines is exactly the noise they are withheld for. PHP's call sites
    come from the parse tree, which tells a real call from a header, so
    *withheld_call* carries its answer for the same lines.
    """
    if withheld_call:
        return True
    sink_patterns = _function_scoped_reader_patterns(language)
    return any(
        pattern.search(line) for _index, line in withheld for pattern in sink_patterns
    )


def _unscanned_scope_dimensions(
    functions: list[dict[str, Any]],
    entry_points: list[dict[str, Any]],
    source_lines: list[str],
    *,
    tree: Any,
    language: str,
    function_scoped_records: bool,
    file_scope: _FileScope,
    withheld_call: bool = False,
    executable_file_scope: Callable[[], bool] = lambda: True,
) -> set[str]:
    """Dimensions whose empty value is an unmade measurement, not a negative.

    Every line of a parsed file is one of: inside a callable span, read by the
    file-scope readers, labelled by the grammar as something no reader could
    match (commentary, a docstring, a declaration, inline HTML), or held back
    as a declaration header. Only the last can hide a signal the readers never
    saw, so the trio is declared when the readers **returned nothing** and a
    held-back line carries a sink. Both halves are load-bearing:

    * Without the second, a file the readers genuinely read end to end and
      found clean -- a constants module, a header of prototypes -- would be
      declared debt, and a flag that is always on distinguishes nothing.
    * Without the first, the flag could be raised once a reader has reported
      something -- and it must not be. `unavailable` means zero on both sides
      of the contract (`code_structural_metadata.validated_structural_metadata`
      and the backend's payload validator), so declaring a dimension that
      retained a record would either reject the whole repository's sync or
      force the indexer to drop signal it really found.

    The entry-point dimension is separate. Every entry rule but the file-scope
    catalogue is keyed on a callable, so a file with no callable was measured
    for entry points only in a language that has a file-scope catalogue, or
    when *executable_file_scope* says no file-scope code runs: a file of types,
    enums or macros has nowhere an entry point could live.
    """
    if _file_is_commentary_only(tree, source_lines):
        return set()
    unscanned: set[str] = set()
    if not function_scoped_records and _withheld_reader_signal(
        file_scope.withheld, language, withheld_call=withheld_call
    ):
        unscanned |= FUNCTION_SCOPED_DIMENSIONS
    if (
        not functions
        and not entry_points
        and language not in _GLOBAL_ENTRY_LINE_PATTERNS
        and executable_file_scope()
    ):
        unscanned.add("entry_points")
    return unscanned


def _unread_body_dimensions(records: dict[str, Any]) -> set[str]:
    """What a code body no reader looked at leaves unmeasured.

    Every function-scoped dimension that retained no record: `unavailable`
    means zero records, so one a reader did fill elsewhere in the file stays.
    `dataflow` keeps none, so the file always owes a whole-file read.
    """
    return {dimension for dimension in FUNCTION_SCOPED_DIMENSIONS if not records.get(dimension)}


_TOP_LEVEL_DECLARATION_PREFIXES = (
    "class ",
    "interface ",
    "struct ",
    "enum ",
    "namespace ",
    "package ",
)

# Grammar nodes outside every callable that hold nothing a reader could match:
# a TypeScript interface member or a Go interface method reads as a call by its
# shape alone, a C prototype is a declaration with a parameter list, and PHP's
# inline HTML is document text whose prose (`Print this page`) is not PHP.
_FILE_SCOPE_DECLARATION_NODE_TYPES: dict[str, frozenset[str]] = {
    "go": frozenset({"type_declaration"}),
    "typescript": frozenset({
        "abstract_method_signature",
        "ambient_declaration",
        "function_signature",
        "interface_declaration",
        "method_signature",
        "type_alias_declaration",
    }),
    "php": frozenset({"text"}),
}
# A C/C++ declaration is a prototype when its declarator is a bare function
# declarator; `int (*hook)(int) = run;` carries an `init_declarator` instead.
_PROTOTYPE_CONTAINER_TYPES = frozenset({"declaration", "field_declaration"})

# The whole-tree node collections each family's readers take, which the shared
# query pass matches alongside the extractors' queries.
_WHOLE_TREE_NODE_TYPES: dict[str, tuple[frozenset[str], ...]] = {
    "c": (_CALL_EXPRESSION_TYPES,),
    "cpp": (_CPP_HTTP_SCAN_TYPES,),
    "csharp": (
        _CSHARP_LAMBDA_TYPES, _CSHARP_CALLABLE_DECLARATION_TYPES, _CSHARP_INVOCATION_TYPES,
    ),
    "javascript": (_JAVASCRIPT_CALLABLE_TYPES, _CALL_EXPRESSION_TYPES, _COMMENT_NODE_TYPES),
    "php": (_PHP_CLOSURE_TYPES,),
    "ruby": (_RUBY_CALL_TYPES,),
    "typescript": (_JAVASCRIPT_CALLABLE_TYPES, _CALL_EXPRESSION_TYPES, _COMMENT_NODE_TYPES),
}


class _FileScope(NamedTuple):
    """The file-scope complement of the callable spans, as the readers see it.

    *scanned* is what the ``<top-level>`` scope reads, with grammar-labelled
    content blanked out of each line. *withheld* is declaration header lines
    the readers do not take. *inline_text_lines* is the first line of every
    non-blank PHP inline-HTML run outside a callable.
    """

    scanned: list[tuple[int, str]]
    withheld: list[tuple[int, str]]
    inline_text_lines: list[int]


def _callable_intervals(functions: list[dict[str, Any]]) -> list[tuple[int, int]]:
    """Merged 0-based, inclusive line intervals covered by any callable span."""
    spans = sorted(
        (max(0, int(function["line_start"]) - 1), int(function["line_end"]) - 1)
        for function in functions
    )
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _within_one_interval(
    intervals: list[tuple[int, int]], starts: list[int], first: int, last: int
) -> bool:
    position = bisect_right(starts, first) - 1
    return position >= 0 and intervals[position][1] >= last


@lru_cache(maxsize=None)
def _file_scope_candidate_types(language: str) -> frozenset[str]:
    """Every node type `_is_file_scope_unread_node` can accept in *language*."""
    return frozenset({
        *_COMMENT_NODE_TYPES,
        "expression_statement",
        *_FILE_SCOPE_DECLARATION_NODE_TYPES.get(language, ()),
        *(_PROTOTYPE_CONTAINER_TYPES if language in {"c", "cpp"} else ()),
    })


def _is_file_scope_unread_node(node: Any, language: str) -> bool:
    if _is_comment_node(node):
        return True
    node_type = getattr(node, "type", "")
    if node_type in _FILE_SCOPE_DECLARATION_NODE_TYPES.get(language, ()):
        return True
    return language in {"c", "cpp"} and node_type in _PROTOTYPE_CONTAINER_TYPES and any(
        child.type == "function_declarator"
        for child in getattr(node, "named_children", ()) or ()
    )


def _file_scope_lines(
    tree: Any,
    functions: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
    source: bytes,
) -> _FileScope:
    """Return the synthetic ``<top-level>`` scope: every line no callable covers.

    Module initializers, PHP request scripts, Go package variables and C macro
    bodies execute without any enclosing callable, so the readers take the
    complement of the callable spans in every language and whether or not the
    file has a callable at all. What the complement leaves out is decided by
    the grammar, not by a line prefix: commentary, docstrings and declarations
    are blanked out of the lines that hold them, which is what keeps a
    docstring's `os.system(...)` example and an interface's `get(id)` member
    from reading as a sink and a call.
    """
    intervals = _callable_intervals(functions)
    starts = [start for start, _end in intervals]
    masked: dict[int, list[tuple[int, int | None]]] = {}
    inline_text_lines: list[int] = []
    # Every node the grammar labels unread, outside the callables. One nested
    # in another is blanked again inside the same span, which changes nothing;
    # inline HTML, the one kind recorded beyond its span, never nests.
    for node in _named_nodes_of_types(tree, _file_scope_candidate_types(language)):
        first, last = node.start_point[0], node.end_point[0]
        if _within_one_interval(intervals, starts, first, last):
            continue
        if _is_file_scope_unread_node(node, language):
            if (
                language == "php"
                and node.type == "text"
                and source[node.start_byte:node.end_byte].strip()
                and not (node.start_byte == 0 and source.startswith(b"#!"))
            ):
                text = source[node.start_byte:node.end_byte]
                inline_text_lines.append(first + 1 + text[: len(text) - len(text.lstrip())].count(b"\n"))
            start_line, start_column, end_line, end_column = _node_character_range(
                node, source
            )
            for line_number in range(start_line, end_line + 1):
                masked.setdefault(line_number - 1, []).append((
                    start_column if line_number == start_line else 0,
                    end_column if line_number == end_line else None,
                ))

    scanned: list[tuple[int, str]] = []
    withheld: list[tuple[int, str]] = []
    for index, line in enumerate(source_lines):
        if _within_one_interval(intervals, starts, index, index):
            continue
        for start, end in masked.get(index, ()):
            stop = len(line) if end is None else min(end, len(line))
            if start < stop:
                line = line[:start] + " " * (stop - start) + line[stop:]
        if not line.strip():
            continue
        if line.strip().startswith(_TOP_LEVEL_DECLARATION_PREFIXES):
            withheld.append((index, line))
        else:
            scanned.append((index, line))
    return _FileScope(scanned, withheld, sorted(inline_text_lines))


# What file scope holds that never executes, per grammar family. Neither kind
# of declaration opens a `<top-level>` segment however much source it spans.
#
# An inert declaration runs nothing and holds nothing that could: namespace,
# package and import lines, `declare(...)`, PHP tags and attributes, type-only
# declarations, and declarations whose values are constant expressions. A
# reader that matches text in one -- `use DOMDocument;`, a constant naming a
# function -- reports a signal that no review is owed for.
_FILE_SCOPE_INERT_TYPES: dict[str, frozenset[str]] = {
    "php": frozenset({
        "php_tag", "php_end_tag", "namespace_use_declaration", "declare_statement",
        "const_declaration", "attribute_list", "empty_statement",
        # Class members whose initializers are constant expressions.
        "property_declaration", "enum_case", "use_declaration",
    }),
    "python": frozenset({"import_statement", "import_from_statement", "future_import_statement"}),
    "javascript": frozenset({"import_statement", "empty_statement", "hash_bang_line"}),
    "typescript": frozenset({
        "import_statement", "interface_declaration", "type_alias_declaration",
        "enum_declaration", "ambient_declaration", "function_signature",
        "empty_statement", "hash_bang_line",
    }),
    "go": frozenset({"package_clause", "import_declaration", "type_declaration", "const_declaration"}),
    "java": frozenset({"package_declaration", "import_declaration", "module_declaration"}),
    "c": frozenset({
        "preproc_include", "type_definition", "struct_specifier", "enum_specifier",
        "union_specifier", "empty_declaration",
    }),
    "cpp": frozenset({
        "preproc_include", "type_definition", "struct_specifier", "enum_specifier",
        "union_specifier", "using_declaration", "alias_declaration",
        "namespace_alias_definition", "static_assert_declaration", "concept_definition",
        "empty_declaration",
    }),
    "csharp": frozenset({
        "using_directive", "extern_alias_directive", "global_attribute",
        "delegate_declaration", "enum_declaration",
    }),
    "ruby": frozenset(),
}
# A definition declares code that runs elsewhere: a function whose body is a
# callable (with its header and decorators), a macro expanded where it is
# used, or a C declaration whose initializer is a constant expression. A
# reader signal inside one still counts, so a sink in a macro body is owed
# review wherever the indexer could not attribute it to a callable.
_FILE_SCOPE_DEFINITION_TYPES: dict[str, frozenset[str]] = {
    "php": frozenset({"function_definition"}),
    "python": frozenset({"function_definition", "decorated_definition"}),
    "javascript": frozenset({"function_declaration", "generator_function_declaration"}),
    "typescript": frozenset({
        "function_declaration", "generator_function_declaration", "module", "internal_module",
    }),
    "go": frozenset({"function_declaration", "method_declaration"}),
    "c": frozenset({
        "preproc_def", "preproc_function_def", "preproc_call", "function_definition",
        "declaration",
    }),
    "cpp": frozenset({
        "preproc_def", "preproc_function_def", "preproc_call", "class_specifier",
        "function_definition", "template_declaration",
    }),
}
# Nodes whose children are file-scope statements in their own right.
_FILE_SCOPE_CONTAINER_TYPES: dict[str, frozenset[str]] = {
    "php": frozenset({"namespace_definition", "compound_statement"}),
    "c": frozenset({
        "preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif", "preproc_elifdef",
    }),
    "cpp": frozenset({
        "preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif", "preproc_elifdef",
        "linkage_specification", "namespace_definition", "declaration_list",
    }),
    "csharp": frozenset({
        "namespace_declaration", "file_scoped_namespace_declaration", "declaration_list",
    }),
}
# Type declarations whose bodies are declarative: their methods are callables
# and their fields are definitions. A member opens a segment only when it is
# a block of code that runs without being a callable -- an initializer block
# or a PHP property hook -- and otherwise counts a reader signal only when it
# is not inert, so a sink in a field initializer is still owed review.
_FILE_SCOPE_CLASS_TYPES: dict[str, frozenset[str]] = {
    "php": frozenset({
        "class_declaration", "interface_declaration", "trait_declaration", "enum_declaration",
    }),
    "python": frozenset({"class_definition"}),
    "javascript": frozenset({"class_declaration"}),
    "typescript": frozenset({"class_declaration", "abstract_class_declaration"}),
    "java": frozenset({
        "class_declaration", "interface_declaration", "enum_declaration",
        "record_declaration", "annotation_type_declaration",
    }),
    "csharp": frozenset({
        "class_declaration", "struct_declaration", "interface_declaration",
        "record_declaration", "record_struct_declaration",
    }),
    "ruby": frozenset({"class", "module", "singleton_class"}),
}
_FILE_SCOPE_INITIALIZER_TYPES: dict[str, frozenset[str]] = {
    "java": frozenset({"static_initializer", "block"}),
    "javascript": frozenset({"class_static_block"}),
    "typescript": frozenset({"class_static_block"}),
    "php": frozenset({"property_hook"}),
}
# Member children that list a member's code blocks, such as PHP's hooks.
_FILE_SCOPE_INITIALIZER_LIST_TYPES = frozenset({"property_hook_list"})
_RUBY_IMPORT_CALLS = frozenset({"require", "require_relative", "load", "autoload"})
# A value that runs nothing when bound: a literal, a container of literals, a
# function or class value, or a type. Anything else -- a name, a call, an
# interpolated string, an operator over non-literals -- is a non-literal
# initializer, and counts.
_LITERAL_LEAF_TYPES = frozenset({
    "integer", "float", "number", "true", "false", "null", "none", "nil", "boolean",
    "string_content", "string_fragment", "escape_sequence", "string_value",
    "nowdoc_string", "heredoc_start", "heredoc_end", "character", "simple_symbol",
    "hash_key_symbol", "property_identifier", "field_identifier", "comment",
    "system_lib_string", "string_start", "string_end",
})
_LITERAL_CONTAINER_TYPES = frozenset({
    "string", "encapsed_string", "heredoc", "heredoc_body", "nowdoc", "nowdoc_body",
    "concatenated_string", "template_string", "string_literal", "char_literal",
    "interpreted_string_literal", "raw_string_literal", "verbatim_string_literal",
    "array_creation_expression", "array_element_initializer", "list", "tuple",
    "dictionary", "pair", "set", "array", "object", "parenthesized_expression",
    "expression_statement", "unary_expression", "unary_op_expression",
    "initializer_list", "expression_list", "literal_value", "keyed_element",
    "literal_element", "element", "composite_literal", "hash", "array_initializer",
    "symbol_array", "string_array",
})
_FUNCTION_VALUE_TYPES = frozenset({
    "anonymous_function", "arrow_function", "function", "function_expression",
    "generator_function", "lambda", "class", "func_literal", "lambda_expression",
    "anonymous_method_expression",
})


def _is_literal_value(node: Any) -> bool:
    stack = [node]
    while stack:
        current = stack.pop()
        node_type = current.type
        if (
            node_type in _LITERAL_LEAF_TYPES
            or node_type in _FUNCTION_VALUE_TYPES
            or node_type.endswith(("_literal", "type", "type_identifier"))
            and node_type not in _LITERAL_CONTAINER_TYPES
        ):
            continue
        if node_type not in _LITERAL_CONTAINER_TYPES:
            return False
        stack.extend(current.named_children)
    return True


def _binding_values(node: Any) -> list[Any] | None:
    """The values a binding statement assigns, or None for any other statement."""
    node_type = node.type
    if node_type in {"expression_statement", "global_statement"} and len(node.named_children) == 1:
        return _binding_values(node.named_children[0])
    if node_type in {"assignment_expression", "assignment"}:
        right = node.child_by_field_name("right")
        return [right] if right is not None else []
    if node_type in {"lexical_declaration", "variable_declaration", "declaration", "field_declaration"}:
        declarators = [
            child for child in node.named_children
            if child.type in {"variable_declarator", "init_declarator"}
        ]
        values = [declarator.child_by_field_name("value") for declarator in declarators]
        return [value for value in values if value is not None]
    if node_type == "var_declaration":
        specs = [
            spec
            for child in node.named_children
            for spec in ([child] if child.type == "var_spec" else child.named_children)
            if spec.type == "var_spec"
        ]
        return [value for spec in specs if (value := spec.child_by_field_name("value")) is not None]
    return None


def _content_lines(node: Any, source: bytes) -> range:
    """0-based lines holding a node's non-blank bytes; empty for blank text."""
    text = source[node.start_byte:node.end_byte]
    stripped = text.strip()
    if not stripped:
        return range(0)
    first = node.start_point[0] + text[: len(text) - len(text.lstrip())].count(b"\n")
    return range(first, first + stripped.count(b"\n") + 1)


def _php_output_lines(node: Any, source: bytes) -> list[int]:
    """Lines of inline HTML a PHP file sends back; a shebang is not output."""
    texts = [node] if node.type == "text" else [
        child for child in node.named_children if child.type == "text"
    ]
    return [
        line
        for text in texts
        if not (text.start_byte == 0 and source.startswith(b"#!"))
        for line in _content_lines(text, source)
    ]


# PHP builtins whose calls with constant arguments only declare a name:
# `define()` is the call spelling of a constant declaration, and
# `class_alias()` names a class that already exists. Both run nothing a
# reviewer could read.
_PHP_DECLARING_CALLS = frozenset({"define", "class_alias"})
# Probes that ask whether a name is declared; with a literal argument they
# read nothing but the symbol table.
_PHP_EXISTENCE_PROBES = frozenset({
    "defined", "function_exists", "class_exists", "interface_exists",
    "trait_exists", "enum_exists", "is_callable",
})
_PHP_EXIT_NAMES = frozenset({"die", "exit"})
# Operands a constant expression is built from: constant and class-constant
# names (`__DIR__`, `Invoice::class`) and operators over them.
_PHP_CONSTANT_NAME_TYPES = frozenset({"name", "qualified_name", "relative_name"})
# `Invoice::class`, `self::LIMIT`: a class constant of a class named in the
# source. `acme()::X`, `(new Acme)::X` and `$obj::X` evaluate their scope first.
_PHP_CLASS_CONSTANT_SCOPE_TYPES = frozenset({
    "name", "qualified_name", "relative_name", "relative_scope",
})
_PHP_CONSTANT_OPERATOR_TYPES = frozenset({
    "binary_expression", "unary_op_expression", "parenthesized_expression",
})


def _php_constant_expression(node: Any) -> bool:
    """Whether a PHP value is fixed at compile time: no variable, no call.

    Literals, arrays of constant values, constant and class-constant names and
    operators over them all qualify (`RISK_SPAM | RISK_XSS`, `ROOT . 'tmp/'`,
    `[Mail::class]`).
    """
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in _PHP_CONSTANT_NAME_TYPES or _is_literal_value(current):
            continue
        if current.type == "class_constant_access_expression":
            if all(child.type in _PHP_CLASS_CONSTANT_SCOPE_TYPES for child in current.named_children):
                continue
            return False
        if current.type not in _PHP_CONSTANT_OPERATOR_TYPES and current.type not in _LITERAL_CONTAINER_TYPES:
            return False
        stack.extend(child for child in current.named_children if not _is_comment_node(child))
    return True


def _php_global_call_name(node: Any, source: bytes) -> str:
    """The lowercased name of a call to a global PHP function, else ''."""
    if node.type != "function_call_expression":
        return ""
    function = node.child_by_field_name("function")
    if function is None or function.type not in {"name", "qualified_name"}:
        return ""
    name = _node_text(function, source)
    name = name[1:] if name.startswith("\\") else name
    return "" if "\\" in name else name.lower()


def _php_constant_arguments(call: Any) -> bool:
    arguments = call.child_by_field_name("arguments")
    return all(
        argument.type == "argument"
        and argument.named_children
        and _php_constant_expression(argument.named_children[-1])
        for argument in (arguments.named_children if arguments is not None else ())
        if not _is_comment_node(argument)
    )


def _php_literal_exit(node: Any, source: bytes) -> bool:
    """`die`, `exit;`, `exit(1)`, `die('No direct access')`: an exit whose
    message, if any, is a constant."""
    if node.type == "expression_statement" and len(node.named_children) == 1:
        node = node.named_children[0]
    if node.type == "exit_statement":
        return all(_php_constant_expression(child) for child in node.named_children)
    if node.type == "name":
        return _node_text(node, source).lower() in _PHP_EXIT_NAMES
    return _php_global_call_name(node, source) in _PHP_EXIT_NAMES and _php_constant_arguments(node)


def _php_existence_probe(node: Any, source: bytes, *, combined: bool = False) -> bool:
    """`defined('X')`, `!\\function_exists('x')`: a literal declaration probe.

    *combined* also accepts the probes joined by `&&`, `||`, `and` and `or`,
    the shape an `if` condition takes; a guard's left operand is one probe.
    """
    while node.type == "parenthesized_expression" and len(node.named_children) == 1:
        node = node.named_children[0]
    if node.type == "unary_op_expression":
        operator = node.child_by_field_name("operator")
        argument = node.child_by_field_name("argument")
        if operator is None or argument is None or operator.type != "!":
            return False
        return _php_existence_probe(argument, source, combined=combined)
    if combined and node.type == "binary_expression":
        operator = node.child_by_field_name("operator")
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        return (
            operator is not None and left is not None and right is not None
            and operator.type.lower() in {"&&", "||", "and", "or"}
            and _php_existence_probe(left, source, combined=True)
            and _php_existence_probe(right, source, combined=True)
        )
    return (
        _php_global_call_name(node, source) in _PHP_EXISTENCE_PROBES
        and _php_constant_arguments(node)
    )


def _php_declares_only(node: Any, source: bytes) -> bool:
    """A literal declaring call, or a direct-access guard.

    `defined('ACME') || die();` and `\\defined('_JEXEC') or die;` stop a
    file requested on its own and run nothing when it is included, which is
    the only way it does anything; `defined('X') or define('X', 1);` is a
    guarded constant declaration.
    """
    if _php_global_call_name(node, source) in _PHP_DECLARING_CALLS:
        return _php_constant_arguments(node)
    if node.type != "binary_expression":
        return False
    operator = node.child_by_field_name("operator")
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    return (
        operator is not None and left is not None and right is not None
        and operator.type.lower() in {"||", "or"}
        and left.type == "function_call_expression"
        and _php_existence_probe(left, source)
        and (_php_literal_exit(right, source) or _php_declares_only(right, source))
    )


def _php_existence_guarded_statements(node: Any, source: bytes) -> list[Any] | None:
    """The statements an `if` over literal existence probes holds, or None.

    `if (!function_exists('x')) { function x() {...} }` declares a function
    and `if (!defined('X')) { die(...); }` is a direct-access guard. The
    conditions read nothing, so the statement is a container: what runs is
    each branch's own statements, less an exit that only enforces the guard.
    An `elseif` whose condition reads anything else makes it ordinary code.
    """
    if node.type != "if_statement":
        return None
    branches = [node, *_field_children(node, "alternative")]
    bodies: list[Any] = []
    for branch in branches:
        condition = branch.child_by_field_name("condition")
        body = branch.child_by_field_name("body")
        if body is None or (branch.type != "else_clause" and (
            condition is None or not _php_existence_probe(condition, source, combined=True)
        )):
            return None
        bodies.append(body)
    return [
        statement
        for body in bodies
        for statement in (
            body.named_children if body.type in {"compound_statement", "colon_block"} else [body]
        )
        if not _php_literal_exit(statement, source)
    ]


# A line whose code is only closing punctuation: the `};` that ends an
# anonymous class, the `);` after a closure.
_CLOSING_PUNCTUATION_LINE = re.compile(r"[\]\)\};,\s]*")


def _holds_code(text: str) -> bool:
    """Whether a line of an executing statement, comments blanked, holds code a segment owes.

    Blank lines, commentary and closing punctuation inside a statement run
    nothing of their own. They are only ever read at a segment's edge, where
    a statement spans a callable, so no line that starts or ends a statement
    is lost.
    """
    stripped = text.strip()
    return bool(stripped) and not _CLOSING_PUNCTUATION_LINE.fullmatch(stripped)


def _is_executable_file_scope_node(node: Any, language: str, source: bytes) -> bool:
    """Whether one file-scope statement runs when the file is loaded or requested."""
    node_type = node.type
    if language == "php" and node_type == "const_declaration":
        # A constant expression runs nothing, except the `new` PHP allows
        # in a global constant's initializer, which runs a constructor.
        return _has_descendant_type(node, "object_creation_expression")
    if (
        language == "php"
        and node_type == "expression_statement"
        and len(node.named_children) == 1
        and _php_declares_only(node.named_children[0], source)
    ):
        return False
    # A PHP value built from literals and constants is fixed when the file loads.
    fixed_value = _php_constant_expression if language == "php" else _is_literal_value
    if language == "php" and node_type == "global_declaration":
        # `global $CFG;` at file scope names a variable already in scope.
        return False
    if node_type == "return_statement":
        # A file that returns a literal -- a configuration array, a bare
        # `return;` -- computes nothing; what it returns is read where it is
        # included.
        return any(
            not fixed_value(child)
            for child in node.named_children
            if not _is_comment_node(child)
        )
    if (
        _is_comment_node(node)
        or node_type in _FILE_SCOPE_INERT_TYPES.get(language, ())
        or node_type in _FILE_SCOPE_DEFINITION_TYPES.get(language, ())
        or node_type in _FILE_SCOPE_CLASS_TYPES.get(language, ())
    ):
        return False
    if node_type == "export_statement":
        declaration = node.child_by_field_name("declaration")
        if declaration is not None:
            return _is_executable_file_scope_node(declaration, language, source)
        value = node.child_by_field_name("value")
        return value is not None and not _is_literal_value(value)
    if language == "ruby" and node_type == "call":
        method = node.child_by_field_name("method")
        if (
            method is not None
            and _node_text(method, source) in _RUBY_IMPORT_CALLS
            and node.child_by_field_name("receiver") is None
        ):
            return False
    values = _binding_values(node)
    if values is not None:
        return any(not fixed_value(value) for value in values)
    return not fixed_value(node)


def _has_descendant_type(node: Any, node_type: str) -> bool:
    stack = list(node.named_children)
    while stack:
        current = stack.pop()
        if current.type == node_type:
            return True
        stack.extend(current.named_children)
    return False


def _carries_file_scope_signal(node: Any, language: str) -> bool:
    """Whether a reader signal inside a non-executing node is owed review.

    Comments, inert declarations and literal values hold nothing that runs,
    so a reader matching their text (`use DOMDocument;`, a docblock quoting
    `$_GET`) reports a signal that opens no segment. A definition, a field
    with a computed initializer, or anything else that holds code counts it.
    """
    if _is_comment_node(node) or node.type in _FILE_SCOPE_INERT_TYPES.get(language, ()):
        return False
    values = _binding_values(node)
    if values is not None:
        return any(not _is_literal_value(value) for value in values)
    return not _is_literal_value(node)


def _executable_file_scope_lines(
    tree: Any,
    functions: list[dict[str, Any]],
    language: str,
    source: bytes,
    code_lines: list[str],
    signal_lines: set[int],
) -> set[int]:
    """0-based lines of file-scope code that executes, outside every callable.

    The walk descends into namespaces and preprocessor conditionals, whose
    children are file-scope statements, and into type bodies for their
    initializer blocks and property hooks. *signal_lines* are file-scope lines
    a sink or source reader reported; one counts wherever it sits in code that
    could run -- a statement, a definition, a computed member initializer --
    and never in a comment, an inert declaration or a literal.
    """
    intervals = _callable_intervals(functions)
    starts = [start for start, _end in intervals]
    containers = _FILE_SCOPE_CONTAINER_TYPES.get(language, frozenset())
    class_types = _FILE_SCOPE_CLASS_TYPES.get(language, frozenset())
    initializers = _FILE_SCOPE_INITIALIZER_TYPES.get(language, frozenset())
    signals = sorted(signal_lines)
    lines: set[int] = set()

    def signals_within(node: Any) -> list[int]:
        return signals[
            bisect_left(signals, node.start_point[0]):bisect_right(signals, node.end_point[0])
        ]

    def holding_code(rows: Iterable[int]) -> list[int]:
        return [row for row in rows if row < len(code_lines) and _holds_code(code_lines[row])]

    root = getattr(tree, "root_node", None)
    stack = list(reversed(list(getattr(root, "named_children", ()) or ())))
    while stack:
        node = stack.pop()
        first, last = node.start_point[0], node.end_point[0]
        if _within_one_interval(intervals, starts, first, last):
            continue
        if node.type in containers:
            body = node.child_by_field_name("body")
            skipped = {
                (child.start_byte, child.end_byte)
                for field in ("name", "condition", "value")
                if (child := node.child_by_field_name(field)) is not None
            }
            children = body.named_children if body is not None else [
                child for child in node.named_children
                if (child.start_byte, child.end_byte) not in skipped
            ]
            stack.extend(reversed(list(children)))
            continue
        if language == "php" and (
            guarded := _php_existence_guarded_statements(node, source)
        ) is not None:
            stack.extend(reversed(guarded))
            continue
        if node.type in class_types:
            body = node.child_by_field_name("body")
            for member in body.named_children if body is not None else ():
                if member.type in class_types:
                    stack.append(member)
                    continue
                blocks = [member] if member.type in initializers else [
                    block
                    for child in member.named_children
                    if child.type in _FILE_SCOPE_INITIALIZER_LIST_TYPES
                    for block in child.named_children
                    if block.type in initializers
                ]
                for block in blocks:
                    lines.update(holding_code(range(block.start_point[0], block.end_point[0] + 1)))
                if (
                    not blocks
                    and (within := signals_within(member))
                    and _carries_file_scope_signal(member, language)
                ):
                    lines.update(within)
            continue
        if language == "php" and node.type in {"text", "text_interpolation"}:
            lines.update(_php_output_lines(node, source))
        elif _is_executable_file_scope_node(node, language, source):
            lines.update(holding_code(_content_lines(node, source)))
        elif (within := signals_within(node)) and _carries_file_scope_signal(node, language):
            lines.update(within)
    return {
        line for line in lines if not _within_one_interval(intervals, starts, line, line)
    }


def _top_level_segments(
    functions: list[dict[str, Any]], executable_lines: set[int]
) -> list[dict[str, int]]:
    """The ``<top-level>`` scope as contiguous line segments between callables.

    Each segment runs from the first to the last executable file-scope line of
    one gap between callable spans, so it never overlaps a callable and the
    declarations, blank and comment lines inside a gap do not split it. These
    are the spans the review gate holds the file scope to, published as
    `<top-level>` callable records beside the real callables.
    """
    intervals = _callable_intervals(functions)
    starts = [start for start, _end in intervals]
    segments: list[list[int]] = []
    for index in sorted(executable_lines):
        gap = bisect_right(starts, index)
        if segments and segments[-1][2] == gap:
            segments[-1][1] = index
        else:
            segments.append([index, index, gap])
    return [{"line_start": first + 1, "line_end": last + 1} for first, last, _gap in segments]


def _java_fetch_call_matches_type(
    line: str,
    call_start: int,
    pattern: str,
    receivers: dict[str, str],
) -> bool:
    if "openStream" in pattern:
        return True
    prefix = line[:call_start]
    if "getInputStream" in pattern and re.search(
        r"\bnew\s+URL\s*\(.*\)\s*\.\s*openConnection\s*\(\s*\)\s*$", prefix
    ):
        return True
    if "send" in pattern and re.search(r"\bHttpClient\s*\.\s*newHttpClient\s*\(\s*\)\s*$", prefix):
        return True
    receiver = re.search(r"(?:this\.)?([A-Za-z_]\w*)\s*$", prefix)
    if receiver is None:
        return False
    declared_type = receivers.get(receiver.group(1))
    if "getInputStream" in pattern:
        return declared_type in {"URLConnection", "HttpURLConnection"}
    if "getResponseCode" in pattern:
        return declared_type == "HttpURLConnection"
    return declared_type == "HttpClient"


def _java_fetch_bindings(lines: list[str]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for line in lines:
        for declared_type, name in re.findall(
            r"\b([A-Z][\w.]*|var|int|long|short|byte|boolean)\s+([A-Za-z_]\w*)\s*(?=[=;,)]|$)",
            line,
        ):
            bindings[name] = declared_type.rsplit(".", 1)[-1]
        inferred = re.search(
            r"\bvar\s+([A-Za-z_]\w*)\s*=\s*HttpClient\.newHttpClient\s*\(",
            line,
        )
        if inferred:
            bindings[inferred.group(1)] = "HttpClient"
    return bindings


def _csharp_fetch_bindings(
    lines: list[str], known: dict[str, str] | None = None
) -> dict[str, str]:
    bindings: dict[str, str] = dict(known or {})
    for line in lines:
        for declared_type, name in re.findall(
            r"\b(HttpClient|WebClient|HttpWebRequest|WebRequest|IHttpClientFactory)\??\s+([A-Za-z_]\w*)\b",
            line,
        ):
            bindings[name] = declared_type
        inferred = re.search(
            r"\bvar\s+([A-Za-z_]\w*)\s*=\s*(?:new\s+(HttpClient|WebClient)\b|WebRequest\.Create(?:Http)?\s*\()",
            line,
        )
        if inferred:
            bindings[inferred.group(1)] = inferred.group(2) or (
                "WebRequest" if "WebRequest.Create" in line else "HttpClient"
            )
        factory_call = re.search(
            r"\bvar\s+([A-Za-z_]\w*)\s*=\s*(?:this\.)?([A-Za-z_]\w*)\.CreateClient\s*\(",
            line,
        )
        if factory_call and bindings.get(factory_call.group(2)) == "IHttpClientFactory":
            bindings[factory_call.group(1)] = "HttpClient"
    return bindings


def _csharp_fetch_call_matches_type(
    line: str, call_start: int, pattern: str, bindings: dict[str, str]
) -> bool:
    if "JsonAsync" in pattern:
        return True
    receiver = re.search(r"(?:this\.)?([A-Za-z_]\w*)\s*$", line[:call_start])
    if receiver is None:
        prefix = line[:call_start]
        expected = "WebClient" if "Download" in pattern else "HttpClient"
        if "GetResponse" not in pattern and re.search(
            rf"\bnew\s+{expected}\s*\([^)]*\)\s*$", prefix
        ):
            return True
        return expected == "HttpClient" and bool(
            re.search(r"\b(?:GetClient|CreateClient)\s*\([^)]*\)\s*$", prefix)
        )
    declared_type = bindings.get(receiver.group(1))
    if "Download" in pattern:
        return declared_type == "WebClient"
    if "GetResponse" in pattern:
        return declared_type in {"WebRequest", "HttpWebRequest"}
    return declared_type == "HttpClient"


def _go_http_aliases(source_lines: list[str]) -> set[str]:
    """Names this file binds the `net/http` package to."""
    aliases: set[str] = set()
    for line in source_lines:
        # The word boundary belongs to the alias: an import-block row is a bare
        # `"net/http"` after indentation, where no boundary precedes the quote.
        imported = re.search(r"(?:\b(\w+)\s+)?[\"`]net/http[\"`]", line)
        if imported:
            alias = imported.group(1)
            aliases.add("http" if alias in {None, "import"} else alias)
    return aliases


def _go_fetch_bindings(lines: list[str], http_aliases: set[str]) -> set[str]:
    bindings: set[str] = set()
    package_names = "|".join(re.escape(alias) for alias in sorted(http_aliases))
    if not package_names:
        return bindings
    for line in lines:
        bindings.update(re.findall(
            rf"\b([A-Za-z_]\w*)\s+\*?(?:{package_names})\.Client\b", line
        ))
        bindings.update(re.findall(
            rf"\b([A-Za-z_]\w*)\s*:?=\s*(?:&?(?:{package_names})\.Client\s*\{{|(?:{package_names})\.DefaultClient\b)",
            line,
        ))
    return bindings


def _php_interpolated_calls(node: Any) -> list[Any]:
    """The interpolations of a PHP string literal that reach a call.

    `"{$pdo->exec($sql)}"` runs the method; `"$pdo->exec($sql)"` reads the
    `exec` *property* and renders `($sql)` verbatim, which is why the test is
    whether the grammar put a call inside the interpolation rather than
    whether it put an expression there. A `nowdoc` and a single-quoted
    `string` interpolate nothing and have no such child at all.
    """
    reached: list[Any] = []
    for child in node.named_children:
        if child.type in _PHP_STRING_BODY_TYPES:
            reached.extend(_php_interpolated_calls(child))
        elif child.type not in _PHP_STRING_PART_TYPES and any(
            descendant.type in _CALL_NODE_TYPES["php"]
            for descendant in _walk_named_nodes(child)
        ):
            reached.append(child)
    return reached


def _span_outside(
    span: tuple[int, int | None], holes: list[tuple[int, int | None]]
) -> list[tuple[int, int | None]]:
    """*span* with each of *holes* -- ordered and disjoint -- taken out of it.

    `None` is the end of the line, which is past every column on it.
    """
    start, end = span
    pieces: list[tuple[int, int | None]] = []
    cursor = start
    for hole_start, hole_end in holes:
        stop = hole_start if end is None else min(hole_start, end)
        if cursor < stop:
            pieces.append((cursor, stop))
        if hole_end is None:
            return pieces
        cursor = max(cursor, hole_end)
        if end is not None and cursor >= end:
            return pieces
    if end is None or cursor < end:
        pieces.append((cursor, end))
    return pieces


def _php_quoted_spans(tree: Any, source: bytes) -> dict[int, list[tuple[int, int | None]]]:
    """Per line, the character columns each PHP string literal covers as text.

    A line cannot tell a call from the text of a string that names one, so
    `$help = 'call $pdo->exec($sql) to run it';` reported a `sql_exec` the file
    never runs -- and through it a classification priority and a hunt the file
    had not earned. The grammar can tell them apart, and these are its spans.

    Where PHP evaluates part of a literal it is code, not text: an
    `encapsed_string` or `heredoc` carries `{$...}` as a child expression, and
    the span of one that reaches a call is taken back out. Covering it instead
    dropped the `sql_exec` and `process_exec` of `"rows: {$pdo->exec($sql)}"`,
    which the file does run. Every other byte of the literal stays covered, so
    a call named in its text is still only text.

    Only where a match *starts* is tested, and the content is left in place
    rather than blanked, because four PHP rows read a literal on purpose:
    `header('Location`, the `http` of `file_get_contents` and `fopen`, and
    `preg_replace`'s `/e`. Each of those starts outside the quote that holds
    what it reads, so rejecting by match start keeps every one of them.
    """
    spans: dict[int, list[tuple[int, int | None]]] = {}
    for node in _named_nodes_of_types(tree, _PHP_STRING_TYPES):
        start_line, start_column, end_line, end_column = _node_character_range(node, source)
        holes = [
            _node_character_range(call, source)
            for call in _php_interpolated_calls(node)
        ]
        for line_number in range(start_line, end_line + 1):
            covered = (
                start_column if line_number == start_line else 0,
                end_column if line_number == end_line else None,
            )
            spans.setdefault(line_number - 1, []).extend(_span_outside(covered, [
                (
                    hole_start_column if line_number == hole_start_line else 0,
                    hole_end_column if line_number == hole_end_line else None,
                )
                for hole_start_line, hole_start_column, hole_end_line, hole_end_column in holes
                if hole_start_line <= line_number <= hole_end_line
            ]))
    return spans


def _starts_inside_quote(spans: list[tuple[int, int | None]], column: int) -> bool:
    """Whether *column* is strictly inside one of *spans*."""
    return any(
        start < column and (end is None or column < end) for start, end in spans
    )


def _detect_sinks(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
    file_scope_lines: list[tuple[int, str]],
    quoted_spans: dict[int, list[tuple[int, int | None]]] | None = None,
) -> list[dict[str, Any]]:
    """Detect security-sensitive API calls in callable bodies and file scope.

    *quoted_spans* names the string literals a language's grammar resolved, for
    the languages whose rows are read off a line; a match starting inside one
    is reading text, not a call. See `_php_quoted_spans`.
    """
    sinks: list[dict[str, Any]] = []
    java_class_receivers: dict[int, dict[str, str]] = {}
    java_class_for_line: dict[int, dict[str, Any]] = {}
    csharp_class_receivers: dict[int, dict[str, str]] = {}
    csharp_class_for_line: dict[int, dict[str, Any]] = {}
    go_http_aliases: set[str] = set()
    if language == "java":
        callable_lines = {
            line
            for function in functions
            for line in range(function["line_start"], function["line_end"] + 1)
        }
        for cls in sorted(classes, key=lambda item: item["line_end"] - item["line_start"], reverse=True):
            for line in range(cls["line_start"], cls["line_end"] + 1):
                java_class_for_line[line] = cls
            java_class_receivers[id(cls)] = _java_fetch_bindings([
                source_lines[line - 1]
                for line in range(cls["line_start"], cls["line_end"] + 1)
                if line not in callable_lines
            ])
    elif language == "csharp":
        callable_lines = {
            line
            for function in functions
            for line in range(function["line_start"], function["line_end"] + 1)
        }
        for cls in sorted(classes, key=lambda item: item["line_end"] - item["line_start"], reverse=True):
            for line in range(cls["line_start"], cls["line_end"] + 1):
                csharp_class_for_line[line] = cls
            csharp_class_receivers[id(cls)] = _csharp_fetch_bindings([
                source_lines[line - 1]
                for line in range(cls["line_start"], cls["line_end"] + 1)
                if line not in callable_lines
            ])
    elif language == "go":
        go_http_aliases = _go_http_aliases(source_lines)
    seen: set[tuple[str, str, int]] = set()
    readers = _sink_line_readers(language)
    gate = _sink_line_gate(language)
    case_blind = language in _CASE_BLIND_SINK_LANGUAGES

    scopes = [
        (func, _function_scan_lines(func, source_lines))
        for func in functions
        if not func.get("is_declaration", False)
    ]
    if file_scope_lines:
        scopes.append(({"name": "<top-level>"}, file_scope_lines))

    for func, scan_lines in scopes:
        java_fetch_receivers: dict[str, str] = {}
        csharp_fetch_receivers: dict[str, str] = {}
        go_fetch_receivers: set[str] = set()
        # Each line is filtered once, and a line holding no literal a gated
        # pattern requires is offered only to the patterns that require none.
        readable = [
            (line_idx, line_text, line_text.lower() if case_blind else line_text)
            for line_idx, line_text in scan_lines
            if source_lines[line_idx]
        ]
        if language == "java":
            cls = java_class_for_line.get(func.get("line_start", 0))
            if cls is not None:
                java_fetch_receivers.update(java_class_receivers[id(cls)])
            java_fetch_receivers.update(_java_fetch_bindings(func.get("params", [])))
            java_fetch_receivers.update(_java_fetch_bindings([line for _, line, _ in readable]))
        elif language == "csharp":
            cls = csharp_class_for_line.get(func.get("line_start", 0))
            if cls is not None:
                csharp_fetch_receivers.update(csharp_class_receivers[id(cls)])
            csharp_fetch_receivers = _csharp_fetch_bindings(
                func.get("params", []), csharp_fetch_receivers
            )
            csharp_fetch_receivers = _csharp_fetch_bindings(
                [line for _, line, _ in readable], csharp_fetch_receivers
            )
        elif language == "go":
            go_fetch_receivers.update(_go_fetch_bindings(func.get("params", []), go_http_aliases))
            go_fetch_receivers.update(_go_fetch_bindings([line for _, line, _ in readable], go_http_aliases))
        admitted = readable if gate is None else [
            line for line in readable if gate.search(line[2])
        ]
        for sink_def, patterns in readers:
            for pat, compiled, literals in patterns:
                if go_fetch_receivers and sink_def["kind"] == "url_fetch" and ".Do" in pat:
                    # A variable bound to a `net/http` client fetches whatever it is named.
                    names = "|".join(re.escape(name) for name in sorted(go_fetch_receivers))
                    compiled, literals = re.compile(rf"{pat}|\b(?:{names})\.Do\s*\("), ()
                for line_idx, line_text, probe in admitted if literals else readable:
                    if literals and not any(literal in probe for literal in literals):
                        continue
                    matches = compiled.finditer(line_text)
                    if language == "java" and sink_def["kind"] == "url_fetch":
                        matches = (
                            match for match in matches
                            if _java_fetch_call_matches_type(
                                line_text, match.start(), pat, java_fetch_receivers
                            )
                        )
                    elif language == "csharp" and sink_def["kind"] == "url_fetch":
                        matches = (
                            match for match in matches
                            if _csharp_fetch_call_matches_type(
                                line_text, match.start(), pat, csharp_fetch_receivers
                            )
                        )
                    if quoted_spans is not None:
                        quoted = quoted_spans.get(line_idx, [])
                        matches = (
                            match for match in matches
                            if not _starts_inside_quote(quoted, match.start())
                        )
                    if next(matches, None) is not None:
                        identity = (sink_def["kind"], func["name"], line_idx)
                        if identity in seen:
                            continue
                        seen.add(identity)
                        snippet = line_text.strip()
                        if len(snippet) > 120:
                            snippet = snippet[:117] + "..."
                        sinks.append({
                            "kind": sink_def["kind"],
                            "line": line_idx + 1,
                            "function": func["name"],
                            "snippet": snippet,
                            "vuln_classes": list(sink_def["vuln_classes"]),
                        })
                        # Retain distinct lines so a safe-looking early call
                        # cannot hide a later call that handles request data.

    return sinks


# Common language keywords to exclude from the line-read call sites of every
# language but PHP. `defined` is the C preprocessor's operator in
# `#if defined(X)`, which file scope reads.
_CALL_NOISE = frozenset({
    "if", "else", "for", "while", "switch", "case", "return", "throw",
    "new", "delete", "try", "catch", "finally", "import", "from",
    "class", "def", "function", "var", "let", "const", "static",
    "async",
    "public", "private", "protected", "void", "int", "float",
    "double", "long", "short", "char", "boolean", "String",
    "True", "False", "None", "null", "undefined", "this", "self",
    "typeof", "instanceof", "sizeof", "assert", "print", "println",
    "func", "go", "defer", "select", "chan", "range", "type", "struct",
    "interface", "map", "make", "append", "len", "cap", "copy", "close",
    "string", "bool", "byte", "error", "nil", "fmt", "log",
    "puts", "raise", "rescue", "ensure", "yield", "begin", "end",
    "do", "then", "elsif", "unless", "until", "when", "module",
    "require", "include", "extend", "attr_accessor", "attr_reader",
    "echo", "isset", "empty", "unset", "array", "list",
    "foreach", "elseif", "endforeach", "endif", "endwhile",
    "defined",
})


@lru_cache(maxsize=8192)
def _parameter_name_pattern(name: str) -> re.Pattern[str]:
    """A caller parameter named as a whole word. Names recur across files and
    a per-call compile would churn the regex cache every other reader uses."""
    return re.compile(r"\b" + re.escape(name) + r"\b")


def _detect_call_sites(
    functions: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
    file_scope_lines: list[tuple[int, str]],
) -> list[dict[str, Any]]:
    """Detect function calls in each callable body and in file scope.

    A call site carries ``passes_caller_params: true`` when the call forwards
    any of the caller's parameter names as arguments -- a lightweight signal
    for data-flow propagation -- and omits it otherwise.
    """
    calls: list[dict[str, Any]] = []
    scopes = [
        (func, _function_scan_lines(func, source_lines))
        for func in functions
        if not func.get("is_declaration", False)
    ]
    if file_scope_lines:
        scopes.append(({"name": "<top-level>", "params": []}, file_scope_lines))

    for func, scan_lines in scopes:
        # Keyed on the line, not the function: a literal `exec("ls")` at the top
        # of a handler must not hide the `exec($tainted)` fifty lines down, which
        # is the call the taint scheduler exists to reach. One line repeating a
        # callee is still one site.
        seen_callees: set[tuple[str, int]] = set()

        param_names: set[str] = set()
        for p in func.get("params", []):
            tokens = re.split(r"[\s:=,*&]+", p.strip())
            for tok in tokens:
                tok = tok.strip().lstrip("$")
                if tok and tok not in _CALL_NOISE and len(tok) > 1:
                    param_names.add(tok)

        for line_idx, line_text in scan_lines:
            if not source_lines[line_idx]:
                continue
            for m in _CALL_RE.finditer(line_text):
                callee = m.group(1)
                simple_name = callee.rsplit(".", 1)[-1]
                if simple_name in _CALL_NOISE:
                    continue
                if simple_name == func["name"]:
                    continue
                if (simple_name, line_idx) in seen_callees:
                    continue
                seen_callees.add((simple_name, line_idx))

                passes_params = False
                if param_names:
                    call_end = m.end()
                    rest_of_line = line_text[call_end:]
                    for pn in param_names:
                        if _parameter_name_pattern(pn).search(rest_of_line):
                            passes_params = True
                            break

                call = {"caller": func["name"], "callee": callee, "line": line_idx + 1}
                if passes_params:
                    call["passes_caller_params"] = True
                calls.append(call)

    return calls


# PHP's call shapes, read from the parse tree rather than off a line: a method
# call, a static call and a construction are their own nodes, so `->delete()`,
# `::make()` and `new Invoice()` are calls by grammar and not by spelling.
_PHP_CALL_KINDS = {
    "function_call_expression": "function",
    "member_call_expression": "method",
    "nullsafe_member_call_expression": "nullsafe_method",
    "scoped_call_expression": "static",
    "object_creation_expression": "new",
}
_PHP_CALLABLE_NODE_TYPES = frozenset(
    {"anonymous_function", "arrow_function", "function_definition", "method_declaration"}
)
_PHP_CALL_QUERY = "\n".join((
    "[" + " ".join(f"({node_type})" for node_type in _PHP_CALL_KINDS) + "] @call",
    "[" + " ".join(f"({node_type})" for node_type in sorted(_PHP_CALLABLE_NODE_TYPES)) + "] @callable",
))
# Language constructs that read like a function call. The grammar gives most of
# them their own node; `isset`, `empty`, `exit` and `die` parse as calls, and a
# construct is never a function a caller could reach. PHP keywords ignore case.
_PHP_CALL_CONSTRUCTS = frozenset({
    "die", "echo", "empty", "exit", "include", "include_once", "isset", "print",
    "require", "require_once", "unset",
})
_PHP_PARAMETER_TYPES = frozenset(
    {"property_promotion_parameter", "simple_parameter", "variadic_parameter"}
)
_PHP_SELF_RECEIVERS = frozenset({"$this", "self", "static"})
# A receiver is the object or scope text of a call, which a fluent chain makes
# arbitrarily long; the bound keeps it a readable citation, not a copy.
_PHP_CALL_TEXT_LIMIT = 120


def _php_parameter_names(callable_node: Any, source: bytes) -> frozenset[str]:
    """The variable names a PHP callable's parameters bind, without `$`."""
    parameters = callable_node.child_by_field_name("parameters")
    names: set[str] = set()
    for parameter in parameters.named_children if parameters is not None else ():
        variable = (
            parameter.child_by_field_name("name")
            if parameter.type in _PHP_PARAMETER_TYPES
            else None
        )
        if variable is not None:
            names.add(_node_text(variable, source).lstrip("$"))
    return frozenset(names)


def _php_arguments_use(arguments: Any, names: frozenset[str], source: bytes) -> bool:
    """Whether a variable named in *names* appears anywhere in *arguments*."""
    stack = [arguments]
    while stack:
        node = stack.pop()
        if node.type == "variable_name":
            name = node.named_children[0] if node.named_children else None
            if name is not None and _node_text(name, source) in names:
                return True
            continue
        stack.extend(node.named_children)
    return False


def _php_call_text(node: Any, source: bytes) -> str:
    return _snippet(" ".join(_node_text(node, source).split()), _PHP_CALL_TEXT_LIMIT)


def _php_call_shape(call: Any) -> tuple[Any, Any, Any] | None:
    """`(callee node, receiver node, arguments node)` of one PHP call node."""
    if call.type == "function_call_expression":
        return call.child_by_field_name("function"), None, call.child_by_field_name("arguments")
    if call.type == "object_creation_expression":
        children = call.named_children
        target = next(
            (child for child in children if child.type in {"name", "qualified_name", "variable_name"}),
            None,
        )
        if target is None:
            # `new class (...) { ... }`: the anonymous class is a class record,
            # and its constructor is a callable of its own.
            return None
        arguments = next((child for child in children if child.type == "arguments"), None)
        return target, None, arguments
    receiver = call.child_by_field_name("scope" if call.type == "scoped_call_expression" else "object")
    return call.child_by_field_name("name"), receiver, call.child_by_field_name("arguments")


# Sinks only the parse tree can tell from their lookalikes, so they have no
# line pattern and the streaming fallback does not report them: a backtick
# shell command (a backtick on a line is as often a string or a comment), a
# callable or class chosen at run time, and a Guzzle client built by the short
# name the file imports it under. The mass-assignment builtins and
# variable-variable assignments are read here as well; a line can only
# approximate them, which is what `_PHP_STREAM_MASS_ASSIGNMENT` and
# `_PHP_STREAM_VARIABLE_VARIABLE` do.
_PHP_AST_SINK_QUERY = "\n".join((
    "(shell_command_expression) @shell",
    "(assignment_expression left: (dynamic_variable_name)) @variable_variable",
    "(function_call_expression) @call",
    "(member_call_expression) @method",
    "(nullsafe_member_call_expression) @method",
    "(scoped_call_expression) @method",
    "(object_creation_expression) @new",
))
# The builtins that call a callable they are handed, by the position of the
# argument that names it; a named argument is always `callback`.
# `preg_replace_callback_array` takes an array of them, one per pattern.
_PHP_DYNAMIC_CALLERS = {
    "call_user_func": 0, "call_user_func_array": 0, "forward_static_call": 0,
    "forward_static_call_array": 0, "array_map": 0, "register_shutdown_function": 0,
    "spl_autoload_register": 0, "set_error_handler": 0, "set_exception_handler": 0,
    "ob_start": 0, "preg_replace_callback_array": 0,
    "array_filter": 1, "array_walk": 1, "array_walk_recursive": 1, "array_reduce": 1,
    "usort": 1, "uasort": 1, "uksort": 1, "preg_replace_callback": 1, "iterator_apply": 1,
}
# The magic constants a `[$this, __FUNCTION__]` callable names its method by.
_PHP_MAGIC_METHOD_NAMES = frozenset({"__FUNCTION__", "__METHOD__"})
# Callees that name their function in the source text: `acme_render(...)`,
# `\Acme\render(...)`. Every other callee is a value chosen at run time.
_PHP_NAMED_CALLEE_TYPES = frozenset({"name", "qualified_name", "relative_name"})
_PHP_LITERAL_CALLABLE_TYPES = frozenset({"anonymous_function", "arrow_function"})
_PHP_GUZZLE_CLIENT = "GuzzleHttp\\Client"


def _php_literal_string(node: Any) -> bool:
    return node.type in {"string", "nowdoc"} or (
        node.type == "encapsed_string"
        and all(child.type in _PHP_STRING_PART_TYPES for child in node.named_children)
    )


def _php_literal_callable(node: Any, source: bytes) -> bool:
    """Whether a callable argument names its function in the source text."""
    if _php_literal_string(node) or node.type in _PHP_LITERAL_CALLABLE_TYPES:
        return True
    arguments = node.child_by_field_name("arguments")
    if arguments is not None and [child.type for child in arguments.named_children] == ["variadic_placeholder"]:
        # A first-class callable, `trim(...)` or `$this->format(...)`.
        callee = node.child_by_field_name("function") or node.child_by_field_name("name")
        return callee is not None and callee.type in _PHP_NAMED_CALLEE_TYPES
    if node.type != "array_creation_expression":
        return False
    elements = [child for child in node.named_children if child.type == "array_element_initializer"]
    method = elements[-1].named_children[-1] if elements and elements[-1].named_children else None
    return method is not None and (
        _php_literal_string(method)
        or (method.type == "name" and _node_text(method, source).upper() in _PHP_MAGIC_METHOD_NAMES)
    )


def _php_callback_values(name: str, values: list[Any], source: bytes) -> list[Any]:
    """The callable values a callback builtin is handed; empty when there is none.

    A spread argument is returned as itself: what it unpacks is chosen at run time."""
    argument = next(
        (
            value for value in values
            if (label := value.child_by_field_name("name")) is not None
            and _node_text(label, source) == "callback"
        ),
        values[_PHP_DYNAMIC_CALLERS[name]] if _PHP_DYNAMIC_CALLERS[name] < len(values) else None,
    )
    if argument is None:
        return []
    if argument.type != "argument" or not argument.named_children:
        return [argument]
    value = argument.named_children[-1]
    if name == "preg_replace_callback_array" and value.type == "array_creation_expression":
        return [
            element.named_children[-1]
            for element in value.named_children
            if element.type == "array_element_initializer" and element.named_children
        ]
    return [] if value.type == "null" else [value]


def _php_callback_sink_kinds(name: str) -> list[str]:
    """The sink kinds a call to the function a literal callback names would be."""
    call = name + "("
    return [
        definition["kind"]
        for definition, patterns in _sink_line_readers("php")
        if any(compiled.search(call) for _pattern, compiled, _literals in patterns)
    ]


def _php_ast_sinks(
    tree: Any,
    source: bytes,
    locator: _PhpCallableLocator,
    source_lines: list[str],
    import_targets: list[dict[str, Any]],
    known: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """The PHP sinks read off the parse tree, one per kind, callable and line."""
    parser = _get_parser("php")
    if parser is None:
        return []
    classes = {definition["kind"]: definition["vuln_classes"] for definition in _SINK_DEFINITIONS}
    guzzle_names = {
        target.get("alias") or target["qualified_name"].rsplit("\\", 1)[-1]
        for target in import_targets
        if target.get("kind") == "class" and target.get("qualified_name") == _PHP_GUZZLE_CLIENT
    }
    captures = _ts_query_captures(parser.language, _PHP_AST_SINK_QUERY, tree.root_node)
    found: list[tuple[str, Any]] = [("process_exec", node) for node in captures.get("shell", [])]
    found.extend(("mass_assignment", node) for node in captures.get("variable_variable", []))
    for call in captures.get("call", []):
        function = call.child_by_field_name("function")
        arguments = call.child_by_field_name("arguments")
        values = [
            argument for argument in (arguments.named_children if arguments is not None else ())
            if argument.type in {"argument", "variadic_unpacking"}
        ]
        if function is None:
            continue
        callee = function
        while callee.type == "parenthesized_expression" and callee.named_children:
            callee = callee.named_children[0]
        if callee.type not in _PHP_NAMED_CALLEE_TYPES:
            if not _php_literal_callable(callee, source):
                found.append(("dynamic_invocation", call))
            continue
        name = _node_text(function, source).lstrip("\\").lower()
        if name in _PHP_DYNAMIC_CALLERS:
            for callable_value in _php_callback_values(name, values, source):
                if not _php_literal_callable(callable_value, source):
                    found.append(("dynamic_invocation", call))
                elif _php_literal_string(callable_value):
                    found.extend(
                        (kind, call)
                        for kind in _php_callback_sink_kinds(_node_text(callable_value, source)[1:-1])
                    )
        elif name in {"extract", "import_request_variables"} or (name == "parse_str" and len(values) == 1):
            found.append(("mass_assignment", call))
    for method_call in captures.get("method", []):
        # `$client->$fn()`, `$client->{$fn}()`, `Acme::$fn()`: the method is a
        # value chosen at run time.
        method = method_call.child_by_field_name("name")
        if method is not None and method.type != "name" and not _php_literal_string(method):
            found.append(("dynamic_invocation", method_call))
    for creation in captures.get("new", []):
        target = next(
            (
                child for child in creation.named_children
                if child.type not in {"arguments", "attribute_list"}
            ),
            None,
        )
        if target is None or target.type in {"declaration_list", "base_clause", "anonymous_class"}:
            continue
        if target.type not in {"name", "qualified_name"}:
            # `new $cls`, `new $this->handler`, `new $classes[$mode]`,
            # `new ($factory)`: the class is a value chosen at run time.
            # `new namespace\Acme` and `new (Acme::class)` name it in source.
            if not _php_constant_expression(target):
                found.append(("dynamic_invocation", creation))
            continue
        text = _node_text(target, source)
        if (
            target.type == "qualified_name" and text.lstrip("\\") == _PHP_GUZZLE_CLIENT
        ) or (target.type == "name" and text in guzzle_names):
            found.append(("url_fetch", creation))
    seen = {(sink["kind"], sink["function"], sink["line"]) for sink in known}
    sinks: list[dict[str, Any]] = []
    for kind, node in sorted(found, key=lambda item: item[1].start_byte):
        caller = locator.innermost(node.start_byte, node.end_byte)
        line_index = node.start_point[0]
        identity = (kind, caller["name"] if caller is not None else "<top-level>", line_index + 1)
        if identity in seen:
            continue
        seen.add(identity)
        sinks.append({
            "kind": kind,
            "line": line_index + 1,
            "function": identity[1],
            "snippet": _snippet(source_lines[line_index]) if line_index < len(source_lines) else "",
            "vuln_classes": list(classes[kind]),
        })
    return sinks


class _PhpCallableLocator:
    """The innermost PHP callable holding a byte range, for the parse-tree readers."""

    def __init__(self, functions: list[dict[str, Any]]) -> None:
        self.callables = [
            function for function in functions if not function.get("is_declaration", False)
        ]
        self._starts = [function["_start_byte"] for function in self.callables]
        # Callable spans nest, so the innermost callable holding a range is the
        # last one opening before it or one of that callable's enclosing callables.
        self._enclosing: list[int] = []
        open_callables: list[int] = []
        for index, function in enumerate(self.callables):
            while (
                open_callables
                and self.callables[open_callables[-1]]["_end_byte"] <= function["_start_byte"]
            ):
                open_callables.pop()
            self._enclosing.append(open_callables[-1] if open_callables else -1)
            open_callables.append(index)

    def position(self, start_byte: int, end_byte: int) -> int:
        """Index of the innermost callable holding the range, or -1 for file scope."""
        position = bisect_right(self._starts, start_byte) - 1
        while position >= 0 and self.callables[position]["_end_byte"] < end_byte:
            position = self._enclosing[position]
        return position

    def innermost(self, start_byte: int, end_byte: int) -> dict[str, Any] | None:
        position = self.position(start_byte, end_byte)
        return self.callables[position] if position >= 0 else None


def _detect_php_call_sites(
    tree: Any,
    functions: list[dict[str, Any]],
    source: bytes,
    withheld: list[tuple[int, str]],
) -> tuple[list[dict[str, Any]], bool]:
    """PHP call sites from the parse tree, and whether a withheld line held one.

    Each call is attributed to its innermost callable, or to `<top-level>`,
    and kept once per line per callee. It names its `receiver` when it has one
    and carries `passes_caller_params: true` when an argument mentions a
    variable one of the caller's parameters binds. A call on a declaration
    header line the file-scope readers withhold is not recorded, because the
    sink readers do not read that line either; the second value reports that
    such a call exists, so the gap is declared.
    """
    parser = _get_parser("php")
    if parser is None:
        return [], False
    captures = _ts_query_captures(parser.language, _PHP_CALL_QUERY, tree.root_node)
    callable_nodes = {
        (node.start_byte, node.end_byte): node for node in captures.get("callable", [])
    }
    locator = _PhpCallableLocator(functions)
    callables = locator.callables
    parameter_names: dict[int, frozenset[str]] = {}
    withheld_lines = {index for index, _line in withheld}
    sites: dict[int, dict[tuple[str, int], dict[str, Any]]] = {}
    withheld_call = False

    for call in captures.get("call", []):
        shape = _php_call_shape(call)
        if shape is None or shape[0] is None:
            continue
        target, receiver_node, arguments = shape
        callee = _php_call_text(
            target.named_children[-1] if target.type == "qualified_name" else target, source
        )
        call_kind = _PHP_CALL_KINDS[call.type]
        if call_kind == "function" and callee.lower() in _PHP_CALL_CONSTRUCTS:
            continue
        receiver = _php_call_text(receiver_node, source) if receiver_node is not None else ""

        position = locator.position(call.start_byte, call.end_byte)
        caller = callables[position] if position >= 0 else None
        node = (
            callable_nodes.get((caller["_start_byte"], caller["_end_byte"]))
            if caller is not None
            else None
        )
        if node is not None and callee == caller["name"] and (
            (call_kind == "function" and node.type == "function_definition")
            or (node.type == "method_declaration" and receiver in _PHP_SELF_RECEIVERS)
        ):
            # Direct recursion. A same-named call through another receiver --
            # `parent::__construct()` in a constructor -- is a different callee.
            continue
        line_index = target.start_point[0]
        if caller is None and line_index in withheld_lines:
            withheld_call = True
            continue

        names: frozenset[str] = frozenset()
        if node is not None:
            if position not in parameter_names:
                parameter_names[position] = _php_parameter_names(node, source)
            names = parameter_names[position]
        passes_params = bool(
            names and arguments is not None and _php_arguments_use(arguments, names, source)
        )
        scope_sites = sites.setdefault(position, {})
        existing = scope_sites.get((callee, line_index))
        if existing is not None:
            if passes_params:
                existing["passes_caller_params"] = True
            continue
        site = {
            "caller": caller["name"] if caller is not None else "<top-level>",
            "callee": callee,
            "line": line_index + 1,
            "_column": target.start_point[1],
        }
        if receiver:
            site["receiver"] = receiver
        if passes_params:
            site["passes_caller_params"] = True
        scope_sites[(callee, line_index)] = site

    # Callers in source order and `<top-level>` last, each read top to bottom:
    # the order the line readers produce, which decides what the signal limit keeps.
    calls: list[dict[str, Any]] = []
    for position in [*range(len(callables)), -1]:
        ordered = sorted(
            sites.get(position, {}).values(),
            key=lambda record: (record["line"], record["_column"]),
        )
        for site in ordered:
            del site["_column"]
        calls.extend(ordered)
    return calls, withheld_call


def _detect_exports(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Detect exported symbols based on language conventions."""
    exports: list[dict[str, Any]] = []

    if language == "c":
        seen_names: set[str] = set()
        for func in functions:
            if "static" in func.get("modifiers", []) or func["name"] in seen_names:
                continue
            seen_names.add(func["name"])
            exports.append({
                "name": func["name"],
                "kind": "function",
                "line": func["line_start"],
            })
    elif language == "go":
        for func in functions:
            if func["name"] and func["name"][0].isupper():
                exports.append({"name": func["name"], "kind": "function", "line": func["line_start"]})
        for cls in classes:
            if cls["name"] and cls["name"][0].isupper():
                exports.append({"name": cls["name"], "kind": "type", "line": cls["line_start"]})
    elif language in ("javascript", "typescript"):
        export_re = re.compile(r"\bexport\s+(?:default\s+)?(?:abstract\s+)?(?:function|class|const|let|var|type|interface|enum)\s+(\w+)")
        named_export_re = re.compile(r"\bexport\s*\{([^}]+)\}")
        module_exports_re = re.compile(r"\bmodule\.exports\s*=")
        for idx, line in enumerate(source_lines):
            m = export_re.search(line)
            if m:
                exports.append({"name": m.group(1), "kind": "named_export", "line": idx + 1})
                continue
            m = named_export_re.search(line)
            if m:
                for name in m.group(1).split(","):
                    name = name.strip().split(" as ")[-1].strip()
                    if name:
                        exports.append({"name": name, "kind": "named_export", "line": idx + 1})
                continue
            if module_exports_re.search(line):
                exports.append({"name": "module.exports", "kind": "cjs_export", "line": idx + 1})
    elif language == "python":
        all_re = re.compile(r"__all__\s*=\s*\[([^\]]*)\]")
        has_all = False
        for idx, line in enumerate(source_lines):
            m = all_re.search(line)
            if m:
                has_all = True
                for name in re.findall(r"['\"](\w+)['\"]", m.group(1)):
                    exports.append({"name": name, "kind": "all_export", "line": idx + 1})
        if not has_all:
            for func in functions:
                if not func["name"].startswith("_"):
                    exports.append({"name": func["name"], "kind": "public_function", "line": func["line_start"]})
            for cls in classes:
                if not cls["name"].startswith("_"):
                    exports.append({"name": cls["name"], "kind": "public_class", "line": cls["line_start"]})
    elif language == "java":
        for func in functions:
            if "public" in func.get("modifiers", []):
                exports.append({"name": func["name"], "kind": "public_method", "line": func["line_start"]})
        for cls in classes:
            if cls.get("_java_public"):
                exports.append({"name": cls["name"], "kind": "public_class", "line": cls["line_start"]})
    elif language == "ruby":
        for func in functions:
            if not func.get("_ruby_route"):
                exports.append({"name": func["name"], "kind": "method", "line": func["line_start"]})
    elif language == "php":
        for func in functions:
            if func.get("is_closure", False):
                continue
            if "public" in func.get("modifiers", []) or not func.get("modifiers"):
                exports.append({"name": func["name"], "kind": "public_method", "line": func["line_start"]})
    elif language == "csharp":
        for func in functions:
            if "public" in func.get("modifiers", []):
                exports.append({"name": func["name"], "kind": "public_method", "line": func["line_start"]})
        for cls in classes:
            if cls.get("_csharp_public"):
                exports.append({"name": cls["name"], "kind": "public_class", "line": cls["line_start"]})

    return exports


def _uncommented_source(tree: Any, source: bytes) -> bytes:
    """*source* with every grammar comment blanked and its line breaks kept."""
    visible = bytearray(source)
    for node in _named_nodes_of_types(tree, _COMMENT_NODE_TYPES):
        visible[node.start_byte:node.end_byte] = re.sub(
            rb"[^\r\n]", b" ", source[node.start_byte:node.end_byte]
        )
    return bytes(visible)


def _resolve_import_targets(
    imports: list[str],
    language: str,
) -> list[dict[str, str]]:
    """Resolve import strings to likely file targets within the repo."""
    targets: list[dict[str, str]] = []

    for imp in imports:
        target: dict[str, str] = {"raw": imp, "resolved": ""}

        if language == "python":
            m = re.match(r"from\s+([\w.]+)\s+import", imp)
            if m:
                target["resolved"] = m.group(1).replace(".", "/") + ".py"
            elif imp.startswith("import "):
                mod = imp.removeprefix("import ").strip().split(",")[0].strip()
                target["resolved"] = mod.replace(".", "/") + ".py"
        elif language in ("javascript", "typescript"):
            m = re.search(r"""from\s+['"]([^'"]+)['"]""", imp)
            if m:
                path = m.group(1)
                if path.startswith("."):
                    target["resolved"] = path
        elif language == "go":
            target["resolved"] = imp
        elif language == "ruby":
            if "/" in imp or imp.startswith("."):
                target["resolved"] = imp + ".rb" if not imp.endswith(".rb") else imp
            else:
                target["resolved"] = imp
        elif language in ("c", "cpp"):
            if not imp.startswith("<"):
                target["resolved"] = imp
        elif language == "java":
            target["resolved"] = imp.replace(".", "/") + ".java"
        elif language == "lua":
            target["resolved"] = imp.replace(".", "/") + ".lua"
        elif language in {"shell", "powershell"}:
            if imp.startswith(("./", "../", ".\\", "..\\")):
                target["resolved"] = imp.replace("\\", "/")

        targets.append(target)

    return targets


def _cpp_qualified_name(
    namespace: str,
    declared_scope: str,
    name: str,
) -> str:
    if namespace and (
        declared_scope == namespace or declared_scope.startswith(f"{namespace}::")
    ):
        symbol_scope = declared_scope
    else:
        symbol_scope = "::".join(
            part for part in (namespace, declared_scope) if part
        )
    dotted_scope = symbol_scope.replace("::", ".")
    return f"{dotted_scope}.{name}" if dotted_scope else name


def _enrich_qualified_names(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
    source: bytes,
) -> None:
    """Set qualified_name to ClassName.method for methods inside classes."""
    if language == "cpp":
        for cls in classes:
            containers = [
                candidate
                for candidate in classes
                if candidate is not cls
                and candidate["_start_byte"] <= cls["_start_byte"]
                and cls["_end_byte"] <= candidate["_end_byte"]
            ]
            containers.sort(key=lambda candidate: candidate["_start_byte"])
            namespace = cls.get("_cpp_namespace", "").replace("::", ".")
            class_parts = [
                *(candidate["name"] for candidate in containers),
                cls["name"],
            ]
            cls["_qualified_name"] = ".".join(
                [*([namespace] if namespace else []), *class_parts]
            )

        for func in functions:
            containers = [
                cls
                for cls in classes
                if cls["_start_byte"] <= func["_start_byte"]
                and func["_end_byte"] <= cls["_end_byte"]
            ]
            if containers and not func.get("_cpp_is_friend", False):
                containers.sort(
                    key=lambda candidate: (
                        candidate["_end_byte"] - candidate["_start_byte"]
                    )
                )
                func["qualified_name"] = (
                    f"{containers[0]['_qualified_name']}.{func['name']}"
                )
            else:
                func["qualified_name"] = _cpp_qualified_name(
                    func.get("_cpp_namespace", ""),
                    func.get("_cpp_declared_scope", ""),
                    func["name"],
                )
        _bound_callable_names(functions, source)
        return

    if language == "php":
        # PHP spells a namespaced symbol with its own separator; the method
        # separator stays `.` as in every other language here. A closure is a
        # value bound to a variable, and variables are not namespaced.
        for func in functions:
            if func["_php_namespace"] and not func.get("is_closure", False):
                func["qualified_name"] = f"{func['_php_namespace']}\\{func['name']}"
    for cls in classes:
        owner = (
            f"{cls['_php_namespace']}\\{cls['name']}"
            if cls.get("_php_namespace")
            else cls["name"]
        )
        for func in functions:
            if cls["_start_byte"] <= func["_start_byte"] and func["_end_byte"] <= cls["_end_byte"]:
                func["qualified_name"] = f"{owner}.{func['name']}"

    _bound_callable_names(functions, source)
    _disambiguate_qualified_names(functions)


def _disambiguate_qualified_names(functions: list[dict[str, Any]]) -> None:
    """Make `(qualified_name, line_start, line_end)` unique within a file.

    `code-index sync` keys a callable on that tuple and refuses the WHOLE
    repository when two rows share one, because it builds a single payload per
    repo. Minified and obfuscated sources defeat it honestly: they reuse short
    names across scopes and put the program on one line, so two real functions
    collide. Qualifying the loser with its byte offset -- the same
    `@line:col` shape the extractors already use for anonymous callables --
    keeps both rows and leaves `name` as authored for citation.
    """
    seen: dict[tuple[str, int, int], int] = {}
    for func in sorted(functions, key=lambda f: f.get("_start_byte", 0)):
        identity = (func["qualified_name"], func["line_start"], func["line_end"])
        if identity not in seen:
            seen[identity] = 1
            continue
        offset = func.get("_start_byte")
        suffix = offset if offset is not None else seen[identity]
        seen[identity] += 1
        func["qualified_name"] = (
            f"{func['qualified_name']}@{func['line_start']}:{suffix}"
        )


# `api/code_analysis.py:StructuralCallableRecord` caps both names, and
# `code-index` build and sync degrade a file with a callable past either.
STRUCTURAL_CALLABLE_NAME_LIMIT = 512
STRUCTURAL_QUALIFIED_NAME_LIMIT = 1024


def _bound_callable_names(functions: list[dict[str, Any]], source: bytes) -> None:
    """Name a callable by its position when a derived name is empty or past the cap."""
    for func in functions:
        name_fits = 0 < len(func["name"]) <= STRUCTURAL_CALLABLE_NAME_LIMIT
        # Leaves room for the `@line:offset` `_disambiguate_qualified_names` may append.
        qualified_fits = 0 < len(func["qualified_name"]) <= STRUCTURAL_QUALIFIED_NAME_LIMIT - 32
        if name_fits and qualified_fits:
            continue
        start = func.get("_start_byte")
        column = 0 if start is None else _source_character_column(source, start)
        position = f"<anonymous@{func['line_start']}:{column}>"
        if not name_fits:
            func["name"] = position
        if not qualified_fits:
            func["qualified_name"] = position


def _cpp_function_identity(function: dict[str, Any]) -> tuple[Any, ...]:
    qualified_name = re.sub(
        r"\s*([*&<>,()\[\]])\s*",
        r"\1",
        re.sub(
            r"\s+",
            " ",
            function["qualified_name"].replace("::", ".").strip(),
        ),
    )
    return (
        qualified_name,
        function["_cpp_parameter_signature"],
        function["_cpp_qualifier_signature"],
    )


def _deduplicate_cpp_functions(
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Collapse repeated declarations, retaining every distinct definition."""
    by_identity: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for function in functions:
        identity = _cpp_function_identity(function)
        by_identity.setdefault(identity, []).append(function)

    retained: list[dict[str, Any]] = []
    for matching_functions in by_identity.values():
        definitions = [
            function
            for function in matching_functions
            if not function["is_declaration"]
        ]
        retained.extend(definitions or matching_functions[:1])
    return sorted(retained, key=lambda function: function["_start_byte"])


def _remove_internal_structural_fields(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
) -> None:
    for function in functions:
        for field_name in (
            "_body_end_column",
            "_body_end_line",
            "_body_start_column",
            "_body_start_line",
            "_initializer_ranges",
            "_ruby_route",
            "_excluded_ranges",
            "_cpp_parameter_signature",
            "_cpp_qualifier_signature",
            "_cpp_declared_scope",
            "_cpp_is_friend",
            "_cpp_namespace",
            "_php_namespace",
            "_end_byte",
            "_start_byte",
        ):
            function.pop(field_name, None)
    for cls in classes:
        for field_name in (
            "_cpp_namespace",
            "_php_namespace",
            "_java_public",
            "_csharp_public",
            "_end_byte",
            "_qualified_name",
            "_start_byte",
        ):
            cls.pop(field_name, None)


# ---------------------------------------------------------------------------
# Lightweight regex-based extractors
#
# These cover security-relevant file families that the tree-sitter pipeline
# ignores (Dockerfile, shell, Lua, HTML/templates, CSS). They return the same
# dict shape as the tree-sitter path so downstream consumers keep working.
# ---------------------------------------------------------------------------


def _index_lightweight(
    file_path: str,
    language: str,
    source_lines: list[str],
    total_lines: int,
) -> dict[str, Any]:
    """Dispatch helper for lightweight extractors."""
    dispatch = {
        "blade": _extract_blade,
        "shell": _extract_shell,
        "powershell": _extract_powershell,
        "lua": _extract_lua,
        "html": _extract_html,
        "css": _extract_css,
        "twig": _extract_twig,
    }
    local_docker_sources: list[str] = []
    if language == "dockerfile":
        funcs, entry_points, sinks, exports, imports, local_docker_sources = (
            _extract_dockerfile(source_lines)
        )
    elif language == "freemarker":
        # The one lightweight extractor whose result depends on the filename and
        # not only on the bytes: the extension carries FreeMarker's output format,
        # which decides whether auto-escaping is on before any directive is read.
        funcs, entry_points, sinks, exports, imports = _extract_freemarker(
            source_lines, file_path=file_path
        )
    else:
        fn = dispatch.get(language)
        if fn is None:
            return _empty_index(file_path, language, total_lines=total_lines)
        funcs, entry_points, sinks, exports, imports = fn(source_lines)
    import_targets = _resolve_import_targets(imports, language)
    imports.extend(local_docker_sources)
    import_targets.extend(
        {
            "raw": path,
            "resolved": "" if any(char in path for char in "*?[") else path.removeprefix("./"),
        }
        for path in local_docker_sources
    )
    indexed: dict[str, Any] = {
        "file_path": file_path,
        "language": language,
        "total_functions": len(funcs),
        "total_lines": total_lines,
        "functions": funcs,
        "entry_points": entry_points,
        "security_sinks": sinks,
        "call_sites": [],
        "imports": imports,
        "import_targets": import_targets,
        "exports": exports,
        "classes": [],
    }
    if language == "blade":
        # Blade's taint sources are its echo constructs, and a `{{-- --}}`
        # comment can contain one. Only the whole-file construct scan can tell
        # the two apart, so this language reads its own sources rather than
        # taking the bounded per-line table `_attach_bounded_security_sources`
        # would apply.
        indexed["security_sources"] = _blade_template_sources(source_lines)
    return indexed


# --- Dockerfile -------------------------------------------------------------

def language_for_file(file_path: str) -> str | None:
    """Return the language key for a file, or None if unsupported.

    Recognises both tree-sitter-backed languages (by extension) and the
    lightweight regex-based extractors. Dockerfiles are matched by basename
    (``Dockerfile`` or ``Dockerfile.<variant>``).
    """
    return structural_language_for_file(file_path)


def index_file(
    file_path: str,
    language: str,
    source: bytes | None = None,
) -> dict[str, Any]:
    """Parse one bounded source value and return explicit coverage status."""
    if source is None:
        try:
            with open(file_path, "rb") as fh:
                source = fh.read()
        except OSError as exc:
            warnings.warn(f"Cannot read {file_path}: {exc}")
            return _empty_index(file_path, language)

    # Tree-sitter starts a row only at LF; the snapshot also counts a bare CR.
    source = re.sub(rb"\r(?!\n)", b"\n", source)
    source_lines = _source_lines(source)
    total_lines = len(source_lines)

    # Lightweight regex-based extractors run regardless of tree-sitter availability
    if language in LIGHTWEIGHT_LANGUAGES:
        try:
            indexed = _index_lightweight(file_path, language, source_lines, total_lines)
            _bound_callable_names(indexed["functions"], source)
            _disambiguate_qualified_names(indexed["functions"])
            _attach_bounded_security_sources(
                indexed, file_path=file_path, language=language, source=source
            )
            return _complete_index_metadata(
                indexed,
                source_size=len(source),
                analysis_mode="lightweight_regex",
                # The lightweight extractors are whole-file line readers, so no
                # dimension of theirs depends on a callable being found; only a
                # code body they hold but do not read leaves one unmeasured.
                unscanned_dimensions=(
                    _unread_body_dimensions(indexed)
                    if _holds_unread_code(language, source_lines)
                    else set()
                ),
            )
        except MemoryError:
            raise
        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"lightweight extractor for '{language}' on {file_path} failed: {exc}; "
                "using bounded streaming security fallback.",
                stacklevel=2,
            )
            return _fallback_from_bytes(
                file_path,
                language,
                source,
                degradation_reason="lightweight_extractor_error",
            )

    if not _TS_AVAILABLE:
        warnings.warn(
            "tree-sitter is not installed; returning degraded index without "
            "structural analysis. Install tree-sitter and language grammars "
            "for full indexing.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_unavailable",
        )

    if language not in _TS_SUPPORTED_LANGUAGES:
        indexed = _empty_index(file_path, language, total_lines=total_lines)
        indexed.update(
            {
                "structural_index_available": False,
                "analysis_status": "unsupported",
                "analysis_mode": "none",
                "degradation_reason": "unsupported_language",
                "source_size": len(source),
                "bytes_scanned": len(source),
                "unavailable_dimensions": list(_UNSUPPORTED_UNAVAILABLE_DIMENSIONS),
                "artifact_truncated": False,
                "truncated_dimensions": [],
                "signal_counts": {dimension: 0 for dimension in _SIGNAL_DIMENSIONS},
            }
        )
        return indexed

    parse_lang = language
    if file_path.endswith(".tsx"):
        parse_lang = "tsx"

    parser = _get_parser(parse_lang)
    if parser is None:
        warnings.warn(
            f"tree-sitter grammar for '{language}' not available; returning "
            "degraded index.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_grammar_unavailable",
        )

    try:
        tree = parser.parse(source)
    except MemoryError:
        raise
    except Exception as exc:  # noqa: BLE001 - retain bounded signal coverage
        warnings.warn(
            f"tree-sitter parse for '{language}' on {file_path} failed: {exc}; "
            "using bounded streaming security fallback.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_parse_error",
        )
    if tree is None:
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_parse_failed",
        )
    if bool(getattr(tree.root_node, "has_error", False)):
        warnings.warn(
            f"tree-sitter parse for '{language}' on {file_path} contains error nodes; "
            "using bounded streaming security fallback instead of claiming complete structure.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_syntax_error",
        )

    lang_obj = getattr(parser, "language", None)
    if lang_obj is not None:
        _SHARED_TREE_QUERIES.open(
            tree.root_node, lang_obj, _whole_tree_queries(parse_lang, lang_obj)
        )
    try:
        functions = _extract_functions_ts(tree, parse_lang, source)
        classes = _extract_classes_ts(tree, parse_lang, source)
        php_includes = _php_includes(tree, source, file_path) if language == "php" else []
        imports, import_targets = _extract_import_records(
            tree, parse_lang, source, php_includes
        )

        effective_lang = "typescript" if parse_lang == "tsx" else language
        uncommented = _uncommented_source(tree, source)
        code_lines = _source_lines(uncommented)
        # The line readers read code and never commentary, and
        # `_uncommented_source` blanked each comment where it stood: a line
        # holding both keeps its code at its own columns, and a line that is
        # all commentary reads as empty. That is the answer `_file_scope_lines`
        # already gives by blanking the comment spans it masks, and the one
        # `_attach_bounded_security_sources` gives by reading `uncommented`.
        # Reading the raw line instead reported a sink for the text of a
        # trailing comment that neither of the other two readers of the same
        # artifact agreed with.
        reader_lines = [code if code.strip() else "" for code in code_lines]
        _enrich_qualified_names(functions, classes, effective_lang, source)
        if effective_lang == "cpp":
            functions = _deduplicate_cpp_functions(functions)
        file_scope = _file_scope_lines(
            tree, functions, effective_lang, source_lines, source
        )
        entry_points = _detect_entry_points(
            tree, functions, classes, effective_lang, source_lines, source, file_path
        )
        entry_points.extend(
            _detect_top_level_entry_points(
                tree, effective_lang, source_lines, entry_points, file_scope.scanned
            )
        )
        if effective_lang == "php":
            entry_points.extend(_detect_php_file_scope_entry(
                file_scope,
                source,
                tree,
                _executable_file_scope_lines(
                    tree, functions, effective_lang, source, code_lines, set()
                ),
            ))
        sinks = _detect_sinks(
            functions, classes, effective_lang, reader_lines, file_scope.scanned,
            _php_quoted_spans(tree, source) if effective_lang == "php" else None,
        )
        if effective_lang == "php":
            locator = _PhpCallableLocator(functions)
            sinks.extend(_php_include_sinks(php_includes, locator, source_lines))
            sinks.extend(
                _php_ast_sinks(tree, source, locator, source_lines, import_targets, sinks)
            )
        withheld_call = False
        if effective_lang == "php":
            call_sites, withheld_call = _detect_php_call_sites(
                tree, functions, source, file_scope.withheld
            )
        else:
            call_sites = _detect_call_sites(
                functions, effective_lang, reader_lines, file_scope.scanned
            )
        unscanned = _unscanned_scope_dimensions(
            functions,
            entry_points,
            source_lines,
            tree=tree,
            language=effective_lang,
            function_scoped_records=bool(sinks or call_sites),
            file_scope=file_scope,
            withheld_call=withheld_call,
            executable_file_scope=lambda: bool(_executable_file_scope_lines(
                tree, functions, effective_lang, source, code_lines,
                {sink["line"] - 1 for sink in sinks if sink["function"] == "<top-level>"},
            )),
        )
        if effective_lang == "php" and any(
            node.type == "text" and _holds_inline_script(_node_text(node, source))
            for node in _named_nodes_of_types(tree, _file_scope_candidate_types("php"))
        ):
            unscanned |= _unread_body_dimensions(
                {"security_sinks": sinks, "call_sites": call_sites}
            )
        exports = _detect_exports(functions, classes, effective_lang, code_lines)
        security_observations: dict[str, Any] = {}
        _attach_bounded_security_sources(
            security_observations,
            file_path=file_path,
            language=effective_lang,
            source=uncommented,
        )
        if effective_lang == "java":
            for func in functions:
                if not any(re.fullmatch(r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)", annotation)
                           for annotation in func["annotations"]):
                    continue
                for param in func["params"]:
                    if not param.strip() or "@" in param:
                        continue
                    parameter_type = param.strip().rsplit(" ", 1)[0].rsplit(".", 1)[-1]
                    if parameter_type in {"Principal", "Model", "ModelMap"}:
                        continue
                    security_observations["security_sources"].append({
                        "kind": "http_request_input",
                        "line": func.get("_body_start_line", func["line_start"]),
                        "snippet": param[:120],
                        "detection": "structural_model_binding",
                    })
            security_observations["signal_counts"]["security_sources"] = len(
                security_observations["security_sources"]
            )
        if effective_lang == "python":
            routed = {
                (entry["name"], entry["line"])
                for entry in entry_points
                if entry["kind"] in {"fastapi_route", "fastapi_router"}
            }
            for func in functions:
                if (func["name"], func["line_start"]) not in routed:
                    continue
                for param in func["params"]:
                    if (
                        not param.strip()
                        or "Depends" in param
                        or re.search(r":\s*(?:Request|Response|BackgroundTasks|WebSocket)\b", param)
                    ):
                        continue
                    security_observations["security_sources"].append({
                        "kind": "http_request_input",
                        "line": func["line_start"],
                        "snippet": param[:120],
                        "detection": "structural_model_binding",
                    })
            security_observations["signal_counts"]["security_sources"] = len(
                security_observations["security_sources"]
            )
        if effective_lang == "csharp":
            for func in functions:
                if not func["is_entry_point"] or not (
                    func.get("_minimal_api_route")
                    or any(
                        entry["kind"] == "aspnet_action" and entry["name"] == func["name"]
                        and entry["line"] == func["line_start"]
                        for entry in entry_points
                    )
                ):
                    continue
                for param in func["params"]:
                    if (
                        not param.strip()
                        or "[FromServices" in param
                        or re.search(
                            r"\b(?:CancellationToken|HttpContext|HttpRequest|HttpResponse|ClaimsPrincipal|IServiceProvider|ILogger)\??\s+\w+\b",
                            param,
                        )
                    ):
                        continue
                    if func.get("_minimal_api_route") and not re.search(
                        r"\b(?:string|int|long|short|bool|decimal|double|float|Guid|DateTime|DateOnly|TimeOnly)\??\s+\w+\b|\[From(?:Body|Query|Route|Form|Header)\b",
                        param,
                    ):
                        continue
                    security_observations["security_sources"].append({
                        "kind": "http_request_input",
                        "line": func["line_start"],
                        "snippet": param[:120],
                        "detection": "structural_model_binding",
                    })
            security_observations["signal_counts"]["security_sources"] = len(
                security_observations["security_sources"]
            )
        # Past the signal limit the function registry is truncated, so the file
        # owes a whole-file span and its file-scope segments would prove nothing.
        top_level_segments: list[dict[str, int]] = []
        if len(functions) <= STRUCTURAL_SIGNAL_LIMIT:
            signal_lines = {
                sink["line"] - 1 for sink in sinks if sink["function"] == "<top-level>"
            } | {
                source_record["line"] - 1
                for source_record in security_observations["security_sources"]
            }
            top_level_segments = _top_level_segments(
                functions,
                _executable_file_scope_lines(
                    tree, functions, effective_lang, source, code_lines, signal_lines
                ),
            )
        _remove_internal_structural_fields(functions, classes)
    except MemoryError:
        _SHARED_TREE_QUERIES.close()
        raise
    except Exception as exc:  # noqa: BLE001 - retain bounded signal coverage
        _SHARED_TREE_QUERIES.close()
        warnings.warn(
            f"tree-sitter extraction for '{language}' on {file_path} failed: {exc}; "
            "using bounded streaming security fallback.",
            stacklevel=2,
        )
        return _fallback_from_bytes(
            file_path,
            language,
            source,
            degradation_reason="tree_sitter_analysis_error",
        )
    _SHARED_TREE_QUERIES.close()

    return _complete_index_metadata(
        {
            "file_path": file_path,
            "language": language,
            "total_functions": len(functions),
            "total_exports": len(exports),
            "total_lines": total_lines,
            "functions": functions,
            "top_level_segments": top_level_segments,
            "entry_points": entry_points,
            "security_sinks": sinks,
            "security_sources": security_observations["security_sources"],
            "call_sites": call_sites,
            "imports": imports,
            "import_targets": import_targets,
            "exports": exports,
            "classes": classes,
            "signal_counts": security_observations["signal_counts"],
        },
        source_size=len(source),
        analysis_mode="tree_sitter",
        unscanned_dimensions=unscanned,
    )


def _empty_index(
    file_path: str,
    language: str,
    total_lines: int = 0,
) -> dict[str, Any]:
    """Return an empty structural index stub."""
    return {
        "file_path": file_path,
        "language": language,
        "total_functions": 0,
        "total_exports": 0,
        "total_lines": total_lines,
        "functions": [],
        "entry_points": [],
        "security_sinks": [],
        "security_sources": [],
        "call_sites": [],
        "imports": [],
        "import_targets": [],
        "exports": [],
        "classes": [],
    }
