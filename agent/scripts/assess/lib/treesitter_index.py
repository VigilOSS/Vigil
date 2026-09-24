"""Tree-sitter structural indexing for code analysis.

Parses source files using tree-sitter to extract function/method definitions,
class structures, import statements, entry points, security sinks, and call
sites.  All tree-sitter imports are guarded so the module remains importable
(returning empty/degraded results) when tree-sitter packages are absent.
"""
from __future__ import annotations

import re
import warnings
from functools import lru_cache
from typing import Any

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
    _SINK_DEFINITIONS,
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


def _ts_query_captures(lang_obj: Any, query_str: str, root_node: Any) -> dict[str, list[Any]]:
    """Run a tree-sitter query and return ``{capture_name: [nodes]}``."""
    if tree_sitter is None:
        return {}
    # 0.25+: Query() constructor + QueryCursor
    if hasattr(tree_sitter, "QueryCursor"):
        try:
            query = _compiled_ts_query(lang_obj, query_str)
        except Exception:
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
    except Exception:
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
    "freemarker",
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


def _cpp_http_route_callbacks(tree: Any, source: bytes) -> list[Any]:
    """Find cpp-httplib server handlers, which occupy a route call's second argument."""
    callbacks: list[Any] = []
    aliases: set[tuple[int, int, str]] = set()
    server_bindings: set[tuple[int, int, str]] = set()
    declarations: list[Any] = []
    route_calls: list[Any] = []
    for node in _walk_named_nodes(tree.root_node):
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
    for node in _walk_named_nodes(tree.root_node):
        if node.type != "call_expression":
            continue
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


def _source_character_column(source: bytes, byte_offset: int) -> int:
    line_start = source.rfind(b"\n", 0, byte_offset) + 1
    return len(source[line_start:byte_offset].decode("utf-8", errors="replace"))


def _node_character_range(node: Any, source: bytes) -> tuple[int, int, int, int]:
    return (
        node.start_point[0] + 1,
        _source_character_column(source, node.start_byte),
        node.end_point[0] + 1,
        _source_character_column(source, node.end_byte),
    )


def _public_node_span(node: Any, source: bytes) -> dict[str, int]:
    start_line, start_column, end_line, end_column = _node_character_range(
        node, source
    )
    return {
        "start_byte": int(node.start_byte),
        "end_byte": int(node.end_byte),
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
    }


def _attach_callable_spans(
    parsed: dict[str, Any],
    *,
    callable_node: Any,
    source: bytes,
) -> None:
    parsed["source_span"] = _public_node_span(callable_node, source)
    body = callable_node.child_by_field_name("body")
    if body is None:
        return
    parsed["body_span"] = _public_node_span(body, source)
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
        parsed["source_span"] = _public_node_span(container, source)
        parsed["body_span"] = _public_node_span(body, source)
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
    yield node
    for child in node.named_children:
        yield from _walk_named_nodes(child)


def _normalized_javascript_target(value: str) -> str:
    return value.replace(".prototype.", ".").removesuffix(".prototype")


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
            target = _normalized_javascript_target(_node_text(values[0], source))
            property_node = values[1]
            property_name = _node_text(property_node, source).strip("'\"`")
            if not target or not property_name:
                return None
            return f"{target}.{property_name}"
        current = current.parent
    return None


def _javascript_callable_name(node: Any, source: bytes) -> str:
    explicit_name = node.child_by_field_name("name")
    if explicit_name is not None:
        return _node_text(explicit_name, source)

    define_property_name = _javascript_define_property_name(node, source)
    if define_property_name:
        return define_property_name

    parent = node.parent
    if parent is not None and parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
        if name is not None:
            return _node_text(name, source)
    if parent is not None and parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        if left is not None:
            return _normalized_javascript_target(_node_text(left, source))
    if parent is not None and parent.type in {"pair", "public_field_definition"}:
        key = parent.child_by_field_name("key") or parent.child_by_field_name("name")
        if key is not None:
            return _node_text(key, source).strip("'\"`")

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
        for node in _walk_named_nodes(tree.root_node)
        if node.type in _JAVASCRIPT_CALLABLE_TYPES
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


def _extract_php_closures(tree: Any, source: bytes) -> list[dict[str, Any]]:
    return [
        _parse_php_closure(node, source)
        for node in _walk_named_nodes(tree.root_node)
        if node.type in _PHP_CLOSURE_TYPES
    ]


def _extract_ruby_route_blocks(tree: Any, source: bytes) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for node in _walk_named_nodes(tree.root_node):
        if node.type != "call" or node.child_by_field_name("receiver") is not None:
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
            "source_span": _public_node_span(node, source),
            "body_span": _public_node_span(block, source),
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
                "source_span": _public_node_span(node, source),
            })
    return declarations


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
    elif query_language == "ruby":
        functions = sorted(
            functions + _extract_ruby_route_blocks(tree, source),
            key=lambda function: function["_start_byte"],
        )
    elif query_language == "csharp":
        for node in _walk_named_nodes(tree.root_node):
            if node.type != "lambda_expression":
                continue
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
                          "simple_parameter",
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

    if query_language == "csharp":
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
        elif query_language == "php":
            text = text.removeprefix("use").strip().rstrip(";")
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


def _extract_ruby_imports(source: bytes) -> list[str]:
    """Extract require/require_relative/load from Ruby source via regex."""
    imports: list[str] = []
    for line in source.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for m in _RUBY_REQUIRE_RE.finditer(line):
            imports.append(m.group(1))
    return imports


def _detect_top_level_entry_points(
    tree: Any,
    language: str,
    source_lines: list[str],
    attributed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Detect registrations and guards written as direct program children.

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
        line = source_lines[line_number - 1]
        for pattern in patterns:
            identity = (line_number, pattern["kind"])
            if identity in seen or not re.search(pattern["pattern"], line):
                continue
            if any(
                entry["kind"] == pattern["kind"] and entry["line"] in statement_lines
                for entry in attributed
            ):
                continue
            entry_points.append({
                "name": "<top-level>",
                "line": line_number,
                "kind": pattern["kind"],
                "annotation": "",
            })
            seen.add(identity)
    return entry_points


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


def _detect_entry_points(
    tree: Any,
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
    source: bytes,
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
        for node in _walk_named_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            target = node.child_by_field_name("function")
            if target is None:
                continue
            match = re.fullmatch(
                r"(app|router)\.(?:get|post|put|delete)", _node_text(target, source)
            )
            if match is not None:
                js_route_calls.append((node, match.group(1)))

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
            and cls is not None
            and cls["name"].endswith("Controller")
            and (cls.get("extends") or "").endswith("Controller")
            and not func.get("is_closure")
            and not func["name"].startswith("__")
            and not func["annotations"]
            and not any(modifier in {"private", "protected"} for modifier in func["modifiers"])
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
                if re.search(lp["pattern"], source_lines[line_no]):
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
        by_name = {func["name"]: func for func in functions}
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
                func = by_name.get(_node_text(argument, source))
                if func is None or func["is_entry_point"]:
                    continue
                kind = "express_route" if receiver == "app" else "express_router"
                entry_points.append({
                    "name": func["name"],
                    "line": func["line_start"],
                    "kind": kind,
                    "annotation": "",
                })
                func["is_entry_point"] = True

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
            lines.extend((line_index, line[start:end]) for start, end in visible if start < end)
    return lines


# Comment openers the per-line pattern readers skip. This is a cheap prefix
# test, not a lexer, and it stays one: `*` is a `/* ... */` continuation and
# `#` is a comment in Python, Ruby, PHP and shell but a preprocessor directive
# in C and C++, which is close enough when a false skip costs one line of one
# detector -- and nowhere near enough to decide whether a whole file holds any
# source at all. That question is `_file_is_commentary_only`'s, and it asks the
# grammar. `/*` is deliberately absent: a block comment can close mid-line and
# `/* legacy */ system(cmd);` is a sink, so skipping the line would be a miss.
_LINE_COMMENT_PREFIXES = ("//", "#", "*")

# Dimensions whose only reader is `_function_scan_lines`: `_detect_sinks` and
# `_detect_call_sites` see nothing else, and the caller-parameter propagation
# signal rides on the call sites. Public because `code-coverage` reads the
# published list back and must ask the same question of it.
FUNCTION_SCOPED_DIMENSIONS = frozenset({"call_sites", "dataflow", "security_sinks"})

# Commentary as the grammars label it. `expression_statement` is here for the
# bare string Python and Ruby use as a docstring: the language evaluates it, so
# the parser cannot call it a comment, but it holds no call and no sink.
_COMMENT_NODE_TYPES = frozenset({"comment", "line_comment", "block_comment"})
_DOCSTRING_NODE_TYPES = frozenset({"string", "concatenated_string", "string_literal"})

UNSCANNED_SCOPE_DEGRADATION_REASON = "unscanned_function_scope"


def _is_scannable_source_line(text: str) -> bool:
    """Whether a line is source the function-scoped pattern readers accept."""
    stripped = text.strip()
    return bool(stripped) and not stripped.startswith(_LINE_COMMENT_PREFIXES)


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


@lru_cache(maxsize=None)
def _function_scoped_reader_patterns(language: str) -> tuple[re.Pattern[str], ...]:
    """The sink catalogue `_detect_sinks` would have run over a line."""
    return tuple(
        re.compile(pattern)
        for definition in _SINK_DEFINITIONS
        for pattern in definition["patterns"].get(language, [])
    )


def _unread_reader_signal(
    functions: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
) -> bool:
    """Whether source a function-scoped reader would have matched went unread.

    A callable covers its whole reported span, not only the segments
    `_function_scan_lines` hands the detectors. The difference is the signature
    line, which holds a parameter list and never a call site or a sink; reading
    `def add(a, b):` as unread signal would make every file in every language
    a gap.

    "Would have matched" is likewise not "is any line at all". Imports, class
    headers, type declarations and package statements sit outside every
    callable in almost every file ever written; treating them as a gap would
    leave 72% of this repository permanently degraded, and a flag that is
    always on distinguishes nothing -- which is the ADR 0015 failure in the
    other direction. A call and the sink catalogue are the two shapes these
    readers key on, so a line carrying neither costs nothing by going unread.
    The call test borrows `_detect_call_sites`' own noise vocabulary, so a
    keyword or a CSS `var(--x)` is not mistaken for a call the reader missed.
    """
    scanned: set[int] = set()
    for function in functions:
        if function.get("is_declaration", False):
            continue
        scanned.update(
            range(max(0, int(function["line_start"]) - 1), int(function["line_end"]))
        )
    sink_patterns = _function_scoped_reader_patterns(language)
    for index, line in enumerate(source_lines):
        if index in scanned or not _is_scannable_source_line(line):
            continue
        if any(pattern.search(line) for pattern in sink_patterns):
            return True
        if any(
            match.group(1).rsplit(".", 1)[-1] not in _CALL_NOISE
            for match in _CALL_RE.finditer(line)
        ):
            return True
    return False


def _unscanned_scope_dimensions(
    functions: list[dict[str, Any]],
    entry_points: list[dict[str, Any]],
    source_lines: list[str],
    *,
    tree: Any,
    language: str,
    function_scoped_records: bool,
) -> set[str]:
    """Dimensions whose empty value is an unmade measurement, not a negative.

    A file the parser handled cleanly can still contribute no scanned span: a
    Laravel `routes/web.php`, a Blade template, a module-level script, a header
    of prototypes. `security_sinks: []` there is an unmade measurement, not a
    clean negative, and ADR 0015 forbids reporting the two as the same value.

    The trio is declared when the readers **returned nothing** and either
    bounded no scan at all, or left source they would have matched unread. Both
    halves are load-bearing:

    * Without the second, one callable buys a measurement of the whole file.
      A PHP closure is a callable, so `Route::get('/health', function () {})`
      turned a route file's unread `DB::statement(...)` into a claimed clean.
    * Without the first, the flag cannot be raised at all once a callable has
      reported something -- and it must not be. `unavailable` means zero on
      both sides of the contract (`code_index_sync._validated_structural_metadata`
      and the backend's payload validator), so declaring a dimension that
      retained a record would either reject the whole repository's sync or
      force the indexer to drop signal it really found. A non-empty list is not
      a clean negative, so it is not the value ADR 0015 is about; what it does
      not yet carry is a *partial* measurement, which this contract has no
      slot for.
    """
    if _file_is_commentary_only(tree, source_lines):
        return set()
    unscanned: set[str] = set()
    scanned_any_scope = any(
        _function_scan_lines(function, source_lines)
        for function in functions
        if not function.get("is_declaration", False)
    )
    if not function_scoped_records and (
        not scanned_any_scope
        or _unread_reader_signal(functions, language, source_lines)
    ):
        unscanned |= FUNCTION_SCOPED_DIMENSIONS
    if not functions and not entry_points:
        # Every entry-point rule but the top-level guard is keyed on a callable,
        # so with no callable the catalogue never ran and the guard found nothing.
        unscanned.add("entry_points")
    return unscanned


_TOP_LEVEL_DECLARATION_PREFIXES = (
    "class ",
    "interface ",
    "struct ",
    "enum ",
    "namespace ",
    "package ",
)


def _top_level_scan_lines(
    functions: list[dict[str, Any]], language: str, source_lines: list[str]
) -> list[tuple[int, str]]:
    """Return executable-looking lines outside every reported callable span.

    The structural readers historically scanned callable bodies only. Once a
    file had any callable record, executable module initializers beside those
    callables disappeared from both sink and call-site results while metadata
    still claimed complete coverage. Preserve the callable records and scan
    their complement as the synthetic ``<top-level>`` scope.
    """
    if not functions and language != "php":
        return []
    callable_lines: set[int] = set()
    for function in functions:
        callable_lines.update(
            range(max(0, int(function["line_start"]) - 1), int(function["line_end"]))
        )
    lines: list[tuple[int, str]] = []
    for index, line in enumerate(source_lines):
        stripped = line.strip()
        if (
            index in callable_lines
            or not _is_scannable_source_line(line)
            or stripped.startswith(_TOP_LEVEL_DECLARATION_PREFIXES)
        ):
            continue
        if language in {"c", "cpp"} and (
            (stripped.endswith(";") and "(" in stripped and "=" not in stripped)
            or (
                language == "cpp"
                and "::" in stripped
                and re.match(r"^[~\w:<>,*&\s]+::[~\w]+\s*\(", stripped)
            )
        ):
            # Function prototypes and out-of-class method signatures are
            # declarations, not executable top-level calls. Initializers with
            # an assignment stay visible because C++ global construction does
            # execute before main.
            continue
        lines.append((index, line))
    return lines


def _java_fetch_call_matches_type(
    line: str,
    call_start: int,
    pattern: str,
    receivers: dict[str, str],
) -> bool:
    receiver = re.search(r"(?:this\.)?([A-Za-z_]\w*)\s*$", line[:call_start])
    if receiver is None:
        return False
    declared_type = receivers.get(receiver.group(1))
    if "openStream" in pattern:
        return declared_type == "URL"
    if "getInputStream" in pattern:
        return declared_type in {"URLConnection", "HttpURLConnection"}
    if "getResponseCode" in pattern:
        return declared_type == "HttpURLConnection"
    return declared_type == "HttpClient"


def _java_fetch_bindings(lines: list[str]) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for line in lines:
        if not _is_scannable_source_line(line):
            continue
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
        if not _is_scannable_source_line(line):
            continue
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
    receiver = re.search(r"(?:this\.)?([A-Za-z_]\w*)\s*$", line[:call_start])
    if receiver is None:
        prefix = line[:call_start]
        expected = "WebClient" if "Download" in pattern else "HttpClient"
        if "GetResponse" not in pattern and re.search(
            rf"\bnew\s+{expected}\s*\([^)]*\)\s*$", prefix
        ):
            return True
        factory = re.search(
            r"(?:this\.)?([A-Za-z_]\w*)\.CreateClient\s*\([^)]*\)\s*$", prefix
        )
        return bool(
            expected == "HttpClient"
            and factory
            and bindings.get(factory.group(1)) == "IHttpClientFactory"
        )
    declared_type = bindings.get(receiver.group(1))
    if "Download" in pattern:
        return declared_type == "WebClient"
    if "GetResponse" in pattern:
        return declared_type in {"WebRequest", "HttpWebRequest"}
    return declared_type == "HttpClient"


def _go_fetch_bindings(lines: list[str], http_aliases: set[str]) -> set[str]:
    bindings: set[str] = set()
    package_names = "|".join(re.escape(alias) for alias in sorted(http_aliases))
    if not package_names:
        return bindings
    for line in lines:
        if not _is_scannable_source_line(line):
            continue
        bindings.update(re.findall(
            rf"\b([A-Za-z_]\w*)\s+\*?(?:{package_names})\.Client\b", line
        ))
        bindings.update(re.findall(
            rf"\b([A-Za-z_]\w*)\s*:?=\s*(?:&?(?:{package_names})\.Client\s*\{{|(?:{package_names})\.DefaultClient\b)",
            line,
        ))
    return bindings


def _detect_sinks(
    functions: list[dict[str, Any]],
    classes: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Detect security-sensitive API calls within function bodies using regex."""
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
        for line in source_lines:
            if not _is_scannable_source_line(line):
                continue
            imported = re.search(r"\b(?:(\w+)\s+)?[\"`]net/http[\"`]", line)
            if imported:
                alias = imported.group(1)
                go_http_aliases.add("http" if alias in {None, "import"} else alias)
    seen: set[tuple[str, str, int]] = set()

    scopes = [
        (func, _function_scan_lines(func, source_lines))
        for func in functions
        if not func.get("is_declaration", False)
    ]
    top_level_lines = _top_level_scan_lines(functions, language, source_lines)
    if top_level_lines:
        scopes.append(({"name": "<top-level>"}, top_level_lines))

    for func, scan_lines in scopes:
        java_fetch_receivers: dict[str, str] = {}
        csharp_fetch_receivers: dict[str, str] = {}
        go_fetch_receivers: set[str] = set()
        if language == "java":
            cls = java_class_for_line.get(func.get("line_start", 0))
            if cls is not None:
                java_fetch_receivers.update(java_class_receivers[id(cls)])
            java_fetch_receivers.update(_java_fetch_bindings(func.get("params", [])))
            java_fetch_receivers.update(_java_fetch_bindings([line for _, line in scan_lines]))
        elif language == "csharp":
            cls = csharp_class_for_line.get(func.get("line_start", 0))
            if cls is not None:
                csharp_fetch_receivers.update(csharp_class_receivers[id(cls)])
            csharp_fetch_receivers = _csharp_fetch_bindings(
                func.get("params", []), csharp_fetch_receivers
            )
            csharp_fetch_receivers = _csharp_fetch_bindings(
                [line for _, line in scan_lines], csharp_fetch_receivers
            )
        elif language == "go":
            go_fetch_receivers.update(_go_fetch_bindings(func.get("params", []), go_http_aliases))
            go_fetch_receivers.update(_go_fetch_bindings([line for _, line in scan_lines], go_http_aliases))
        for sink_def in _SINK_DEFINITIONS:
            lang_patterns = sink_def["patterns"].get(language, [])
            for pat in lang_patterns:
                compiled = re.compile(pat)
                for line_idx, line_text in scan_lines:
                    if not _is_scannable_source_line(line_text):
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
                    elif language == "go" and sink_def["kind"] == "url_fetch" and ".Do" in pat:
                        matches = (
                            match for match in matches
                            if match.group().split(".", 1)[0] == "DefaultClient"
                            or match.group().split(".", 1)[0] in go_fetch_receivers
                        )
                    elif language == "php" and sink_def["kind"] == "sql_exec" and "->query" in pat:
                        matches = (
                            match for match in matches
                            if not re.match(r"\$(?:request|req)->query\s*\(", match.group())
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


# Common language keywords to exclude from call-site detection. Module-level so
# `_unread_reader_signal` asks the same question of an unread line that
# `_detect_call_sites` would have asked of a read one.
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
})


def _detect_call_sites(
    functions: list[dict[str, Any]],
    language: str,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Detect function calls within each function body using regex.

    Each call site includes a ``passes_caller_params`` boolean indicating
    whether the call forwards any of the caller's parameter names as
    arguments -- a lightweight signal for data-flow propagation.
    """
    calls: list[dict[str, Any]] = []
    scopes = [
        (func, _function_scan_lines(func, source_lines))
        for func in functions
        if not func.get("is_declaration", False)
    ]
    top_level_lines = _top_level_scan_lines(functions, language, source_lines)
    if top_level_lines:
        scopes.append(({"name": "<top-level>", "params": []}, top_level_lines))

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
            if not _is_scannable_source_line(line_text):
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
                        if re.search(r'\b' + re.escape(pn) + r'\b', rest_of_line):
                            passes_params = True
                            break

                calls.append({
                    "caller": func["name"],
                    "callee": callee,
                    "line": line_idx + 1,
                    "passes_caller_params": passes_params,
                })

    return calls


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
            if not _is_scannable_source_line(line):
                continue
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
            if not _is_scannable_source_line(line):
                continue
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
        elif language == "php":
            parts = imp.strip().rstrip(";")
            target["resolved"] = parts.replace("\\", "/")
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
        return

    for cls in classes:
        for func in functions:
            if cls["line_start"] <= func["line_start"] <= func["line_end"] <= cls["line_end"]:
                func["qualified_name"] = f"{cls['name']}.{func['name']}"

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
            "_end_byte",
            "_start_byte",
        ):
            function.pop(field_name, None)
    for cls in classes:
        for field_name in (
            "_cpp_namespace",
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

    source_lines = source.decode("utf-8", errors="replace").splitlines()
    total_lines = len(source_lines)

    # Lightweight regex-based extractors run regardless of tree-sitter availability
    if language in LIGHTWEIGHT_LANGUAGES:
        try:
            return _complete_index_metadata(
                _attach_bounded_security_sources(
                    _index_lightweight(file_path, language, source_lines, total_lines),
                    file_path=file_path,
                    language=language,
                    source=source,
                ),
                source_size=len(source),
                analysis_mode="lightweight_regex",
                # The lightweight extractors are whole-file line readers; no
                # dimension of theirs depends on a callable being found.
                unscanned_dimensions=set(),
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

    try:
        functions = _extract_functions_ts(tree, parse_lang, source)
        classes = _extract_classes_ts(tree, parse_lang, source)
        imports = _extract_imports_ts(tree, parse_lang, source)

        effective_lang = "typescript" if parse_lang == "tsx" else language
        _enrich_qualified_names(functions, classes, effective_lang)
        if effective_lang == "cpp":
            functions = _deduplicate_cpp_functions(functions)
        entry_points = _detect_entry_points(
            tree, functions, classes, effective_lang, source_lines, source
        )
        entry_points.extend(
            _detect_top_level_entry_points(
                tree, effective_lang, source_lines, entry_points
            )
        )
        sinks = _detect_sinks(functions, classes, effective_lang, source_lines)
        call_sites = _detect_call_sites(functions, effective_lang, source_lines)
        unscanned = _unscanned_scope_dimensions(
            functions,
            entry_points,
            source_lines,
            tree=tree,
            language=effective_lang,
            function_scoped_records=bool(sinks or call_sites),
        )
        exports = _detect_exports(functions, classes, effective_lang, source_lines)
        import_targets = _resolve_import_targets(imports, effective_lang)
        security_observations: dict[str, Any] = {}
        _attach_bounded_security_sources(
            security_observations,
            file_path=file_path,
            language=effective_lang,
            source=source,
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
        _remove_internal_structural_fields(functions, classes)
    except MemoryError:
        raise
    except Exception as exc:  # noqa: BLE001 - retain bounded signal coverage
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

    return _complete_index_metadata(
        {
            "file_path": file_path,
            "language": language,
            "total_functions": len(functions),
            "total_exports": len(exports),
            "total_lines": total_lines,
            "functions": functions,
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
