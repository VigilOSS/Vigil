"""Lua module edges for agent navigation across script trees."""

from assess.lib.treesitter_index import index_file


def test_lua_require_names_resolve_to_likely_repository_files() -> None:
    source = b'local db = require("lib.db")\nlocal codec = require("codec")\n'
    indexed = index_file("src/main.lua", "lua", source)

    assert indexed["analysis_status"] == "complete"
    assert indexed["import_targets"] == [
        {"raw": "lib.db", "resolved": "lib/db.lua"},
        {"raw": "codec", "resolved": "codec.lua"},
    ]


def test_lua_constant_redis_command_with_script_key_is_not_an_injection_sink() -> None:
    indexed = index_file("cache.lua", "lua", b"return redis.call('GET', KEYS[1])\n")

    assert any(source["kind"] == "script_argument" for source in indexed["security_sources"])
    assert not any("injection" in sink["vuln_classes"] for sink in indexed["security_sinks"])


def test_lua_argument_chosen_redis_command_remains_a_sink() -> None:
    indexed = index_file("cache.lua", "lua", b"return redis.call(ARGV[1], KEYS[1])\n")

    assert any(sink["kind"] == "redis_dynamic_command" for sink in indexed["security_sinks"])


def test_lua_one_line_function_does_not_own_next_functions_sink() -> None:
    source = b"""local function helper() return 1 end
function public() os.execute(cmd) end
"""
    indexed = index_file("module.lua", "lua", source)

    assert next(function for function in indexed["functions"] if function["name"] == "helper")["line_end"] == 1
    assert any(sink["kind"] == "os_execute" and sink["function"] == "public"
               for sink in indexed["security_sinks"])


def test_lua_local_function_is_not_a_public_export() -> None:
    source = b"""local function helper() return 1 end
function public() return helper() end
"""
    indexed = index_file("module.lua", "lua", source)

    assert {symbol["name"] for symbol in indexed["exports"]} == {"public"}
