from __future__ import annotations

from vigil_cli.goose_reasoning_proxy import make_server, repair_messages


def test_repair_messages_only_fills_missing_assistant_tool_reasoning() -> None:
    body = {
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "reasoning_content": "I will read alpha",
                "tool_calls": [{"id": "c0", "type": "function"}],
            },
            {"role": "tool", "tool_call_id": "c0", "content": "alpha"},
            {"role": "assistant", "tool_calls": [{"id": "c1", "type": "function"}]},
            {"role": "tool", "tool_call_id": "c1", "content": "bravo"},
            {"role": "assistant", "reasoning_content": "", "tool_calls": [{"id": "c2"}]},
            {"role": "tool", "tool_call_id": "c2", "content": "charlie"},
            {"role": "assistant", "content": "final answer"},
        ]
    }

    assert repair_messages(body, " ") == 2
    messages = body["messages"]
    assert messages[2]["reasoning_content"] == "I will read alpha"
    assert messages[4]["reasoning_content"] == " "
    assert messages[6]["reasoning_content"] == " "
    assert "reasoning_content" not in messages[8]
    assert repair_messages(body, " ") == 0


def test_proxy_factory_binds_only_loopback_on_an_ephemeral_port() -> None:
    server = make_server("https://api.deepseek.com", 0, " ", debug=False)
    try:
        host, port = server.server_address[:2]
        assert host == "127.0.0.1"
        assert isinstance(port, int) and port > 0
    finally:
        server.server_close()


def test_repair_messages_leaves_non_object_json_unchanged() -> None:
    body: object = []

    assert repair_messages(body, " ") == 0
    assert body == []
