from urllib.parse import parse_qs, urlsplit

from assess.commands import code_dispatch
from test_code_dispatch_list import _FakeClient, _config


def test_queue_listing_passes_dispatch_identity_to_backend(monkeypatch, tmp_path):
    filters, output = code_dispatch._parse_list_filters(["--agent-id", "acme-hunter-b", "--json"])
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _FakeClient)
    _FakeClient.requested = []

    code_dispatch._list(_config(tmp_path), filters, output)

    query = parse_qs(urlsplit(_FakeClient.requested[-1]).query)
    assert query["agent_name"] == ["acme-hunter-b"]
