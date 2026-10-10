from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from assess.commands import agent
from assess.lib.tenant_references import TenantReferenceError, validate_tenant_reference_paths


@pytest.mark.parametrize("layout", ["fresh", "adopted"])
def test_blue_tenant_context_uses_private_workspace_references_not_application_assets(tmp_path, monkeypatch, layout):
    workspace = tmp_path / "workspace"
    application = tmp_path / "application"
    application_agent = application / "agent"
    (application_agent / "references/tenants").mkdir(parents=True)
    tenant_root = workspace / ("agent/references/tenants" if layout == "adopted" else "tenant-references")
    tenant_root.mkdir(parents=True)
    tenant = tenant_root / "acme-okta.md"
    tenant.write_text("# Synthetic private Acme tenant context\n")
    engagement = workspace / ("agent/engagements/acme" if layout == "adopted" else "engagements/acme")
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text(json.dumps({
        "engagement_type": "blue", "tenant_reference_paths": [str(tenant)],
    }))
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(workspace))
    args = SimpleNamespace(
        prompt_context=dict.fromkeys(agent._PROMPT_CONTEXT_FIELDS, "not applicable"),
        rate_budget=None, no_target_traffic=True,
    )
    rendered = agent._dispatch_prompt(
        {"agent_id": "investigator-1", "agent_role": "investigator"},
        engagement_dir=engagement, agent_root=application_agent, source_identity=[], args=args,
    )
    assert str(tenant) in rendered
    assert str(application_agent / "references/tenants") not in rendered


@pytest.mark.parametrize("link", ["file", "ancestor"])
def test_tenant_reference_validation_rejects_in_tree_aliases_and_symlinked_ancestors(tmp_path, link):
    agent_root = tmp_path / "agent"
    tenant_root = agent_root / "references/tenants"
    tenant_root.mkdir(parents=True)
    reference = tenant_root / "acme.md"
    reference.write_text("# Synthetic Acme tenant context\n")
    if link == "file":
        alias = tenant_root / "alias.md"
        alias.symlink_to(reference)
        reference = alias
    else:
        real_agent = tmp_path / "retained-agent"
        agent_root.rename(real_agent)
        agent_root.symlink_to(real_agent, target_is_directory=True)
    with pytest.raises(TenantReferenceError, match="symlink|symbolic"):
        validate_tenant_reference_paths([str(reference)], tenant_root=tenant_root)
