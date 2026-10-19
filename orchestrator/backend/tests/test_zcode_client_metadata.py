"""ZCode is an asserted client identity, never provider attestation."""
import pytest
from pydantic import ValidationError

from app.api.assessment_operator import DispatchClientBindingCreate, DispatchCreate


def test_zcode_identity_uses_existing_assertion_boundary():
    request = DispatchCreate(agent_id="ACME-1", agent_role="code-architect", client_name="zcode")
    assert request.launcher_effective_client == "zcode"
    assert request.provider_observed_client == "unknown"
    binding = DispatchClientBindingCreate(asserted_client="zcode",
        asserted_session_namespace="acme/workspace", asserted_client_handle="native-1")
    assert binding.asserted_client_handle == "native-1"


def test_zcode_cannot_claim_provider_observation():
    with pytest.raises(ValidationError):
        DispatchCreate(agent_id="ACME-1", agent_role="code-architect",
                       client_name="zcode", provider_observed_client="zcode")
