from __future__ import annotations

import httpx
import pytest

from m365_assessor.auth.provider import AuthResult, StaticAccessTokenProvider
from m365_assessor.core.graph import GraphClient


@pytest.fixture
def auth_result() -> AuthResult:
    return AuthResult(
        access_token="test-token",  # noqa: S106 - inert unit-test token
        tenant_id="tenant-id",
        client_id="client-id",
        method="interactive",
        identity="tester@example.invalid",
        granted_permissions={"Organization.Read.All", "User.Read"},
        permission_source="token_response",
    )


@pytest.fixture
def graph_factory(auth_result: AuthResult):
    clients: list[httpx.AsyncClient] = []

    def factory(handler: httpx.MockTransport) -> GraphClient:
        http = httpx.AsyncClient(transport=handler)
        clients.append(http)
        return GraphClient(StaticAccessTokenProvider(auth_result), http_client=http)

    yield factory
