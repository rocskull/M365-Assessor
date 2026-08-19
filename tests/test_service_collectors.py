from __future__ import annotations

import httpx
import pytest

from m365_assessor.collectors.base import CollectionContext
from m365_assessor.collectors.registry import default_registry
from m365_assessor.config import Settings
from m365_assessor.core.service import ServicePayload, SnapshotServiceClient
from m365_assessor.models.enums import CollectorStatus


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("collector_id", "service", "payload_key", "expected_key"),
    [
        ("exo001", "exchange", "organization_config", "organization_config"),
        ("exo002", "exchange", "safe_links", "safe_links"),
        ("exo003", "exchange", "mailboxes", "mailboxes"),
        ("teams001", "teams", "client_configuration", "client_configuration"),
        ("teams002", "teams", "meeting_policies", "meeting_policies"),
        ("teams003", "teams", "messaging_policies", "messaging_policies"),
        ("sps001", "sharepoint", "tenant", "tenant"),
        ("sps002", "sharepoint", "sites", "sites"),
        ("purview001", "purview", "audit_config", "audit_config"),
        ("purview002", "purview", "label_policies", "label_policies"),
        ("fabric001", "fabric", "tenant_settings_json", "tenant_settings_json"),
    ],
)
async def test_service_collector_uses_injected_read_client(
    graph_factory,
    collector_id: str,
    service: str,
    payload_key: str,
    expected_key: str,
) -> None:
    graph = graph_factory(httpx.MockTransport(lambda _request: pytest.fail("no Graph call")))
    collector = default_registry().get(collector_id)
    client = SnapshotServiceClient({"data": {payload_key: [{"DisplayName": "Example"}]}})
    result = await collector.collect(
        CollectionContext(
            graph=graph,
            settings=Settings(),
            granted_permissions=set(),
            service_clients={service: client},
        )
    )
    assert result.status is CollectorStatus.SUCCESS
    assert expected_key in result.data
    assert "display_name" in str(result.data[expected_key])


class _PartialClient:
    async def collect(self, commands: dict[str, str]) -> ServicePayload:
        del commands
        return ServicePayload(data={"meeting_policies": []}, errors=["one command denied"])

    async def health_check(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_partial_service_evidence_is_retained(graph_factory) -> None:
    graph = graph_factory(httpx.MockTransport(lambda _request: pytest.fail("no Graph call")))
    collector = default_registry().get("teams002")
    result = await collector.collect(
        CollectionContext(
            graph=graph,
            settings=Settings(),
            granted_permissions=set(),
            service_clients={"teams": _PartialClient()},
        )
    )
    assert result.status is CollectorStatus.PARTIAL
    assert result.data == {"meeting_policies": []}
    assert result.api_errors == ["one command denied"]
