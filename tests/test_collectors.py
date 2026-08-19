from __future__ import annotations

import httpx
import pytest

from m365_assessor.collectors.base import CollectionContext
from m365_assessor.collectors.registry import CollectorRegistry, default_registry
from m365_assessor.collectors.runner import CollectorRunner
from m365_assessor.config import Settings
from m365_assessor.models.enums import CollectorStatus


def test_registry_contains_unique_expected_ids() -> None:
    registry = default_registry()
    assert [item.metadata.id for item in registry.all()] == [
        "entra001",
        "entra002",
        "entra003",
        "entra004",
        "entra005",
        "entra006",
        "entra007",
        "entra008",
        "entra009",
        "entra010",
        "exo001",
        "exo002",
        "exo003",
        "fabric001",
        "purview001",
        "purview002",
        "sps001",
        "sps002",
        "teams001",
        "teams002",
        "teams003",
    ]


def test_registry_rejects_duplicate() -> None:
    registry = CollectorRegistry()
    collector = default_registry().get("entra001")
    registry.register(collector)
    with pytest.raises(ValueError, match="Duplicate"):
        registry.register(collector)


@pytest.mark.asyncio
async def test_tenant_collector_normalizes_organization(graph_factory) -> None:
    graph = graph_factory(
        httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "tenant-id",
                            "displayName": "Contoso",
                            "verifiedDomains": [{"name": "contoso.example", "isDefault": True}],
                        }
                    ]
                },
            )
        )
    )
    context = CollectionContext(
        graph=graph,
        settings=Settings(),
        granted_permissions={"Organization.Read.All"},
    )
    result = await default_registry().get("entra001").collect(context)
    assert result.status is CollectorStatus.SUCCESS
    assert result.data["organization"]["displayName"] == "Contoso"


@pytest.mark.asyncio
async def test_missing_permission_is_not_assessed(graph_factory) -> None:
    graph = graph_factory(
        httpx.MockTransport(lambda _request: pytest.fail("Graph should not be called"))
    )
    context = CollectionContext(graph=graph, settings=Settings(), granted_permissions=set())
    result = await CollectorRunner().run([default_registry().get("entra001")], context)
    assert result["entra001"].status is CollectorStatus.NOT_ASSESSED
    assert "Organization.Read.All" in (result["entra001"].limitation_reason or "")


@pytest.mark.asyncio
async def test_service_collector_has_clear_missing_client_reason(graph_factory) -> None:
    graph = graph_factory(httpx.MockTransport(lambda _request: pytest.fail("no API call expected")))
    context = CollectionContext(graph=graph, settings=Settings(), granted_permissions=set())
    result = await CollectorRunner().run([default_registry().get("teams001")], context)
    assert result["teams001"].status is CollectorStatus.NOT_ASSESSED
    assert "service client" in (result["teams001"].limitation_reason or "")
