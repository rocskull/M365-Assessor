from __future__ import annotations

import httpx
import pytest

from m365_assessor.core.graph import GraphApiError


@pytest.mark.asyncio
async def test_pagination_collects_every_page(graph_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer test-token"
        if "page=2" in str(request.url):
            return httpx.Response(200, json={"value": [{"id": "2"}]})
        return httpx.Response(
            200,
            json={
                "value": [{"id": "1"}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?page=2",
            },
        )

    graph = graph_factory(httpx.MockTransport(handler))
    result = await graph.paginate("/users")
    assert [item["id"] for item in result.items] == ["1", "2"]
    assert result.pages_collected == 2
    assert result.objects_collected == 2


@pytest.mark.asyncio
async def test_throttling_respects_retry_after(auth_result) -> None:
    calls = 0
    delays: list[float] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "3"}, json={"error": {}})
        return httpx.Response(200, json={"value": []})

    async def sleep(delay: float) -> None:
        delays.append(delay)

    from m365_assessor.auth.provider import StaticAccessTokenProvider
    from m365_assessor.core.graph import GraphClient

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    graph = GraphClient(
        StaticAccessTokenProvider(auth_result), http_client=http, retry_count=1, sleep=sleep
    )
    assert await graph.get("/users") == {"value": []}
    assert calls == 2
    assert delays == [3]
    await http.aclose()


@pytest.mark.asyncio
async def test_graph_error_omits_response_body(graph_factory) -> None:
    graph = graph_factory(
        httpx.MockTransport(
            lambda _request: httpx.Response(
                403, headers={"request-id": "safe-id"}, text="sensitive tenant body"
            )
        )
    )
    with pytest.raises(GraphApiError) as caught:
        await graph.get("/organization")
    assert "safe-id" in str(caught.value)
    assert "sensitive" not in str(caught.value)


@pytest.mark.asyncio
async def test_rejects_cross_host_next_link(graph_factory) -> None:
    graph = graph_factory(
        httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={"value": [], "@odata.nextLink": "https://evil.invalid/steal"},
            )
        )
    )
    with pytest.raises(GraphApiError, match="outside"):
        await graph.paginate("/users")


@pytest.mark.asyncio
async def test_non_list_pagination_value_fails(graph_factory) -> None:
    graph = graph_factory(
        httpx.MockTransport(lambda _request: httpx.Response(200, json={"value": {"bad": True}}))
    )
    with pytest.raises(GraphApiError, match="non-list"):
        await graph.paginate("/users")
