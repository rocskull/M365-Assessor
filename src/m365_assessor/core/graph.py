from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from m365_assessor.auth.provider import AccessTokenProvider

logger = logging.getLogger(__name__)


class GraphApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class GraphCollection:
    items: list[dict[str, Any]] = field(default_factory=list)
    pages_collected: int = 0
    objects_collected: int = 0
    api_errors: list[str] = field(default_factory=list)


Sleep = Callable[[float], Awaitable[None]]


class GraphClient:
    def __init__(
        self,
        token_provider: AccessTokenProvider,
        *,
        http_client: httpx.AsyncClient | None = None,
        base_url: str = "https://graph.microsoft.com/v1.0",
        timeout: float = 30,
        retry_count: int = 4,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        self.token_provider = token_provider
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retry_count = retry_count
        self._client = http_client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = http_client is None
        self._sleep = sleep

    async def __aenter__(self) -> GraphClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._owns_client:
            await self._client.aclose()

    def _url(self, path_or_url: str) -> str:
        if path_or_url.startswith("https://"):
            expected = urlparse(self.base_url)
            actual = urlparse(path_or_url)
            if actual.scheme != "https" or actual.netloc.casefold() != expected.netloc.casefold():
                raise GraphApiError("Rejected pagination link outside the configured Graph host")
            return path_or_url
        return f"{self.base_url}/{path_or_url.lstrip('/')}"

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        raw = response.headers.get("Retry-After")
        if raw:
            try:
                return max(0.0, float(raw))
            except ValueError:
                try:
                    parsed = parsedate_to_datetime(raw)
                    return float(max(0.0, (parsed - datetime.now(UTC)).total_seconds()))
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(2.0**attempt, 30.0)

    async def request(
        self, method: str, path_or_url: str, *, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        url = self._url(path_or_url)
        for attempt in range(self.retry_count + 1):
            token = await self.token_provider.get_access_token()
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=params if attempt == 0 else None,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                    timeout=self.timeout,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt >= self.retry_count:
                    raise GraphApiError(
                        f"Graph transport failed after retries: {type(exc).__name__}"
                    ) from exc
                await self._sleep(min(2**attempt, 30))
                continue
            if response.status_code == 429 or response.status_code >= 500:
                if attempt >= self.retry_count:
                    raise GraphApiError(
                        f"Graph returned HTTP {response.status_code} after retries",
                        response.status_code,
                    )
                delay = self._retry_delay(response, attempt)
                logger.warning(
                    "Graph request throttled or unavailable; retrying",
                    extra={"context": {"status": response.status_code, "delay_seconds": delay}},
                )
                await self._sleep(delay)
                continue
            if response.is_error:
                request_id = response.headers.get("request-id") or response.headers.get(
                    "client-request-id"
                )
                raise GraphApiError(
                    f"Graph request failed with HTTP {response.status_code}; "
                    f"request_id={request_id or 'unknown'}",
                    response.status_code,
                )
            if not response.content:
                return {}
            payload = response.json()
            if not isinstance(payload, dict):
                raise GraphApiError(
                    "Graph returned a non-object JSON response", response.status_code
                )
            return payload
        raise GraphApiError("Graph request retry loop ended unexpectedly")

    async def get(
        self, path_or_url: str, *, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return await self.request("GET", path_or_url, params=params)

    async def paginate(
        self, path_or_url: str, *, params: dict[str, str] | None = None
    ) -> GraphCollection:
        result = GraphCollection()
        next_link: str | None = path_or_url
        next_params = params
        while next_link:
            page = await self.get(next_link, params=next_params)
            next_params = None
            result.pages_collected += 1
            values = page.get("value", [])
            if not isinstance(values, list):
                raise GraphApiError("Graph collection response has a non-list value property")
            for item in values:
                if isinstance(item, dict):
                    result.items.append(item)
            next_value = page.get("@odata.nextLink")
            next_link = next_value if isinstance(next_value, str) and next_value else None
        result.objects_collected = len(result.items)
        return result
