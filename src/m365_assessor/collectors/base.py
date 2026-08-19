from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from m365_assessor.config import Settings
from m365_assessor.core.graph import GraphClient
from m365_assessor.models.assessment import utc_now
from m365_assessor.models.enums import CollectorStatus

if TYPE_CHECKING:
    from m365_assessor.core.service import ServiceClient


class CollectorMetadata(BaseModel):
    id: str
    name: str
    description: str
    area: str
    required_permissions: set[str] = Field(default_factory=set)
    expected_api_calls: list[str] = Field(default_factory=list)
    implemented: bool = True


class NormalizedCollection(BaseModel):
    status: CollectorStatus
    data: dict[str, Any] = Field(default_factory=dict)
    objects_collected: int = 0
    pages_collected: int = 0
    api_errors: list[str] = Field(default_factory=list)
    limitation_reason: str | None = None


@dataclass
class CollectionContext:
    graph: GraphClient
    settings: Settings
    granted_permissions: set[str]
    service_clients: dict[str, ServiceClient] | None = None


class Collector(ABC):
    metadata: CollectorMetadata

    @abstractmethod
    async def collect(self, context: CollectionContext) -> NormalizedCollection: ...

    @abstractmethod
    def validate(self, collection: NormalizedCollection) -> list[str]: ...

    @abstractmethod
    async def health_check(self, context: CollectionContext) -> bool: ...

    @staticmethod
    def now() -> datetime:
        return utc_now()
