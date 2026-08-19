from __future__ import annotations

from importlib.metadata import entry_points

from m365_assessor.collectors.base import Collector
from m365_assessor.collectors.builtin import TenantCollector
from m365_assessor.collectors.entra import entra_collectors
from m365_assessor.collectors.services import service_collectors


class CollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[str, Collector] = {}

    def register(self, collector: Collector) -> None:
        collector_id = collector.metadata.id
        if collector_id in self._collectors:
            raise ValueError(f"Duplicate collector ID: {collector_id}")
        self._collectors[collector_id] = collector

    def get(self, collector_id: str) -> Collector:
        try:
            return self._collectors[collector_id]
        except KeyError as exc:
            raise KeyError(f"Unknown collector ID: {collector_id}") from exc

    def all(self) -> list[Collector]:
        return sorted(self._collectors.values(), key=lambda item: item.metadata.id)

    def discover_plugins(self) -> None:
        for entry_point in entry_points(group="m365_assessor.collectors"):
            factory = entry_point.load()
            collector = factory()
            if not isinstance(collector, Collector):
                raise TypeError(
                    f"Collector entry point {entry_point.name} returned an invalid type"
                )
            self.register(collector)


def default_registry() -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(TenantCollector())
    for collector in entra_collectors():
        registry.register(collector)
    for collector in service_collectors():
        registry.register(collector)
    return registry
