from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from m365_assessor.collectors.base import CollectionContext, Collector
from m365_assessor.models.assessment import CollectorExecution
from m365_assessor.models.enums import CollectorStatus

logger = logging.getLogger(__name__)


class CollectorRunner:
    def __init__(self, concurrency: int = 4) -> None:
        self._semaphore = asyncio.Semaphore(concurrency)

    async def run(
        self, collectors: list[Collector], context: CollectionContext
    ) -> dict[str, CollectorExecution]:
        executions = await asyncio.gather(*(self._run_one(item, context) for item in collectors))
        return {execution.collector_id: execution for execution in executions}

    async def _run_one(
        self, collector: Collector, context: CollectionContext
    ) -> CollectorExecution:
        metadata = collector.metadata
        started = datetime.now(UTC)
        logger.info("Collector started", extra={"context": {"collector_id": metadata.id}})
        if not metadata.implemented:
            result = await collector.collect(context)
            return CollectorExecution(
                collector_id=metadata.id,
                name=metadata.name,
                area=metadata.area,
                status=result.status,
                started_at=started,
                completed_at=datetime.now(UTC),
                limitation_reason=result.limitation_reason,
            )
        normalized_grants = {item.casefold() for item in context.granted_permissions}
        missing = sorted(
            permission
            for permission in metadata.required_permissions
            if permission.casefold() not in normalized_grants
        )
        if missing:
            return CollectorExecution(
                collector_id=metadata.id,
                name=metadata.name,
                area=metadata.area,
                status=CollectorStatus.NOT_ASSESSED,
                started_at=started,
                completed_at=datetime.now(UTC),
                limitation_reason=f"Missing required permissions: {', '.join(missing)}",
            )
        try:
            async with self._semaphore:
                result = await collector.collect(context)
            validation_errors = collector.validate(result)
            if validation_errors:
                result.status = CollectorStatus.ERROR
                result.api_errors.extend(validation_errors)
            execution = CollectorExecution(
                collector_id=metadata.id,
                name=metadata.name,
                area=metadata.area,
                status=result.status,
                started_at=started,
                completed_at=datetime.now(UTC),
                objects_collected=result.objects_collected,
                pages_collected=result.pages_collected,
                api_errors=result.api_errors,
                limitation_reason=result.limitation_reason,
                data=result.data,
            )
        except Exception as exc:
            logger.exception("Collector failed", extra={"context": {"collector_id": metadata.id}})
            execution = CollectorExecution(
                collector_id=metadata.id,
                name=metadata.name,
                area=metadata.area,
                status=CollectorStatus.ERROR,
                started_at=started,
                completed_at=datetime.now(UTC),
                api_errors=[type(exc).__name__],
                limitation_reason=f"Collector failed: {type(exc).__name__}",
            )
        logger.info(
            "Collector completed",
            extra={
                "context": {
                    "collector_id": metadata.id,
                    "status": execution.status,
                    "objects": execution.objects_collected,
                }
            },
        )
        return execution
