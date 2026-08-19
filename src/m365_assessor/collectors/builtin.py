from __future__ import annotations

from m365_assessor.collectors.base import (
    CollectionContext,
    Collector,
    CollectorMetadata,
    NormalizedCollection,
)
from m365_assessor.models.enums import CollectorStatus


class TenantCollector(Collector):
    metadata = CollectorMetadata(
        id="entra001",
        name="Entra ID",
        description="Discovers normalized Microsoft 365 tenant metadata.",
        area="entra",
        required_permissions={"Organization.Read.All"},
        expected_api_calls=["GET /organization"],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        page = await context.graph.get(
            "/organization",
            params={"$select": "id,displayName,verifiedDomains,tenantType,countryLetterCode"},
        )
        organizations = page.get("value", [])
        if not isinstance(organizations, list) or not organizations:
            return NormalizedCollection(
                status=CollectorStatus.ERROR,
                api_errors=["Microsoft Graph returned no organization objects."],
                limitation_reason="Tenant organization metadata could not be discovered.",
            )
        organization = organizations[0]
        if not isinstance(organization, dict):
            return NormalizedCollection(
                status=CollectorStatus.ERROR,
                api_errors=["Microsoft Graph returned an invalid organization object."],
            )
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={"organization": organization},
            objects_collected=1,
            pages_collected=1,
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        organization = collection.data.get("organization")
        if collection.status is CollectorStatus.SUCCESS and not isinstance(organization, dict):
            return ["Successful tenant collection is missing organization evidence."]
        return []

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get("/organization", params={"$select": "id"})
            return True
        except Exception:
            return False
