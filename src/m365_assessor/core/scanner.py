from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from m365_assessor import __version__
from m365_assessor.auth.provider import (
    AuthResult,
    MicrosoftAuthenticator,
    StaticAccessTokenProvider,
)
from m365_assessor.benchmarks.catalog import FrameworkCatalog, FrameworkDefinition
from m365_assessor.collectors.base import CollectionContext
from m365_assessor.collectors.registry import CollectorRegistry, default_registry
from m365_assessor.collectors.runner import CollectorRunner
from m365_assessor.config import Settings
from m365_assessor.core.graph import GraphClient
from m365_assessor.core.service import ServiceClient, default_service_clients
from m365_assessor.models.assessment import (
    AssessmentDocument,
    AssessmentMetadata,
    AssessmentSummary,
    AuthenticationSummary,
    TenantInfo,
)
from m365_assessor.models.enums import AssessmentStatus, CollectorStatus
from m365_assessor.permissions import PermissionAnalyzer, load_permission_matrix
from m365_assessor.rules.engine import RuleEngine
from m365_assessor.rules.loader import RuleRegistry, default_rule_registry
from m365_assessor.rules.models import RuleDefinition


def _selected_rules(
    rules: list[RuleDefinition],
    frameworks: list[FrameworkDefinition],
    collector_ids: set[str],
) -> list[RuleDefinition]:
    selected = {(item.mapping_key.casefold(), item.version) for item in frameworks}
    output: list[RuleDefinition] = []
    for rule in rules:
        if rule.collector_dependencies and not set(rule.collector_dependencies) <= collector_ids:
            continue
        mappings = [
            mapping
            for mapping in rule.benchmarks
            if (mapping.framework.casefold(), mapping.version) in selected
        ]
        if mappings:
            output.append(rule.model_copy(update={"benchmarks": mappings}))
    return output


class DryRunCollector(BaseModel):
    id: str
    name: str
    area: str
    implemented: bool
    required_permissions: list[str] = Field(default_factory=list)
    expected_api_calls: list[str] = Field(default_factory=list)


class DryRunPlan(BaseModel):
    tenant_id: str | None
    auth_method: str
    frameworks: list[str]
    collectors: list[DryRunCollector]
    checks: list[str]
    required_permissions: list[str]
    note: str = "No authentication or tenant API call was performed."


def build_dry_run(
    settings: Settings,
    framework_ids: list[str],
    registry: CollectorRegistry | None = None,
    rules: RuleRegistry | None = None,
    area: str | None = None,
) -> DryRunPlan:
    registry = registry or default_registry()
    rules = rules or default_rule_registry(settings.rule_directory)
    selected_frameworks = FrameworkCatalog.load(settings.framework_directory).select(framework_ids)
    collectors = [item for item in registry.all() if area is None or item.metadata.area == area]
    selected_rules = _selected_rules(
        rules.all(), selected_frameworks, {item.metadata.id for item in collectors}
    )
    matrix = load_permission_matrix()
    matrix_entries = [
        entry for area_definition in matrix.areas.values() for entry in area_definition.permissions
    ]
    selected_collector_ids = {item.metadata.id for item in collectors}
    selected_check_ids = {item.check_id for item in selected_rules}
    matrix_permissions = {
        entry.permission
        for entry in matrix_entries
        if selected_collector_ids.intersection(entry.required_by_collectors)
        or selected_check_ids.intersection(entry.affected_checks)
    }
    required = sorted(
        {permission for item in collectors for permission in item.metadata.required_permissions}
        | {permission for rule in selected_rules for permission in rule.required_permissions}
        | matrix_permissions
    )
    return DryRunPlan(
        tenant_id=settings.tenant_id,
        auth_method=settings.auth_method,
        frameworks=framework_ids,
        collectors=[
            DryRunCollector(
                id=item.metadata.id,
                name=item.metadata.name,
                area=item.metadata.area,
                implemented=item.metadata.implemented,
                required_permissions=sorted(
                    item.metadata.required_permissions
                    | {
                        entry.permission
                        for entry in matrix_entries
                        if item.metadata.id in entry.required_by_collectors
                    }
                ),
                expected_api_calls=item.metadata.expected_api_calls,
            )
            for item in collectors
        ],
        checks=[item.check_id for item in selected_rules],
        required_permissions=required,
    )


class Scanner:
    def __init__(
        self,
        settings: Settings,
        *,
        registry: CollectorRegistry | None = None,
        rules: RuleRegistry | None = None,
        framework_catalog: FrameworkCatalog | None = None,
        authenticator: MicrosoftAuthenticator | None = None,
    ) -> None:
        self.settings = settings
        self.registry = registry or default_registry()
        self.rules = rules or default_rule_registry(settings.rule_directory)
        self.framework_catalog = framework_catalog or FrameworkCatalog.load(
            settings.framework_directory
        )
        self.authenticator = authenticator or MicrosoftAuthenticator(settings)

    async def scan(
        self,
        framework_ids: list[str],
        *,
        area: str | None = None,
        auth_result: AuthResult | None = None,
        graph_client: GraphClient | None = None,
        service_clients: dict[str, ServiceClient] | None = None,
    ) -> AssessmentDocument:
        selected_frameworks = self.framework_catalog.select(framework_ids)
        authentication = auth_result or await self.authenticator.authenticate()
        collectors = [
            collector
            for collector in self.registry.all()
            if area is None or collector.metadata.area == area
        ]
        selected_rules = _selected_rules(
            self.rules.all(),
            selected_frameworks,
            {item.metadata.id for item in collectors},
        )
        owns_graph = graph_client is None
        graph = graph_client or GraphClient(
            StaticAccessTokenProvider(authentication),
            timeout=self.settings.timeout,
            retry_count=self.settings.retry_count,
        )
        context = CollectionContext(
            graph=graph,
            settings=self.settings,
            granted_permissions=authentication.granted_permissions,
            service_clients=(
                service_clients
                if service_clients is not None
                else default_service_clients(self.settings, collectors)
            ),
        )
        try:
            executions = await CollectorRunner(self.settings.concurrency).run(collectors, context)
        finally:
            if owns_graph:
                await graph.__aexit__()
        check_results = RuleEngine().evaluate(
            selected_rules, executions, authentication.granted_permissions
        )
        findings = [
            item
            for item in check_results
            if item.status in {AssessmentStatus.FAIL, AssessmentStatus.WARNING}
        ]
        analyzer = PermissionAnalyzer(load_permission_matrix())
        collector_statuses = {item_id: item.status for item_id, item in executions.items()}
        check_statuses = {item.check_id: item.status for item in check_results}
        coverage = analyzer.coverage(
            authentication.granted_permissions, collector_statuses, check_statuses
        )
        for coverage_area in coverage:
            for collector_id in coverage_area.affected_collectors:
                execution = executions.get(collector_id)
                if execution and execution.limitation_reason:
                    coverage_area.reasons.append(f"{collector_id}: {execution.limitation_reason}")
        tenant = self._tenant(authentication.tenant_id, executions.get("entra001"))
        started = min((item.started_at for item in executions.values()), default=datetime.now(UTC))
        return AssessmentDocument(
            assessment=AssessmentMetadata(
                tool_version=__version__,
                client_name=self.settings.client_name,
                started_at=started,
                completed_at=datetime.now(UTC),
                scope=[area] if area else [item.metadata.area for item in collectors],
                frameworks=[item.selection() for item in selected_frameworks],
            ),
            tenant=tenant,
            authentication=AuthenticationSummary(
                method=authentication.method,
                identity=authentication.identity,
                tenant_id=authentication.tenant_id,
                client_id=authentication.client_id,
                permission_source=authentication.permission_source,
            ),
            coverage=coverage,
            collectors=executions,
            checks=check_results,
            findings=findings,
            summary=AssessmentSummary.from_results(check_results),
            benchmark_results={
                item.id: {"version": item.version, "mapping_status": item.mapping_status}
                for item in selected_frameworks
            },
        )

    @staticmethod
    def _tenant(tenant_id: str, execution: Any) -> TenantInfo:
        if execution is None or execution.status is not CollectorStatus.SUCCESS:
            return TenantInfo(tenant_id=tenant_id)
        organization = execution.data.get("organization", {})
        domains = organization.get("verifiedDomains", []) if isinstance(organization, dict) else []
        verified = [
            str(item.get("name")) for item in domains if isinstance(item, dict) and item.get("name")
        ]
        primary = next(
            (
                str(item.get("name"))
                for item in domains
                if isinstance(item, dict) and item.get("isDefault") and item.get("name")
            ),
            None,
        )
        return TenantInfo(
            tenant_id=str(organization.get("id", tenant_id)),
            display_name=organization.get("displayName"),
            primary_domain=primary,
            verified_domains=verified,
        )
