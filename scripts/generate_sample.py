from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from m365_assessor import __version__
from m365_assessor.collectors.registry import default_registry
from m365_assessor.models.assessment import (
    AssessmentDocument,
    AssessmentMetadata,
    AssessmentSummary,
    AuthenticationSummary,
    CheckResult,
    CollectorExecution,
    CoverageArea,
    FrameworkSelection,
    TenantInfo,
)
from m365_assessor.models.enums import AssessmentStatus, CollectorStatus, CoverageStatus
from m365_assessor.reporting.generator import generate_reports
from m365_assessor.rules.loader import default_rule_registry


def build_sample() -> AssessmentDocument:
    timestamp = datetime(2026, 8, 19, 9, 30, tzinfo=UTC)
    checks: list[CheckResult] = []
    for index, rule in enumerate(default_rule_registry().all(), 1):
        if index % 11 == 0:
            status = AssessmentStatus.NOT_ASSESSED
            observation = "Mock permission gap prevented collection of the required evidence."
        elif index % 7 == 0:
            status = AssessmentStatus.FAIL
            observation = "The synthetic tenant value did not satisfy the expected condition."
        else:
            status = AssessmentStatus.PASS
            observation = "The synthetic tenant value satisfied the expected condition."
        checks.append(
            CheckResult(
                check_id=rule.check_id,
                title=rule.title,
                severity=rule.severity,
                status=status,
                service=rule.service,
                category=rule.category,
                description=rule.description,
                rationale=rule.rationale,
                business_impact=rule.business_impact,
                benchmark=rule.benchmarks,
                evidence={"mock_dataset": {"synthetic": True, "sequence": index}},
                affected_resources=[f"mock-resource-{index}"]
                if status is AssessmentStatus.FAIL
                else [],
                observation=observation,
                recommendation=rule.recommendation,
                remediation=rule.remediation,
                references=rule.references,
                timestamp=timestamp,
            )
        )
    collectors = {
        item.metadata.id: CollectorExecution(
            collector_id=item.metadata.id,
            name=item.metadata.name,
            area=item.metadata.area,
            status=(
                CollectorStatus.PARTIAL
                if item.metadata.area == "purview"
                else CollectorStatus.SUCCESS
            ),
            objects_collected=1,
            pages_collected=1,
            limitation_reason=(
                "Mock dataset omits one licensed Purview workload."
                if item.metadata.area == "purview"
                else None
            ),
            data={"mock": True},
        )
        for item in default_registry().all()
    }
    coverage = [
        CoverageArea(
            area="entra", name="Entra ID", status=CoverageStatus.ASSESSED, coverage_percent=98
        ),
        CoverageArea(
            area="exchange",
            name="Exchange Online",
            status=CoverageStatus.ASSESSED,
            coverage_percent=100,
        ),
        CoverageArea(
            area="teams",
            name="Microsoft Teams",
            status=CoverageStatus.ASSESSED,
            coverage_percent=94,
        ),
        CoverageArea(
            area="sharepoint",
            name="SharePoint Online",
            status=CoverageStatus.ASSESSED,
            coverage_percent=100,
        ),
        CoverageArea(
            area="purview",
            name="Microsoft Purview",
            status=CoverageStatus.PARTIAL,
            coverage_percent=87,
            reasons=["One licensed workload was unavailable in the synthetic dataset."],
        ),
        CoverageArea(
            area="forms",
            name="Microsoft Forms",
            status=CoverageStatus.NOT_ASSESSED,
            coverage_percent=0,
            reasons=["Forms collection is not implemented in this release."],
        ),
        CoverageArea(
            area="fabric",
            name="Microsoft Fabric",
            status=CoverageStatus.ASSESSED,
            coverage_percent=100,
        ),
    ]
    return AssessmentDocument(
        assessment=AssessmentMetadata(
            id=UUID("11111111-1111-4111-8111-111111111111"),
            tool_version=__version__,
            client_name="Contoso (synthetic sample)",
            started_at=timestamp,
            completed_at=timestamp,
            scope=["entra", "exchange", "teams", "sharepoint", "purview", "fabric"],
            frameworks=[
                FrameworkSelection(
                    id="cis-m365-7.0.0",
                    name="CIS Microsoft 365 Foundations Benchmark",
                    version="7.0.0",
                ),
                FrameworkSelection(
                    id="nist-csf-2.0", name="NIST Cybersecurity Framework", version="2.0"
                ),
            ],
        ),
        tenant=TenantInfo(
            tenant_id="22222222-2222-4222-8222-222222222222",
            display_name="Contoso (synthetic sample)",
            primary_domain="contoso.example",
            verified_domains=["contoso.example"],
        ),
        authentication=AuthenticationSummary(
            method="certificate",
            identity="synthetic-service-principal",
            tenant_id="22222222-2222-4222-8222-222222222222",
            client_id="33333333-3333-4333-8333-333333333333",
            permission_source="synthetic_fixture",
        ),
        coverage=coverage,
        collectors=collectors,
        checks=checks,
        findings=[item for item in checks if item.status is AssessmentStatus.FAIL],
        summary=AssessmentSummary.from_results(checks),
        benchmark_results={
            "cis-m365-7.0.0": {"version": "7.0.0", "mapping_status": "implemented_97_control_pack"},
            "nist-csf-2.0": {"version": "2.0", "mapping_status": "implemented_97_control_pack"},
        },
    )


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    generate_reports(build_sample(), root / "examples" / "sample-report")
