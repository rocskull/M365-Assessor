from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from m365_assessor.models.enums import (
    AssessmentStatus,
    CollectorStatus,
    CoverageStatus,
    Severity,
)


def utc_now() -> datetime:
    return datetime.now(UTC)


class FrameworkSelection(BaseModel):
    id: str
    name: str
    version: str


class BenchmarkMapping(BaseModel):
    framework: str
    benchmark: str
    version: str
    control: str


class PermissionResult(BaseModel):
    permission: str
    detected: bool
    required_by_collectors: list[str] = Field(default_factory=list)
    affected_checks: list[str] = Field(default_factory=list)
    limitation_severity: Severity = Severity.MEDIUM
    reason: str | None = None
    verification_source: str = "token"


class CoverageArea(BaseModel):
    area: str
    name: str
    status: CoverageStatus
    coverage_percent: float = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    detected_permissions: list[str] = Field(default_factory=list)
    missing_permissions: list[str] = Field(default_factory=list)
    affected_collectors: list[str] = Field(default_factory=list)
    affected_checks: list[str] = Field(default_factory=list)


class CollectorExecution(BaseModel):
    collector_id: str
    name: str
    area: str
    status: CollectorStatus
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime = Field(default_factory=utc_now)
    objects_collected: int = 0
    pages_collected: int = 0
    api_errors: list[str] = Field(default_factory=list)
    limitation_reason: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class CheckResult(BaseModel):
    check_id: str
    title: str
    severity: Severity
    status: AssessmentStatus
    service: str
    category: str
    description: str = ""
    rationale: str = ""
    business_impact: str = ""
    benchmark: list[BenchmarkMapping] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    affected_resources: list[str] = Field(default_factory=list)
    observation: str = ""
    recommendation: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)


class AssessmentMetadata(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tool: str = "m365-assessor"
    tool_version: str = "1.2.0"
    client_name: str | None = None
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    scope: list[str] = Field(default_factory=list)
    frameworks: list[FrameworkSelection] = Field(default_factory=list)
    dry_run: bool = False


class TenantInfo(BaseModel):
    tenant_id: str
    display_name: str | None = None
    primary_domain: str | None = None
    verified_domains: list[str] = Field(default_factory=list)


class AuthenticationSummary(BaseModel):
    method: str
    identity: str | None = None
    tenant_id: str
    client_id: str
    permission_source: str
    # Tokens and credentials are deliberately absent.


class AssessmentSummary(BaseModel):
    total_checks: int = 0
    pass_count: int = 0
    fail_count: int = 0
    warning_count: int = 0
    not_applicable_count: int = 0
    not_assessed_count: int = 0
    error_count: int = 0
    pass_percentage: float = 0
    failure_percentage: float = 0
    coverage_percentage: float = 0
    severity_distribution: dict[str, int] = Field(default_factory=dict)

    @classmethod
    def from_results(cls, results: list[CheckResult]) -> AssessmentSummary:
        counts = {status: 0 for status in AssessmentStatus}
        severity: dict[str, int] = {item.value: 0 for item in Severity}
        for result in results:
            counts[result.status] += 1
            if result.status in {AssessmentStatus.FAIL, AssessmentStatus.WARNING}:
                severity[result.severity.value] += 1
        assessed = (
            counts[AssessmentStatus.PASS]
            + counts[AssessmentStatus.FAIL]
            + counts[AssessmentStatus.WARNING]
        )
        applicable = (
            assessed + counts[AssessmentStatus.NOT_ASSESSED] + counts[AssessmentStatus.ERROR]
        )
        return cls(
            total_checks=len(results),
            pass_count=counts[AssessmentStatus.PASS],
            fail_count=counts[AssessmentStatus.FAIL],
            warning_count=counts[AssessmentStatus.WARNING],
            not_applicable_count=counts[AssessmentStatus.NOT_APPLICABLE],
            not_assessed_count=counts[AssessmentStatus.NOT_ASSESSED],
            error_count=counts[AssessmentStatus.ERROR],
            pass_percentage=round(100 * counts[AssessmentStatus.PASS] / assessed, 2)
            if assessed
            else 0,
            failure_percentage=round(
                100 * (counts[AssessmentStatus.FAIL] + counts[AssessmentStatus.WARNING]) / assessed,
                2,
            )
            if assessed
            else 0,
            coverage_percentage=round(100 * assessed / applicable, 2) if applicable else 0,
            severity_distribution=severity,
        )


class AssessmentDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment: AssessmentMetadata
    tenant: TenantInfo
    authentication: AuthenticationSummary
    coverage: list[CoverageArea]
    collectors: dict[str, CollectorExecution]
    checks: list[CheckResult]
    findings: list[CheckResult]
    summary: AssessmentSummary
    benchmark_results: dict[str, Any] = Field(default_factory=dict)
