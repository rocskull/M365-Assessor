from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from m365_assessor.models.assessment import BenchmarkMapping
from m365_assessor.models.enums import Severity


class EvaluationSpec(BaseModel):
    type: Literal[
        "exists",
        "equals",
        "not_equals",
        "count_gte",
        "in",
        "lte",
        "gte",
        "between",
        "all",
        "any",
        "not",
        "collection",
        "equals_ci",
        "in_ci",
        "contains",
        "not_contains",
        "truthy",
        "falsy",
        "restriction_set",
    ]
    field: str = ""
    expected: Any = None
    fields: list[str] = Field(default_factory=list)
    conditions: list[EvaluationSpec] = Field(default_factory=list)
    quantifier: Literal["all", "any", "none"] = "all"
    min_count: int = Field(default=0, ge=0)


class RuleDefinition(BaseModel):
    check_id: str
    title: str
    description: str
    category: str
    service: str
    severity: Severity
    rationale: str
    business_impact: str = ""
    remediation: str
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    benchmarks: list[BenchmarkMapping] = Field(default_factory=list)
    required_permissions: set[str] = Field(default_factory=set)
    collector_dependencies: list[str] = Field(default_factory=list)
    evaluation: EvaluationSpec
    evidence_fields: list[str] = Field(default_factory=list)
