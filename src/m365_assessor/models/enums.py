from enum import StrEnum


class AssessmentStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class CollectorStatus(StrEnum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


class CoverageStatus(StrEnum):
    ASSESSED = "ASSESSED"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"
