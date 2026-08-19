"""Data-driven deterministic security-check engine."""

from m365_assessor.rules.engine import RuleEngine
from m365_assessor.rules.loader import RuleRegistry

__all__ = ["RuleEngine", "RuleRegistry"]
