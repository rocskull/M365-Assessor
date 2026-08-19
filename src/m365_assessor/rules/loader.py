from __future__ import annotations

from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

import yaml

from m365_assessor.rules.models import RuleDefinition


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, RuleDefinition] = {}

    def register(self, rule: RuleDefinition) -> None:
        if rule.check_id in self._rules:
            raise ValueError(f"Duplicate check ID: {rule.check_id}")
        self._rules[rule.check_id] = rule

    def all(self) -> list[RuleDefinition]:
        return sorted(self._rules.values(), key=lambda item: item.check_id)

    def discover_plugins(self) -> None:
        for entry_point in entry_points(group="m365_assessor.rules"):
            loaded = entry_point.load()()
            rules = [loaded] if isinstance(loaded, RuleDefinition) else loaded
            for rule in rules:
                if not isinstance(rule, RuleDefinition):
                    raise TypeError(f"Rule entry point {entry_point.name} returned an invalid type")
                self.register(rule)

    @classmethod
    def load_directory(cls, directory: Path) -> RuleRegistry:
        registry = cls()
        for path in sorted(directory.rglob("*.yaml")):
            payload: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and {"defaults", "rules"} <= payload.keys():
                defaults = payload["defaults"]
                packed_rules = payload["rules"]
                if not isinstance(defaults, dict) or not isinstance(packed_rules, list):
                    raise ValueError(f"Invalid packed rule definition in {path}")
                values = [
                    {**defaults, **value} if isinstance(value, dict) else value
                    for value in packed_rules
                ]
            else:
                values = payload if isinstance(payload, list) else [payload]
            for value in values:
                if not isinstance(value, dict):
                    raise ValueError(f"Invalid rule definition in {path}")
                registry.register(RuleDefinition.model_validate(value))
        return registry


def default_rule_registry(extra_directory: Path | None = None) -> RuleRegistry:
    directory = Path(__file__).resolve().parent / "definitions"
    registry = RuleRegistry.load_directory(directory)
    if extra_directory is not None:
        extra = RuleRegistry.load_directory(extra_directory)
        for rule in extra.all():
            registry.register(rule)
    return registry
