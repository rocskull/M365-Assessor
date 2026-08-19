from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from m365_assessor.models.assessment import FrameworkSelection


class FrameworkDefinition(BaseModel):
    id: str
    name: str
    provider: str
    version: str
    kind: str
    mapping_key: str
    description: str
    reference_url: str
    mapping_status: str

    def selection(self) -> FrameworkSelection:
        return FrameworkSelection(id=self.id, name=self.name, version=self.version)


class FrameworkCatalog:
    def __init__(self, definitions: list[FrameworkDefinition]) -> None:
        self._definitions = {item.id: item for item in definitions}
        if len(self._definitions) != len(definitions):
            raise ValueError("Duplicate framework ID")

    @classmethod
    def load(cls, directory: Path | None = None) -> FrameworkCatalog:
        definitions: list[FrameworkDefinition] = []
        project_directory = Path(__file__).resolve().parents[3] / "config" / "frameworks"
        if project_directory.exists():
            payloads = [
                path.read_text(encoding="utf-8")
                for path in sorted(project_directory.glob("*.yaml"))
                if not path.name.endswith(".example.yaml")
            ]
        else:
            resource = files("m365_assessor").joinpath("data/frameworks")
            payloads = [
                item.read_text(encoding="utf-8")
                for item in sorted(resource.iterdir(), key=lambda item: item.name)
                if item.name.endswith(".yaml") and not item.name.endswith(".example.yaml")
            ]
        if directory is not None:
            payloads.extend(
                path.read_text(encoding="utf-8") for path in sorted(directory.glob("*.yaml"))
            )
        for raw in payloads:
            value: Any = yaml.safe_load(raw)
            if not isinstance(value, dict):
                raise ValueError("framework definition must be a YAML mapping")
            definitions.append(FrameworkDefinition.model_validate(value))
        return cls(definitions)

    def all(self) -> list[FrameworkDefinition]:
        return sorted(self._definitions.values(), key=lambda item: item.id)

    def select(self, ids: list[str]) -> list[FrameworkDefinition]:
        missing = sorted(set(ids) - self._definitions.keys())
        if missing:
            raise ValueError(f"Unknown framework(s): {', '.join(missing)}")
        return [self._definitions[item] for item in ids]
