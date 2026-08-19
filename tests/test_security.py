from __future__ import annotations

import json
from pathlib import Path

from m365_assessor.security import generate_sbom


def test_sbom_is_cyclonedx_compatible_and_contains_application(tmp_path: Path) -> None:
    output = generate_sbom(tmp_path / "sbom.json")
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["metadata"]["component"]["name"] == "m365-assessor"
    assert payload["components"]
