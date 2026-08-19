from __future__ import annotations

import json
import re
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from uuid import uuid4

from m365_assessor import __version__


def generate_sbom(output: Path) -> Path:
    """Generate a dependency-only CycloneDX-compatible JSON SBOM without network access."""
    if output.name != output.name.strip() or output.suffix.casefold() != ".json":
        raise ValueError("SBOM output must be a .json file")
    output.parent.mkdir(parents=True, exist_ok=True)
    # Walk only this application's runtime dependency closure. Enumerating the
    # interpreter would incorrectly include unrelated global packages.
    resolved: dict[str, str] = {}
    pending = ["m365-assessor"]
    requirement_name = re.compile(r"^[A-Za-z0-9_.-]+")
    while pending:
        requested = pending.pop()
        normalized = requested.casefold().replace("_", "-")
        if normalized in resolved:
            continue
        try:
            package = distribution(requested)
        except PackageNotFoundError:
            continue
        canonical_name = (package.metadata.get("Name") or requested).casefold().replace("_", "-")
        resolved[canonical_name] = package.version
        for requirement in package.requires or []:
            # Optional extras are not part of the installed runtime surface.
            if "extra ==" in requirement or "extra==" in requirement:
                continue
            match = requirement_name.match(requirement)
            if match:
                pending.append(match.group())

    components = []
    for name, version in sorted(resolved.items()):
        if name == "m365-assessor":
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
            }
        )
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "m365-assessor", "version": __version__}
        },
        "components": components,
    }
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8", newline="\n")
    return output
