from __future__ import annotations

import json
from pathlib import Path

from m365_assessor.models.assessment import AssessmentDocument


def write_evidence_cache(document: AssessmentDocument, output_directory: Path) -> Path:
    cache_root = output_directory.resolve() / "evidence"
    cache_root.mkdir(parents=True, exist_ok=True)
    for execution in document.collectors.values():
        area = cache_root / execution.area
        area.mkdir(parents=True, exist_ok=True)
        destination = area / f"{execution.collector_id}.json"
        destination.write_text(
            json.dumps(execution.model_dump(mode="json"), indent=2, ensure_ascii=False),
            encoding="utf-8",
            newline="\n",
        )
    scan_path = output_directory.resolve() / "scan.json"
    scan_path.write_text(document.model_dump_json(indent=2), encoding="utf-8", newline="\n")
    return scan_path
