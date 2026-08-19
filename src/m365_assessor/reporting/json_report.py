from __future__ import annotations

import os
import tempfile
from pathlib import Path

from m365_assessor.models.assessment import AssessmentDocument
from m365_assessor.reporting.io import validate_report_filename


def write_json_report(
    document: AssessmentDocument,
    output_directory: Path,
    filename: str = "assessment.json",
) -> Path:
    validate_report_filename(filename, ".json")
    output_directory.mkdir(parents=True, exist_ok=True)
    destination = output_directory.resolve() / filename
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".assessment-", suffix=".tmp", dir=output_directory.resolve()
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(document.model_dump_json(indent=2))
            stream.write("\n")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination
