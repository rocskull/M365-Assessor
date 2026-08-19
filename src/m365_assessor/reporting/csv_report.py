from __future__ import annotations

import csv
from pathlib import Path

from m365_assessor.models.assessment import AssessmentDocument
from m365_assessor.reporting.io import atomic_report_path, validate_report_filename

HEADERS = [
    "Finding ID",
    "Title",
    "Severity",
    "Status",
    "Service",
    "Category",
    "CIS Framework",
    "CIS Version",
    "CIS Control",
    "Observation",
    "Recommendation",
    "Resource",
    "Timestamp",
]


def write_csv_report(
    document: AssessmentDocument,
    output_directory: Path,
    filename: str = "findings.csv",
) -> Path:
    validate_report_filename(filename, ".csv")
    output_directory.mkdir(parents=True, exist_ok=True)
    destination = output_directory.resolve() / filename
    with atomic_report_path(destination) as temporary:
        with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=HEADERS, extrasaction="ignore")
            writer.writeheader()
            for finding in document.findings:
                cis = next(
                    (mapping for mapping in finding.benchmark if mapping.framework == "CIS"),
                    None,
                )
                resources = finding.affected_resources or [""]
                for resource in resources:
                    writer.writerow(
                        {
                            "Finding ID": finding.check_id,
                            "Title": finding.title,
                            "Severity": finding.severity.value,
                            "Status": finding.status.value,
                            "Service": finding.service,
                            "Category": finding.category,
                            "CIS Framework": cis.benchmark if cis else "",
                            "CIS Version": cis.version if cis else "",
                            "CIS Control": cis.control if cis else "",
                            "Observation": finding.observation,
                            "Recommendation": finding.recommendation,
                            "Resource": resource,
                            "Timestamp": finding.timestamp.isoformat(),
                        }
                    )
    return destination
