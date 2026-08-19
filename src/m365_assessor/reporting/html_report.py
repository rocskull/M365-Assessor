from __future__ import annotations

from collections import Counter
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from m365_assessor.models.assessment import AssessmentDocument
from m365_assessor.reporting.io import atomic_report_path, validate_report_filename


def write_html_report(
    document: AssessmentDocument,
    output_directory: Path,
    filename: str = "assessment.html",
) -> Path:
    validate_report_filename(filename, ".html")
    output_directory.mkdir(parents=True, exist_ok=True)
    destination = output_directory.resolve() / filename
    environment = Environment(
        loader=PackageLoader("m365_assessor.reporting", "templates"),
        autoescape=select_autoescape(["html", "xml", "j2"], default=True),
    )
    template = environment.get_template("assessment.html.j2")
    severity_counts = Counter(item.severity.value for item in document.findings)
    service_counts = Counter(item.service for item in document.findings)
    category_counts = Counter(item.category for item in document.findings)
    maximum = max(
        [*severity_counts.values(), *service_counts.values(), *category_counts.values(), 1]
    )
    with atomic_report_path(destination) as temporary:
        temporary.write_text(
            template.render(
                report=document,
                severity_counts=severity_counts,
                service_counts=service_counts,
                category_counts=category_counts,
                chart_max=maximum,
            ),
            encoding="utf-8",
            newline="\n",
        )
    return destination
