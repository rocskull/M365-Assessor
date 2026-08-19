from datetime import datetime
from pathlib import Path

from typer.testing import CliRunner

from m365_assessor.api import create_app
from m365_assessor.cli.app import _assessment_output, _framework_ids, app
from m365_assessor.config import Settings

runner = CliRunner()


def test_fastapi_discovery_endpoints() -> None:
    paths = {route.path for route in create_app().routes}
    assert {
        "/health",
        "/collectors",
        "/checks",
        "/frameworks",
        "/permission-matrix",
        "/scans",
        "/scans/dry-run",
    } <= paths


def test_collectors_list_marks_service_collectors_implemented() -> None:
    result = runner.invoke(app, ["collectors", "list"])
    assert result.exit_code == 0
    assert "entra001" in result.stdout
    assert "exo003" in result.stdout
    assert "implemented" in result.stdout


def test_checks_list_reports_phase_two_checks() -> None:
    result = runner.invoke(app, ["checks", "list"])
    assert result.exit_code == 0
    assert "M365-ENTRA-001" in result.stdout
    assert "M365-ENTRA-024" in result.stdout


def test_dry_run_does_not_authenticate() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--tenant",
            "tenant-id",
            "--framework",
            "cis-m365-7.0.0",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert '"note": "No authentication or tenant API call was performed."' in result.stdout
    assert "GET /organization" in result.stdout


def test_frameworks_can_be_selected_by_number() -> None:
    assert _framework_ids(["1,2"], Settings()) == ["cis-m365-7.0.0", "nist-csf-2.0"]
    assert _framework_ids(["2", "1"], Settings()) == ["nist-csf-2.0", "cis-m365-7.0.0"]


def test_client_output_is_sanitized_and_timestamped(tmp_path: Path) -> None:
    settings, stem = _assessment_output(
        Settings(),
        "Example Client / India",
        tmp_path,
        datetime(2026, 8, 19, 16, 45, 10),
    )
    assert stem == "Example-Client-India-m365-assessment-20260819-164510"
    assert settings.client_name == "Example Client / India"
    assert settings.output_directory == tmp_path / stem


def test_client_and_output_are_prompted_when_interactive(tmp_path: Path, monkeypatch) -> None:
    responses = iter(["Prompted Client", str(tmp_path)])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.prompt", lambda *_args, **_kwargs: next(responses))
    settings, stem = _assessment_output(
        Settings(),
        None,
        None,
        datetime(2026, 8, 19, 16, 45, 10),
    )
    assert settings.client_name == "Prompted Client"
    assert settings.output_directory == tmp_path / stem


def test_benchmarks_list_includes_selection_numbers() -> None:
    result = runner.invoke(app, ["benchmarks", "list"])
    assert result.exit_code == 0
    assert "1    cis-m365-7.0.0" in result.stdout
    assert "2    nist-csf-2.0" in result.stdout
