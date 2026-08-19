from __future__ import annotations

import asyncio
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
import uvicorn

from m365_assessor.auth.provider import AuthenticationError, AuthResult, MicrosoftAuthenticator
from m365_assessor.benchmarks.catalog import FrameworkCatalog
from m365_assessor.collectors.registry import default_registry
from m365_assessor.config import Settings, load_settings
from m365_assessor.core.cache import write_evidence_cache
from m365_assessor.core.scanner import Scanner, build_dry_run
from m365_assessor.logging import configure_logging
from m365_assessor.models.assessment import AssessmentDocument
from m365_assessor.permissions import PermissionAnalyzer, load_permission_matrix
from m365_assessor.reporting.generator import SUPPORTED_FORMATS, generate_reports
from m365_assessor.rules.loader import default_rule_registry
from m365_assessor.security import generate_sbom
from m365_assessor.storage.repository import AssessmentRepository

app = typer.Typer(no_args_is_help=True, help="Read-only Microsoft 365 security assessment tool.")
auth_app = typer.Typer(no_args_is_help=True, help="Authenticate to Microsoft 365.")
tenant_app = typer.Typer(no_args_is_help=True, help="Inspect tenant metadata.")
collectors_app = typer.Typer(no_args_is_help=True, help="Inspect collector plugins.")
checks_app = typer.Typer(no_args_is_help=True, help="Inspect security checks.")
benchmarks_app = typer.Typer(no_args_is_help=True, help="Inspect assessment frameworks.")
app.add_typer(auth_app, name="auth")
app.add_typer(tenant_app, name="tenant")
app.add_typer(collectors_app, name="collectors")
app.add_typer(checks_app, name="checks")
app.add_typer(benchmarks_app, name="benchmarks")


def _settings(config: Path | None, **updates: Any) -> Settings:
    settings = load_settings(config)
    values = settings.model_dump()
    values.update({key: value for key, value in updates.items() if value is not None})
    return Settings.model_validate(values)


def _framework_ids(requested: list[str], settings: Settings) -> list[str]:
    catalog = FrameworkCatalog.load(settings.framework_directory)
    available = catalog.all()
    if requested:
        raw_values = requested
    elif settings.frameworks:
        raw_values = settings.frameworks
    elif sys.stdin.isatty():
        typer.echo("Select one or more assessment frameworks:")
        for number, framework in enumerate(available, 1):
            typer.echo(f"  [{number}] {framework.name} {framework.version} ({framework.id})")
        raw = typer.prompt("Framework numbers (comma-separated)", default="1")
        raw_values = [raw]
    else:
        raw_values = ["cis-m365-7.0.0"]
        typer.echo("[!] Non-interactive session: defaulting to cis-m365-7.0.0")
    choices = [
        item for raw_value in raw_values for item in re.split(r"[,\s]+", raw_value.strip()) if item
    ]
    selected: list[str] = []
    for choice in choices:
        if choice.isdecimal():
            number = int(choice)
            if number < 1 or number > len(available):
                raise ValueError(
                    f"Framework number {number} is out of range; choose 1-{len(available)}."
                )
            framework_id = available[number - 1].id
        else:
            framework_id = choice
        if framework_id not in selected:
            selected.append(framework_id)
    catalog.select(selected)
    return selected


def _safe_client_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("._-")
    if not normalized:
        raise typer.BadParameter("Client name must contain at least one letter or number.")
    return normalized[:80]


def _assessment_output(
    settings: Settings,
    client_name: str | None,
    output_option: Path | None,
    timestamp: datetime | None = None,
) -> tuple[Settings, str]:
    display_name = client_name or settings.client_name
    if not display_name:
        if not sys.stdin.isatty():
            raise typer.BadParameter(
                "Client name is required for report naming; use --client-name."
            )
        display_name = typer.prompt("Client name")
    safe_name = _safe_client_name(display_name)
    output_root = output_option
    if output_root is None and sys.stdin.isatty():
        output_root = Path(
            typer.prompt("Output root folder", default=str(settings.output_directory))
        )
    output_root = output_root or settings.output_directory
    if ".." in output_root.parts:
        raise typer.BadParameter("Output folder cannot contain parent traversal ('..').")
    current = timestamp or datetime.now().astimezone()
    stamp = current.strftime("%Y%m%d-%H%M%S")
    report_stem = f"{safe_name}-m365-assessment-{stamp}"
    output_directory = output_root.expanduser().resolve() / report_stem
    updated = Settings.model_validate(
        {
            **settings.model_dump(),
            "client_name": display_name.strip(),
            "output_directory": output_directory,
        }
    )
    return updated, report_stem


def _area(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.casefold()
    aliases = {"identity": "entra", "entra id": "entra", "sharepoint online": "sharepoint"}
    return aliases.get(normalized, normalized)


def _confirm_discovered_tenant(
    settings: Settings, authentication: AuthResult, assume_yes: bool
) -> Settings:
    if settings.tenant_id is not None:
        return settings
    typer.echo("[+] Microsoft sign-in successful")
    typer.echo(f"[+] Discovered tenant: {authentication.tenant_id}")
    typer.echo(f"[+] Signed-in identity: {authentication.identity or 'Unknown'}")
    if not assume_yes:
        if not sys.stdin.isatty():
            raise typer.BadParameter(
                "Tenant discovery requires confirmation. Run interactively or pass --yes."
            )
        if not typer.confirm("Continue the read-only assessment against this tenant?"):
            typer.echo("Assessment cancelled; no tenant data was collected.")
            raise typer.Abort()
    return settings.model_copy(update={"tenant_id": authentication.tenant_id})


@auth_app.command("login")
def auth_login(
    tenant: str | None = typer.Option(None, "--tenant", help="Microsoft Entra tenant ID."),
    auth_method: str | None = typer.Option(None, "--auth", help="Authentication method."),
    config: Path | None = typer.Option(None, "--config", exists=True, dir_okay=False),
) -> None:
    """Authenticate and report the non-secret identity summary."""
    settings = _settings(config, tenant_id=tenant, auth_method=auth_method)
    configure_logging(settings.log_level)
    try:
        result = asyncio.run(MicrosoftAuthenticator(settings).authenticate())
    except AuthenticationError as exc:
        typer.echo(f"[!] Authentication failed: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo("[+] Authentication successful")
    typer.echo(f"Tenant: {result.tenant_id}")
    typer.echo(f"Identity: {result.identity or 'application identity'}")
    typer.echo(f"Permission discovery source: {result.permission_source}")


@collectors_app.command("list")
def collectors_list() -> None:
    """List registered collector IDs and implementation state."""
    typer.echo("Collector ID  Name                  Area        State")
    for collector in default_registry().all():
        state = "implemented" if collector.metadata.implemented else "planned"
        typer.echo(
            f"{collector.metadata.id:<13} {collector.metadata.name:<21} "
            f"{collector.metadata.area:<11} {state}"
        )


@checks_app.command("list")
def checks_list() -> None:
    """List checks that meet the implementation quality gate."""
    rules = default_rule_registry().all()
    if not rules:
        typer.echo("No checks are registered. Verify the packaged rule files and configuration.")
        return
    for rule in rules:
        typer.echo(f"{rule.check_id:<22} {rule.severity.value:<14} {rule.title}")


@benchmarks_app.command("list")
def benchmarks_list() -> None:
    """List versioned benchmark/compliance framework definitions."""
    typer.echo("No.  Framework ID         Version  Mapping state       Name")
    for number, framework in enumerate(FrameworkCatalog.load().all(), 1):
        typer.echo(
            f"{number:<4} {framework.id:<20} {framework.version:<8} "
            f"{framework.mapping_status:<19} {framework.name}"
        )


@app.command("permissions")
def permissions_command(
    tenant: str | None = typer.Option(None, "--tenant"),
    auth_method: str | None = typer.Option(None, "--auth"),
    config: Path | None = typer.Option(None, "--config", exists=True, dir_okay=False),
) -> None:
    """Authenticate and generate a permission/coverage preflight report."""
    settings = _settings(config, tenant_id=tenant, auth_method=auth_method)
    configure_logging(settings.log_level)
    try:
        auth = asyncio.run(MicrosoftAuthenticator(settings).authenticate())
    except AuthenticationError as exc:
        typer.echo(f"[!] Authentication failed: {exc}", err=True)
        raise typer.Exit(2) from exc
    analyzer = PermissionAnalyzer(load_permission_matrix())
    typer.echo("Permission                                  Status  Affected collectors")
    for area_results in analyzer.permission_results(auth.granted_permissions).values():
        for result in area_results:
            status = (
                "PASS"
                if result.detected
                else "RUNTIME"
                if result.verification_source == "collector"
                else "MISSING"
            )
            affected = ",".join(result.required_by_collectors) or "-"
            typer.echo(f"{result.permission:<43} {status:<7} {affected}")
    typer.echo("\nCoverage & Permission Report")
    typer.echo("Area                   Status         Coverage  Explanation")
    for area in analyzer.coverage(auth.granted_permissions):
        explanation = area.reasons[0] if area.reasons else "Required permissions detected."
        typer.echo(
            f"{area.name:<22} {area.status.value:<14} {area.coverage_percent:>7.2f}%  {explanation}"
        )
    typer.echo(
        f"\nPermission evidence source: {auth.permission_source}. "
        "Graph API responses remain the authoritative runtime test."
    )


@tenant_app.command("info")
def tenant_info(
    tenant: str = typer.Option(..., "--tenant"),
    auth_method: str | None = typer.Option(None, "--auth"),
    config: Path | None = typer.Option(None, "--config", exists=True, dir_okay=False),
) -> None:
    """Authenticate and discover tenant organization metadata."""
    settings = _settings(config, tenant_id=tenant, auth_method=auth_method)
    configure_logging(settings.log_level)
    try:
        document = asyncio.run(Scanner(settings).scan(["cis-m365-7.0.0"], area="entra"))
    except AuthenticationError as exc:
        typer.echo(f"[!] Authentication failed: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(document.tenant.model_dump_json(indent=2))


@app.command("scan")
def scan_command(
    tenant: str | None = typer.Option(
        None,
        "--tenant",
        help="Target tenant ID. Optional for interactive and device-code discovery.",
    ),
    auth_method: str | None = typer.Option(None, "--auth"),
    framework: list[str] = typer.Option([], "--framework", "--benchmark"),
    client_name: str | None = typer.Option(
        None,
        "--client-name",
        "-C",
        help="Client name used in the timestamped report folder and filenames.",
    ),
    category: str | None = typer.Option(None, "--category", help="Limit collection to an area."),
    output: Path | None = typer.Option(None, "--output", "-O", file_okay=False),
    dry_run: bool = typer.Option(False, "--dry-run"),
    assume_yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Confirm a tenant discovered through delegated sign-in.",
    ),
    cache: bool | None = typer.Option(None, "--cache/--no-cache"),
    evidence_input: Path | None = typer.Option(
        None, "--evidence-input", exists=True, dir_okay=False
    ),
    sharepoint_url: str | None = typer.Option(None, "--sharepoint-url"),
    config: Path | None = typer.Option(None, "--config", exists=True, dir_okay=False),
) -> None:
    """Run a read-only assessment or preview its requirements."""
    settings = _settings(
        config,
        tenant_id=tenant,
        client_name=client_name,
        output_directory=output,
        auth_method=auth_method,
        cache=cache,
        evidence_input=evidence_input,
        sharepoint_url=sharepoint_url,
    )
    try:
        framework_ids = _framework_ids(framework, settings)
    except ValueError as exc:
        typer.echo(f"[!] {exc}", err=True)
        raise typer.Exit(2) from exc
    if dry_run:
        plan = build_dry_run(settings, framework_ids, area=_area(category))
        typer.echo(plan.model_dump_json(indent=2))
        return
    settings, report_stem = _assessment_output(settings, client_name, output)
    typer.echo(f"[+] Report directory: {settings.output_directory}")
    configure_logging(settings.log_level)
    typer.echo("[+] Starting read-only assessment")
    try:
        authentication = None
        if settings.tenant_id is None and settings.auth_method in {"interactive", "device-code"}:
            authentication = asyncio.run(MicrosoftAuthenticator(settings).authenticate())
            settings = _confirm_discovered_tenant(settings, authentication, assume_yes)
        document = asyncio.run(
            Scanner(settings).scan(
                framework_ids,
                area=_area(category),
                auth_result=authentication,
            )
        )
    except AuthenticationError as exc:
        typer.echo(f"[!] Authentication failed: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo("[+] Authentication successful")
    for execution in document.collectors.values():
        marker = "+" if execution.status.value == "SUCCESS" else "!"
        detail = execution.limitation_reason or f"{execution.objects_collected} objects"
        typer.echo(f"[{marker}] {execution.name}: {execution.status.value} - {detail}")
    report_paths = generate_reports(
        document,
        settings.output_directory,
        filename_stem=report_stem,
    )
    if settings.cache:
        cache_path = write_evidence_cache(document, settings.output_directory)
        typer.echo(f"[+] Evidence cache generated: {cache_path}")
    repository = AssessmentRepository(settings.database_url)
    repository.initialize()
    repository.save(document)
    typer.echo(f"[+] {document.summary.total_checks} controls evaluated")
    typer.echo(f"[+] Coverage areas reported: {len(document.coverage)}")
    for name, report_path in report_paths.items():
        typer.echo(f"Report generated ({name}): {report_path}")


def _load_document(path: Path) -> AssessmentDocument:
    try:
        return AssessmentDocument.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"Invalid assessment JSON: {exc}") from exc


@app.command("report")
def report_command(
    input_path: Path = typer.Option(..., "--input", exists=True, dir_okay=False),
    output: Path = typer.Option(Path("reports"), "--output", "-O", file_okay=False),
) -> None:
    """Regenerate all report formats from a normalized assessment JSON file."""
    document = _load_document(input_path)
    for name, path in generate_reports(document, output).items():
        typer.echo(f"[+] Generated {name}: {path}")


@app.command("export")
def export_command(
    input_path: Path = typer.Option(..., "--input", exists=True, dir_okay=False),
    formats: str = typer.Option("html,json,csv,xlsx", "--format"),
    output: Path = typer.Option(Path("reports"), "--output", "-O", file_okay=False),
) -> None:
    """Export selected report formats from an assessment JSON file."""
    selected = {item.strip().casefold() for item in formats.split(",") if item.strip()}
    if not selected or selected - SUPPORTED_FORMATS:
        raise typer.BadParameter(
            "--format must contain one or more of: " + ",".join(sorted(SUPPORTED_FORMATS))
        )
    document = _load_document(input_path)
    for name, path in generate_reports(document, output, selected).items():
        typer.echo(f"[+] Generated {name}: {path}")


@app.command("serve")
def serve_command(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", min=1, max=65535),
) -> None:
    """Run the FastAPI discovery service."""
    uvicorn.run("m365_assessor.api:app", host=host, port=port, log_config=None)


@app.command("sbom")
def sbom_command(
    output: Path = typer.Option(Path("reports/m365-assessor-sbom.json"), "--output"),
) -> None:
    """Generate an offline CycloneDX-compatible dependency SBOM."""
    typer.echo(f"[+] SBOM generated: {generate_sbom(output)}")


if __name__ == "__main__":
    app()
