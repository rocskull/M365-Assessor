from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from m365_assessor.config import Settings


class ServiceCollectionError(RuntimeError):
    """A supported service interface was unavailable or rejected the session."""


@dataclass
class ServicePayload:
    data: dict[str, Any]
    errors: list[str] = field(default_factory=list)


class ServiceClient(Protocol):
    async def collect(self, commands: dict[str, str]) -> ServicePayload: ...

    async def health_check(self) -> bool: ...


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _safe_env_name(value: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
        raise ServiceCollectionError("Credential environment-variable name is invalid.")
    return value


class SnapshotServiceClient:
    """Offline/replay client for cached evidence and deterministic testing."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    async def collect(self, commands: dict[str, str]) -> ServicePayload:
        del commands
        errors = self.payload.get("errors", [])
        data = self.payload.get("data", self.payload)
        return ServicePayload(
            data=data if isinstance(data, dict) else {},
            errors=[str(item) for item in errors] if isinstance(errors, list) else [],
        )

    async def health_check(self) -> bool:
        return True


class PowerShellServiceClient:
    """Runs a fixed read-only command set through Microsoft-supported modules."""

    _MARKER = "__M365_ASSESSOR_JSON__"

    def __init__(
        self, service: str, settings: Settings, command_catalog: dict[str, str] | None = None
    ) -> None:
        self.service = service
        self.settings = settings
        self.command_catalog = command_catalog or {}
        self._cached_payload: ServicePayload | None = None
        self._lock = asyncio.Lock()

    async def health_check(self) -> bool:
        return shutil.which(self.settings.powershell_executable) is not None

    async def collect(self, commands: dict[str, str]) -> ServicePayload:
        async with self._lock:
            if self._cached_payload is None:
                command_set = self.command_catalog or commands
                self._cached_payload = await self._collect_locked(command_set)
            names = set(commands)
            return ServicePayload(
                data={
                    key: value for key, value in self._cached_payload.data.items() if key in names
                },
                errors=[
                    error
                    for error in self._cached_payload.errors
                    if error.split(":", 1)[0] in names
                ],
            )

    async def _collect_locked(self, commands: dict[str, str]) -> ServicePayload:
        executable = shutil.which(self.settings.powershell_executable)
        if executable is None:
            raise ServiceCollectionError(
                f"PowerShell executable '{self.settings.powershell_executable}' was not found."
            )
        script = self._script(commands)
        process = await asyncio.create_subprocess_exec(
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(script.encode("utf-8")), timeout=self.settings.timeout * 4
        )
        output = stdout.decode("utf-8", errors="replace")
        error_output = stderr.decode("utf-8", errors="replace").strip()
        marker_index = output.rfind(self._MARKER)
        if marker_index < 0:
            detail = error_output.splitlines()[-1] if error_output else "No JSON payload returned."
            raise ServiceCollectionError(f"{self.service} collection failed: {detail[:300]}")
        raw = output[marker_index + len(self._MARKER) :].strip()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ServiceCollectionError(
                f"{self.service} returned an invalid JSON payload."
            ) from exc
        if not isinstance(payload, dict):
            raise ServiceCollectionError(f"{self.service} returned an invalid payload type.")
        data = payload.get("data", {})
        errors = payload.get("errors", [])
        return ServicePayload(
            data=data if isinstance(data, dict) else {},
            errors=[str(item) for item in errors] if isinstance(errors, list) else [],
        )

    def _script(self, commands: dict[str, str]) -> str:
        connection = self._connection_script()
        blocks = []
        for name, command in commands.items():
            safe_name = _ps_quote(name)
            blocks.append(
                "try { $data["
                + safe_name
                + "] = @(& { "
                + command
                + " }) } catch { $errors += "
                + safe_name
                + " + ': ' + $_.Exception.Message }"
            )
        return "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                "$ProgressPreference = 'SilentlyContinue'",
                connection,
                "$data = [ordered]@{}",
                "$errors = @()",
                *blocks,
                "$payload = [ordered]@{ data = $data; errors = $errors }",
                f"Write-Output '{self._MARKER}'",
                "$payload | ConvertTo-Json -Depth 30 -Compress",
            ]
        )

    def _connection_script(self) -> str:
        settings = self.settings
        tenant = _ps_quote(settings.tenant_id or "")
        exchange_organization = _ps_quote(
            settings.exchange_organization or settings.tenant_id or ""
        )
        client = _ps_quote(settings.client_id or "")
        certificate = _ps_quote(
            str(settings.service_certificate_path or settings.certificate_path or "")
        )
        auth = settings.auth_method
        if self.service in {"exchange", "purview"}:
            connect = (
                "Connect-ExchangeOnline" if self.service == "exchange" else "Connect-IPPSSession"
            )
            module = "ExchangeOnlineManagement"
            if auth == "certificate":
                password_env = _safe_env_name(settings.service_certificate_password_env)
                args = (
                    f"-AppId {client} -CertificateFilePath {certificate} "
                    f"-CertificatePassword (ConvertTo-SecureString $env:{password_env} "
                    f"-AsPlainText -Force) -Organization {exchange_organization}"
                )
            elif auth == "managed-identity" and self.service == "exchange":
                args = f"-ManagedIdentity -Organization {exchange_organization}"
            elif auth in {"interactive", "device-code"}:
                args = "-Device"
            else:
                raise ServiceCollectionError(
                    f"{self.service} PowerShell supports device, certificate, or applicable "
                    "managed-identity authentication; client secrets are not passed to modules."
                )
            return f"Import-Module {module}; {connect} {args} -ShowBanner:$false"
        if self.service == "teams":
            if auth == "certificate":
                password_env = _safe_env_name(settings.service_certificate_password_env)
                cert_load = (
                    f"$certPassword = ConvertTo-SecureString $env:{password_env} "
                    "-AsPlainText -Force; "
                    "$cert = [System.Security.Cryptography.X509Certificates."
                    "X509Certificate2]::new("
                    f"{certificate}, $certPassword)"
                )
                connect = (
                    f"{cert_load}; Connect-MicrosoftTeams -TenantId {tenant} "
                    f"-ApplicationId {client} -Certificate $cert"
                )
            elif auth in {"interactive", "device-code"}:
                connect = f"Connect-MicrosoftTeams -TenantId {tenant}"
            else:
                raise ServiceCollectionError(
                    "Teams collection requires interactive/device or certificate authentication."
                )
            return f"Import-Module MicrosoftTeams; {connect}"
        if self.service == "sharepoint":
            if settings.sharepoint_url is None:
                raise ServiceCollectionError(
                    "SharePoint tenant URL is required when automatic discovery is unavailable."
                )
            url = _ps_quote(str(settings.sharepoint_url))
            if auth == "certificate":
                password_env = _safe_env_name(settings.service_certificate_password_env)
                connect = (
                    f"Connect-PnPOnline -Url {url} -Tenant {tenant} -ClientId {client} "
                    f"-CertificatePath {certificate} -CertificatePassword "
                    f"(ConvertTo-SecureString $env:{password_env} -AsPlainText -Force)"
                )
            elif auth == "device-code":
                connect = f"Connect-PnPOnline -Url {url} -DeviceLogin -ClientId {client}"
            elif auth == "interactive":
                connect = f"Connect-PnPOnline -Url {url} -Interactive -ClientId {client}"
            else:
                raise ServiceCollectionError(
                    "SharePoint collection requires interactive/device or certificate "
                    "authentication."
                )
            return f"Import-Module PnP.PowerShell; {connect}"
        if self.service == "fabric":
            if auth in {"interactive", "device-code"}:
                connect = f"Connect-AzAccount -Tenant {tenant} -UseDeviceAuthentication"
            elif auth == "service-principal":
                secret_env = _safe_env_name(settings.client_secret_env)
                connect = (
                    f"$secret = ConvertTo-SecureString $env:{secret_env} -AsPlainText -Force; "
                    f"$credential = [PSCredential]::new({client}, $secret); "
                    f"Connect-AzAccount -ServicePrincipal -Tenant {tenant} -Credential $credential"
                )
            elif auth == "certificate" and settings.certificate_thumbprint:
                thumbprint = _ps_quote(settings.certificate_thumbprint)
                connect = (
                    f"Connect-AzAccount -ServicePrincipal -Tenant {tenant} "
                    f"-ApplicationId {client} -CertificateThumbprint {thumbprint}"
                )
            elif auth == "managed-identity":
                connect = f"Connect-AzAccount -Identity -Tenant {tenant}"
            else:
                raise ServiceCollectionError(
                    "Fabric collection requires device, secret, certificate-thumbprint, or "
                    "managed-identity authentication."
                )
            return (
                f"Import-Module Az.Accounts; {connect}; "
                "$token = Get-AzAccessToken -ResourceUrl 'https://api.fabric.microsoft.com'; "
                "$fabricToken = $token.Token | ConvertFrom-SecureString -AsPlainText; "
                "function Invoke-M365ReadRest { param($Uri, $Headers); "
                f"for($attempt=0; $attempt -le {settings.retry_count}; $attempt++) {{ "
                "try { return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get } "
                "catch { if ($_.Exception.Response.StatusCode.value__ -ne 429 -or "
                f"$attempt -eq {settings.retry_count}) {{ throw }}; "
                "$retry = $_.Exception.Response.Headers['Retry-After']; "
                "if (-not $retry) { $retry = [Math]::Pow(2, $attempt) }; "
                "Start-Sleep -Seconds ([int]$retry) } } }"
            )
        raise ServiceCollectionError(f"Unsupported service adapter: {self.service}")


def load_snapshot_clients(path: Path) -> dict[str, ServiceClient]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("evidence_input must contain a JSON object keyed by service")
    return {
        service: SnapshotServiceClient(value)
        for service, value in payload.items()
        if isinstance(value, dict)
    }


def default_service_clients(
    settings: Settings, collectors: list[Any] | None = None
) -> dict[str, ServiceClient]:
    if settings.evidence_input is not None:
        return load_snapshot_clients(settings.evidence_input)
    if not settings.service_collection_enabled:
        return {}
    catalogs: dict[str, dict[str, str]] = {}
    for collector in collectors or []:
        service = getattr(collector, "service", None)
        commands = getattr(collector, "commands", None)
        if isinstance(service, str) and isinstance(commands, dict):
            catalogs.setdefault(service, {}).update(commands)
    return {
        name: PowerShellServiceClient(name, settings, catalogs.get(name))
        for name in ("exchange", "teams", "sharepoint", "purview", "fabric")
    }
