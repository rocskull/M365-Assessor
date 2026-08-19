from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AuthMethod = Literal[
    "interactive", "device-code", "service-principal", "certificate", "managed-identity"
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="M365_ASSESSOR_", env_file=".env", extra="forbid", case_sensitive=False
    )

    tenant_id: str | None = None
    client_id: str | None = None
    client_name: str | None = None
    exchange_organization: str | None = None
    auth_method: AuthMethod = "interactive"
    auth_scopes: list[str] = Field(
        default_factory=lambda: [
            "User.Read",
            "Organization.Read.All",
            "User.Read.All",
            "RoleManagement.Read.Directory",
            "GroupMember.Read.All",
            "Policy.Read.All",
            "GroupSettings.Read.All",
            "Policy.Read.DeviceConfiguration",
            "AuditLog.Read.All",
            "Policy.Read.AuthenticationMethod",
            "Group.Read.All",
            "Device.Read.All",
            "Application.Read.All",
            "DelegatedPermissionGrant.Read.All",
        ]
    )
    sharepoint_url: HttpUrl | None = None
    output_directory: Path = Path("reports")
    frameworks: list[str] = Field(default_factory=list)
    log_level: str = "INFO"
    concurrency: int = Field(default=4, ge=1, le=20)
    timeout: float = Field(default=30, gt=0, le=300)
    retry_count: int = Field(default=4, ge=0, le=10)
    cache: bool = False
    database_url: str = "sqlite:///./m365-assessor.db"
    client_secret_env: str = "M365_ASSESSOR_CLIENT_SECRET"
    certificate_path: Path | None = None
    certificate_thumbprint: str | None = None
    certificate_password_env: str = "M365_ASSESSOR_CERTIFICATE_PASSWORD"
    service_certificate_path: Path | None = None
    service_certificate_password_env: str = "M365_ASSESSOR_SERVICE_CERTIFICATE_PASSWORD"
    powershell_executable: str = "pwsh"
    service_collection_enabled: bool = True
    evidence_input: Path | None = None
    framework_directory: Path | None = None
    rule_directory: Path | None = None

    @field_validator("output_directory")
    @classmethod
    def reject_parent_traversal(cls, value: Path) -> Path:
        if ".." in value.parts:
            raise ValueError("output_directory cannot contain parent traversal")
        return value

    @field_validator(
        "evidence_input", "framework_directory", "rule_directory", "service_certificate_path"
    )
    @classmethod
    def validate_evidence_input(cls, value: Path | None) -> Path | None:
        if value is not None and ".." in value.parts:
            raise ValueError("evidence_input cannot contain parent traversal")
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("unsupported log level")
        return normalized


def load_settings(path: Path | None = None) -> Settings:
    values: object = {}
    if path is not None:
        with path.open("r", encoding="utf-8") as stream:
            values = yaml.safe_load(stream) or {}
        if not isinstance(values, dict):
            raise ValueError("configuration must be a YAML mapping")
    return Settings.model_validate(values)
