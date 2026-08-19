from fastapi import FastAPI
from pydantic import BaseModel, Field

from m365_assessor import __version__
from m365_assessor.benchmarks.catalog import FrameworkCatalog
from m365_assessor.collectors.registry import default_registry
from m365_assessor.config import AuthMethod, Settings
from m365_assessor.core.scanner import Scanner, build_dry_run
from m365_assessor.permissions import load_permission_matrix
from m365_assessor.rules.loader import default_rule_registry


class ScanRequest(BaseModel):
    tenant_id: str
    frameworks: list[str] = Field(default_factory=lambda: ["cis-m365-7.0.0"])
    area: str | None = None


class DryRunRequest(ScanRequest):
    auth_method: AuthMethod = "service-principal"


def create_app() -> FastAPI:
    app = FastAPI(
        title="Microsoft 365 Security Assessor",
        version=__version__,
        description="Read-only Microsoft 365 security assessment API.",
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/collectors")
    async def collectors() -> list[dict[str, object]]:
        return [item.metadata.model_dump(mode="json") for item in default_registry().all()]

    @app.get("/checks")
    async def checks() -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in default_rule_registry().all()]

    @app.get("/frameworks")
    async def frameworks() -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in FrameworkCatalog.load().all()]

    @app.get("/permission-matrix")
    async def permission_matrix() -> dict[str, object]:
        return load_permission_matrix().model_dump(mode="json")

    @app.post("/scans/dry-run")
    async def dry_run(request: DryRunRequest) -> dict[str, object]:
        settings = Settings(tenant_id=request.tenant_id, auth_method=request.auth_method)
        return build_dry_run(settings, request.frameworks, area=request.area).model_dump(
            mode="json"
        )

    @app.post("/scans")
    async def scan(request: ScanRequest) -> dict[str, object]:
        settings = Settings(tenant_id=request.tenant_id)
        document = await Scanner(settings).scan(request.frameworks, area=request.area)
        return document.model_dump(mode="json")

    return app


app = create_app()
