from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

import msal
from azure.identity.aio import ManagedIdentityCredential
from pydantic import BaseModel, Field, SecretStr

from m365_assessor.auth.cache import SecureTokenCacheStore
from m365_assessor.config import Settings

logger = logging.getLogger(__name__)
GRAPH_DEFAULT_SCOPE = "https://graph.microsoft.com/.default"


class AuthenticationError(RuntimeError):
    """An actionable authentication failure."""


class AuthResult(BaseModel):
    access_token: SecretStr = Field(repr=False)
    tenant_id: str
    client_id: str
    method: str
    identity: str | None = None
    granted_permissions: set[str] = Field(default_factory=set)
    permission_source: str = "token_response"
    expires_in: int | None = None


class AccessTokenProvider(Protocol):
    async def get_access_token(self) -> str: ...


@dataclass
class StaticAccessTokenProvider:
    result: AuthResult

    async def get_access_token(self) -> str:
        return self.result.access_token.get_secret_value()


def _decode_claims_for_diagnostics(token: str) -> dict[str, Any]:
    """Decode unverified claims for coverage hints, never for authorization decisions."""
    try:
        encoded = token.split(".")[1]
        encoded += "=" * (-len(encoded) % 4)
        decoded = base64.urlsafe_b64decode(encoded.encode("ascii"))
        value = json.loads(decoded)
        return value if isinstance(value, dict) else {}
    except (IndexError, ValueError, UnicodeError, json.JSONDecodeError):
        return {}


def _permissions_from_result(result: dict[str, Any]) -> tuple[set[str], str]:
    response_scope = result.get("scope")
    if isinstance(response_scope, str) and response_scope.strip():
        return set(response_scope.split()), "token_response"
    token = result.get("access_token")
    claims = _decode_claims_for_diagnostics(token) if isinstance(token, str) else {}
    scopes = claims.get("scp")
    roles = claims.get("roles")
    if isinstance(scopes, str):
        return set(scopes.split()), "token_claims_diagnostic"
    if isinstance(roles, list):
        return {str(role) for role in roles}, "token_claims_diagnostic"
    return set(), "unavailable"


def _friendly_auth_error(result: dict[str, Any]) -> AuthenticationError:
    code = str(result.get("error", "authentication_failed"))
    detail = str(
        result.get("error_description", "Microsoft identity platform rejected the request")
    )
    lowered = detail.lower()
    if "aadsts65001" in lowered or "consent" in lowered:
        guidance = "Administrator or user consent is required for the requested permissions."
    elif "aadsts700016" in lowered:
        guidance = "The client ID was not found in this tenant. Verify tenant and client IDs."
    elif "aadsts7000215" in lowered or "secret" in lowered:
        guidance = "The client credential is invalid or expired. Rotate the referenced credential."
    elif "aadsts500011" in lowered or "tenant" in lowered:
        guidance = "The tenant or resource is invalid. Verify the tenant ID and cloud environment."
    elif "conditional access" in lowered or "aadsts530" in lowered:
        guidance = (
            "A Conditional Access policy blocked authentication; ask the tenant administrator."
        )
    else:
        guidance = "Verify the tenant, client registration, redirect URI, and granted permissions."
    return AuthenticationError(f"{code}: {guidance} Provider detail: {detail[:500]}")


class MicrosoftAuthenticator:
    def __init__(
        self, settings: Settings, cache_store: SecureTokenCacheStore | None = None
    ) -> None:
        self.settings = settings
        self.cache_store = cache_store or SecureTokenCacheStore()

    def _require_client_id(self) -> str:
        if not self.settings.client_id:
            raise AuthenticationError("Missing client ID; set M365_ASSESSOR_CLIENT_ID.")
        return self.settings.client_id

    def _authority_tenant(self, method: str) -> str:
        if self.settings.tenant_id:
            return self.settings.tenant_id
        if method in {"interactive", "device-code"}:
            return "organizations"
        raise AuthenticationError(
            "Missing tenant ID; app-only authentication requires --tenant or "
            "M365_ASSESSOR_TENANT_ID."
        )

    def _scopes(self, app_only: bool = False) -> list[str]:
        if app_only:
            return [GRAPH_DEFAULT_SCOPE]
        return [
            scope if scope.startswith("https://") else f"https://graph.microsoft.com/{scope}"
            for scope in self.settings.auth_scopes
        ]

    async def authenticate(self) -> AuthResult:
        method = self.settings.auth_method
        if method == "managed-identity":
            return await self._managed_identity()
        return await asyncio.to_thread(self._authenticate_msal)

    def _authenticate_msal(self) -> AuthResult:
        method = self.settings.auth_method
        client_id = self._require_client_id()
        authority_tenant = self._authority_tenant(method)
        discovering_tenant = self.settings.tenant_id is None
        authority = f"https://login.microsoftonline.com/{authority_tenant}"
        cache = msal.SerializableTokenCache()
        serialized = self.cache_store.load()
        if serialized:
            cache.deserialize(serialized)

        if method in {"interactive", "device-code"}:
            app = msal.PublicClientApplication(client_id, authority=authority, token_cache=cache)
            # Discovery must always let the assessor select an account instead
            # of silently choosing the first cached account from another tenant.
            accounts = [] if discovering_tenant else app.get_accounts()
            result: dict[str, Any] | None = None
            if accounts:
                result = app.acquire_token_silent(self._scopes(), account=accounts[0])
            if not result:
                if method == "interactive":
                    result = app.acquire_token_interactive(
                        scopes=self._scopes(), prompt="select_account"
                    )
                else:
                    flow = app.initiate_device_flow(scopes=self._scopes())
                    if "user_code" not in flow:
                        raise _friendly_auth_error(cast(dict[str, Any], flow))
                    print(flow["message"])
                    result = app.acquire_token_by_device_flow(flow)
        else:
            credential: str | dict[str, Any]
            if method == "service-principal":
                credential = os.getenv(self.settings.client_secret_env, "")
                if not credential:
                    raise AuthenticationError(
                        "Client secret environment variable "
                        f"{self.settings.client_secret_env} is empty."
                    )
            elif method == "certificate":
                credential = self._certificate_credential()
            else:
                raise AuthenticationError(f"Unsupported authentication method: {method}")
            confidential = msal.ConfidentialClientApplication(
                client_id, authority=authority, client_credential=credential, token_cache=cache
            )
            result = confidential.acquire_token_for_client(scopes=self._scopes(app_only=True))

        if cache.has_state_changed:
            self.cache_store.save(cache.serialize())
        if not result or "access_token" not in result:
            raise _friendly_auth_error(result or {})
        normalized = self._normalize_result(result, authority_tenant, client_id, method)
        if discovering_tenant and normalized.tenant_id in {"", "common", "organizations"}:
            raise AuthenticationError(
                "Microsoft sign-in succeeded but the tenant ID could not be discovered from "
                "the returned token. Supply --tenant explicitly."
            )
        return normalized

    def _certificate_credential(self) -> dict[str, Any]:
        path = self.settings.certificate_path
        thumbprint = self.settings.certificate_thumbprint
        if path is None or thumbprint is None:
            raise AuthenticationError("Certificate auth requires certificate_path and thumbprint.")
        try:
            private_key = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise AuthenticationError(f"Unable to read the certificate private key: {exc}") from exc
        credential: dict[str, Any] = {"private_key": private_key, "thumbprint": thumbprint}
        passphrase = os.getenv(self.settings.certificate_password_env)
        if passphrase:
            credential["passphrase"] = passphrase
        return credential

    async def _managed_identity(self) -> AuthResult:
        tenant_id = self.settings.tenant_id or "managed"
        client_id = self.settings.client_id
        credential = ManagedIdentityCredential(client_id=client_id)
        try:
            token = await credential.get_token(GRAPH_DEFAULT_SCOPE)
        except Exception as exc:
            raise AuthenticationError(
                "Managed Identity authentication failed. Confirm the workload identity "
                "and Graph roles."
            ) from exc
        finally:
            await credential.close()
        raw = {"access_token": token.token, "expires_in": token.expires_on}
        return self._normalize_result(raw, tenant_id, client_id or "managed", "managed-identity")

    @staticmethod
    def _normalize_result(
        result: dict[str, Any], tenant_id: str, client_id: str, method: str
    ) -> AuthResult:
        permissions, source = _permissions_from_result(result)
        claims = result.get("id_token_claims")
        claims = (
            claims
            if isinstance(claims, dict)
            else _decode_claims_for_diagnostics(str(result["access_token"]))
        )
        return AuthResult(
            access_token=str(result["access_token"]),
            tenant_id=str(claims.get("tid", tenant_id)),
            client_id=client_id,
            method=method,
            identity=claims.get("preferred_username") or claims.get("name") or claims.get("oid"),
            granted_permissions=permissions,
            permission_source=source,
            expires_in=result.get("expires_in"),
        )
