import base64
import json

import pytest
import typer
from keyring.errors import KeyringError

from m365_assessor.auth.cache import SecureTokenCacheStore
from m365_assessor.auth.provider import (
    AuthenticationError,
    AuthResult,
    MicrosoftAuthenticator,
    _permissions_from_result,
)
from m365_assessor.cli.app import _confirm_discovered_tenant
from m365_assessor.config import Settings


def _fake_jwt(claims: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


def test_permissions_prefer_token_response_scope() -> None:
    permissions, source = _permissions_from_result({"scope": "User.Read Policy.Read.All"})
    assert permissions == {"User.Read", "Policy.Read.All"}
    assert source == "token_response"


def test_application_roles_can_supply_diagnostic_hint() -> None:
    permissions, source = _permissions_from_result(
        {"access_token": _fake_jwt({"roles": ["Directory.Read.All"]})}
    )
    assert permissions == {"Directory.Read.All"}
    assert source == "token_claims_diagnostic"


def test_missing_client_id_is_actionable() -> None:
    with pytest.raises(AuthenticationError, match="Missing client ID"):
        MicrosoftAuthenticator(Settings())._require_client_id()


def test_delegated_authentication_uses_organizations_for_discovery() -> None:
    authenticator = MicrosoftAuthenticator(Settings(client_id="client"))
    assert authenticator._authority_tenant("interactive") == "organizations"
    assert authenticator._authority_tenant("device-code") == "organizations"


def test_app_only_authentication_still_requires_tenant() -> None:
    authenticator = MicrosoftAuthenticator(
        Settings(client_id="client", auth_method="service-principal")
    )
    with pytest.raises(AuthenticationError, match="app-only authentication requires"):
        authenticator._authority_tenant("service-principal")


def test_discovered_tenant_can_be_confirmed_non_interactively() -> None:
    settings = Settings(client_id="client")
    authentication = AuthResult(
        access_token=_fake_jwt({"tid": "discovered-tenant"}),
        tenant_id="discovered-tenant",
        client_id="client",
        method="interactive",
        identity="assessor@example.com",
    )
    confirmed = _confirm_discovered_tenant(settings, authentication, assume_yes=True)
    assert confirmed.tenant_id == "discovered-tenant"


def test_noninteractive_discovery_requires_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(client_id="client")
    authentication = AuthResult(
        access_token=_fake_jwt({"tid": "discovered-tenant"}),
        tenant_id="discovered-tenant",
        client_id="client",
        method="interactive",
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.BadParameter, match="requires confirmation"):
        _confirm_discovered_tenant(settings, authentication, assume_yes=False)


def test_interactive_discovery_forces_account_picker(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    class MemoryCacheStore:
        def load(self) -> None:
            return None

        def save(self, serialized: str) -> None:
            observed["cache"] = serialized

    class PublicClient:
        def __init__(self, client_id: str, *, authority: str, token_cache: object) -> None:
            observed.update(client_id=client_id, authority=authority, token_cache=token_cache)

        def get_accounts(self) -> list[object]:
            raise AssertionError("Tenant discovery must not silently select a cached account")

        def acquire_token_interactive(self, *, scopes: list[str], prompt: str) -> dict[str, object]:
            observed.update(scopes=scopes, prompt=prompt)
            return {
                "access_token": "token",
                "scope": "User.Read",
                "id_token_claims": {
                    "tid": "discovered-tenant",
                    "preferred_username": "assessor@example.com",
                },
            }

    monkeypatch.setattr("msal.PublicClientApplication", PublicClient)
    authenticator = MicrosoftAuthenticator(
        Settings(client_id="client", auth_method="interactive"),
        cache_store=MemoryCacheStore(),  # type: ignore[arg-type]
    )
    result = authenticator._authenticate_msal()
    assert observed["authority"] == "https://login.microsoftonline.com/organizations"
    assert observed["prompt"] == "select_account"
    assert result.tenant_id == "discovered-tenant"
    assert result.identity == "assessor@example.com"


def test_keyring_failure_uses_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object) -> None:
        raise KeyringError("no backend")

    monkeypatch.setattr("keyring.set_password", fail)
    monkeypatch.setattr("keyring.get_password", fail)
    store = SecureTokenCacheStore()
    store.save("serialized")
    assert store.load() == "serialized"


def test_certificate_config_requires_path_and_thumbprint() -> None:
    authenticator = MicrosoftAuthenticator(
        Settings(tenant_id="tenant", client_id="client", auth_method="certificate")
    )
    with pytest.raises(AuthenticationError, match="certificate_path"):
        authenticator._certificate_credential()
