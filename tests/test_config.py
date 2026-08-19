from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from m365_assessor.config import Settings, load_settings


def test_defaults_are_safe() -> None:
    settings = Settings()
    assert settings.auth_method == "interactive"
    assert settings.concurrency == 4
    assert "User.Read" in settings.auth_scopes


def test_load_safe_yaml(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("tenant_id: tenant\nconcurrency: 2\n", encoding="utf-8")
    assert load_settings(path).tenant_id == "tenant"
    assert load_settings(path).concurrency == 2


def test_rejects_parent_traversal() -> None:
    with pytest.raises(ValidationError):
        Settings(output_directory=Path("../outside"))


def test_rejects_unsafe_yaml_object(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.yaml"
    path.write_text("!!python/object/apply:os.system ['whoami']", encoding="utf-8")
    with pytest.raises(yaml.constructor.ConstructorError):
        load_settings(path)
