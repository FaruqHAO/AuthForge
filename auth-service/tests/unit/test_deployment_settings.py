"""Regression checks for deployment signing keys."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_jwt_signing_key_is_loaded_from_environment(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "deployment-jwt-key-" + "a" * 40)
    settings = Settings()
    assert settings.jwt.secret_key == "deployment-jwt-key-" + "a" * 40


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_deployment_rejects_placeholder_key(monkeypatch, environment):
    monkeypatch.setenv("SECRET_KEY", "change-me-to-a-random-64-char-hex-string")
    with pytest.raises(ValidationError, match="Set unique"):
        Settings(environment=environment)


def test_production_rejects_reused_signing_key(monkeypatch):
    key = "same-signing-key-" + "a" * 40
    monkeypatch.setenv("SECRET_KEY", key)
    monkeypatch.setenv("JWT_SECRET_KEY", key)
    with pytest.raises(ValidationError, match="must be different"):
        Settings(environment="production")
