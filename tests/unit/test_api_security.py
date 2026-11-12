"""Production API startup rejects known placeholder and weak keys."""

import pytest

from shadow313.api.server import create_app


@pytest.mark.parametrize(
    "api_key",
    [
        None,
        "",
        "replace-with-a-random-api-key",
        "change-me",
        "short-key",
    ],
)
def test_production_rejects_missing_placeholder_or_short_api_key(monkeypatch, api_key):
    monkeypatch.setenv("SHADOW313_ENV", "production")
    if api_key is None:
        monkeypatch.delenv("SHADOW313_API_KEY", raising=False)
    else:
        monkeypatch.setenv("SHADOW313_API_KEY", api_key)

    with pytest.raises(RuntimeError, match="non-placeholder value"):
        create_app()


def test_production_accepts_randomized_api_key(monkeypatch):
    monkeypatch.setenv("SHADOW313_ENV", "production")
    monkeypatch.setenv("SHADOW313_API_KEY", "a" * 48)

    app = create_app()

    assert app.title == "Shadow313 NEXUS API"


def test_development_keeps_short_test_keys_usable(monkeypatch):
    monkeypatch.setenv("SHADOW313_ENV", "development")
    monkeypatch.delenv("SHADOW313_API_KEY", raising=False)

    app = create_app(api_key="test-key")

    assert app.title == "Shadow313 NEXUS API"
