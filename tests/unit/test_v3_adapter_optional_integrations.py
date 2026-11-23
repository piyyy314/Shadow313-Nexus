"""Regression tests for optional V3 bridge integrations missing from this checkout."""

import asyncio
from types import SimpleNamespace

import pytest

from shadow313.v3.bridge import v3_adapter


class Output:
    def __init__(self):
        self.messages = []

    def info(self, message):
        self.messages.append(("info", str(message)))

    def warning(self, message):
        self.messages.append(("warning", str(message)))

    def success(self, message):
        self.messages.append(("success", str(message)))


def make_context():
    return SimpleNamespace(
        output=Output(),
        session=SimpleNamespace(
            session_id="v3-optional-test",
            write=lambda *_args, **_kwargs: None,
            increment_findings=lambda: None,
        ),
    )


@pytest.fixture(autouse=True)
def reset_model_registry():
    v3_adapter.ModelRegistry._instance = None


def test_status_reports_missing_lstm_as_unavailable():
    context = make_context()

    result = asyncio.run(v3_adapter.v3_status(context))

    assert result["success"] is True
    assert result["lstm_loaded"] is False
    assert result["lstm_available"] is False
    assert "not included in this checkout" in result["lstm_message"]
    assert any(level == "warning" for level, _ in context.output.messages)


def test_detect_returns_unavailable_instead_of_import_error():
    context = make_context()

    result = asyncio.run(v3_adapter.v3_detect(context))

    assert result["success"] is False
    assert result["available"] is False
    assert result["component"] == "v3_lstm_detector"


def test_incident_response_returns_unavailable_instead_of_import_error():
    context = make_context()

    result = asyncio.run(v3_adapter.v3_incident_response(context))

    assert result["success"] is False
    assert result["available"] is False
    assert result["component"] == "v3_incident_response"


def test_attestation_returns_unavailable_instead_of_import_error():
    context = make_context()

    result = asyncio.run(v3_adapter.v3_attest(context))

    assert result["success"] is False
    assert result["available"] is False
    assert result["component"] == "v3_tpm_attestation"
