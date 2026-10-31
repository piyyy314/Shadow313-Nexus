"""Regression coverage for the outstanding Vercel review findings."""

import importlib
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadow313.core.crypto_store import SLHDSASigner
from shadow313.core.kernel import Kernel


@pytest.mark.parametrize(
    "failure",
    [
        ModuleNotFoundError("optional dependency"),
        ImportError("broken import"),
        SyntaxError("invalid module"),
        RuntimeError("initialization failed"),
    ],
)
def test_loader_records_failures_and_continues(monkeypatch, failure):
    kernel = Kernel.__new__(Kernel)
    kernel._BUILTIN_MODULES = [
        ("broken", "example.broken.Module"),
        ("working", "example.working.Module"),
    ]
    kernel._load_errors = []
    kernel._modules = {}
    kernel._registry = {}
    kernel.out = Mock()

    def working_module(*, kernel):
        return SimpleNamespace(register=lambda k: k.register("working", lambda: "ok"))

    def import_module(path):
        if path == "example.broken":
            if isinstance(failure, RuntimeError):

                def broken_module(**kwargs):
                    raise failure

                return SimpleNamespace(Module=broken_module)
            raise failure
        return SimpleNamespace(Module=working_module)

    monkeypatch.setattr(importlib, "import_module", import_module)
    kernel._autoload_modules()

    assert kernel.load_errors == [
        {"module": "broken", "error": str(failure), "type": type(failure).__name__}
    ]
    assert kernel._registry["working"]() == "ok"
    assert "working" in kernel._modules
    errors = kernel.load_errors
    errors.clear()
    assert len(kernel.load_errors) == 1


def test_pyspx_receipt_verifiable_with_advertised_public_key():
    backend = pytest.importorskip("pyspx.shake_128f")
    signer = SLHDSASigner.generate()
    receipt_data = {"session_id": "test-session", "result": "ok"}
    receipt = signer.sign_receipt(receipt_data)
    payload = json.dumps(receipt_data, sort_keys=True).encode()
    signature = bytes.fromhex(receipt["signature"])
    public_key = bytes.fromhex(receipt["public_key"])

    assert signer.available
    assert receipt["algorithm"] == "SPHINCS+-SHAKE-128f"
    assert signer.algorithm_name == receipt["algorithm"]
    assert backend.verify(payload, signature, public_key)
    assert signer.verify(payload, signature)
    assert not signer.verify(payload + b"tampered", signature)
    assert not signer.verify(payload, b"invalid signature")
    assert not SLHDSASigner.generate().verify(payload, signature)
    assert signer.public_key == public_key
    # Signing another message must not regenerate the advertised key pair.
    assert backend.verify(b"another message", signer.sign(b"another message"), public_key)


def test_pyspx_private_key_restores_same_public_key():
    backend = pytest.importorskip("pyspx.shake_128f")
    public_key, private_key = backend.generate_keypair(bytes(backend.crypto_sign_SEEDBYTES))
    signer = SLHDSASigner(private_key=private_key)
    assert signer.public_key == public_key
    assert backend.verify(b"message", signer.sign(b"message"), public_key)


def test_invalid_pyspx_key_is_not_silently_downgraded():
    pytest.importorskip("pyspx.shake_128f")
    with pytest.raises(ValueError, match="private key"):
        SLHDSASigner(private_key=b"invalid")


def test_pyspx_signing_error_is_not_silently_downgraded(monkeypatch):
    backend = pytest.importorskip("pyspx.shake_128f")
    signer = SLHDSASigner.generate()
    monkeypatch.setattr(backend, "sign", Mock(side_effect=RuntimeError("backend failed")))
    with pytest.raises(RuntimeError, match="backend failed"):
        signer.sign_receipt({"result": "ok"})


def test_missing_pyspx_labels_symmetric_fallback_honestly(monkeypatch):
    monkeypatch.setitem(sys.modules, "pyspx.shake_128f", None)
    signer = SLHDSASigner()
    receipt = signer.sign_receipt({"result": "ok"})
    payload = json.dumps({"result": "ok"}, sort_keys=True).encode()
    signature = bytes.fromhex(receipt["signature"])
    assert not signer.available
    assert receipt["algorithm"] == "HMAC-SHA3-256"
    assert signer.algorithm_name == receipt["algorithm"]
    assert receipt["public_key"] is None
    assert signer.public_key is None
    assert signer.verify(payload, signature)
    assert not signer.verify(payload + b"tampered", signature)
    assert not SLHDSASigner().verify(payload, signature)
