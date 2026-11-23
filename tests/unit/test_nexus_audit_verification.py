"""Regression tests for truthful NEXUS receipt and audit reporting."""

from types import SimpleNamespace

from shadow313.v4.nexus.nexus import NEXUSModule


class FakeEngine:
    def __init__(self, receipts, verifications):
        self.receipts = receipts
        self.verifications = verifications

    def list_receipts(self, limit=20):
        return self.receipts[:limit]

    def verify(self, receipt_id):
        return self.verifications[receipt_id]


class FakeOutput:
    def __init__(self):
        self.messages = []

    def section(self, message):
        self.messages.append(message)

    def result(self, data, title=""):
        self.messages.append((title, data))

    def warn(self, message):
        self.messages.append(message)

    def info(self, message):
        self.messages.append(message)

    def success(self, message):
        self.messages.append(message)


def make_module(tmp_path, receipts=None, verifications=None, audit_log=True):
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    if audit_log:
        (session_dir / "audit.log").write_text('{"event":"scan"}\n', encoding="utf-8")

    engine = FakeEngine(receipts or [], verifications or {})
    module = object.__new__(NEXUSModule)
    module.session = SimpleNamespace(session_dir=session_dir, id="test-session")
    module.kernel = SimpleNamespace(
        get_module=lambda name: SimpleNamespace(engine=engine) if name == "temporal" else None
    )
    module.out = FakeOutput()
    return module


def verified_receipt(receipt_id, bind_index, signer_trusted=True, valid=True):
    checks = {
        "signature_verified": valid,
        "signer_trusted": signer_trusted,
        "sha3_512_matches": valid,
    }
    return (
        {"receipt_id": receipt_id, "bind_index": bind_index},
        {"valid": valid, "checks": checks},
    )


def test_missing_audit_log_is_not_reported_as_valid(tmp_path):
    module = make_module(tmp_path, audit_log=False)

    result = module._verify_audit_chain()

    assert result["valid"] is None
    assert result["status"] == "not_available"
    assert result["tamper_evident"] is False


def test_receipts_require_trusted_signers_for_tamper_evident_status(tmp_path):
    receipt, verification = verified_receipt("313-v4-00000001", 1, signer_trusted=False)
    module = make_module(
        tmp_path,
        [receipt],
        {receipt["receipt_id"]: verification},
    )

    result = module._verify_audit_chain()

    assert result["valid"] is None
    assert result["receipt_integrity_valid"] is True
    assert result["trusted_receipt_chain"] is False
    assert result["tamper_evident"] is False
    assert result["untrusted_signers"] == [receipt["receipt_id"]]
    assert result["audit_log_authenticated"] is False


def test_fully_verified_trusted_receipts_are_reported_with_scope(tmp_path):
    first, first_result = verified_receipt("313-v4-00000001", 1)
    second, second_result = verified_receipt("313-v4-00000002", 2)
    module = make_module(
        tmp_path,
        [first, second],
        {
            first["receipt_id"]: first_result,
            second["receipt_id"]: second_result,
        },
    )

    result = module._verify_audit_chain()

    assert result["receipt_integrity_valid"] is True
    assert result["trusted_receipt_chain"] is True
    assert result["tamper_evident"] is True
    assert result["valid"] is None
    assert result["audit_log_authenticated"] is False


def test_invalid_receipt_is_reported(tmp_path):
    receipt, verification = verified_receipt(
        "313-v4-00000009", 9, signer_trusted=True, valid=False
    )
    module = make_module(
        tmp_path,
        [receipt],
        {receipt["receipt_id"]: verification},
    )

    result = module._verify_audit_chain()

    assert result["receipt_integrity_valid"] is False
    assert result["tamper_evident"] is False
    assert result["invalid_receipts"] == [receipt["receipt_id"]]


def test_bind_index_gap_is_reported_without_claiming_tampering(tmp_path):
    first, first_result = verified_receipt("313-v4-00000001", 1)
    third, third_result = verified_receipt("313-v4-00000003", 3)
    module = make_module(
        tmp_path,
        [first, third],
        {
            first["receipt_id"]: first_result,
            third["receipt_id"]: third_result,
        },
    )

    result = module._verify_audit_chain()

    assert result["receipt_integrity_valid"] is True
    assert result["bind_index_gaps"] == [{"from": 1, "to": 3}]
    assert result["trusted_receipt_chain"] is False
    assert result["tamper_evident"] is False

def test_insider_demo_does_not_claim_production_detection(tmp_path):
    module = make_module(tmp_path)

    result = module._demonstrate_insider_attack()

    assert result["sha3_chain_recomputed"] is True
    assert result["nexus_detection_executed"] is False
    assert result["nexus_detected"] is None
    assert result["cve_candidate"] is False

def test_invalid_utf8_audit_log_returns_malformed_status(tmp_path):
    module = make_module(tmp_path)
    (module.session.session_dir / "audit.log").write_bytes(b"\\xff")

    result = module._verify_audit_chain()

    assert result["valid"] is False
    assert result["status"] == "malformed_audit_log"
    assert result["audit_log_authenticated"] is False


def test_legacy_presence_only_verifier_cannot_claim_receipt_integrity(tmp_path):
    receipt = {"receipt_id": "313-v4-00000001", "bind_index": 1}
    verification = {
        "valid": True,
        "checks": {
            "sha3_512_present": True,
            "signature_present": True,
        },
    }
    module = make_module(
        tmp_path,
        [receipt],
        {receipt["receipt_id"]: verification},
    )

    result = module._verify_audit_chain()

    assert result["receipt_integrity_valid"] is False
    assert result["invalid_receipts"] == [receipt["receipt_id"]]
    assert result["tamper_evident"] is False



def test_bare_nexus_command_defaults_to_status():
    class FakeKernel:
        _modules = {}

        def __init__(self):
            self.out = FakeOutput()
            self.session = SimpleNamespace(id="test-session")

        def get_module(self, _name):
            return None

        def ai_status(self):
            return {"backend": "disabled", "available": False}

    module = NEXUSModule(FakeKernel())

    result = module.run()

    assert result["status"]["version"] == "4.0.0-NEXUS"
    assert result["status"]["ai_available"] is False
