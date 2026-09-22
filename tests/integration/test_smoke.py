"""
Integration smoke tests — shadow313 v4 NEXUS
Tests that the CLI entry point, kernel, and core modules work end-to-end.
"""
import pytest
import sys
from pathlib import Path


class TestCLIEntryPoint:
    def test_import_main(self):
        from shadow313.cli.main import main, build_parser
        assert callable(main)
        assert callable(build_parser)

    def test_parser_builds(self):
        from shadow313.cli.main import build_parser
        parser = build_parser()
        assert parser is not None

    def test_version_flag(self, capsys):
        from shadow313.cli.main import main
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "4.0.0" in captured.out

    def test_help_flag(self, capsys):
        from shadow313.cli.main import main
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        assert exc_info.value.code == 0

    def test_no_command_exits_zero(self, capsys):
        from shadow313.cli.main import main
        result = main(["--no-banner"])
        assert result == 0


class TestKernelBootstrap:
    def test_kernel_initializes(self, tmp_path):
        from shadow313.core.kernel import Kernel
        kernel = Kernel(config_path=str(tmp_path / "config.yaml"))
        assert kernel is not None
        assert kernel.config is not None
        assert kernel.session is not None
        assert kernel.out is not None
        assert kernel.ai is not None

    def test_kernel_loads_v1_modules(self, tmp_path):
        from shadow313.core.kernel import Kernel
        kernel = Kernel(config_path=str(tmp_path / "config.yaml"))
        # Core v1 modules should be loaded
        for module_name in ["recon", "vuln", "exploit", "network", "defense",
                            "quantum", "plugins", "cicd", "docs"]:
            assert module_name in kernel._modules, f"Module '{module_name}' not loaded"

    def test_kernel_registers_commands(self, tmp_path):
        from shadow313.core.kernel import Kernel
        kernel = Kernel(config_path=str(tmp_path / "config.yaml"))
        # Core commands should be registered
        for cmd in ["recon", "vuln", "exploit", "network", "defense",
                    "quantum", "plugins", "cicd", "docs", "ask", "learn"]:
            assert cmd in kernel._registry, f"Command '{cmd}' not registered"

    def test_kernel_ai_status(self, tmp_path):
        from shadow313.core.kernel import Kernel
        kernel = Kernel(config_path=str(tmp_path / "config.yaml"))
        status = kernel.ai_status()
        assert "backend"   in status
        assert "model"     in status
        assert "available" in status

    def test_kernel_repr(self, tmp_path):
        from shadow313.core.kernel import Kernel
        kernel = Kernel(config_path=str(tmp_path / "config.yaml"))
        r = repr(kernel)
        assert "Kernel" in r
        assert "v4"     in r

    def test_kernel_dispatch_unknown_command(self, tmp_path, capsys):
        from shadow313.core.kernel import Kernel
        kernel = Kernel(config_path=str(tmp_path / "config.yaml"))
        result = kernel.dispatch("nonexistent_command_xyz")
        assert result is None
        captured = capsys.readouterr()
        assert "Unknown" in captured.err or "Unknown" in captured.out


class TestStatusCommand:
    def test_status_command(self, tmp_path):
        """FIX: 'status' command was missing in v1 — verify it works in v4."""
        from shadow313.cli.main import main
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"), "status"])
        assert result == 0


class TestSessionCommand:
    def test_session_list(self, tmp_path):
        from shadow313.cli.main import main
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"), "session", "--list"])
        assert result == 0

    def test_session_purge_nonexistent(self, tmp_path):
        from shadow313.cli.main import main
        result = main([
            "--no-banner",
            "--config", str(tmp_path / "config.yaml"),
            "session", "--purge", "00000000-0000-4000-8000-000000000000"
        ])
        # Should not crash — just report not found
        assert result == 0


class TestDocsModule:
    def test_docs_command(self, tmp_path):
        from shadow313.cli.main import main
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"), "docs"])
        assert result == 0

    def test_docs_topic_recon(self, tmp_path):
        from shadow313.cli.main import main
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"),
                       "docs", "--topic", "recon"])
        assert result == 0

    def test_docs_glossary(self, tmp_path):
        from shadow313.cli.main import main
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"),
                       "docs", "--glossary"])
        assert result == 0

    def test_learn_no_module(self, tmp_path):
        from shadow313.cli.main import main
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"), "learn"])
        assert result == 0


class TestPluginModule:
    def test_plugin_list(self, tmp_path):
        from shadow313.cli.main import main
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"),
                       "plugin", "--list"])
        assert result == 0


class TestCICDModule:
    def test_cicd_generate_github_actions(self, tmp_path):
        from shadow313.cli.main import main
        import os
        os.chdir(tmp_path)
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"),
                       "cicd", "--generate", "github-actions"])
        assert result == 0
        assert (tmp_path / ".github" / "workflows" / "shadow313.yml").exists()

    def test_cicd_generate_gitlab_ci(self, tmp_path):
        from shadow313.cli.main import main
        import os
        os.chdir(tmp_path)
        result = main(["--no-banner", "--config", str(tmp_path / "config.yaml"),
                       "cicd", "--generate", "gitlab-ci"])
        assert result == 0

    def test_cicd_secret_scan_empty_diff(self, tmp_path):
        from shadow313.modules.cicd.cicd import SecretScanner
        scanner  = SecretScanner()
        findings = scanner.scan_diff("")
        assert findings == []

    def test_cicd_secret_scan_clean_directory(self, tmp_path):
        (tmp_path / "clean.py").write_text('print("Hello, World!")\n')
        from shadow313.modules.cicd.cicd import SecretScanner
        scanner  = SecretScanner()
        findings = scanner.scan_directory(str(tmp_path))
        assert len(findings) == 0


class TestQuantumModule:
    def test_quantum_classify_rsa(self):
        from shadow313.modules.quantum.quantum import classify_algorithm
        r = classify_algorithm("RSA-2048")
        assert r["vuln"] == "VULNERABLE"
        assert "Shor" in r["reason"]

    def test_quantum_classify_aes256(self):
        from shadow313.modules.quantum.quantum import classify_algorithm
        r = classify_algorithm("AES-256")
        assert r["vuln"] == "SAFE"

    def test_quantum_source_scan_python(self, tmp_path):
        f = tmp_path / "crypto.py"
        f.write_text("from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n")
        from shadow313.modules.quantum.quantum import SourceCodeScanner
        scanner  = SourceCodeScanner(lang="Python")
        findings = scanner.scan_file(str(f))
        assert len(findings) > 0
        assert any(fn["algorithm"] == "RSA" for fn in findings)


class TestTemporalBinding:
    def test_temporal_bind_and_verify(self, tmp_path):
        from shadow313.v4.temporal_binding.temporal_binding import TemporalBindingEngine
        engine  = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        receipt = engine.bind({"test": "integration"}, session_id="test", module="smoke")
        assert receipt.timestamp % 1000 == 313
        result = engine.verify(receipt.receipt_id)
        assert result["valid"] is True

    def test_temporal_list_receipts(self, tmp_path):
        from shadow313.v4.temporal_binding.temporal_binding import TemporalBindingEngine
        engine = TemporalBindingEngine(receipts_dir=tmp_path, ipfs_enabled=False)
        engine.bind({"a": 1})
        engine.bind({"b": 2})
        receipts = engine.list_receipts()
        assert len(receipts) == 2


class TestSTIXIntegration:
    def test_stix_parse_and_build_roundtrip(self, tmp_path):
        import json
        from shadow313.v4.stix.stix_handler import STIXParser, STIXBuilder

        # Build a bundle from findings
        findings = [{"cve": "CVE-2024-1234", "description": "Test", "cvss_v3": 9.8}]
        builder  = STIXBuilder()
        bundle   = builder.findings_to_bundle(findings, session_id="test")

        # Save to file
        bundle_file = tmp_path / "test_bundle.json"
        bundle_file.write_text(json.dumps(bundle))

        # Parse it back
        parser = STIXParser()
        result = parser.parse_file(str(bundle_file))
        assert "error" not in result
        assert result["object_count"] >= 1


class TestV2RAGModule:
    def test_rag_upsert_and_query(self, tmp_path):
        from shadow313.v2.rag.rag_engine import SecurityKnowledgeBase
        kb = SecurityKnowledgeBase(chroma_path=str(tmp_path / "chroma"))
        kb.upsert("test1", "Apache Log4j remote code execution vulnerability",
                  {"source": "test"}, namespace="cve")
        results = kb.query("Log4j vulnerability", top_k=3)
        assert len(results) >= 1

    def test_rag_stats(self, tmp_path):
        from shadow313.v2.rag.rag_engine import SecurityKnowledgeBase
        kb    = SecurityKnowledgeBase(chroma_path=str(tmp_path / "chroma"))
        stats = kb.stats()
        assert "backend"    in stats
        assert "namespaces" in stats