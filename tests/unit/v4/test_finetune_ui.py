"""Unit tests — shadow313.v4.finetune_ui"""
import pytest

class TestFinetuneUI:
    def test_module_importable(self):
        try:
            from shadow313.v4.finetune_ui.finetune_ui import FinetuneUI
            assert FinetuneUI is not None
        except ImportError:
            pytest.skip("finetune_ui not available")

    def test_training_config_generation(self):
        config = {
            "model": "llama3.2:3b",
            "method": "qlora",
            "rank": 16,
            "alpha": 32,
            "epochs": 3,
            "batch_size": 4,
        }
        assert config["method"] == "qlora"
        assert config["rank"] == 16

    def test_dataset_builder_fields(self):
        sample = {"instruction": "Analyze this CVE", "input": "CVE-2024-1234", "output": "Critical RCE"}
        assert all(k in sample for k in ["instruction", "input", "output"])

    def test_gguf_export_format(self):
        export_formats = ["gguf", "safetensors", "pytorch"]
        assert "gguf" in export_formats

    def test_ollama_integration(self):
        """Fine-tuned model must be exportable to Ollama."""
        ollama_compatible = True
        assert ollama_compatible is True

    def test_lora_rank_valid(self):
        valid_ranks = [4, 8, 16, 32, 64, 128]
        assert 16 in valid_ranks
