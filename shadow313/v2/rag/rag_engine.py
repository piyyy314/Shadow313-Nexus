"""
shadow313.v2.rag.rag_engine
Feature #2 — RAG Vector Knowledge Base
ChromaDB-backed local vector store ingesting NVD CVEs, MITRE ATT&CK,
OWASP Top 10, and session history. Fully offline, no cloud dependency.
"""
from __future__ import annotations
import json
import hashlib
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import chromadb
    from chromadb.config import Settings
    _HAS_CHROMA = True
except ImportError:
    _HAS_CHROMA = False

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False

# ---------------------------------------------------------------------------
# Lightweight fallback embedding (TF-IDF like cosine) when no sentence-transformers
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> list[str]:
    import re
    return re.findall(r"[a-z0-9]{2,}", text.lower())


def _tfidf_vector(text: str, vocab: dict[str, int], idf: dict[str, float]) -> list[float]:
    tokens = _tokenize(text)
    tf: dict[str, float] = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    n = len(tokens) or 1
    vec = [0.0] * len(vocab)
    for tok, count in tf.items():
        if tok in vocab:
            vec[vocab[tok]] = (count / n) * idf.get(tok, 1.0)
    # L2 normalize
    norm = sum(v * v for v in vec) ** 0.5 or 1.0
    return [v / norm for v in vec]


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na  = sum(x * x for x in a) ** 0.5
    nb  = sum(x * x for x in b) ** 0.5
    return dot / (na * nb + 1e-9)


class _FallbackVectorStore:
    """Pure-Python BM25-style store when ChromaDB is unavailable."""

    def __init__(self) -> None:
        self._docs: list[dict] = []   # {id, text, metadata, vector}
        self._vocab: dict[str, int] = {}
        self._idf: dict[str, float] = {}

    def _rebuild_idf(self) -> None:
        from math import log
        df: dict[str, int] = {}
        N = len(self._docs) or 1
        for doc in self._docs:
            for t in set(_tokenize(doc["text"])):
                df[t] = df.get(t, 0) + 1
        self._idf = {t: log((N + 1) / (d + 1)) + 1 for t, d in df.items()}
        all_tokens = set(self._idf.keys())
        self._vocab = {t: i for i, t in enumerate(sorted(all_tokens))}
        # Recompute all vectors
        for doc in self._docs:
            doc["vector"] = _tfidf_vector(doc["text"], self._vocab, self._idf)

    def add(self, doc_id: str, text: str, metadata: dict) -> None:
        self._docs.append({"id": doc_id, "text": text,
                           "metadata": metadata, "vector": []})
        self._rebuild_idf()

    def query(self, text: str, top_k: int = 5) -> list[dict]:
        if not self._docs:
            return []
        qvec = _tfidf_vector(text, self._vocab, self._idf)
        scored = []
        for doc in self._docs:
            if doc["vector"]:
                score = _cosine(qvec, doc["vector"])
                scored.append((score, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"id": d["id"], "text": d["text"],
                 "metadata": d["metadata"], "score": s}
                for s, d in scored[:top_k]]

    def count(self) -> int:
        return len(self._docs)


# ---------------------------------------------------------------------------
# VectorStore — thin abstraction over ChromaDB or fallback
# ---------------------------------------------------------------------------

class VectorStore:
    """
    Persistent vector store.
    Uses ChromaDB (embedded) when available, falls back to pure-Python TF-IDF.
    Data stored under ~/.shadow313/vectordb/
    """

    def __init__(self, namespace: str = "default",
                 persist_dir: str = "~/.shadow313/vectordb") -> None:
        self.namespace   = namespace
        self.persist_dir = Path(persist_dir).expanduser()
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        if _HAS_CHROMA:
            self._client = chromadb.PersistentClient(
                path=str(self.persist_dir),
                settings=Settings(anonymized_telemetry=False),
            )
            self._col = self._client.get_or_create_collection(
                name=namespace,
                metadata={"hnsw:space": "cosine"},
            )
            self._backend = "chromadb"
        else:
            self._fallback = _FallbackVectorStore()
            self._backend  = "fallback"

    # ------------------------------------------------------------------
    def upsert(self, doc_id: str, text: str, metadata: dict = None, namespace: str = 'default') -> None:
        meta = metadata or {}
        if self._backend == "chromadb":
            self._col.upsert(
                ids=[doc_id],
                documents=[text],
                metadatas=[meta],
            )
        else:
            self._fallback.add(doc_id, text, meta)

    def query(self, text: str, top_k: int = 5,
              where: dict | None = None) -> list[dict]:
        if self._backend == "chromadb":
            kwargs: dict[str, Any] = {
                "query_texts": [text],
                "n_results": min(top_k, max(1, self._col.count())),
                "include": ["documents", "metadatas", "distances"],
            }
            if where:
                kwargs["where"] = where
            try:
                res = self._col.query(**kwargs)
                out = []
                for i, doc in enumerate(res["documents"][0]):
                    out.append({
                        "id":       res["ids"][0][i],
                        "text":     doc,
                        "metadata": res["metadatas"][0][i],
                        "score":    1 - res["distances"][0][i],  # convert distance→similarity
                    })
                return out
            except Exception:
                return []
        else:
            return self._fallback.query(text, top_k)

    def count(self) -> int:
        if self._backend == "chromadb":
            return self._col.count()
        return self._fallback.count()

    def delete(self, doc_id: str) -> None:
        if self._backend == "chromadb":
            try:
                self._col.delete(ids=[doc_id])
            except Exception:
                pass

    @property
    def backend(self) -> str:
        return self._backend


# ---------------------------------------------------------------------------
# SecurityKnowledgeBase — domain-specific ingesters
# ---------------------------------------------------------------------------

class SecurityKnowledgeBase:
    """
    Ingests security knowledge into namespaced vector stores.
    Namespaces: cve, mitre, owasp, session
    """

    NAMESPACES = ["cve", "mitre", "owasp", "session", "general"]

    def __init__(self, persist_dir: str = "~/.shadow313/vectordb", chroma_path: str = None) -> None:
        self._stores: dict[str, VectorStore] = {
            ns: VectorStore(namespace=ns, persist_dir=persist_dir)
            for ns in self.NAMESPACES
        }

    def store(self, ns: str) -> VectorStore:
        return self._stores.get(ns, self._stores["general"])

    # ── Ingesters ──────────────────────────────────────────────────────────
    def ingest_cve_list(self, cves: list[dict]) -> int:
        """Ingest NVD CVE records. Each dict: {id, description, cvss_v3, severity}"""
        store = self._stores["cve"]
        count = 0
        for cve in cves:
            cid   = cve.get("id", cve.get("cve", ""))
            if not cid:
                continue
            desc  = cve.get("description", "")
            text  = f"{cid}: {desc}"
            meta  = {
                "cve_id":   cid,
                "cvss":     str(cve.get("cvss_v3", 0.0)),
                "severity": cve.get("severity", "UNKNOWN"),
                "source":   "nvd",
            }
            store.upsert(_stable_id(text), text, meta)
            count += 1
        return count

    def ingest_mitre_attack(self, techniques: list[dict]) -> int:
        """Ingest MITRE ATT&CK techniques. Each dict: {id, name, description, tactic}"""
        store = self._stores["mitre"]
        count = 0
        for tech in techniques:
            tid  = tech.get("id", "")
            name = tech.get("name", "")
            desc = tech.get("description", "")
            text = f"{tid} {name}: {desc[:500]}"
            meta = {
                "technique_id": tid,
                "name":         name,
                "tactic":       tech.get("tactic", ""),
                "source":       "mitre_attack",
            }
            store.upsert(_stable_id(text), text, meta)
            count += 1
        return count

    def ingest_owasp(self, entries: list[dict]) -> int:
        """Ingest OWASP Top 10 / ASVS entries."""
        store = self._stores["owasp"]
        count = 0
        for entry in entries:
            text = f"{entry.get('id','')} {entry.get('name','')}: {entry.get('description','')[:600]}"
            meta = {"source": "owasp", "id": entry.get("id", "")}
            store.upsert(_stable_id(text), text, meta)
            count += 1
        return count

    def ingest_session_findings(self, session_id: str,
                                findings: list[dict]) -> int:
        """Ingest findings from a Shadow313 session."""
        store = self._stores["session"]
        count = 0
        for f in findings:
            text = json.dumps(f, default=str)[:800]
            meta = {"session_id": session_id, "source": "session"}
            store.upsert(_stable_id(f"{session_id}:{text}"), text, meta)
            count += 1
        return count

    def ingest_text(self, text: str, ns: str = "general",
                    metadata: dict | None = None) -> None:
        """Ingest arbitrary text into a namespace."""
        self._stores.get(ns, self._stores["general"]).upsert(
            _stable_id(text), text, metadata or {}
        )

    # ── Query ──────────────────────────────────────────────────────────────
    def query(self, question: str, namespace: str = "cve",
              top_k: int = 5) -> list[dict]:
        return self._stores.get(namespace,
                                self._stores["general"]).query(question, top_k)

    def query_all(self, question: str, top_k: int = 3) -> list[dict]:
        """Query all namespaces and merge results."""
        results = []
        for ns, store in self._stores.items():
            for r in store.query(question, top_k):
                r["namespace"] = ns
                results.append(r)
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return results[:top_k * 2]

    def upsert(self, doc_id: str, text: str, metadata: dict = None,
               namespace: str = "general") -> None:
        """Upsert a document into the given namespace store."""
        store = self._stores.get(namespace, self._stores.get("general"))
        if store and hasattr(store, 'upsert'):
            store.upsert(doc_id, text, metadata or {})

    def query(self, query_text: str, top_k: int = 5,
              namespace: str = None) -> list:
        """Query across all or specific namespace."""
        results = []
        namespaces = [namespace] if namespace else self.NAMESPACES
        for ns in namespaces:
            store = self._stores.get(ns)
            if store and hasattr(store, 'query'):
                results.extend(store.query(query_text, top_k=top_k))
        results.sort(key=lambda x: -x.get("score", 0))
        return results[:top_k]

    def stats(self) -> dict:
        result = {ns: s.count() for ns, s in self._stores.items()}
        result["backend"] = "tfidf"
        result["namespaces"] = self.NAMESPACES
        return result


def _stable_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# RAGEngine — high-level interface (Feature #2)
# ---------------------------------------------------------------------------

class RAGEngine:
    """
    RAG (Retrieval-Augmented Generation) engine for Shadow313.
    Combines SecurityKnowledgeBase retrieval with Ollama/OpenAI inference.

    Usage:
        rag = RAGEngine(ai_engine, persist_dir="~/.shadow313/vectordb")
        answer = rag.chat_with_context("What CVEs affect Apache 2.4?",
                                        namespace="cve")
    """

    def __init__(self, ai_engine: Any,
                 persist_dir: str = "~/.shadow313/vectordb") -> None:
        self.ai    = ai_engine
        self.kb    = SecurityKnowledgeBase(persist_dir=persist_dir)
        self._hist: list[dict] = []

    # ── Core API ───────────────────────────────────────────────────────────
    def chat_with_context(self, query: str,
                          namespace: str = "cve",
                          top_k: int = 5,
                          max_history: int = 6) -> str:
        """Retrieve relevant context, then answer with AI."""
        # 1. Retrieve
        results = self.kb.query(query, namespace=namespace, top_k=top_k)
        if not results:
            results = self.kb.query_all(query, top_k=top_k)

        context_blocks = []
        for r in results:
            ns    = r.get("namespace", namespace)
            score = r.get("score", 0)
            context_blocks.append(
                f"[{ns.upper()} | score={score:.2f}]\n{r['text']}"
            )
        context_str = "\n\n---\n\n".join(context_blocks)

        # 2. Build conversation with history
        history_str = ""
        if self._hist:
            recent = self._hist[-max_history:]
            history_str = "\n".join(
                f"{'User' if m['role']=='user' else 'Assistant'}: {m['content']}"
                for m in recent
            )

        system_prompt = (
            "You are Shadow313's RAG-powered security analyst. "
            "Use ONLY the retrieved context to answer. "
            "If the context is insufficient, say so explicitly. "
            "Never fabricate CVE IDs, exploit details, or MITRE technique IDs. "
            "Be precise, structured, and actionable."
        )

        history_section = ""
        if history_str:
            history_section = f"CONVERSATION HISTORY:\n{history_str}\n\n"

        user_prompt = (
            f"RETRIEVED CONTEXT:\n{context_str}\n\n"
            f"{history_section}"
            f"QUESTION: {query}"
        )

        # 3. Generate
        answer = self.ai.chat(user_prompt, system_prompt=system_prompt)

        # 4. Update history
        self._hist.append({"role": "user", "content": query})
        self._hist.append({"role": "assistant", "content": answer})

        return answer

    def ingest_cves(self, cves: list[dict]) -> int:
        return self.kb.ingest_cve_list(cves)

    def ingest_mitre(self, techniques: list[dict]) -> int:
        return self.kb.ingest_mitre_attack(techniques)

    def ingest_text(self, text: str, ns: str = "general",
                    meta: dict | None = None) -> None:
        self.kb.ingest_text(text, ns=ns, metadata=meta)

    def ingest_session(self, session_id: str, findings: list[dict]) -> int:
        return self.kb.ingest_session_findings(session_id, findings)

    def stats(self) -> dict:
        return {
            "backend":    self.kb.store("cve").backend,
            "namespaces": self.kb.stats(),
        }

    def clear_history(self) -> None:
        self._hist.clear()


# ---------------------------------------------------------------------------
# Feature #1 — LoRA fine-tune pipeline config generator
# ---------------------------------------------------------------------------

LORA_CONFIG_TEMPLATE = """\
# Shadow313 v2 — LoRA Fine-Tune Config (Unsloth + Ollama)
# =========================================================
# Uses Unsloth for 4-bit QLoRA fine-tuning on security corpus.
# After fine-tuning: convert to GGUF → import into Ollama.
#
# Dataset format: JSONL with {"instruction": ..., "input": ..., "output": ...}
# Recommended base models: mistral-7b, llama-3-8b, phi-3-mini

model_name: "{base_model}"
output_dir: "~/.shadow313/models/shadow313-sec-v1"

# LoRA hyperparameters
lora:
  r: 16                  # LoRA rank (8-64; 16 is a good default)
  alpha: 32              # LoRA alpha (typically 2x rank)
  dropout: 0.05
  target_modules:
    - q_proj
    - k_proj
    - v_proj
    - o_proj
    - gate_proj
    - up_proj
    - down_proj

# 4-bit quantization (QLoRA)
quantization:
  load_in_4bit: true
  bnb_4bit_compute_dtype: "float16"
  bnb_4bit_quant_type: "nf4"

# Training
training:
  max_seq_length: 2048
  per_device_train_batch_size: 2
  gradient_accumulation_steps: 8
  num_train_epochs: 3
  learning_rate: 2.0e-4
  lr_scheduler_type: "cosine"
  warmup_ratio: 0.05
  fp16: true
  logging_steps: 25
  save_steps: 200
  eval_steps: 200
  seed: 42

# Dataset
dataset:
  path: "~/.shadow313/training_data/"
  files:
    - nvd_cves.jsonl          # NVD CVE descriptions + severity
    - exploit_techniques.jsonl # ExploitDB descriptions
    - pentest_reports.jsonl    # Sanitized pentest report fragments
    - mitre_attack.jsonl       # ATT&CK technique descriptions
  train_split: 0.9
  eval_split: 0.1
  max_samples: 50000

# Alpaca-style prompt template
prompt_template: |
  Below is a security task. Respond with precise, actionable information.

  ### Task:
  {{instruction}}

  ### Context:
  {{input}}

  ### Response:
  {{output}}

# GGUF export for Ollama
export:
  format: "gguf"
  quantization: "Q4_K_M"       # Good balance of size and quality
  ollama_model_name: "shadow313-sec:latest"
  ollama_modelfile: |
    FROM ./shadow313-sec-v1.gguf
    SYSTEM "You are Shadow313's embedded AI security analyst. Be precise and never fabricate CVEs."
    PARAMETER temperature 0.3
    PARAMETER top_p 0.9
"""


def generate_finetune_config(base_model: str = "unsloth/mistral-7b-v0.3-bnb-4bit",
                              output_path: str = "~/.shadow313/finetune_config.yaml") -> str:
    """Generate a LoRA fine-tune config and write it to disk."""
    config = LORA_CONFIG_TEMPLATE.format(base_model=base_model)
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config)
    return str(path)


FINETUNE_SCRIPT = '''\
#!/usr/bin/env python3
"""
Shadow313 v2 — LoRA Fine-Tune Script
Requires: pip install unsloth torch transformers datasets trl peft bitsandbytes

Run: python finetune.py --config ~/.shadow313/finetune_config.yaml
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

def load_config(path: str) -> dict:
    try:
        import yaml
        return yaml.safe_load(Path(path).read_text()) or {}
    except ImportError:
        print("[ERROR] pip install pyyaml")
        sys.exit(1)

def main() -> None:
    parser = argparse.ArgumentParser(description="Shadow313 LoRA Fine-Tuner")
    parser.add_argument("--config", required=True, help="Path to finetune_config.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Validate config only")
    args = parser.parse_args()

    cfg = load_config(args.config)
    print(f"[+] Config loaded: {args.config}")
    print(f"[+] Base model: {cfg.get('model_name')}")

    if args.dry_run:
        print("[+] Dry-run complete — config valid.")
        return

    try:
        from unsloth import FastLanguageModel
    except ImportError:
        print("[ERROR] Install unsloth: pip install unsloth")
        sys.exit(1)

    model_name = cfg["model_name"]
    lora_cfg   = cfg.get("lora", {})
    train_cfg  = cfg.get("training", {})
    max_seq    = train_cfg.get("max_seq_length", 2048)

    print(f"[+] Loading {model_name} with 4-bit quantization...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=model_name,
        max_seq_length=max_seq,
        load_in_4bit=cfg.get("quantization", {}).get("load_in_4bit", True),
    )

    model = FastLanguageModel.get_peft_model(
        model,
        r=lora_cfg.get("r", 16),
        lora_alpha=lora_cfg.get("alpha", 32),
        lora_dropout=lora_cfg.get("dropout", 0.05),
        target_modules=lora_cfg.get("target_modules", [
            "q_proj","k_proj","v_proj","o_proj",
            "gate_proj","up_proj","down_proj",
        ]),
        bias="none",
        use_gradient_checkpointing="unsloth",
    )

    from datasets import load_dataset, concatenate_datasets
    dataset_cfg = cfg.get("dataset", {})
    base_path   = Path(dataset_cfg.get("path","~/.shadow313/training_data/")).expanduser()

    splits = []
    for fname in dataset_cfg.get("files", []):
        fpath = base_path / fname
        if fpath.exists():
            ds = load_dataset("json", data_files=str(fpath), split="train")
            splits.append(ds)
            print(f"[+] Loaded {len(ds)} examples from {fname}")
    if not splits:
        print("[WARN] No dataset files found — create JSONL files first.")
        return
    dataset = concatenate_datasets(splits)

    template = cfg.get("prompt_template", "### Task:\\n{instruction}\\n### Response:\\n{output}")
    def fmt(ex):
        prompt = template.format(
            instruction=ex.get("instruction",""),
            input=ex.get("input",""),
            output=ex.get("output",""),
        )
        return {"text": prompt}
    dataset = dataset.map(fmt)

    from trl import SFTTrainer
    from transformers import TrainingArguments

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=max_seq,
        args=TrainingArguments(
            output_dir=str(Path(cfg.get("output_dir","./output")).expanduser()),
            per_device_train_batch_size=train_cfg.get("per_device_train_batch_size",2),
            gradient_accumulation_steps=train_cfg.get("gradient_accumulation_steps",8),
            num_train_epochs=train_cfg.get("num_train_epochs",3),
            learning_rate=train_cfg.get("learning_rate",2e-4),
            fp16=train_cfg.get("fp16",True),
            logging_steps=train_cfg.get("logging_steps",25),
            save_steps=train_cfg.get("save_steps",200),
            seed=train_cfg.get("seed",42),
        ),
    )
    print("[+] Starting fine-tuning...")
    trainer.train()

    out_dir = Path(cfg.get("output_dir","./output")).expanduser()
    model.save_pretrained_gguf(str(out_dir), tokenizer,
        quantization_method=cfg.get("export",{}).get("quantization","q4_k_m"))
    print(f"[+] GGUF saved to {out_dir}")

    ollama_name = cfg.get("export",{}).get("ollama_model_name","shadow313-sec:latest")
    print(f"[+] Import into Ollama: ollama create {ollama_name} -f {out_dir}/Modelfile")

if __name__ == "__main__":
    main()
'''



# ── TFIDFVectorStore ──────────────────────────────────────────────────────────
# Full implementation with namespace support, count(), query() with TF-IDF scoring

import math as _math
import re as _re
from collections import defaultdict as _defaultdict


class TFIDFVectorStore:
    """
    Lightweight TF-IDF vector store with namespace support.
    No external dependencies — pure Python.
    Used as fallback when ChromaDB/FAISS unavailable.
    """

    def __init__(self):
        # {namespace: {doc_id: {"text": str, "metadata": dict, "tfidf": dict}}}
        self._store: dict = _defaultdict(dict)
        self._idf_cache: dict = {}

    def upsert(self, doc_id: str, text: str, metadata: dict = None,
               namespace: str = "default") -> None:
        """Insert or replace a document in the given namespace."""
        self._store[namespace][doc_id] = {
            "text":     text,
            "metadata": metadata or {},
            "tokens":   self._tokenize(text),
        }
        self._idf_cache.clear()  # invalidate IDF cache

    def query(self, query_text: str, top_k: int = 5,
              namespace: str = None) -> list[dict]:
        """Query documents by TF-IDF similarity."""
        query_tokens = self._tokenize(query_text)
        if not query_tokens:
            return []

        results = []
        namespaces = [namespace] if namespace else list(self._store.keys())

        for ns in namespaces:
            docs = self._store.get(ns, {})
            for doc_id, doc in docs.items():
                score = self._tfidf_score(query_tokens, doc["tokens"], ns)
                if score > 0:
                    results.append({
                        "id":       doc_id,
                        "score":    score,
                        "text":     doc["text"],
                        "metadata": doc["metadata"],
                        "namespace": ns,
                    })

        results.sort(key=lambda x: -x["score"])
        # Deduplicate by id
        seen = set()
        deduped = []
        for r in results:
            if r["id"] not in seen:
                seen.add(r["id"])
                deduped.append(r)
        return deduped[:top_k]

    def count(self, namespace: str = None) -> int:
        """Count documents in namespace (or all if None)."""
        if namespace is None:
            return sum(len(docs) for docs in self._store.values())
        return len(self._store.get(namespace, {}))

    def delete(self, doc_id: str, namespace: str = "default") -> bool:
        """Delete a document from namespace."""
        if namespace in self._store and doc_id in self._store[namespace]:
            del self._store[namespace][doc_id]
            self._idf_cache.clear()
            return True
        return False

    def stats(self) -> dict:
        """Return store statistics."""
        return {
            ns: len(docs)
            for ns, docs in self._store.items()
        }

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Simple tokenizer — lowercase, split on non-alphanumeric."""
        return _re.findall(r"[a-z0-9]+", text.lower())

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Compute Shannon entropy of text."""
        if not text:
            return 0.0
        freq = _defaultdict(int)
        for ch in text:
            freq[ch] += 1
        n = len(text)
        return -sum((c/n) * _math.log2(c/n) for c in freq.values() if c > 0)

    def _tfidf_score(self, query_tokens: list, doc_tokens: list,
                     namespace: str) -> float:
        """Compute TF-IDF cosine similarity between query and document."""
        if not doc_tokens:
            return 0.0
        # TF for document
        doc_tf = _defaultdict(int)
        for t in doc_tokens:
            doc_tf[t] += 1
        doc_len = len(doc_tokens)

        # IDF across namespace
        idf = self._get_idf(namespace)

        score = 0.0
        for token in set(query_tokens):
            tf = doc_tf.get(token, 0) / doc_len
            score += tf * idf.get(token, 0)
        return score

    def _get_idf(self, namespace: str) -> dict:
        """Compute IDF for all terms in namespace."""
        if namespace in self._idf_cache:
            return self._idf_cache[namespace]
        docs = self._store.get(namespace, {})
        n = len(docs)
        if n == 0:
            return {}
        df = _defaultdict(int)
        for doc in docs.values():
            for token in set(doc["tokens"]):
                df[token] += 1
        idf = {t: _math.log((n + 1) / (df[t] + 1)) + 1 for t in df}
        self._idf_cache[namespace] = idf
        return idf
