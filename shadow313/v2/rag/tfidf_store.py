"""shadow313.v2.rag.tfidf_store — Pure-Python TF-IDF fallback vector store."""
from __future__ import annotations
import json
import math
import re
from pathlib import Path
from typing import Any


def _tokenize(text: str) -> list[str]:
    """Tokenise text into lowercase words (alpha + alphanumeric, min 2 chars)."""
    return re.findall(r'\b[a-z0-9][a-z0-9]{1,}\b', text.lower())


def _tfidf(docs: list[list[str]]) -> list[dict[str, float]]:
    N = len(docs)
    df: dict[str, int] = {}
    for doc in docs:
        for term in set(doc):
            df[term] = df.get(term, 0) + 1
    vectors = []
    for doc in docs:
        tf: dict[str, float] = {}
        for term in doc:
            tf[term] = tf.get(term, 0) + 1
        vec = {}
        for term, count in tf.items():
            idf = math.log((N + 1) / (df.get(term, 0) + 1)) + 1
            vec[term] = (count / len(doc)) * idf
        vectors.append(vec)
    return vectors


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    common = set(a) & set(b)
    if not common:
        return 0.0
    dot  = sum(a[t] * b[t] for t in common)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class TFIDFVectorStore:
    """Lightweight TF-IDF vector store — no external dependencies."""

    def __init__(self, store_path: str | None = None) -> None:
        self._docs:     list[dict[str, Any]] = []
        self._vectors:  list[dict[str, float]] = []
        self._store_path = Path(store_path) if store_path else None

    def add(self, text: str, metadata: dict | None = None) -> None:
        self._docs.append({"text": text, "metadata": metadata or {}})
        self._rebuild()

    def add_batch(self, items: list[dict]) -> None:
        for item in items:
            self._docs.append({
                "text":     item.get("text", ""),
                "metadata": item.get("metadata", {}),
            })
        self._rebuild()

    def query(self, text: str, top_k: int = 5) -> list[dict]:
        if not self._docs:
            return []
        q_tokens = _tokenize(text)
        q_vec    = {}
        for term in q_tokens:
            q_vec[term] = q_vec.get(term, 0) + 1
        scores = [(i, _cosine(q_vec, v)) for i, v in enumerate(self._vectors)]
        scores.sort(key=lambda x: x[1], reverse=True)
        results = []
        for i, score in scores[:top_k]:
            if score > 0:
                results.append({
                    "text":     self._docs[i]["text"],
                    "metadata": self._docs[i]["metadata"],
                    "score":    round(score, 4),
                })
        return results

    def save(self) -> None:
        if self._store_path:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._store_path, "w") as fh:
                json.dump(self._docs, fh)

    def load(self) -> None:
        if self._store_path and self._store_path.exists():
            with open(self._store_path) as fh:
                self._docs = json.load(fh)
            self._rebuild()

    def _rebuild(self) -> None:
        tokenized    = [_tokenize(d["text"]) for d in self._docs]
        self._vectors = _tfidf(tokenized) if tokenized else []

    def count(self) -> int:
        return len(self._docs)