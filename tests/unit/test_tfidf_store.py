"""The standalone add/query TF-IDF store, distinct from rag_engine's upsert store."""

import math

import pytest

from shadow313.v2.rag.tfidf_store import TFIDFVectorStore, _cosine, _tfidf, _tokenize


def test_tokenization_handles_identifiers_punctuation_and_minimum_length():
    assert _tokenize("A CVE-2026-12345: SHA256, RCE! x 12") == [
        "cve",
        "2026",
        "12345",
        "sha256",
        "rce",
        "12",
    ]
    assert _tokenize("?! x") == []


def test_tfidf_uses_document_frequency_and_handles_empty_documents():
    vectors = _tfidf([["shared", "shared", "rare"], ["shared"], []])
    assert vectors[0]["shared"] == pytest.approx(2 / 3 * (math.log(4 / 3) + 1))
    assert vectors[0]["rare"] == pytest.approx(1 / 3 * (math.log(4 / 2) + 1))
    assert vectors[2] == {}
    assert _tfidf([]) == []


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ({}, {}, 0),
        ({"a": 1}, {"b": 1}, 0),
        ({"a": 0}, {"a": 1}, 0),
        ({"a": 1, "b": 1}, {"a": 1}, 1 / math.sqrt(2)),
        ({"a": 2}, {"a": 5}, 1),
    ],
)
def test_cosine_similarity_boundaries(left, right, expected):
    assert _cosine(left, right) == pytest.approx(expected)


def test_query_ranks_matches_filters_zero_scores_and_honors_top_k():
    store = TFIDFVectorStore()
    store.add_batch(
        [
            {"text": "remote execution", "metadata": {"id": "exact"}},
            {"text": "remote monitoring storage", "metadata": {"id": "partial"}},
            {"text": "unrelated certificates", "metadata": {"id": "other"}},
            {},
        ]
    )
    results = store.query("remote execution", top_k=10)
    assert [r["metadata"]["id"] for r in results] == ["exact", "partial"]
    assert results[0]["score"] > results[1]["score"] > 0
    assert all(0 <= r["score"] <= 1 for r in results)
    assert len(store.query("remote", top_k=1)) == 1
    assert store.query("remote", top_k=0) == []
    assert store.query("absentword") == []
    assert store.query("") == []


def test_add_rebuilds_vectors_and_tied_matches_preserve_insertion_order():
    store = TFIDFVectorStore()
    assert store.query("security") == []
    store.add("security", {"id": 1})
    assert store.query("security")[0]["metadata"] == {"id": 1}
    store.add("security", {"id": 2})
    store.add("", {"id": 3})
    assert [r["metadata"]["id"] for r in store.query("security")] == [1, 2]
    assert store.count() == 3


def test_save_load_round_trip_rebuilds_searchable_vectors(tmp_path):
    path = tmp_path / "nested/store.json"
    store = TFIDFVectorStore(str(path))
    store.load()
    assert store.count() == 0
    store.add("vulnerability remediation", {"source": "synthetic"})
    before = store.query("remediation")
    store.save()
    restored = TFIDFVectorStore(str(path))
    restored.load()
    assert restored.count() == 1
    assert restored.query("remediation") == before
    restored.add("network anomaly")
    assert restored.count() == 2
    assert restored.query("network")[0]["text"] == "network anomaly"


def test_persistence_without_path_is_optional():
    store = TFIDFVectorStore()
    store.add("local data")
    store.save()
    store.load()
    assert store.count() == 1
