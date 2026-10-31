"""Optional Chroma adapter and coarse-clock event regressions, fully offline."""

from types import SimpleNamespace

import pytest

from shadow313.v2.rag import rag_engine
from shadow313.v4.core.event_bus import Event


@pytest.mark.parametrize("metadata", [None, {}, {"source": "fixture"}])
def test_chroma_upsert_omits_absent_metadata(tmp_path, monkeypatch, metadata):
    calls = []

    class Collection:
        def upsert(self, **kwargs):
            if "metadatas" in kwargs and any(not value for value in kwargs["metadatas"]):
                raise ValueError("Expected metadata to be a non-empty dict")
            calls.append(kwargs)

    collection = Collection()
    client = SimpleNamespace(get_or_create_collection=lambda **kwargs: collection)
    monkeypatch.setattr(rag_engine, "_HAS_CHROMA", True)
    monkeypatch.setattr(
        rag_engine, "chromadb", SimpleNamespace(PersistentClient=lambda **kw: client), raising=False
    )
    monkeypatch.setattr(rag_engine, "Settings", lambda **kwargs: kwargs, raising=False)
    store = rag_engine.VectorStore(persist_dir=str(tmp_path))
    store.upsert("fixture-id", "fixture text", metadata)
    assert calls[0]["ids"] == ["fixture-id"]
    assert calls[0]["documents"] == ["fixture text"]
    if metadata:
        assert calls[0]["metadatas"] == [metadata]
    else:
        assert "metadatas" not in calls[0]


def test_chroma_results_normalize_absent_metadata(monkeypatch):
    store = rag_engine.VectorStore.__new__(rag_engine.VectorStore)
    store._backend = "chromadb"
    store._col = SimpleNamespace(
        count=lambda: 1,
        query=lambda **kw: {
            "documents": [["text"]],
            "ids": [["id"]],
            "metadatas": [[None]],
            "distances": [[0.1]],
        },
    )
    assert store.query("text")[0]["metadata"] == {}


def test_chroma_path_alias_is_used(tmp_path, monkeypatch):
    monkeypatch.setattr(rag_engine, "_HAS_CHROMA", False)
    path = tmp_path / "isolated-store"
    kb = rag_engine.SecurityKnowledgeBase(chroma_path=str(path))
    assert all(store.persist_dir == path for store in kb._stores.values())


def test_event_ids_remain_unique_with_frozen_clock(monkeypatch):
    monkeypatch.setattr("time.time_ns", lambda: 123456789)
    events = [Event(topic="fixture", payload=i) for i in range(1000)]
    assert len({event.event_id for event in events}) == 1000
    assert all(event.event_id.startswith("evt-") for event in events)
    assert Event(topic="fixture", payload={}, event_id="external-id").event_id == "external-id"


def test_event_ids_do_not_depend_on_clock_across_threads(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr("time.time_ns", lambda: 42)
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(lambda i: Event(topic="fixture", payload=i).event_id, range(1000)))
    assert len(set(ids)) == 1000
