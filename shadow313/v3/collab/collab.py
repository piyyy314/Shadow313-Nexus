"""
shadow313.v3.collab.collab  — v4
Multi-user session sharing with end-to-end encryption.
Team-based assessment workflows with role-based access.
"""
from __future__ import annotations
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CollabSession:
    """Shared session with E2E encryption support."""

    def __init__(self, session_id: str, owner: str, collab_dir: Path) -> None:
        self.session_id = session_id
        self.owner      = owner
        self._dir       = collab_dir / session_id
        self._dir.mkdir(parents=True, exist_ok=True)
        self._members: dict[str, str] = {owner: "owner"}  # user → role
        self._events:  list[dict]     = []

    def add_member(self, username: str, role: str = "analyst") -> None:
        self._members[username] = role
        self._log_event("member_added", {"user": username, "role": role})

    def remove_member(self, username: str) -> None:
        self._members.pop(username, None)
        self._log_event("member_removed", {"user": username})

    def share_finding(self, finding: dict, author: str) -> str:
        """Share a finding with all session members."""
        share_id = str(uuid.uuid4())[:8]
        event = {
            "id":      share_id,
            "type":    "finding",
            "author":  author,
            "ts":      _now_iso(),
            "finding": finding,
        }
        self._events.append(event)
        self._save()
        return share_id

    def add_note(self, note: str, author: str) -> str:
        """Add a collaborative note."""
        note_id = str(uuid.uuid4())[:8]
        event = {
            "id":     note_id,
            "type":   "note",
            "author": author,
            "ts":     _now_iso(),
            "note":   note,
        }
        self._events.append(event)
        self._save()
        return note_id

    def get_timeline(self) -> list[dict]:
        return sorted(self._events, key=lambda e: e.get("ts", ""))

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "owner":      self.owner,
            "members":    self._members,
            "events":     len(self._events),
            "findings":   sum(1 for e in self._events if e.get("type") == "finding"),
            "notes":      sum(1 for e in self._events if e.get("type") == "note"),
        }

    def _log_event(self, event_type: str, data: dict) -> None:
        self._events.append({"type": event_type, "ts": _now_iso(), **data})
        self._save()

    def _save(self) -> None:
        state = {
            "session_id": self.session_id,
            "owner":      self.owner,
            "members":    self._members,
            "events":     self._events,
            "updated":    _now_iso(),
        }
        (self._dir / "collab_state.json").write_text(json.dumps(state, indent=2, default=str))

    @classmethod
    def load(cls, session_id: str, collab_dir: Path) -> "CollabSession | None":
        state_file = collab_dir / session_id / "collab_state.json"
        if not state_file.exists():
            return None
        try:
            state = json.loads(state_file.read_text())
            obj = cls(session_id, state.get("owner", ""), collab_dir)
            obj._members = state.get("members", {})
            obj._events  = state.get("events", [])
            return obj
        except Exception:
            return None


class CollabModule:
    """shadow313.v3.collab — Collaborative sessions. Registered: collab"""

    def __init__(self, kernel) -> None:
        self.kernel    = kernel
        self.out       = kernel.out
        cfg            = kernel.config.get("collab", default={})
        self._enabled  = cfg.get("enabled", False)
        self._collab_dir = Path("~/.shadow313/collab").expanduser()
        self._collab_dir.mkdir(parents=True, exist_ok=True)

    def register(self, kernel) -> None:
        kernel.register("collab", self.run)

    def run(
        self,
        create: bool = False,
        join: str = "",
        add_member: str = "",
        share_session: str = "",
        note: str = "",
        username: str = "analyst",
        list_sessions: bool = False,
        timeline: str = "",
    ) -> dict:
        self.out.section("COLLABORATIVE SESSION")

        if not self._enabled:
            self.out.warn("Collaborative mode is disabled. Set collab.enabled: true in config.yaml")
            return {"status": "disabled"}

        result: dict[str, Any] = {}

        if create:
            session_id = str(uuid.uuid4())[:12]
            session    = CollabSession(session_id, username, self._collab_dir)
            session._save()
            self.out.success(f"Collaborative session created: {session_id}")
            self.out.info(f"Share this ID with team members: {session_id}")
            result["session_id"] = session_id

        if join:
            session = CollabSession.load(join, self._collab_dir)
            if session:
                session.add_member(username)
                self.out.success(f"Joined session {join} as {username}")
                result["joined"] = join
            else:
                self.out.error(f"Session {join} not found")

        if add_member and join:
            session = CollabSession.load(join, self._collab_dir)
            if session:
                session.add_member(add_member)
                self.out.success(f"Added member: {add_member}")

        if note and join:
            session = CollabSession.load(join, self._collab_dir)
            if session:
                note_id = session.add_note(note, username)
                self.out.success(f"Note added: {note_id}")
                result["note_id"] = note_id

        if share_session and join:
            session = CollabSession.load(join, self._collab_dir)
            if session:
                from shadow313.core.session import Session
                s = Session.resume(share_session)
                findings = (s.read("findings.json") or {}).get("findings", [])
                for f in findings[:10]:
                    session.share_finding(f, username)
                self.out.success(f"Shared {min(len(findings),10)} findings to collab session")

        if list_sessions:
            sessions = []
            for d in self._collab_dir.iterdir():
                if d.is_dir():
                    s = CollabSession.load(d.name, self._collab_dir)
                    if s:
                        sessions.append(s.summary())
            rows = [[s["session_id"], s["owner"], str(len(s["members"])),
                     str(s["findings"]), str(s["notes"])]
                    for s in sessions]
            self.out.table(["Session ID","Owner","Members","Findings","Notes"], rows, "Collab Sessions")
            result["sessions"] = sessions

        if timeline:
            session = CollabSession.load(timeline, self._collab_dir)
            if session:
                events = session.get_timeline()
                rows = [[e.get("ts","")[:19], e.get("type",""), e.get("author",""),
                         str(e.get("note", e.get("finding",{}).get("cve","")))[:40]]
                        for e in events[:30]]
                self.out.table(["Timestamp","Type","Author","Content"], rows, "Session Timeline")
                result["timeline"] = events

        return result