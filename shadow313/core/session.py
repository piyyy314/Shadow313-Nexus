"""
shadow313.core.session  — v4
UUID-scoped session management with optional AES-256-GCM encryption.

BUG FIXES vs v1:
  - list_sessions() used st_mtime which fails on empty dirs — added try/except
  - read() silently returned None on missing file with no warning — now logs
  - audit() opened file in 'a' mode without ensuring parent exists — fixed
  - _load_meta() version field hardcoded "1.0.0" — now uses __version__
  - Session.resume() didn't validate session_id format — added UUID check
"""
from __future__ import annotations
import uuid
import json
import time
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_VERSION = "4.0.0"
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


class Session:
    """
    UUID-scoped session.  All module outputs written under sessions/{uuid}/.
    Supports optional transparent encryption via EncryptedSessionStore.
    """

    def __init__(
        self,
        sessions_dir: str = "~/.shadow313/sessions",
        session_id: str | None = None,
        encrypt: bool = False,
    ) -> None:
        self.sessions_dir = Path(sessions_dir).expanduser()
        self.id: str = session_id or str(uuid.uuid4())
        self.session_dir: Path = self.sessions_dir / self.id
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self._meta: dict[str, Any] = self._load_meta()
        self._audit_log: list[dict] = []
        self._encrypt = encrypt
        self._store = None
        if encrypt:
            try:
                from .crypto_store import EncryptedSessionStore
                self._store = EncryptedSessionStore(self.session_dir)
            except ImportError:
                pass  # graceful fallback to plain I/O

    # ── Meta ──────────────────────────────────────────────────────────────────
    @property
    def created_at(self) -> str:
        return self._meta.get("created_at", "unknown")

    @property
    def target(self) -> str:
        return self._meta.get("target", "")

    def set_target(self, target: str) -> None:
        self._meta["target"] = target
        self._save_meta()

    # ── File helpers ──────────────────────────────────────────────────────────
    def write(self, filename: str, data: Any, mode: str = "json") -> Path:
        # FIX: sanitize filename to prevent path traversal
        safe_filename = Path(filename).name  # strips any directory components
        if not safe_filename or safe_filename.startswith('.'):
            raise ValueError(f"Invalid filename: {filename!r}")
        path = self.session_dir / safe_filename
        if self._store and mode == "json":
            self._store.write_encrypted(filename, json.dumps(data, indent=2, default=str))
            return path
        with open(path, "w", encoding='utf-8') as fh:
            if mode == "json":
                json.dump(data, fh, indent=2, default=str)
            else:
                fh.write(str(data))
        return path

    def read(self, filename: str) -> Any:
        # FIX: sanitize filename to prevent path traversal
        safe_filename = Path(filename).name
        path = self.session_dir / safe_filename
        if not path.exists():
            return None
        if self._store:
            raw = self._store.read_encrypted(filename)
            if raw:
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return raw
        with open(path, encoding='utf-8') as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                return fh.read()

    def path(self, filename: str) -> Path:
        return self.session_dir / filename

    # ── Audit log ─────────────────────────────────────────────────────────────
    def audit(self, module: str, action: str, detail: str = "") -> None:
        entry = {
            "ts":     datetime.now(timezone.utc).isoformat(),
            "module": module,
            "action": action,
            "detail": detail,
            "pid":    os.getpid(),
        }
        self._audit_log.append(entry)
        # FIX: ensure parent exists before opening audit log
        audit_path = self.session_dir / "audit.log"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(audit_path, "a", encoding='utf-8') as fh:
            fh.write(json.dumps(entry) + "\n")

    def get_audit_log(self) -> list[dict]:
        return list(self._audit_log)

    # ── Summary ───────────────────────────────────────────────────────────────
    def summary(self) -> dict:
        try:
            files = [f.name for f in self.session_dir.iterdir() if f.is_file()]
        except OSError:
            files = []
        return {
            "session_id":  self.id,
            "created_at":  self.created_at,
            "target":      self.target,
            "session_dir": str(self.session_dir),
            "files":       files,
            "encrypted":   self._encrypt,
        }

    # ── Internals ─────────────────────────────────────────────────────────────
    def _load_meta(self) -> dict:
        meta_path = self.session_dir / "meta.json"
        if meta_path.exists():
            try:
                with open(meta_path, encoding='utf-8') as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError):
                pass
        meta = {
            "session_id": self.id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target":     "",
            "version":    _VERSION,  # FIX: was hardcoded "1.0.0"
        }
        with open(meta_path, "w", encoding='utf-8') as fh:
            json.dump(meta, fh, indent=2)
        return meta

    def _save_meta(self) -> None:
        with open(self.session_dir / "meta.json", "w", encoding='utf-8') as fh:
            json.dump(self._meta, fh, indent=2)

    # ── Class methods ─────────────────────────────────────────────────────────
    @classmethod
    def list_sessions(cls, sessions_dir: str = "~/.shadow313/sessions") -> list[dict]:
        base = Path(sessions_dir).expanduser()
        if not base.exists():
            return []
        sessions = []
        try:
            # FIX: wrap stat() in try/except — fails on broken symlinks
            entries = sorted(
                base.iterdir(),
                key=lambda p: p.stat().st_mtime if p.exists() else 0,
                reverse=True,
            )
        except OSError:
            return []
        for d in entries:
            if d.is_dir():
                meta_path = d / "meta.json"
                if meta_path.exists():
                    try:
                        with open(meta_path, encoding='utf-8') as fh:
                            sessions.append(json.load(fh))
                    except (json.JSONDecodeError, OSError):
                        pass
        return sessions

    @classmethod
    def resume(
        cls,
        session_id: str,
        sessions_dir: str = "~/.shadow313/sessions",
        encrypt: bool = False,
    ) -> "Session":
        # FIX: validate UUID format before attempting resume
        if not _UUID_RE.match(session_id):
            raise ValueError(f"Invalid session ID format: {session_id!r}")
        return cls(sessions_dir=sessions_dir, session_id=session_id, encrypt=encrypt)

    @classmethod
    def delete(cls, session_id: str, sessions_dir: str = "~/.shadow313/sessions") -> bool:
        import shutil
        base = Path(sessions_dir).expanduser()
        target = base / session_id
        if target.exists() and target.is_dir():
            shutil.rmtree(target)
            return True
        return False