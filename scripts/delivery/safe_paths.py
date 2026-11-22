"""Safe path resolution for local delivery HTTP handlers."""

from pathlib import Path
from urllib.parse import unquote


def safe_docs_path(docs_root: Path, requested_path: str) -> Path | None:
    """Resolve a request path strictly beneath docs_root, rejecting traversal."""
    decoded = unquote(requested_path)
    if not decoded or "\x00" in decoded or "\\" in decoded:
        return None

    relative = Path(decoded)
    if relative.is_absolute() or not relative.parts:
        return None
    if any(part in {"", ".", ".."} for part in relative.parts):
        return None

    root = Path(docs_root).resolve()
    try:
        candidate = (root / relative).resolve()
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate
