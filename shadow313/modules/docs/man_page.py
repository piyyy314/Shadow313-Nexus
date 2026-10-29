"""shadow313.modules.docs.man_page — troff man page generator."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path


def generate_man_page(module: str, doc: dict) -> str:
    """Return troff source for a module's manual page using its documentation mapping.

    Include flags and at most five command examples.
    """
    date = datetime.now(timezone.utc).strftime("%B %Y")
    lines = [
        f'.TH "SHADOW313-{module.upper()}" "1" "{date}" "shadow313 2.0.0" "Shadow313 Manual"',
        ".SH NAME",
        f"shadow313-{module} \\- {doc.get('title', module)}",
        ".SH SYNOPSIS",
        f".B shadow313 {module}",
        "[OPTIONS]",
        ".SH DESCRIPTION",
        f".P\n{doc.get('description', '')}",
        ".SH OPTIONS",
    ]
    for flag, desc in doc.get("flags", {}).items():
        lines.append(f".TP\n.B {flag}\n{desc}")
    lines.append(".SH EXAMPLES")
    for cmd, desc in doc.get("commands", [])[:5]:
        lines.append(f".PP\n{desc}:\n.nf\n{cmd}\n.fi")
    return "\n".join(lines)


def write_man_pages(module_docs: dict, output_dir: str = ".") -> list[str]:
    """Write section-1 pages under output_dir/man and return their path strings.

    Create directories and replace existing pages. File I/O errors propagate.
    """
    base = Path(output_dir) / "man"
    base.mkdir(parents=True, exist_ok=True)
    written = []
    for module, doc in module_docs.items():
        man = generate_man_page(module, doc)
        path = base / f"shadow313-{module}.1"
        path.write_text(man)
        written.append(str(path))
    return written