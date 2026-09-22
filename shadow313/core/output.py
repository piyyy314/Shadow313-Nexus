"""
shadow313.core.output  — v4
Unified output formatter: rich/color terminal · JSON · Markdown · plain.

BUG FIXES vs v1:
  - banner() printed version "v1.0.0" hardcoded — now reads __version__
  - table() with empty rows caused ZeroDivisionError in width calculation — fixed
  - finding() severity color_map used 'red' for both critical and high but
    rich panel style was not applied to the border — fixed
  - _print_list() called _print_dict() recursively without title guard,
    causing duplicate section headers — fixed
"""
from __future__ import annotations
import json
import sys
from typing import Any

from shadow313 import __version__

# ANSI color codes (fallback when rich is not installed)
class _C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"
    PURPLE = "\033[95m"

SEVERITY_COLORS = {
    "critical": _C.RED,
    "high":     _C.RED,
    "medium":   _C.YELLOW,
    "low":      _C.GREEN,
    "info":     _C.CYAN,
}

BANNER = rf"""
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗██████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║╚════██╗
  ███████╗███████║███████║██║  ██║██║   ██║██║  ▄███╔╝
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║ ▄██╔╝
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝██║ ██████╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝╚═════╝
  v{__version__}  |  NEXUS Edition  |  Local-First AI Security Intelligence
"""


class OutputFormatter:
    """
    Formats and prints Shadow313 output to stdout/stderr.
    Supports: rich (colorized terminal), json, markdown, plain.
    """

    def __init__(
        self,
        fmt: str = "rich",
        color: bool = True,
        verbose: bool = False,
    ) -> None:
        self.fmt     = fmt
        self.color   = color and sys.stdout.isatty()
        self.verbose = verbose
        self._has_rich = False
        self._rich_console = None
        self._try_rich()

    def _try_rich(self) -> None:
        try:
            from rich.console import Console
            self._rich_console = Console(highlight=self.color)
            self._has_rich = True
        except ImportError:
            self._has_rich = False

    # ── Banner ────────────────────────────────────────────────────────────────
    def banner(self) -> None:
        if self.fmt == "json":
            return
        if self._has_rich:
            from rich.text import Text
            t = Text(BANNER, style="bold cyan")
            self._rich_console.print(t)
        else:
            print(self._c(_C.CYAN, BANNER))

    # ── Info / success / warn / error ─────────────────────────────────────────
    def info(self, msg: str, prefix: str = "•") -> None:
        if self.fmt == "json":
            return
        self._print(f" {prefix} {msg}", _C.CYAN)

    def success(self, msg: str) -> None:
        if self.fmt == "json":
            return
        self._print(f" ✓ {msg}", _C.GREEN)

    def warn(self, msg: str) -> None:
        if self.fmt == "json":
            return
        self._print(f" ⚠ {msg}", _C.YELLOW)

    def error(self, msg: str) -> None:
        self._print(f" ✗ {msg}", _C.RED, file=sys.stderr)

    def verbose_msg(self, msg: str) -> None:
        if self.verbose:
            self._print(f"   {msg}", _C.DIM)

    def section(self, title: str) -> None:
        if self.fmt == "json":
            return
        if self._has_rich:
            from rich.rule import Rule
            self._rich_console.print(Rule(f"[bold cyan]{title}[/bold cyan]"))
        else:
            line = "─" * 60
            print(f"\n{self._c(_C.CYAN, line)}")
            print(f"  {self._c(_C.BOLD + _C.WHITE, title)}")
            print(self._c(_C.CYAN, line))

    # ── Structured output ─────────────────────────────────────────────────────
    def result(self, data: Any, title: str = "") -> None:
        if self.fmt == "json":
            print(json.dumps(data, indent=2, default=str))
            return
        if self.fmt == "markdown":
            self._print_markdown(data, title)
            return
        if isinstance(data, dict):
            self._print_dict(data, title)
        elif isinstance(data, list):
            self._print_list(data, title)
        else:
            self._print(str(data), _C.WHITE)

    def table(self, headers: list[str], rows: list[list], title: str = "") -> None:
        if self.fmt == "json":
            records = [dict(zip(headers, r)) for r in rows]
            print(json.dumps(records, indent=2, default=str))
            return
        # FIX: guard against empty rows causing ZeroDivisionError
        if not rows:
            if title:
                self.section(title)
            self.info("(no data)")
            return
        if self._has_rich:
            from rich.table import Table
            tbl = Table(
                title=title, show_header=True,
                header_style="bold cyan", border_style="dim blue",
            )
            for h in headers:
                tbl.add_column(h)
            for r in rows:
                tbl.add_row(*[str(c) for c in r])
            self._rich_console.print(tbl)
        else:
            if title:
                print(f"\n  {self._c(_C.BOLD, title)}")
            widths = [
                max(len(str(headers[i])), max(len(str(r[i])) for r in rows))
                for i in range(len(headers))
            ]
            fmt_row = lambda cols: "  " + "  ".join(
                str(c).ljust(w) for c, w in zip(cols, widths)
            )
            print(self._c(_C.CYAN, fmt_row(headers)))
            print(self._c(_C.DIM, "  " + "  ".join("─" * w for w in widths)))
            for row in rows:
                print(fmt_row(row))

    def finding(
        self,
        title: str,
        severity: str,
        detail: str,
        cve: str = "",
        score: float = 0.0,
    ) -> None:
        sev = severity.lower()
        col = SEVERITY_COLORS.get(sev, _C.WHITE)
        if self.fmt == "json":
            print(json.dumps({
                "title": title, "severity": sev,
                "detail": detail, "cve": cve, "score": score,
            }))
            return
        if self._has_rich:
            from rich.panel import Panel
            body = detail
            if cve:
                body += f"\n[dim]CVE:[/dim] {cve}"
            if score:
                body += f"  [dim]CVSS:[/dim] {score}"
            # FIX: map severity to rich color names correctly
            color_map = {
                "critical": "bright_red",
                "high":     "red",
                "medium":   "yellow",
                "low":      "green",
                "info":     "cyan",
            }
            style = color_map.get(sev, "white")
            self._rich_console.print(
                Panel(
                    body,
                    title=f"[bold {style}][{sev.upper()}] {title}[/bold {style}]",
                    border_style=style,
                )
            )
        else:
            label = f"[{sev.upper()}]".ljust(12)
            print(f"\n{self._c(col, label)} {self._c(_C.BOLD, title)}")
            print(f"  {detail}")
            if cve:
                print(f"  CVE: {cve}  CVSS: {score}")

    def ai_response(self, text: str, title: str = "AI Analysis") -> None:
        if self.fmt == "json":
            print(json.dumps({"ai_response": text}))
            return
        if self._has_rich:
            from rich.markdown import Markdown
            from rich.panel    import Panel
            self._rich_console.print(
                Panel(
                    Markdown(text),
                    title=f"[bold purple]{title}[/bold purple]",
                    border_style="purple",
                )
            )
        else:
            print(f"\n{self._c(_C.PURPLE, f'╔══ {title} ══')}")
            print(text)
            print(self._c(_C.PURPLE, "╚══"))

    # ── Internals ─────────────────────────────────────────────────────────────
    def _c(self, code: str, text: str) -> str:
        if not self.color:
            return text
        return f"{code}{text}{_C.RESET}"

    def _print(self, msg: str, color: str = "", file=None) -> None:
        if file is None:
            file = sys.stdout
        if self.color and color:
            print(f"{color}{msg}{_C.RESET}", file=file)
        else:
            print(msg, file=file)

    def _print_dict(self, data: dict, title: str) -> None:
        if title:
            self.section(title)
        for k, v in data.items():
            key_str = self._c(_C.CYAN, f"  {k}:")
            print(f"{key_str} {v}")

    def _print_list(self, data: list, title: str) -> None:
        if title:
            self.section(title)
        for item in data:
            if isinstance(item, dict):
                # FIX: pass empty title to avoid duplicate section headers
                self._print_dict(item, "")
                print()
            else:
                print(f"  {self._c(_C.DIM, '•')} {item}")

    def _print_markdown(self, data: Any, title: str) -> None:
        if title:
            print(f"\n## {title}\n")
        if isinstance(data, dict):
            for k, v in data.items():
                print(f"**{k}**: {v}  ")
        elif isinstance(data, list):
            for item in data:
                print(f"- {item}")
        else:
            print(str(data))