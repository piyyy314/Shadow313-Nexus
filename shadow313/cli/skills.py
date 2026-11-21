"""Local discovery and structural validation for packaged Shadow313 skills.

This module intentionally uses only the Python standard library so the skill
commands work without booting the full NEXUS kernel or optional AI services.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_SKILL_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_REQUIRED_FRONTMATTER = ("name", "description")
_MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def find_skills_root(explicit_root: str | None = None) -> Path:
    """Locate a skills/ directory without assuming the current working directory."""
    if explicit_root:
        candidate = Path(explicit_root).expanduser().resolve()
        if candidate.name != "skills":
            candidate = candidate / "skills"
        return candidate

    candidates = [Path.cwd(), *Path(__file__).resolve().parents]
    seen: set[Path] = set()
    for base in candidates:
        base = base.resolve()
        if base in seen:
            continue
        seen.add(base)
        candidate = base / "skills"
        if candidate.is_dir():
            return candidate
    return Path.cwd() / "skills"


def discover_skills(root: Path) -> list[tuple[str, Path]]:
    """Return validly named skill folders containing a SKILL.md entrypoint."""
    if not root.is_dir():
        return []
    found = []
    for entry in sorted(root.iterdir(), key=lambda path: path.name.casefold()):
        if entry.is_dir() and _SKILL_ID.fullmatch(entry.name):
            entrypoint = entry / "SKILL.md"
            if entrypoint.is_file():
                found.append((entry.name, entrypoint))
    return found


def _markdown_destination(target: str) -> str:
    """Extract a Markdown destination, excluding an optional quoted title."""
    target = target.strip()
    if target.startswith("<") and ">" in target:
        return target[1 : target.index(">")]
    match = re.match(r"""([^\s]+)(?:\s+["'][^"']*["'])?$""", target)
    return match.group(1) if match else target


def validate_skill(skill_id: str, root: Path) -> list[str]:
    """Return structural validation errors; an empty list means checks passed."""
    if not _SKILL_ID.fullmatch(skill_id):
        return ["Invalid skill ID. Use lowercase letters, digits, and hyphens."]

    resolved_root = root.resolve()
    entrypoint = (resolved_root / skill_id / "SKILL.md").resolve()
    try:
        entrypoint.relative_to(resolved_root)
    except ValueError:
        return ["Skill path escapes the skills directory."]
    if not entrypoint.is_file():
        return [f"Missing entrypoint: {entrypoint}"]

    try:
        content = entrypoint.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"Unable to read SKILL.md: {exc}"]

    if not content.startswith("---\n"):
        return ["SKILL.md must begin with YAML frontmatter (---)."]
    closing = content.find("\n---", 4)
    if closing < 0:
        return ["YAML frontmatter is not closed."]

    errors: list[str] = []
    frontmatter = content[4:closing]
    fields = set()
    for line in frontmatter.splitlines():
        match = re.match(r"^(name|description):(?:\s|$)", line)
        if match:
            fields.add(match.group(1))
    for required in _REQUIRED_FRONTMATTER:
        if required not in fields:
            errors.append(f"Missing required frontmatter field: {required}")

    if not re.search(r"(?m)^#\s+.+", content[closing + 4 :]):
        errors.append("Missing a top-level Markdown heading.")

    # Validate relative Markdown links without following external URLs or anchors.
    for match in _MARKDOWN_LINK.finditer(content):
        target = _markdown_destination(match.group(1))
        if not target or target.startswith(("https://", "http://", "mailto:", "#")):
            continue
        relative = target.split("#", 1)[0].split("?", 1)[0]
        if not relative:
            continue
        linked_path = (entrypoint.parent / relative).resolve()
        try:
            linked_path.relative_to(entrypoint.parent.resolve())
        except ValueError:
            errors.append(f"Local reference escapes skill directory: {target}")
            continue
        if not linked_path.is_file():
            errors.append(f"Broken local reference: {target}")
    return errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadow313 skill",
        description="Discover and validate local OmniSkills.",
    )
    parser.add_argument(
        "--root",
        help="Repository root or skills/ directory (auto-detected by default).",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list", help="List installed repository skills.")
    show = sub.add_parser("show", help="Display a skill's entrypoint.")
    show.add_argument("skill_id")
    validate = sub.add_parser(
        "validate",
        help="Validate skill metadata and local references.",
    )
    validate.add_argument(
        "skill_id",
        nargs="?",
        help="Skill ID; omit to validate every discovered skill.",
    )
    return parser


def run_skill_command(args: argparse.Namespace) -> int:
    root = find_skills_root(args.root)
    if args.action == "list":
        skills = discover_skills(root)
        if not skills:
            print(f"No skills found under {root}")
            return 0
        print(f"Shadow313 skills ({len(skills)}) — {root}")
        for skill_id, _ in skills:
            print(f"  • {skill_id}")
        return 0

    if args.action == "show":
        if not _SKILL_ID.fullmatch(args.skill_id):
            print("Invalid skill ID.", file=sys.stderr)
            return 2
        entrypoint = (root / args.skill_id / "SKILL.md").resolve()
        try:
            entrypoint.relative_to(root.resolve())
        except ValueError:
            print("Skill path escapes the skills directory.", file=sys.stderr)
            return 2
        if not entrypoint.is_file():
            print(f"Skill not found: {args.skill_id}", file=sys.stderr)
            return 1
        try:
            print(entrypoint.read_text(encoding="utf-8"), end="")
        except (OSError, UnicodeError) as exc:
            print(f"Unable to read SKILL.md: {exc}", file=sys.stderr)
            return 1
        return 0

    targets = [args.skill_id] if args.skill_id else [item[0] for item in discover_skills(root)]
    if not targets:
        print(f"No skills found under {root}")
        return 1
    failed = False
    for skill_id in targets:
        errors = validate_skill(skill_id, root)
        if errors:
            failed = True
            print(f"FAIL {skill_id}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS {skill_id}")
    return 1 if failed else 0
