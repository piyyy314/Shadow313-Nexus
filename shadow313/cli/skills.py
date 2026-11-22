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
    """Return every validly named skill folder, including broken entrypoints."""
    if not root.is_dir():
        return []
    return [
        (entry.name, entry / "SKILL.md")
        for entry in sorted(root.iterdir(), key=lambda path: path.name.casefold())
        if entry.is_dir() and _SKILL_ID.fullmatch(entry.name)
    ]


def _markdown_destination(target: str) -> str:
    """Extract a Markdown destination, excluding an optional quoted title."""
    target = target.strip()
    if target.startswith("<") and ">" in target:
        return target[1 : target.index(">")]
    match = re.match(r"""([^\s]+)(?:\s+["'][^"']*["'])?$""", target)
    return match.group(1) if match else target


def _markdown_link_targets(content: str):
    """Yield Markdown link destinations while respecting escaped and nested parentheses."""
    index = 0
    while index < len(content):
        if content[index] != "[":
            index += 1
            continue
        label_end = index + 1
        while label_end < len(content):
            if content[label_end] == "\\":
                label_end += 2
                continue
            if content[label_end] == "]":
                break
            label_end += 1
        if (
            label_end >= len(content)
            or label_end + 1 >= len(content)
            or content[label_end + 1] != "("
        ):
            index += 1
            continue
        target_start = label_end + 2
        cursor = target_start
        depth = 1
        while cursor < len(content) and depth:
            char = content[cursor]
            if char == "\\":
                cursor += 2
                continue
            if char in ("'", '"') and cursor > target_start and content[cursor - 1].isspace():
                quote_char = char
                cursor += 1
                while cursor < len(content):
                    if content[cursor] == "\\\\":
                        cursor += 2
                        continue
                    if content[cursor] == quote_char:
                        break
                    cursor += 1
                if cursor < len(content):
                    cursor += 1
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            cursor += 1
        if depth == 0:
            yield content[target_start : cursor - 1]
            index = cursor
        else:
            index = target_start


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
    closing_match = re.search(r"(?m)^---[ \t]*$", content[4:])
    if closing_match is None:
        return ["YAML frontmatter is not closed."]

    closing_start = 4 + closing_match.start()
    body_start = 4 + closing_match.end()
    if body_start < len(content) and content[body_start] == "\n":
        body_start += 1

    errors: list[str] = []
    frontmatter = content[4:closing_start]
    fields = set()
    for line in frontmatter.splitlines():
        match = re.match(r"^(name|description):(?:\s|$)", line)
        if match:
            fields.add(match.group(1))
    for required in _REQUIRED_FRONTMATTER:
        if required not in fields:
            errors.append(f"Missing required frontmatter field: {required}")

    if not re.search(r"(?m)^#\s+.+", content[body_start:]):
        errors.append("Missing a top-level Markdown heading.")

    # Validate relative Markdown links without following external URLs or anchors.
    for raw_target in _markdown_link_targets(content):
        target = _markdown_destination(raw_target)
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
