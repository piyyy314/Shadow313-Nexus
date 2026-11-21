from __future__ import annotations

import argparse
from pathlib import Path

from shadow313.cli.skills import (
    discover_skills,
    run_skill_command,
    validate_skill,
)


def _write_skill(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_discovers_shadow313_engineering_skill(tmp_path: Path):
    skill = tmp_path / "skills" / "shadow313-nexus-engineer"
    _write_skill(
        skill / "SKILL.md",
        "---\nname: shadow313-nexus-engineer\ndescription: test\n---\n"
        "# Engineer\n",
    )
    assert [name for name, _ in discover_skills(tmp_path / "skills")] == [
        "shadow313-nexus-engineer"
    ]


def test_validation_rejects_path_traversal(tmp_path: Path):
    assert validate_skill("../outside", tmp_path / "skills")


def test_validation_checks_local_references(tmp_path: Path):
    skill = tmp_path / "skills" / "example-skill"
    _write_skill(
        skill / "SKILL.md",
        "---\nname: example-skill\ndescription: test\n---\n"
        "# Example\n[missing](usecases/missing.md)\n",
    )
    assert any(
        "Broken local reference" in item
        for item in validate_skill("example-skill", tmp_path / "skills")
    )


def test_validation_accepts_complete_skill_and_optional_link_title(tmp_path: Path):
    skill = tmp_path / "skills" / "example-skill"
    _write_skill(skill / "references" / "guide.md", "# Guide\n")
    _write_skill(
        skill / "SKILL.md",
        "---\nname: example-skill\ndescription: test\n---\n"
        "# Example\n[guide](references/guide.md \"Guide\")\n",
    )
    assert validate_skill("example-skill", tmp_path / "skills") == []


def test_validation_requires_top_level_frontmatter_fields(tmp_path: Path):
    skill = tmp_path / "skills" / "example-skill"
    _write_skill(
        skill / "SKILL.md",
        "---\nnotes: |\n  name: nested\n  description: nested\n---\n"
        "# Example\n",
    )
    errors = validate_skill("example-skill", tmp_path / "skills")
    assert "Missing required frontmatter field: name" in errors
    assert "Missing required frontmatter field: description" in errors


def test_validation_reports_invalid_utf8_without_raising(tmp_path: Path):
    skill = tmp_path / "skills" / "example-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_bytes(b"---\nname: bad\n\xff")
    assert any(
        "Unable to read SKILL.md" in item
        for item in validate_skill("example-skill", tmp_path / "skills")
    )


def test_validation_rejects_reference_outside_skill_directory(tmp_path: Path):
    skills_root = tmp_path / "skills"
    skill = skills_root / "example-skill"
    _write_skill(
        skill / "SKILL.md",
        "---\nname: example-skill\ndescription: test\n---\n"
        "# Example\n[outside](../../private.md)\n",
    )
    errors = validate_skill("example-skill", skills_root)
    assert any("escapes skill directory" in item for item in errors)


def test_skill_list_command_outputs_discovered_skill(tmp_path: Path, capsys):
    skill = tmp_path / "skills" / "example-skill"
    _write_skill(
        skill / "SKILL.md",
        "---\nname: example-skill\ndescription: test\n---\n# Example\n",
    )
    args = argparse.Namespace(root=str(tmp_path), action="list")
    assert run_skill_command(args) == 0
    assert "example-skill" in capsys.readouterr().out


def test_main_skill_command_bypasses_kernel(tmp_path: Path, capsys):
    from shadow313.cli.main import main

    skill = tmp_path / "skills" / "example-skill"
    _write_skill(
        skill / "SKILL.md",
        "---\nname: example-skill\ndescription: test\n---\n# Example\n",
    )
    assert main(["skill", "--root", str(tmp_path), "list"]) == 0
    assert "example-skill" in capsys.readouterr().out


def test_main_skill_validate_all(tmp_path: Path, capsys):
    from shadow313.cli.main import main

    skill = tmp_path / "skills" / "example-skill"
    _write_skill(
        skill / "SKILL.md",
        "---\nname: example-skill\ndescription: test\n---\n# Example\n",
    )
    assert main(["skill", "--root", str(tmp_path), "validate"]) == 0
    assert "PASS example-skill" in capsys.readouterr().out
