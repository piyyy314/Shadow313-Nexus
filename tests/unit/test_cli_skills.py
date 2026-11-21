from __future__ import annotations

from pathlib import Path

from shadow313.cli.skills import discover_skills, run_skill_command, validate_skill
import argparse


def test_discovers_shadow313_engineering_skill(tmp_path: Path):
    skill = tmp_path / "skills" / "shadow313-nexus-engineer"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: shadow313-nexus-engineer\ndescription: test\n---\n# Engineer\n", encoding="utf-8")
    assert [name for name, _ in discover_skills(tmp_path / "skills")] == ["shadow313-nexus-engineer"]


def test_validation_rejects_path_traversal(tmp_path: Path):
    assert validate_skill("../outside", tmp_path / "skills")


def test_validation_checks_local_references(tmp_path: Path):
    skill = tmp_path / "skills" / "example-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: example-skill\ndescription: test\n---\n# Example\n[missing](usecases/missing.md)\n",
        encoding="utf-8",
    )
    assert any("Broken local reference" in item for item in validate_skill("example-skill", tmp_path / "skills"))


def test_validation_accepts_complete_skill(tmp_path: Path):
    skill = tmp_path / "skills" / "example-skill"
    (skill / "references").mkdir(parents=True)
    (skill / "references" / "guide.md").write_text("# Guide\n", encoding="utf-8")
    (skill / "SKILL.md").write_text(
        "---\nname: example-skill\ndescription: test\n---\n# Example\n[guide](references/guide.md)\n",
        encoding="utf-8",
    )
    assert validate_skill("example-skill", tmp_path / "skills") == []


def test_skill_list_command_outputs_discovered_skill(tmp_path: Path, capsys):
    skill = tmp_path / "skills" / "example-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: example-skill\ndescription: test\n---\n# Example\n", encoding="utf-8")
    args = argparse.Namespace(root=str(tmp_path), action="list")
    assert run_skill_command(args) == 0
    assert "example-skill" in capsys.readouterr().out

def test_main_skill_command_bypasses_kernel(tmp_path: Path, capsys):
    from shadow313.cli.main import main

    skill = tmp_path / "skills" / "example-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\\nname: example-skill\\ndescription: test\\n---\\n# Example\\n",
        encoding="utf-8",
    )
    assert main(["skill", "--root", str(tmp_path), "list"]) == 0
    assert "example-skill" in capsys.readouterr().out


def test_main_skill_validate_all(tmp_path: Path, capsys):
    from shadow313.cli.main import main

    skill = tmp_path / "skills" / "example-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\\nname: example-skill\\ndescription: test\\n---\\n# Example\\n",
        encoding="utf-8",
    )
    assert main(["skill", "--root", str(tmp_path), "validate"]) == 0
    assert "PASS example-skill" in capsys.readouterr().out
