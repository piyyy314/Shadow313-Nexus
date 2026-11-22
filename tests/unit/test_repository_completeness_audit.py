from __future__ import annotations

import ast

from scripts.repository_completeness_audit import (
    AUTH_HINT_RE,
    DEFAULT_SOURCE_ROOTS,
    AuditState,
    route_has_auth_hint,
    scan_packaging,
    scan_text,
)


def test_route_auth_hint_is_scoped_to_each_function():
    source = '''
@app.get("/public")
def public_route():
    return {"ok": True}

@app.get("/private")
def private_route(user=Depends(get_user)):
    return {"ok": True}
'''
    tree = ast.parse(source)
    routes = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    lines = source.splitlines()

    assert route_has_auth_hint(routes[0], lines) is False
    assert route_has_auth_hint(routes[1], lines) is True


def test_continue_on_error_is_a_review_warning_not_automatic_failure(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "example.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("jobs:\n  scan:\n    continue-on-error: true\n", encoding="utf-8")
    state = AuditState(root=tmp_path, out=tmp_path / "audit-results")
    state.files = [workflow]

    scan_text(state)

    ci_findings = [finding for finding in state.findings if finding.category == "ci"]
    assert ci_findings
    assert all(finding.severity == "WARN" for finding in ci_findings)


def test_audit_source_roots_cover_scripts_and_operational_subsystems():
    assert {"scripts", "tools", "ghost-watch-terminal", "migrations", "infra", "ollama"} <= set(DEFAULT_SOURCE_ROOTS)


def test_packaging_audit_reports_missing_python_lock_and_coverage_floor(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'sample'\n", encoding="utf-8")
    state = AuditState(root=tmp_path, out=tmp_path / "audit-results")

    scan_packaging(state)

    messages = {finding.message for finding in state.findings}
    assert "No Python dependency lockfile found" in messages
    assert "No minimum coverage threshold is configured" in messages


def test_auth_hint_regex_is_compiled():
    assert AUTH_HINT_RE.search("Depends(get_user)")
