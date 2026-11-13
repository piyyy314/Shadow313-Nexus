from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_postgresql_migration_generates_complete_offline_ddl():
    repository = Path(__file__).resolve().parents[2]
    config = repository / "alembic-shiatoali.ini"
    environment = os.environ.copy()
    environment["SHIAATOALI_DATABASE_URL"] = (
        "postgresql+psycopg://migration-test:unused@localhost/shadow313_test"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(config),
            "upgrade",
            "head",
            "--sql",
        ],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    for table in (
        "shiatoali_events",
        "shiatoali_alerts",
        "shiatoali_cases",
        "shiatoali_case_alerts",
        "shiatoali_case_activity",
    ):
        assert f"CREATE TABLE {table}" in result.stdout
    assert "UNIQUE (fingerprint)" in result.stdout
    assert "FOREIGN KEY(alert_id)" in result.stdout
