"""Create the initial ShiatoAli SOC schema.

Revision ID: 20261112_0001
Revises:
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20261112_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "shiatoali_events",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("username", sa.String(255)),
        sa.Column("src_ip", sa.String(64)),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_shia_events_host_time", "shiatoali_events", ["host", "timestamp"]
    )
    op.create_index(
        "idx_shia_events_type_time", "shiatoali_events", ["event_type", "timestamp"]
    )

    op.create_table(
        "shiatoali_alerts",
        sa.Column("alert_id", sa.String(36), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "event_id",
            sa.String(36),
            sa.ForeignKey("shiatoali_events.event_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("tactic", sa.String(128), nullable=False),
        sa.Column("technique", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_shia_alerts_created", "shiatoali_alerts", ["created_at"])

    op.create_table(
        "shiatoali_cases",
        sa.Column("case_id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("priority", sa.String(32), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("assignee", sa.String(255)),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_shia_cases_status_updated", "shiatoali_cases", ["status", "updated_at"]
    )

    op.create_table(
        "shiatoali_case_alerts",
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("shiatoali_cases.case_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "alert_id",
            sa.String(36),
            sa.ForeignKey("shiatoali_alerts.alert_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "shiatoali_case_activity",
        sa.Column("activity_id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("shiatoali_cases.case_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_shia_case_activity_case_time",
        "shiatoali_case_activity",
        ["case_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_shia_case_activity_case_time", table_name="shiatoali_case_activity")
    op.drop_table("shiatoali_case_activity")
    op.drop_table("shiatoali_case_alerts")
    op.drop_index("idx_shia_cases_status_updated", table_name="shiatoali_cases")
    op.drop_table("shiatoali_cases")
    op.drop_index("idx_shia_alerts_created", table_name="shiatoali_alerts")
    op.drop_table("shiatoali_alerts")
    op.drop_index("idx_shia_events_type_time", table_name="shiatoali_events")
    op.drop_index("idx_shia_events_host_time", table_name="shiatoali_events")
    op.drop_table("shiatoali_events")
