"""Create identity baseline tables.

Revision ID: 0001_identity_baseline
Revises:
Create Date: 2026-09-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_identity_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=20), nullable=False),
        sa.Column("description", sa.String(length=200), nullable=False),
        sa.CheckConstraint(
            "code IN ('EMPLOYEE','MANAGER','FINANCE','HR_ADMIN')",
            name="ck_roles_code",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code"),
    )
    op.create_table(
        "employees",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=False),
        sa.Column("grade", sa.String(length=10), nullable=False),
        sa.Column("cost_center", sa.String(length=50), nullable=False),
        sa.Column("manager_id", sa.Uuid(), nullable=True),
        sa.Column("home_currency", sa.String(length=3), nullable=False),
        sa.Column("pto_entitlement_days", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("length(home_currency) = 3", name="ck_employees_currency"),
        sa.CheckConstraint("status IN ('ACTIVE','INACTIVE')", name="ck_employees_status"),
        sa.ForeignKeyConstraint(["manager_id"], ["employees.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_employees_cost_center", "employees", ["cost_center"])
    op.create_index("ix_employees_email", "employees", ["email"], unique=True)
    op.create_index("ix_employees_manager_id", "employees", ["manager_id"])
    op.create_table(
        "credentials",
        sa.Column("employee_id", sa.Uuid(), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["employee_id"], ["employees.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("employee_id"),
    )
    op.create_table(
        "employee_roles",
        sa.Column("employee_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["employee_id"], ["employees.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("employee_id", "role_id"),
    )


def downgrade() -> None:
    op.drop_table("employee_roles")
    op.drop_table("credentials")
    op.drop_index("ix_employees_manager_id", table_name="employees")
    op.drop_index("ix_employees_email", table_name="employees")
    op.drop_index("ix_employees_cost_center", table_name="employees")
    op.drop_table("employees")
    op.drop_table("roles")
