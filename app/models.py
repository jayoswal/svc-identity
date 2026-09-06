from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, String, Table, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class RoleCode(StrEnum):
    EMPLOYEE = "EMPLOYEE"
    MANAGER = "MANAGER"
    FINANCE = "FINANCE"
    HR_ADMIN = "HR_ADMIN"


class EmployeeStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


employee_roles = Table(
    "employee_roles",
    Base.metadata,
    Column("employee_id", ForeignKey("employees.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = (
        CheckConstraint(
            "code IN ('EMPLOYEE','MANAGER','FINANCE','HR_ADMIN')",
            name="ck_roles_code",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    code: Mapped[str] = mapped_column(String(20), unique=True)
    description: Mapped[str] = mapped_column(String(200))


class Employee(Base):
    __tablename__ = "employees"
    __table_args__ = (
        CheckConstraint("status IN ('ACTIVE','INACTIVE')", name="ck_employees_status"),
        CheckConstraint("length(home_currency) = 3", name="ck_employees_currency"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200))
    grade: Mapped[str] = mapped_column(String(10))
    cost_center: Mapped[str] = mapped_column(String(50), index=True)
    manager_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("employees.id"), nullable=True, index=True
    )
    home_currency: Mapped[str] = mapped_column(String(3), default="USD")
    pto_entitlement_days: Mapped[int] = mapped_column(default=0)
    status: Mapped[str] = mapped_column(String(10), default=EmployeeStatus.ACTIVE)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    manager: Mapped[Employee | None] = relationship(
        remote_side=lambda: [Employee.id], foreign_keys=[manager_id]
    )
    roles: Mapped[list[Role]] = relationship(secondary=employee_roles, lazy="selectin")
    credential: Mapped[Credential | None] = relationship(
        back_populates="employee", cascade="all, delete-orphan", uselist=False
    )


class Credential(Base):
    __tablename__ = "credentials"

    employee_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("employees.id", ondelete="CASCADE"), primary_key=True
    )
    password_hash: Mapped[str] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    employee: Mapped[Employee] = relationship(back_populates="credential")
