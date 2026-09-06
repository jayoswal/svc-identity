import uuid
from typing import TypedDict

from sqlalchemy import select
from sqlalchemy.orm import Session

from .core.config import settings
from .db import SessionLocal
from .models import Credential, Employee, EmployeeStatus, Role, RoleCode
from .services.identity import GRADE_ENTITLEMENTS, hash_password, verify_password

ROLE_DESCRIPTIONS = {
    RoleCode.EMPLOYEE: "Submit time, leave, and expense records",
    RoleCode.MANAGER: "Review direct-report work",
    RoleCode.FINANCE: "Review financial policy and reimbursement",
    RoleCode.HR_ADMIN: "Manage employees and organization data",
}


class DemoUser(TypedDict):
    id: uuid.UUID
    email: str
    full_name: str
    grade: str
    cost_center: str
    manager_id: uuid.UUID | None
    home_currency: str
    roles: tuple[RoleCode, ...]


DEMO_USERS: tuple[DemoUser, ...] = (
    {
        "id": uuid.UUID("10000000-0000-4000-8000-000000000001"),
        "email": "grace@atlas.dev",
        "full_name": "Grace Hopper",
        "grade": "M2",
        "cost_center": "CC-100",
        "manager_id": None,
        "home_currency": "USD",
        "roles": (RoleCode.EMPLOYEE, RoleCode.MANAGER),
    },
    {
        "id": uuid.UUID("10000000-0000-4000-8000-000000000002"),
        "email": "ada@atlas.dev",
        "full_name": "Ada Lovelace",
        "grade": "IC4",
        "cost_center": "CC-100",
        "manager_id": uuid.UUID("10000000-0000-4000-8000-000000000001"),
        "home_currency": "GBP",
        "roles": (RoleCode.EMPLOYEE,),
    },
    {
        "id": uuid.UUID("10000000-0000-4000-8000-000000000003"),
        "email": "finance@atlas.dev",
        "full_name": "Frances Perkins",
        "grade": "M2",
        "cost_center": "FIN-100",
        "manager_id": None,
        "home_currency": "USD",
        "roles": (RoleCode.EMPLOYEE, RoleCode.FINANCE),
    },
    {
        "id": uuid.UUID("10000000-0000-4000-8000-000000000004"),
        "email": "admin@atlas.dev",
        "full_name": "Henrietta Hill",
        "grade": "M3",
        "cost_center": "HR-100",
        "manager_id": None,
        "home_currency": "USD",
        "roles": (RoleCode.EMPLOYEE, RoleCode.HR_ADMIN),
    },
)


def seed_demo_data(db: Session, password: str) -> None:
    roles: dict[RoleCode, Role] = {}
    for code, description in ROLE_DESCRIPTIONS.items():
        role = db.scalar(select(Role).where(Role.code == code.value))
        if role is None:
            role = Role(code=code.value, description=description)
            db.add(role)
            db.flush()
        roles[code] = role

    for values in DEMO_USERS:
        email = values["email"]
        employee = db.scalar(select(Employee).where(Employee.email == email))
        if employee is None:
            employee = Employee(id=values["id"], email=email)
            db.add(employee)
        employee.full_name = values["full_name"]
        employee.grade = values["grade"]
        employee.cost_center = values["cost_center"]
        employee.manager_id = values["manager_id"]
        employee.home_currency = values["home_currency"]
        employee.pto_entitlement_days = GRADE_ENTITLEMENTS.get(employee.grade, 0)
        employee.status = EmployeeStatus.ACTIVE
        employee.roles = [roles[code] for code in values["roles"]]
        db.flush()
        if employee.credential is None:
            employee.credential = Credential(password_hash=hash_password(password))
        elif not verify_password(employee.credential.password_hash, password):
            employee.credential.password_hash = hash_password(password)
    db.commit()


def main() -> None:
    with SessionLocal() as db:
        seed_demo_data(db, settings.demo_password)
    print(f"Seeded {len(DEMO_USERS)} identity demo users.")


if __name__ == "__main__":
    main()
