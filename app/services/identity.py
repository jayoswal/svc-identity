import uuid
from collections.abc import Iterable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.errors import AppError
from ..models import Employee, EmployeeStatus, Role, RoleCode
from ..schemas import EmployeeResponse

password_hasher = PasswordHasher()
DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$xxDt8jy3aSdmWj+QLBEQGw$"
    "lMevbX/uNJwRMOAhNTvU3GYIgAX4DWiHxxWfQuBvtkQ"
)

GRADE_ENTITLEMENTS = {
    "IC1": 18,
    "IC2": 18,
    "IC3": 20,
    "IC4": 22,
    "IC5": 25,
    "IC6": 25,
    "M1": 22,
    "M2": 25,
    "M3": 25,
    "M4": 30,
}


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def get_employee(
    db: Session, employee_id: uuid.UUID, *, for_update: bool = False
) -> Employee:
    query = select(Employee).where(Employee.id == employee_id)
    if for_update:
        query = query.with_for_update()
    employee = db.scalar(query)
    if employee is None:
        raise AppError(404, "IDENTITY_EMPLOYEE_NOT_FOUND", "Employee not found.")
    return employee


def employee_response(employee: Employee) -> EmployeeResponse:
    return EmployeeResponse(
        id=employee.id,
        email=employee.email,
        full_name=employee.full_name,
        grade=employee.grade,
        cost_center=employee.cost_center,
        manager_id=employee.manager_id,
        home_currency=employee.home_currency,
        pto_entitlement_days=employee.pto_entitlement_days,
        status=EmployeeStatus(employee.status),
        roles=sorted(RoleCode(role.code) for role in employee.roles),
        created_at=employee.created_at,
        updated_at=employee.updated_at,
    )


def resolve_roles(db: Session, codes: Iterable[RoleCode]) -> list[Role]:
    wanted = {code.value for code in codes}
    roles = list(db.scalars(select(Role).where(Role.code.in_(wanted))).all())
    found = {role.code for role in roles}
    if found != wanted:
        raise AppError(
            422,
            "IDENTITY_UNKNOWN_ROLE",
            "One or more roles are not configured.",
            [{"field": "roles", "issue": f"missing: {sorted(wanted - found)}"}],
        )
    return roles


def commit_employee(db: Session, employee: Employee) -> None:
    try:
        db.commit()
        db.refresh(employee)
    except IntegrityError as exc:
        db.rollback()
        raise AppError(
            409,
            "IDENTITY_CONFLICT",
            "Employee data conflicts with existing data.",
        ) from exc


def ensure_email_available(
    db: Session, email: str, employee_id: uuid.UUID | None = None
) -> None:
    query = select(Employee.id).where(Employee.email == email)
    if employee_id is not None:
        query = query.where(Employee.id != employee_id)
    if db.scalar(query) is not None:
        raise AppError(409, "IDENTITY_EMAIL_TAKEN", "Employee email already exists.")


def lock_employee_hierarchy(db: Session) -> None:
    list(
        db.scalars(
            select(Employee.id).order_by(Employee.id).with_for_update()
        ).all()
    )


def ensure_manager(
    db: Session, manager_id: uuid.UUID, employee_id: uuid.UUID | None = None
) -> Employee:
    lock_employee_hierarchy(db)
    manager = get_employee(db, manager_id, for_update=True)
    if (
        manager.status != EmployeeStatus.ACTIVE
        or RoleCode.MANAGER not in {RoleCode(role.code) for role in manager.roles}
    ):
        raise AppError(
            422,
            "IDENTITY_INVALID_MANAGER",
            "Assigned manager must be active and have the MANAGER role.",
        )
    current: Employee | None = manager
    visited: set[uuid.UUID] = set()
    while current is not None:
        if current.id == employee_id or current.id in visited:
            raise AppError(
                422,
                "IDENTITY_INVALID_MANAGER",
                "Manager assignment would create a reporting cycle.",
            )
        visited.add(current.id)
        current = (
            get_employee(db, current.manager_id, for_update=True)
            if current.manager_id is not None
            else None
        )
    return manager


def authenticate(db: Session, email: str, password: str) -> Employee:
    employee = db.scalar(select(Employee).where(Employee.email == email))
    eligible = (
        employee is not None
        and employee.status == EmployeeStatus.ACTIVE
        and employee.credential is not None
    )
    password_hash = (
        employee.credential.password_hash
        if eligible and employee is not None and employee.credential is not None
        else DUMMY_PASSWORD_HASH
    )
    password_valid = verify_password(password_hash, password)
    if not eligible or not password_valid:
        raise AppError(401, "IDENTITY_INVALID_CREDENTIALS", "Invalid email or password.")
    assert employee is not None
    return employee


def employee_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(Employee)) or 0
