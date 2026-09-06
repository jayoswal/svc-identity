import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.auth import Claims, active_user, require
from ..core.errors import AppError
from ..db import get_db
from ..events import publish
from ..models import Employee, EmployeeStatus
from ..schemas import (
    EmployeeCreate,
    EmployeeCreated,
    EmployeeList,
    EmployeeResponse,
    EmployeeUpdate,
)
from ..services.identity import (
    GRADE_ENTITLEMENTS,
    commit_employee,
    employee_count,
    employee_response,
    ensure_email_available,
    ensure_manager,
    get_employee,
    lock_employee_hierarchy,
    resolve_roles,
    serialize_change,
)

router = APIRouter(prefix="/api/v1/identity", tags=["Employees"])


def claim_id(claims: Claims) -> uuid.UUID:
    try:
        return uuid.UUID(claims["sub"])
    except ValueError as exc:
        raise AppError(401, "UNAUTHENTICATED", "Token subject is invalid.") from exc


def require_employee_access(employee: Employee, claims: Claims) -> None:
    requester = claim_id(claims)
    if (
        "HR_ADMIN" not in claims["roles"]
        and employee.id != requester
        and (
            "MANAGER" not in claims["roles"]
            or employee.manager_id != requester
        )
    ):
        raise AppError(403, "IDENTITY_FORBIDDEN", "Employee access is not allowed.")


@router.get("/me", response_model=EmployeeResponse)
def current_employee(
    claims: Claims = Depends(active_user), db: Session = Depends(get_db)
) -> EmployeeResponse:
    return employee_response(get_employee(db, claim_id(claims)))


@router.get("/employees", response_model=EmployeeList)
def list_employees(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    claims: Claims = Depends(require("MANAGER", "HR_ADMIN")),
    db: Session = Depends(get_db),
) -> EmployeeList:
    query = select(Employee).order_by(Employee.full_name).limit(limit).offset(offset)
    total = employee_count(db)
    if "HR_ADMIN" not in claims["roles"]:
        manager_id = claim_id(claims)
        query = (
            select(Employee)
            .where(Employee.manager_id == manager_id)
            .order_by(Employee.full_name)
            .limit(limit)
            .offset(offset)
        )
        total = len(list(db.scalars(select(Employee).where(Employee.manager_id == manager_id))))
    employees = list(db.scalars(query).all())
    return EmployeeList(items=[employee_response(item) for item in employees], total=total)


@router.post(
    "/employees", response_model=EmployeeCreated, status_code=status.HTTP_201_CREATED
)
async def create_employee(
    payload: EmployeeCreate,
    request: Request,
    _: Claims = Depends(require("HR_ADMIN")),
    db: Session = Depends(get_db),
) -> EmployeeCreated:
    ensure_email_available(db, payload.email)
    if payload.manager_id is not None:
        ensure_manager(db, payload.manager_id)
    employee = Employee(
        email=payload.email,
        full_name=payload.full_name,
        grade=payload.grade,
        cost_center=payload.cost_center,
        manager_id=payload.manager_id,
        home_currency=payload.home_currency,
        pto_entitlement_days=GRADE_ENTITLEMENTS.get(payload.grade, 0),
        status=EmployeeStatus.ACTIVE,
        roles=resolve_roles(db, payload.roles),
    )
    db.add(employee)
    commit_employee(db, employee)
    await publish(
        "identity.events",
        "employee.created",
        {
            "employee_id": str(employee.id),
            "email": employee.email,
            "full_name": employee.full_name,
            "cost_center": employee.cost_center,
            "manager_id": str(employee.manager_id) if employee.manager_id else None,
            "home_currency": employee.home_currency,
            "pto_entitlement_days": employee.pto_entitlement_days,
            "status": employee.status,
        },
        request.state.correlation_id,
    )
    return EmployeeCreated(**employee_response(employee).model_dump())


@router.get("/employees/{employee_id}", response_model=EmployeeResponse)
def read_employee(
    employee_id: uuid.UUID,
    claims: Claims = Depends(active_user),
    db: Session = Depends(get_db),
) -> EmployeeResponse:
    employee = get_employee(db, employee_id)
    require_employee_access(employee, claims)
    return employee_response(employee)


@router.patch("/employees/{employee_id}", response_model=EmployeeResponse)
async def update_employee(
    employee_id: uuid.UUID,
    payload: EmployeeUpdate,
    request: Request,
    _: Claims = Depends(require("HR_ADMIN")),
    db: Session = Depends(get_db),
) -> EmployeeResponse:
    lock_employee_hierarchy(db)
    employee = get_employee(db, employee_id, for_update=True)
    changes = payload.model_dump(exclude_unset=True)
    if payload.email is not None:
        ensure_email_available(db, payload.email, employee_id)
    if payload.manager_id is not None:
        if payload.manager_id == employee_id:
            raise AppError(422, "IDENTITY_INVALID_MANAGER", "Employee cannot manage themself.")
        ensure_manager(db, payload.manager_id, employee_id)
    roles = changes.pop("roles", None)
    if roles is not None:
        role_values = {role.value for role in roles}
        if "MANAGER" not in role_values:
            direct_reports = db.scalar(
                select(Employee.id).where(Employee.manager_id == employee_id).limit(1)
            )
            if direct_reports is not None:
                raise AppError(
                    422,
                    "IDENTITY_MANAGER_HAS_REPORTS",
                    "Reassign direct reports before removing the MANAGER role.",
                )
        employee.roles = resolve_roles(db, roles)
        changes["roles"] = [role.value for role in roles]
    for field, value in changes.items():
        if field != "roles":
            setattr(employee, field, value)
    if payload.grade is not None:
        employee.pto_entitlement_days = GRADE_ENTITLEMENTS.get(payload.grade, 0)
        changes["pto_entitlement_days"] = employee.pto_entitlement_days
    commit_employee(db, employee)
    await publish(
        "identity.events",
        "employee.updated",
        {
            "employee_id": str(employee.id),
            "changed": {key: serialize_change(value) for key, value in changes.items()},
        },
        request.state.correlation_id,
    )
    return employee_response(employee)


@router.post("/employees/{employee_id}/deactivate", response_model=EmployeeResponse)
async def deactivate_employee(
    employee_id: uuid.UUID,
    request: Request,
    _: Claims = Depends(require("HR_ADMIN")),
    db: Session = Depends(get_db),
) -> EmployeeResponse:
    lock_employee_hierarchy(db)
    employee = get_employee(db, employee_id, for_update=True)
    direct_report = db.scalar(
        select(Employee.id).where(Employee.manager_id == employee_id).limit(1)
    )
    if direct_report is not None:
        raise AppError(
            422,
            "IDENTITY_MANAGER_HAS_REPORTS",
            "Reassign direct reports before deactivating the manager.",
        )
    employee.status = EmployeeStatus.INACTIVE
    commit_employee(db, employee)
    await publish(
        "identity.events",
        "employee.deactivated",
        {"employee_id": str(employee.id)},
        request.state.correlation_id,
    )
    return employee_response(employee)
