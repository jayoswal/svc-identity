import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import TypedDict, cast

import jwt
from fastapi import Depends, Header
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Employee, EmployeeStatus
from .config import settings
from .errors import AppError


class Claims(TypedDict):
    sub: str
    roles: list[str]
    mgr: str | None
    email: str
    exp: int
    iat: int


def issue_token(employee: Employee) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": str(employee.id),
        "roles": sorted(role.code for role in employee.roles),
        "mgr": str(employee.manager_id) if employee.manager_id else None,
        "email": employee.email,
        "iat": now,
        "exp": now + timedelta(hours=settings.jwt_ttl_hours),
    }
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256")


def current_user(authorization: str = Header(default="")) -> Claims:
    if not authorization.startswith("Bearer "):
        raise AppError(401, "UNAUTHENTICATED", "Missing bearer token.")
    try:
        payload = cast(
            dict[str, object],
            jwt.decode(authorization[7:], settings.jwt_secret, algorithms=["HS256"]),
        )
    except jwt.PyJWTError as exc:
        raise AppError(401, "UNAUTHENTICATED", "Invalid or expired token.") from exc

    sub = payload.get("sub")
    roles = payload.get("roles")
    email = payload.get("email")
    manager = payload.get("mgr")
    issued_at = payload.get("iat")
    expires_at = payload.get("exp")
    if (
        not isinstance(sub, str)
        or not isinstance(email, str)
        or not isinstance(roles, list)
        or not all(isinstance(role, str) for role in roles)
        or manager is not None
        and not isinstance(manager, str)
        or not isinstance(issued_at, int)
        or not isinstance(expires_at, int)
    ):
        raise AppError(401, "UNAUTHENTICATED", "Token claims are invalid.")
    return Claims(
        sub=sub,
        roles=cast(list[str], roles),
        mgr=manager,
        email=email,
        iat=issued_at,
        exp=expires_at,
    )


def active_user(
    claims: Claims = Depends(current_user), db: Session = Depends(get_db)
) -> Claims:
    try:
        employee_id = uuid.UUID(claims["sub"])
    except ValueError as exc:
        raise AppError(401, "UNAUTHENTICATED", "Token subject is invalid.") from exc
    employee = db.get(Employee, employee_id)
    if employee is None or employee.status != EmployeeStatus.ACTIVE:
        raise AppError(401, "UNAUTHENTICATED", "Employee session is no longer active.")
    return Claims(
        sub=str(employee.id),
        roles=sorted(role.code for role in employee.roles),
        mgr=str(employee.manager_id) if employee.manager_id else None,
        email=employee.email,
        iat=claims["iat"],
        exp=claims["exp"],
    )


def require(*roles: str) -> Callable[[Claims], Claims]:
    def dependency(user: Claims = Depends(active_user)) -> Claims:
        if roles and not set(roles).intersection(user["roles"]):
            raise AppError(403, "IDENTITY_FORBIDDEN", "Insufficient role.")
        return user

    return dependency
