import uuid
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import EmployeeStatus, RoleCode


def normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    local, separator, domain = normalized.partition("@")
    if not separator or not local or "." not in domain:
        raise ValueError("must be a valid email address")
    return normalized


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)
    password: str = Field(min_length=1, max_length=256)

    _normalize_email = field_validator("email")(normalize_email)


class TokenResponse(BaseModel):
    token: str
    token_type: Literal["Bearer"] = "Bearer"


class EmployeeBase(BaseModel):
    email: str = Field(max_length=320)
    full_name: str = Field(min_length=1, max_length=200)
    grade: str = Field(min_length=2, max_length=10)
    cost_center: str = Field(min_length=1, max_length=50)
    manager_id: uuid.UUID | None = None
    home_currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
    roles: list[RoleCode] = Field(min_length=1)

    _normalize_email = field_validator("email")(normalize_email)


class EmployeeCreate(EmployeeBase):
    model_config = ConfigDict(extra="forbid")


class EmployeeUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str | None = Field(default=None, max_length=320)
    full_name: str | None = Field(default=None, min_length=1, max_length=200)
    grade: str | None = Field(default=None, min_length=2, max_length=10)
    cost_center: str | None = Field(default=None, min_length=1, max_length=50)
    manager_id: uuid.UUID | None = None
    home_currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    roles: list[RoleCode] | None = Field(default=None, min_length=1)

    @model_validator(mode="before")
    @classmethod
    def reject_nulls(cls, value: object) -> object:
        if isinstance(value, dict):
            non_nullable = {"email", "full_name", "grade", "cost_center", "home_currency", "roles"}
            null_fields = sorted(
                field
                for field in non_nullable
                if value.get(field) is None and field in value
            )
            if null_fields:
                raise ValueError(f"fields may not be null: {', '.join(null_fields)}")
        return value

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str | None) -> str | None:
        return normalize_email(value) if value is not None else None

    @model_validator(mode="after")
    def require_change(self) -> Self:
        if not self.model_fields_set:
            raise ValueError("at least one field is required")
        return self


class EmployeeResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    grade: str
    cost_center: str
    manager_id: uuid.UUID | None
    home_currency: str
    pto_entitlement_days: int
    status: EmployeeStatus
    roles: list[RoleCode]
    created_at: datetime
    updated_at: datetime


class EmployeeCreated(EmployeeResponse):
    provisioning: Literal["PROVISIONING"] = "PROVISIONING"


class EmployeeList(BaseModel):
    items: list[EmployeeResponse]
    total: int
