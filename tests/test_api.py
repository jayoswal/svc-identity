import uuid

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Employee, EmployeeStatus
from tests.conftest import bearer, login


def test_health_echoes_correlation_id(client: TestClient) -> None:
    correlation_id = str(uuid.uuid4())
    response = client.get("/healthz", headers={"X-Correlation-Id": correlation_id})
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "svc-identity"}
    assert response.headers["X-Correlation-Id"] == correlation_id


def test_login_returns_expected_claims(client: TestClient) -> None:
    token = login(client, "ADA@ATLAS.DEV")
    claims = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    assert claims["email"] == "ada@atlas.dev"
    assert claims["roles"] == ["EMPLOYEE"]
    assert claims["mgr"] == "10000000-0000-4000-8000-000000000001"


def test_invalid_login_uses_standard_error(client: TestClient) -> None:
    correlation_id = str(uuid.uuid4())
    response = client.post(
        "/api/v1/auth/login",
        headers={"X-Correlation-Id": correlation_id},
        json={"email": "ada@atlas.dev", "password": "wrong"},
    )
    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "IDENTITY_INVALID_CREDENTIALS",
            "message": "Invalid email or password.",
            "correlation_id": correlation_id,
            "details": [],
        }
    }


def test_unknown_login_still_verifies_password_hash(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str]] = []

    def record_verification(password_hash: str, password: str) -> bool:
        calls.append((password_hash, password))
        return False

    monkeypatch.setattr("app.services.identity.verify_password", record_verification)
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "missing@atlas.dev", "password": "wrong"},
    )
    assert response.status_code == 401
    assert len(calls) == 1
    assert calls[0][1] == "wrong"


def test_current_employee_is_protected(client: TestClient) -> None:
    unauthorized = client.get("/api/v1/identity/me")
    assert unauthorized.status_code == 401

    token = login(client, "ada@atlas.dev")
    response = client.get("/api/v1/identity/me", headers=bearer(token))
    assert response.status_code == 200
    assert response.json()["full_name"] == "Ada Lovelace"
    assert response.json()["roles"] == ["EMPLOYEE"]


def test_employee_cannot_list_directory(client: TestClient) -> None:
    token = login(client, "ada@atlas.dev")
    response = client.get("/api/v1/identity/employees", headers=bearer(token))
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "IDENTITY_FORBIDDEN"


def test_hr_admin_creates_employee(client: TestClient) -> None:
    token = login(client, "admin@atlas.dev")
    response = client.post(
        "/api/v1/identity/employees",
        headers=bearer(token),
        json={
            "email": "new.employee@atlas.dev",
            "full_name": "New Employee",
            "grade": "IC3",
            "cost_center": "CC-100",
            "manager_id": "10000000-0000-4000-8000-000000000001",
            "home_currency": "USD",
            "roles": ["EMPLOYEE"],
        },
    )
    assert response.status_code == 201
    assert response.json()["pto_entitlement_days"] == 20
    assert response.json()["provisioning"] == "PROVISIONING"


def test_patch_rejects_null_for_required_employee_field(client: TestClient) -> None:
    token = login(client, "admin@atlas.dev")
    response = client.patch(
        "/api/v1/identity/employees/10000000-0000-4000-8000-000000000002",
        headers=bearer(token),
        json={"full_name": None},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "IDENTITY_VALIDATION_ERROR"


def test_manager_assignment_requires_manager_role(client: TestClient) -> None:
    token = login(client, "admin@atlas.dev")
    response = client.post(
        "/api/v1/identity/employees",
        headers=bearer(token),
        json={
            "email": "invalid.manager@atlas.dev",
            "full_name": "Invalid Manager",
            "grade": "IC3",
            "cost_center": "CC-100",
            "manager_id": "10000000-0000-4000-8000-000000000003",
            "home_currency": "USD",
            "roles": ["EMPLOYEE"],
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "IDENTITY_INVALID_MANAGER"


def test_manager_assignment_requires_active_manager(
    client: TestClient, db: Session
) -> None:
    manager = db.get(Employee, uuid.UUID("10000000-0000-4000-8000-000000000001"))
    assert manager is not None
    manager.status = EmployeeStatus.INACTIVE
    db.commit()

    token = login(client, "admin@atlas.dev")
    response = client.post(
        "/api/v1/identity/employees",
        headers=bearer(token),
        json={
            "email": "inactive.manager@atlas.dev",
            "full_name": "Inactive Manager Report",
            "grade": "IC3",
            "cost_center": "CC-100",
            "manager_id": str(manager.id),
            "home_currency": "USD",
            "roles": ["EMPLOYEE"],
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "IDENTITY_INVALID_MANAGER"


def test_manager_with_direct_reports_cannot_be_deactivated(client: TestClient) -> None:
    token = login(client, "admin@atlas.dev")
    response = client.post(
        "/api/v1/identity/employees/10000000-0000-4000-8000-000000000001/deactivate",
        headers=bearer(token),
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "IDENTITY_MANAGER_HAS_REPORTS"


def test_manager_assignment_rejects_reporting_cycle(client: TestClient) -> None:
    token = login(client, "admin@atlas.dev")
    promoted = client.patch(
        "/api/v1/identity/employees/10000000-0000-4000-8000-000000000002",
        headers=bearer(token),
        json={"roles": ["EMPLOYEE", "MANAGER"]},
    )
    assert promoted.status_code == 200

    response = client.patch(
        "/api/v1/identity/employees/10000000-0000-4000-8000-000000000001",
        headers=bearer(token),
        json={"manager_id": "10000000-0000-4000-8000-000000000002"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "IDENTITY_INVALID_MANAGER"


def test_deactivated_admin_token_is_rejected(client: TestClient) -> None:
    token = login(client, "admin@atlas.dev")
    response = client.post(
        "/api/v1/identity/employees/10000000-0000-4000-8000-000000000004/deactivate",
        headers=bearer(token),
    )
    assert response.status_code == 200

    denied = client.get("/api/v1/identity/employees", headers=bearer(token))
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "UNAUTHENTICATED"


def test_removed_admin_role_revokes_existing_token(client: TestClient) -> None:
    token = login(client, "admin@atlas.dev")
    response = client.patch(
        "/api/v1/identity/employees/10000000-0000-4000-8000-000000000004",
        headers=bearer(token),
        json={"roles": ["EMPLOYEE"]},
    )
    assert response.status_code == 200

    denied = client.get("/api/v1/identity/employees", headers=bearer(token))
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "IDENTITY_FORBIDDEN"


def test_openapi_contains_committed_identity_surface(client: TestClient) -> None:
    paths = set(client.get("/openapi.json").json()["paths"])
    assert {
        "/api/v1/identity/healthz",
        "/api/v1/auth/login",
        "/api/v1/identity/me",
        "/api/v1/identity/employees",
        "/api/v1/identity/employees/{employee_id}",
        "/api/v1/identity/employees/{employee_id}/deactivate",
    } <= paths
