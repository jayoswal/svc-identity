from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_db
from app.main import app
from app.seed import seed_demo_data


@pytest.fixture(autouse=True)
def _no_amqp_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    """Employee endpoints publish employee.* after commit; stub it out so tests
    don't attempt a real AMQP connection (no broker is available in tests)."""

    async def noop_publish(*_: object, **__: object) -> None:
        return None

    monkeypatch.setattr("app.api.employees.publish", noop_publish)


@pytest.fixture
def db() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    with session_factory() as session:
        seed_demo_data(session, "atlas")
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def client(db: Session) -> Iterator[TestClient]:
    def override_db() -> Iterator[Session]:
        yield db

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def login(client: TestClient, email: str) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": "atlas"})
    assert response.status_code == 200
    token = response.json()["token"]
    assert isinstance(token, str)
    return token


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

