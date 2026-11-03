import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("OTEL_EXPORTER_OTLP_TIMEOUT", "1")

from app.main import add_user, create_app  # noqa: E402
from app.telemetry import setup_telemetry  # noqa: E402


@pytest.fixture
def app(tmp_path):
    application = create_app(str(tmp_path / "billing.db"))
    setup_telemetry(application)
    return application


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def user(app):
    add_user(app.state.db, "jordan", "correct-horse-battery")
    return {"username": "jordan", "password": "correct-horse-battery"}


@pytest.fixture
def customer(client):
    response = client.post(
        "/customers",
        json={"name": "Jordan Rivera", "email": "jordan@example.com", "plan": "team"},
    )
    assert response.status_code == 201
    return response.json()
