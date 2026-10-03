"""Shared temporary-database fixtures for both local demo applications."""

import pytest

from secure_app.app import create_app as create_secure_app
from vulnerable_app.app import create_app as create_vulnerable_app


@pytest.fixture
def vulnerable_app(tmp_path):
    app = create_vulnerable_app(
        {"TESTING": True, "DATABASE": str(tmp_path / "vulnerable-test.sqlite3")}
    )
    yield app


@pytest.fixture
def secure_app(tmp_path):
    app = create_secure_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "secure-test.sqlite3"),
            "SECRET_KEY": "pytest-only-secret-key",
        }
    )
    yield app


@pytest.fixture
def vulnerable_client(vulnerable_app):
    return vulnerable_app.test_client()


@pytest.fixture
def secure_client(secure_app):
    return secure_app.test_client()


def post_with_csrf(client, path, data):
    """Submit a form using the CSRF token rendered in its GET response."""
    page = client.get(path)
    token = page.get_data(as_text=True).split('name="_csrf_token" value="', 1)[1]
    token = token.split('"', 1)[0]
    return client.post(path, data={**data, "_csrf_token": token})
