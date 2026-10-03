"""Behavior and remediation checks for the secure local application."""

import sqlite3

from tests.conftest import post_with_csrf


def test_home_page_and_security_headers(secure_client):
    response = secure_client.get("/")
    assert response.status_code == 200
    assert b"SecureReview Demo" in response.data
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_registration_login_and_password_hash(secure_app, secure_client):
    registered = post_with_csrf(
        secure_client,
        "/register",
        {"username": "demo_user", "password": "a-long-demo-password"},
    )
    assert registered.status_code == 200
    assert b"Registration complete" in registered.data

    with sqlite3.connect(secure_app.config["DATABASE"]) as database:
        stored_password = database.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("demo_user",)
        ).fetchone()[0]
    assert stored_password != "a-long-demo-password"
    assert stored_password.startswith("scrypt:")

    logged_in = post_with_csrf(
        secure_client,
        "/login",
        {"username": "demo_user", "password": "a-long-demo-password"},
    )
    assert logged_in.status_code == 302
    assert secure_client.get("/profile").status_code == 200

    feedback_page = secure_client.get("/feedback").get_data(as_text=True)
    token = feedback_page.split('name="_csrf_token" value="', 1)[1].split('"', 1)[0]
    logged_out = secure_client.post("/logout", data={"_csrf_token": token})
    assert logged_out.status_code == 302
    assert secure_client.get("/profile").status_code == 302


def test_invalid_registration_and_login(secure_client):
    short_password = post_with_csrf(
        secure_client, "/register", {"username": "valid_user", "password": "short"}
    )
    assert short_password.status_code == 400
    assert b"between 12 and 128" in short_password.data

    invalid_username = post_with_csrf(
        secure_client,
        "/register",
        {"username": "<bad>", "password": "a-long-demo-password"},
    )
    assert invalid_username.status_code == 400

    invalid_login = post_with_csrf(
        secure_client, "/login", {"username": "missing", "password": "wrong"}
    )
    assert invalid_login.status_code == 200
    assert b"Invalid username or password" in invalid_login.data


def test_post_without_csrf_token_is_rejected(secure_client):
    response = secure_client.post(
        "/feedback", data={"message": "This request lacks its form token."}
    )
    assert response.status_code == 400

    secure_client.get("/feedback")
    non_ascii_token = secure_client.post(
        "/feedback",
        data={"message": "Local feedback", "_csrf_token": "é"},
    )
    assert non_ascii_token.status_code == 400


def test_search_escapes_html_and_limits_input(secure_client):
    post_with_csrf(
        secure_client,
        "/register",
        {"username": "safe_user", "password": "a-long-demo-password"},
    )
    reflected = secure_client.get("/search", query_string={"q": "<script>alert(1)</script>"})
    assert reflected.status_code == 200
    assert b"&lt;script&gt;" in reflected.data
    assert b"<script>alert(1)</script>" not in reflected.data

    too_long = secure_client.get("/search", query_string={"q": "x" * 101})
    assert too_long.status_code == 400
    assert b"Search term is too long" in too_long.data


def test_feedback_validation_and_valid_submission(secure_client):
    empty = post_with_csrf(secure_client, "/feedback", {"message": "  "})
    assert empty.status_code == 400
    assert b"1-1000 characters" in empty.data

    valid = post_with_csrf(
        secure_client, "/feedback", {"message": "Local demo feedback"}
    )
    assert valid.status_code == 200
    assert b"Thank you for your feedback" in valid.data
