"""Behavior checks for the intentionally insecure local application."""

import sqlite3


def test_home_page_starts(vulnerable_client):
    response = vulnerable_client.get("/")
    assert response.status_code == 200
    assert b"SecureReview Demo" in response.data


def test_registration_and_login(vulnerable_client):
    registered = vulnerable_client.post(
        "/register", data={"username": "demo_user", "password": "demo-password"}
    )
    assert registered.status_code == 200
    assert b"Registration complete" in registered.data

    logged_in = vulnerable_client.post(
        "/login", data={"username": "demo_user", "password": "demo-password"}
    )
    assert logged_in.status_code == 302
    assert vulnerable_client.get("/profile").status_code == 200


def test_demo_database_stores_password_as_plaintext(vulnerable_app, vulnerable_client):
    vulnerable_client.post(
        "/register", data={"username": "plain_user", "password": "demo-password"}
    )
    with sqlite3.connect(vulnerable_app.config["DATABASE"]) as database:
        stored_password = database.execute(
            "SELECT password FROM users WHERE username = ?", ("plain_user",)
        ).fetchone()[0]
    assert stored_password == "demo-password"


def test_invalid_login_is_rejected(vulnerable_client):
    response = vulnerable_client.post(
        "/login", data={"username": "missing", "password": "wrong"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_search_and_feedback_valid_input(vulnerable_client):
    vulnerable_client.post(
        "/register", data={"username": "search_user", "password": "sample"}
    )
    search = vulnerable_client.get("/search?q=search")
    assert search.status_code == 200
    assert b"search_user" in search.data

    feedback = vulnerable_client.post(
        "/feedback", data={"message": "Local demo feedback"}
    )
    assert feedback.status_code == 200
    assert b"Thank you for your feedback" in feedback.data


def test_search_rejects_empty_query_gracefully(vulnerable_client):
    response = vulnerable_client.get("/search")
    assert response.status_code == 200
    assert b"Search demo users" in response.data


def test_demo_search_renders_untrusted_markup_as_html(vulnerable_client):
    response = vulnerable_client.get("/search", query_string={"q": "<b>review</b>"})
    assert response.status_code == 200
    assert b"<p>Search results for: <b>review</b></p>" in response.data
