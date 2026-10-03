"""Remediated local Flask application for secure-coding review exercises."""

import os
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE = PROJECT_ROOT / "instance" / "secure.sqlite3"
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,32}$")
MAX_SEARCH_LENGTH = 100
MAX_FEEDBACK_LENGTH = 1000


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create the remediated application with safe local defaults."""
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECURE_REVIEW_SECRET_KEY") or secrets.token_hex(32),
        DATABASE=str(DEFAULT_DATABASE),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            database_path = Path(app.config["DATABASE"])
            database_path.parent.mkdir(parents=True, exist_ok=True)
            g.db = sqlite3.connect(database_path)
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error: BaseException | None = None) -> None:
        database = g.pop("db", None)
        if database is not None:
            database.close()

    def init_db() -> None:
        database = get_db()
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL
            );
            """
        )
        database.commit()

    @app.before_request
    def enforce_csrf_token() -> None:
        if request.method == "POST":
            submitted_token = request.form.get("_csrf_token", "")
            expected_token = session.get("_csrf_token", "")
            if (
                not expected_token
                or not submitted_token.isascii()
                or not secrets.compare_digest(submitted_token, expected_token)
            ):
                abort(400, description="Invalid or missing form security token.")

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        return response

    @app.context_processor
    def provide_form_security_token() -> dict[str, Any]:
        def csrf_token() -> str:
            return session.setdefault("_csrf_token", secrets.token_urlsafe(32))

        return {"csrf_token": csrf_token}

    with app.app_context():
        init_db()

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        message = ""
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not USERNAME_PATTERN.fullmatch(username):
                message = "Username must be 3-32 letters, numbers, or underscores."
                return render_template("register.html", message=message), 400
            if len(password) < 12 or len(password) > 128:
                message = "Password must be between 12 and 128 characters."
                return render_template("register.html", message=message), 400
            try:
                get_db().execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                get_db().commit()
                message = "Registration complete. You can now log in."
            except sqlite3.IntegrityError:
                message = "That username is already registered."
        return render_template("register.html", message=message)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        message = ""
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                return redirect(url_for("profile"))
            message = "Invalid username or password."
        return render_template("login.html", message=message)

    @app.get("/profile")
    def profile():
        user_id = session.get("user_id")
        if user_id is None:
            return redirect(url_for("login"))
        user = get_db().execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if user is None:
            session.clear()
            return redirect(url_for("login"))
        return render_template("profile.html", username=user["username"])

    @app.route("/search", methods=["GET", "POST"])
    def search():
        term = request.values.get("q", "").strip()
        if len(term) > MAX_SEARCH_LENGTH:
            return render_template(
                "search.html", term="", users=[], message="Search term is too long."
            ), 400
        users = []
        if term:
            users = get_db().execute(
                "SELECT username FROM users WHERE username LIKE ? ORDER BY username",
                (f"%{term}%",),
            ).fetchall()
        return render_template(
            "search.html", term=term, users=users, message=""
        )

    @app.route("/feedback", methods=["GET", "POST"])
    def feedback():
        message = ""
        if request.method == "POST":
            feedback_text = request.form.get("message", "").strip()
            if not feedback_text or len(feedback_text) > MAX_FEEDBACK_LENGTH:
                message = "Feedback must contain 1-1000 characters."
                return render_template("feedback.html", message=message), 400
            get_db().execute(
                "INSERT INTO feedback (message) VALUES (?)", (feedback_text,)
            )
            get_db().commit()
            message = "Thank you for your feedback."
        return render_template("feedback.html", message=message)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=False)
