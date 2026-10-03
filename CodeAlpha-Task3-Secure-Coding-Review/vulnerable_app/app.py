"""Local-only intentionally vulnerable app for secure-coding review exercises.

Do not expose this app to a network or use real credentials or personal data.
"""

import sqlite3
from pathlib import Path
from typing import Any

from flask import Flask, g, redirect, render_template, request, session, url_for
from markupsafe import Markup

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE = PROJECT_ROOT / "instance" / "vulnerable.sqlite3"


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create the deliberately insecure demonstration application."""
    app = Flask(__name__)
    # Intentionally hardcoded teaching example; never use a fixed key in production.
    app.config.update(
        SECRET_KEY="insecure-demo-secret-not-for-real-use",
        DATABASE=str(DEFAULT_DATABASE),
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
                password TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL
            );
            """
        )
        database.commit()

    with app.app_context():
        init_db()

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        message = ""
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            try:
                # Intentionally stores a password as cleartext for review demonstration.
                get_db().execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password),
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
            user = get_db().execute(
                "SELECT id, username FROM users WHERE username = ? AND password = ?",
                (request.form.get("username", ""), request.form.get("password", "")),
            ).fetchone()
            if user:
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
        term = request.values.get("q", "")
        results_html = Markup("")
        if term:
            # Intentionally unsafe SQL construction, restricted to this local demo DB.
            rows = get_db().execute(
                f"SELECT username FROM users WHERE username LIKE '%{term}%'"
            ).fetchall()
            result_items = "".join(f"<li>{row['username']}</li>" for row in rows)
            # Intentionally marks user-controlled data as trusted HTML to demonstrate XSS.
            results_html = Markup(
                f"<p>Search results for: {term}</p><ul>{result_items}</ul>"
            )
        return render_template("search.html", results_html=results_html)

    @app.route("/feedback", methods=["GET", "POST"])
    def feedback():
        message = ""
        if request.method == "POST":
            feedback_text = request.form.get("message", "")
            get_db().execute(
                "INSERT INTO feedback (message) VALUES (?)", (feedback_text,)
            )
            get_db().commit()
            message = "Thank you for your feedback."
        return render_template("feedback.html", message=message)

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    return app


if __name__ == "__main__":
    app = create_app()
    # Intentionally enabled for review; host remains loopback for local-only use.
    app.run(host="127.0.0.1", port=5000, debug=True)
