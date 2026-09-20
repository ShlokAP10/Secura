import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from secrets import token_urlsafe

import bcrypt
from flask import Flask, Response, flash, g, redirect, render_template, request, session, url_for

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "secureauth.db")
MAX_ATTEMPTS = 5
LOCK_MINUTES = 5

app = Flask(__name__)
is_production = os.environ.get("FLASK_ENV") == "production"
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "change-this-secret-key-before-deploying"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Keep HTTP usable for the local demo; production cookies are HTTPS-only.
    SESSION_COOKIE_SECURE=is_production,
)


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    connection = sqlite3.connect(DATABASE)
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            last_login TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    connection.commit()
    connection.close()


def log_event(user_id, event):
    connection = db()
    connection.execute(
        "INSERT INTO login_logs (user_id, event_type, timestamp) VALUES (?, ?, ?)",
        (user_id, event, utcnow().isoformat()),
    )
    connection.commit()


def current_user():
    if "user_id" not in session:
        return None
    return db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in to access that page.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def valid_password(password):
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )


@app.context_processor
def inject_layout_data():
    return {"nav_user": current_user()}


@app.before_request
def csrf_protect():
    if "csrf_token" not in session:
        session["csrf_token"] = token_urlsafe(24)
    if request.method == "POST" and request.form.get("csrf_token") != session.get("csrf_token"):
        flash("Your form session expired. Please try again.", "error")
        return redirect(request.referrer or url_for("home"))


@app.after_request
def add_security_headers(response):
    """Apply browser protections without blocking the Google-hosted fonts."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/security-info")
def security_info():
    return render_template("security_info.html")


@app.route("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not all([username, email, password, confirm]):
            flash("Please complete every field.", "error")
        elif not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Username must be 3–30 letters, numbers, or underscores.", "error")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif not valid_password(password):
            flash("Use 8+ characters with uppercase, lowercase, number, and special character.", "error")
        else:
            connection = db()
            found = connection.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
            if found:
                flash("That username or email is already registered.", "error")
            else:
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                connection.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, hashed, utcnow().isoformat()),
                )
                connection.commit()
                flash("Account created successfully. Your password has been securely hashed.", "success")
                return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("Please enter your email and password.", "error")
            return render_template("login.html")
        connection = db()
        user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            locked_until = datetime.fromisoformat(user["locked_until"]) if user["locked_until"] else None
            if locked_until and locked_until > utcnow():
                remaining = int((locked_until - utcnow()).total_seconds() // 60) + 1
                flash(f"Account temporarily locked. Try again in about {remaining} minute(s).", "error")
                return render_template("login.html", lock_seconds=int((locked_until - utcnow()).total_seconds()))
            if locked_until and locked_until <= utcnow():
                connection.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?", (user["id"],))
                connection.commit()
                user = connection.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
            if bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
                now = utcnow().isoformat()
                connection.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?", (now, user["id"]))
                connection.commit()
                session.clear()
                session["user_id"] = user["id"]
                session["csrf_token"] = token_urlsafe(24)
                log_event(user["id"], "LOGIN_SUCCESS")
                flash("Login successful.", "success")
                return redirect(url_for("dashboard"))
            attempts = user["failed_attempts"] + 1
            if attempts >= MAX_ATTEMPTS:
                until = utcnow() + timedelta(minutes=LOCK_MINUTES)
                connection.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (attempts, until.isoformat(), user["id"]))
                connection.commit()
                log_event(user["id"], "ACCOUNT_LOCKED")
                flash("Too many attempts. This account is locked for 5 minutes.", "error")
            else:
                connection.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user["id"]))
                connection.commit()
                log_event(user["id"], "LOGIN_FAILED")
                flash("Invalid email or password.", "error")
        else:
            flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    logs = db().execute("SELECT event_type, timestamp FROM login_logs WHERE user_id = ? ORDER BY id DESC LIMIT 6", (user["id"],)).fetchall()
    totals = db().execute("SELECT event_type, COUNT(*) AS total FROM login_logs WHERE user_id = ? GROUP BY event_type", (user["id"],)).fetchall()
    counts = {row["event_type"]: row["total"] for row in totals}
    return render_template("dashboard.html", user=user, logs=logs, success_count=counts.get("LOGIN_SUCCESS", 0), failed_count=counts.get("LOGIN_FAILED", 0))


@app.route("/security")
@login_required
def security():
    user = current_user()
    password_hash = user["password_hash"]
    masked_hash = password_hash[:7] + "••••••••••••••••••••••••" + password_hash[-8:]
    return render_template("security.html", user=user, masked_hash=masked_hash)


@app.route("/vault")
@login_required
def vault():
    user = current_user()
    masked_hash = user["password_hash"][:7] + "••••••••••••••••" + user["password_hash"][-8:]
    return render_template("vault.html", user=user, masked_hash=masked_hash)


@app.route("/security-report")
@login_required
def security_report():
    user = current_user()
    report = f"""SECUREAUTH — SECURITY REPORT\n{'=' * 38}\nAccount: {user['username']}\nEmail: {user['email']}\nPassword protection: bcrypt hashed (original password is never included)\nFailed attempts: {user['failed_attempts']} / {MAX_ATTEMPTS}\nLast login: {user['last_login'] or 'Not recorded'}\nAccount lockout: {'Active' if user['locked_until'] else 'Not active'}\nGenerated: {utcnow().isoformat()}\n\nThis is an educational security summary.\n"""
    return Response(report, mimetype="text/plain", headers={"Content-Disposition": "attachment; filename=secureauth-security-report.txt"})


@app.route("/reset-demo", methods=["POST"])
@login_required
def reset_demo():
    session["demo_reset_code"] = token_urlsafe(12)
    flash("Demo reset token created securely. In a real product, this would be emailed to you.", "success")
    return redirect(url_for("security"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user = current_user()
    log_event(user["id"], "LOGOUT")
    session.clear()
    flash("You have been logged out safely.", "success")
    return redirect(url_for("home"))

init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")