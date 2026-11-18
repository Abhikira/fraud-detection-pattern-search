import csv
import hmac
import io
import os
import secrets
import sqlite3
import threading
from datetime import datetime
from decimal import Decimal, InvalidOperation

import mysql.connector
from dotenv import load_dotenv
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from algorithms import ALGORITHMS

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "").lower() == "true",
)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_ENGINE = os.getenv("DB_ENGINE", "sqlite").strip().lower()
DB_PATH = os.getenv(
    "DB_PATH",
    os.path.join(BASE_DIR, "instance", "fraud_detection.sqlite3"),
)
if not os.path.isabs(DB_PATH):
    DB_PATH = os.path.join(BASE_DIR, DB_PATH)
DB = dict(host=os.getenv("DB_HOST", "localhost"), user=os.getenv("DB_USER", "root"),
          password=os.getenv("DB_PASSWORD", ""), database=os.getenv("DB_NAME", "fraud_detection"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "arv.22139893@gmail.com").strip().lower()
EMAIL_DOMAINS = {"gmail.com", "proton.me", "protonmail.com", "protonmail.ch", "pm.me"}
RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
PUBLIC_ENDPOINTS = {"signin", "register", "privacy", "terms", "static"}
_SQLITE_INITIALIZED = set()
_SQLITE_INIT_LOCK = threading.Lock()


class SQLiteCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, statement, args=()):
        statement = statement.replace("INSERT IGNORE INTO", "INSERT OR IGNORE INTO")
        statement = statement.replace("%s", "?")
        values = tuple(
            value.isoformat(sep=" ", timespec="seconds")
            if isinstance(value, datetime)
            else format(value, "f")
            if isinstance(value, Decimal)
            else value
            for value in args
        )
        self.cursor.execute(statement, values)

    def fetchall(self):
        return [self._as_dict(row) for row in self.cursor.fetchall()]

    def fetchone(self):
        row = self.cursor.fetchone()
        return self._as_dict(row) if row is not None else None

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    @staticmethod
    def _as_dict(row):
        values = dict(row)
        if isinstance(values.get("amount"), str):
            values["amount"] = Decimal(values["amount"])
        return values


class SQLiteConnection:
    def __init__(self, connection):
        self.connection = connection

    def cursor(self, dictionary=False):
        return SQLiteCursor(self.connection.cursor())

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def initialize_sqlite_database():
    if DB_PATH in _SQLITE_INITIALIZED:
        return
    with _SQLITE_INIT_LOCK:
        if DB_PATH in _SQLITE_INITIALIZED:
            return
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        connection = sqlite3.connect(DB_PATH)
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            schema_path = os.path.join(BASE_DIR, "schema.sqlite.sql")
            with open(schema_path, encoding="utf-8") as schema_file:
                connection.executescript(schema_file.read())
            connection.commit()
        finally:
            connection.close()
        _SQLITE_INITIALIZED.add(DB_PATH)
def initialize_admin():
    email = ADMIN_EMAIL
    if not email:
        return

    connection = conn()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, role FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user:
            cursor.execute(
                "UPDATE users SET role='ADMIN' WHERE email=%s",
                (email,),
            )

        connection.commit()
    finally:
        connection.close()

def conn():
    if DB_ENGINE == "sqlite":
        initialize_sqlite_database()
        connection = sqlite3.connect(DB_PATH, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return SQLiteConnection(connection)
    if DB_ENGINE == "mysql":
        return mysql.connector.connect(**DB)
    raise RuntimeError("DB_ENGINE must be either 'sqlite' or 'mysql'.")


def query(sql, args=(), many=False):
    connection = conn()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(sql, args)
        return cursor.fetchall()
    finally:
        connection.close()


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


def email_is_allowed(email):
    if not email or len(email) > 254 or email.count("@") != 1 or any(ch.isspace() for ch in email):
        return False
    local, domain = email.rsplit("@", 1)
    return bool(local) and domain in EMAIL_DOMAINS


def api_error(message, status):
    if request.path.startswith("/api/"):
        return jsonify(error=message), status
    return render_template("error.html", message=message, status=status), status


@app.errorhandler(sqlite3.Error)
@app.errorhandler(mysql.connector.Error)
def handle_database_error(error):
    app.logger.exception("Database operation failed")
    return api_error(
        "The configured database is unavailable. Check DB_ENGINE and, if using MySQL, its credentials and schema.",
        503,
    )


@app.before_request
def enforce_access():
    if request.endpoint not in PUBLIC_ENDPOINTS:
        user_id = session.get("user_id")
        if not user_id:
            if request.path.startswith("/api/"):
                return jsonify(error="Sign in is required"), 401
            return redirect(url_for("signin"))
        users = query(
            "SELECT id, email, role, is_active FROM users WHERE id=%s",
            (user_id,),
        )
        if not users or not users[0]["is_active"]:
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify(error="This account is unavailable"), 401
            return redirect(url_for("signin"))
        g.user = users[0]

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get("_csrf_token")
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            return api_error("Invalid or missing CSRF token", 403)

    admin_endpoints = {
        "api_users",
        "update_user",
        "update_pattern",
        "delete_pattern",
    }
    if request.endpoint in admin_endpoints or (
        request.endpoint == "api_patterns" and request.method == "POST"
    ):
        if g.user["role"] != "ADMIN":
            return api_error("Administrator access is required", 403)


def clean(value):
    if isinstance(value, list):
        return [clean(item) for item in value]
    if isinstance(value, dict):
        return {key: clean(item) for key, item in value.items()}
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value


def overall_risk(matches):
    """Return the highest matched severity, escalating three or more hits to HIGH."""
    if not matches:
        return "CLEAN"
    top = max(matches, key=lambda match: RANK[match["severity"]])["severity"]
    return "HIGH" if len(matches) >= 3 else top


def analyze(records, algorithm, user_id):
    search = ALGORITHMS[algorithm]
    results, now = [], datetime.now()
    connection = conn()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM suspicious_patterns")
        patterns = cursor.fetchall()
        for record in records:
            cursor.execute(
                """INSERT INTO transactions (user_id, account_ref, description, amount, created_at)
                   VALUES (%s,%s,%s,%s,%s)""",
                (user_id, record["account_ref"], record["description"], record["amount"], now),
            )
            transaction_id, matches = cursor.lastrowid, []
            for pattern in patterns:
                positions = search(record["description"], pattern["pattern_text"])
                if positions:
                    severity = pattern["severity"].upper()
                    cursor.execute(
                        """INSERT INTO detection_results
                           (transaction_id, pattern_id, algorithm, match_count, positions, risk_level, detected_at)
                           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            transaction_id,
                            pattern["id"],
                            algorithm,
                            len(positions),
                            ",".join(map(str, positions)),
                            severity,
                            now,
                        ),
                    )
                    matches.append(
                        dict(
                            pattern=pattern["pattern_text"],
                            category=pattern["category"],
                            severity=severity,
                            positions=positions,
                            count=len(positions),
                            length=len(pattern["pattern_text"]),
                        )
                    )
            results.append(
                dict(id=transaction_id, **record, matches=matches, risk=overall_risk(matches))
            )
        connection.commit()
    finally:
        connection.close()
    return results


def parse_rows(rows):
    if not isinstance(rows, list):
        raise ValueError("Transactions must be a list.")

    records = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Each transaction must be an object.")
        raw_description = row.get("description") or ""
        if not isinstance(raw_description, str):
            raise ValueError("Transaction descriptions must be text.")
        description = raw_description.strip()
        if not description:
            continue
        raw_amount = row.get("amount")
        try:
            amount = Decimal(str(raw_amount or "0").strip())
        except (InvalidOperation, ValueError):
            raise ValueError("Transaction amounts must be valid numbers.") from None
        if not amount.is_finite() or amount < 0 or amount > Decimal("9999999999.99"):
            raise ValueError("Transaction amounts must be between 0 and 9999999999.99.")

        raw_account_ref = row.get("account_ref") or "UNKNOWN"
        if not isinstance(raw_account_ref, (str, int)):
            raise ValueError("Account references must be text.")
        records.append(
            dict(
                account_ref=str(raw_account_ref).strip()[:50] or "UNKNOWN",
                description=description,
                amount=amount,
            )
        )
    return records


def set_login_session(user):
    session.clear()
    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session["role"] = user["role"]
    csrf_token()


def render_auth(template, error=None, status=200, email=""):
    return render_template(template, error=error, email=email), status


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_auth("signin.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if not email_is_allowed(email):
        return render_auth(
            "signin.html",
            "Use a valid Gmail or Proton email address.",
            401,
            email,
        )

    users = query(
        "SELECT id, email, password_hash, role, is_active FROM users WHERE email=%s",
        (email,),
    )
    if not users:
        app.logger.warning("Login failed: user not found")
        return render_auth("signin.html", "Email or password is incorrect.", 401, email)

    if not users[0]["is_active"]:
        app.logger.warning("Login failed: inactive account")
        return render_auth("signin.html", "Account is inactive.", 401, email)

    if not check_password_hash(users[0]["password_hash"], password):
        app.logger.warning("Login failed: password verification failed")
        return render_auth("signin.html", "Email or password is incorrect.", 401, email)
    set_login_session(users[0])
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_auth("register.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirmation = request.form.get("confirm_password") or ""
    if not email_is_allowed(email):
        return render_auth("register.html", "Use a Gmail or Proton email address.", 400)
    if len(password) < 8 or len(password) > 128:
        return render_auth("register.html", "Password must be 8 to 128 characters.", 400)
    if password != confirmation:
        return render_auth("register.html", "Passwords do not match.", 400)

    role = "ADMIN" if email == ADMIN_EMAIL else "USER"
    connection = conn()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return render_auth("register.html", "An account with that email already exists.", 409)
        cursor.execute(
            """INSERT INTO users (email, password_hash, role, is_active, created_at)
               VALUES (%s,%s,%s,TRUE,%s)""",
            (email, generate_password_hash(password), role, datetime.now()),
        )
        user = dict(id=cursor.lastrowid, email=email, role=role, is_active=True)
        if role == "ADMIN":
            cursor.execute(
                "UPDATE transactions SET user_id=%s WHERE user_id IS NULL",
                (user["id"],),
            )
        connection.commit()
    finally:
        connection.close()
    set_login_session(user)
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("signin"))


@app.route("/")
def index():
    return render_template("index.html", is_admin=g.user["role"] == "ADMIN")


@app.get("/privacy")
def privacy():
    return render_template("privacy.html")


@app.get("/terms")
def terms():
    return render_template("terms.html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) if request.is_json else {}
    if data is None:
        return jsonify(error="Request body must contain valid JSON"), 400
    if not isinstance(data, dict):
        return jsonify(error="Request body must be a JSON object"), 400
    algorithm = request.form.get("algorithm") or data.get("algorithm") or "KMP"
    if not isinstance(algorithm, str):
        return jsonify(error="Algorithm must be a string"), 400
    algorithm = algorithm.upper()
    if algorithm not in ALGORITHMS:
        return jsonify(error="Unknown algorithm"), 400
    if "file" in request.files:
        try:
            text = request.files["file"].read().decode("utf-8-sig")
        except UnicodeDecodeError:
            return jsonify(error="CSV file must use UTF-8 encoding"), 400
        rows = list(csv.DictReader(io.StringIO(text)))
    else:
        rows = data.get("transactions", [])
    try:
        records = parse_rows(rows)
    except ValueError as error:
        return jsonify(error=str(error)), 400
    if not records:
        return jsonify(error="No valid transactions supplied"), 400
    return jsonify(
        clean(dict(algorithm=algorithm, results=analyze(records, algorithm, g.user["id"])))
    )


@app.get("/api/transactions")
def api_transactions():
    rows = query(
        """SELECT t.id, t.account_ref, t.description, t.amount, t.created_at,
                  COUNT(d.id) AS hits,
                  MAX(CASE UPPER(d.risk_level)
                      WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) AS risk_rank
           FROM transactions t LEFT JOIN detection_results d ON d.transaction_id=t.id
           WHERE t.user_id=%s
           GROUP BY t.id ORDER BY t.id DESC LIMIT 200""",
        (g.user["id"],),
    )
    names = {0: "CLEAN", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}
    for row in rows:
        row["risk"] = names[int(row.pop("risk_rank") or 0)]
    return jsonify(clean(rows))


@app.get("/api/detections")
def api_detections():
    rows = query(
        """SELECT d.id, d.transaction_id, p.pattern_text, p.category, d.algorithm,
                  d.match_count, d.positions, d.risk_level, d.detected_at
           FROM detection_results d
           JOIN suspicious_patterns p ON p.id=d.pattern_id
           JOIN transactions t ON t.id=d.transaction_id
           WHERE t.user_id=%s ORDER BY d.id DESC LIMIT 300""",
        (g.user["id"],),
    )
    for row in rows:
        row["risk_level"] = row["risk_level"].upper()
    return jsonify(clean(rows))


@app.get("/api/stats")
def api_stats():
    user_id = g.user["id"]
    stats = query(
        """SELECT (SELECT COUNT(*) FROM transactions WHERE user_id=%s) AS transactions,
                  (SELECT COUNT(DISTINCT d.transaction_id) FROM detection_results d
                   JOIN transactions t ON t.id=d.transaction_id WHERE t.user_id=%s) AS flagged,
                  (SELECT COUNT(*) FROM detection_results d
                   JOIN transactions t ON t.id=d.transaction_id WHERE t.user_id=%s) AS detections,
                  (SELECT COUNT(*) FROM suspicious_patterns) AS patterns""",
        (user_id, user_id, user_id),
    )[0]
    return jsonify(clean(stats))


@app.route("/api/patterns", methods=["GET", "POST"])
def api_patterns():
    if request.method == "POST":
        data = request.json or {}
        text = (data.get("pattern_text") or "").strip()
        severity = (data.get("severity") or "MEDIUM").upper()
        category = (data.get("category") or "Custom").strip()[:60]
        if not text or len(text) > 255 or severity not in RANK:
            return jsonify(error="Pattern text and valid severity are required"), 400
        connection = conn()
        try:
            connection.cursor().execute(
                """INSERT IGNORE INTO suspicious_patterns (pattern_text, category, severity)
                   VALUES (%s,%s,%s)""",
                (text, category or "Custom", severity),
            )
            connection.commit()
        finally:
            connection.close()
    patterns = query("SELECT * FROM suspicious_patterns ORDER BY severity DESC, pattern_text")
    for pattern in patterns:
        pattern["severity"] = pattern["severity"].upper()
    return jsonify(clean(patterns))


@app.delete("/api/patterns/<int:pid>")
def delete_pattern(pid):
    connection = conn()
    try:
        connection.cursor().execute("DELETE FROM suspicious_patterns WHERE id=%s", (pid,))
        connection.commit()
    finally:
        connection.close()
    return jsonify(ok=True)


@app.patch("/api/patterns/<int:pid>")
def update_pattern(pid):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Request body must be a JSON object"), 400

    text = data.get("pattern_text")
    category = data.get("category", "Custom")
    severity = data.get("severity", "MEDIUM")
    if not isinstance(text, str) or not isinstance(category, str) or not isinstance(severity, str):
        return jsonify(error="Pattern text, category, and severity must be text"), 400
    text = text.strip()
    category = (category.strip() or "Custom")[:60]
    severity = severity.upper()
    if not text or len(text) > 255 or severity not in RANK:
        return jsonify(error="Pattern text and valid severity are required"), 400
    if not query("SELECT id FROM suspicious_patterns WHERE id=%s", (pid,)):
        return jsonify(error="Pattern not found"), 404
    if query(
        "SELECT id FROM suspicious_patterns WHERE pattern_text=%s AND id<>%s",
        (text, pid),
    ):
        return jsonify(error="A pattern with that text already exists"), 409

    connection = conn()
    try:
        connection.cursor().execute(
            """UPDATE suspicious_patterns
               SET pattern_text=%s, category=%s, severity=%s
               WHERE id=%s""",
            (text, category, severity, pid),
        )
        connection.commit()
    except (sqlite3.IntegrityError, mysql.connector.IntegrityError):
        connection.rollback()
        return jsonify(error="A pattern with that text already exists"), 409
    finally:
        connection.close()
    return jsonify(ok=True)


@app.get("/api/users")
def api_users():
    return jsonify(
        clean(
            query(
                "SELECT id, email, role, is_active, created_at FROM users ORDER BY id"
            )
        )
    )


@app.patch("/api/users/<int:user_id>")
def update_user(user_id):
    data = request.json or {}
    is_active = data.get("is_active")
    if not isinstance(is_active, bool):
        return jsonify(error="is_active must be true or false"), 400
    if user_id == g.user["id"]:
        return jsonify(error="You cannot suspend your own account"), 400
    users = query("SELECT id, role FROM users WHERE id=%s", (user_id,))
    if not users or users[0]["role"] != "USER":
        return jsonify(error="User account not found"), 404
    connection = conn()
    try:
        connection.cursor().execute(
            "UPDATE users SET is_active=%s WHERE id=%s",
            (is_active, user_id),
        )
        connection.commit()
    finally:
        connection.close()
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
