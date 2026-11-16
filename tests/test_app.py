from io import BytesIO
import unittest
from unittest.mock import patch

from werkzeug.security import check_password_hash, generate_password_hash

import app as fraud_app


CSRF = "test-csrf-token"
USER = {"id": 2, "email": "user@gmail.com", "role": "USER", "is_active": True}
ADMIN = {"id": 1, "email": "abc@gmail.com", "role": "ADMIN", "is_active": True}
PATTERN = {
    "id": 7,
    "pattern_text": "wire details have changed",
    "category": "Business email compromise",
    "severity": "High",
}


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rows = []
        self.lastrowid = 101
        self.rowcount = 1

    def execute(self, sql, args=()):
        self.connection.operations.append((sql, args))
        if sql.startswith("SELECT id FROM users WHERE email"):
            self.rows = []
        elif sql.startswith("SELECT * FROM suspicious_patterns"):
            self.rows = [self.connection.pattern]
        elif sql.startswith("INSERT INTO transactions"):
            self.lastrowid = 101
        elif sql.startswith("INSERT INTO detection_results"):
            self.connection.detections.append(args)
        elif sql.startswith("INSERT INTO users"):
            self.connection.user_insert = args
        elif sql.startswith("UPDATE transactions SET user_id"):
            self.connection.attached_existing_records = args[0]

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeConnection:
    def __init__(self):
        self.pattern = dict(PATTERN)
        self.operations = []
        self.detections = []
        self.committed = False
        self.closed = False
        self.user_insert = None
        self.attached_existing_records = None

    def cursor(self, dictionary=False):
        return FakeCursor(self)

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


class AppRouteTests(unittest.TestCase):
    def setUp(self):
        fraud_app.app.config.update(TESTING=True)
        self.client = fraud_app.app.test_client()

    def authenticate(self, user=USER):
        with self.client.session_transaction() as session:
            session["user_id"] = user["id"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            session["_csrf_token"] = CSRF

    def auth_query(self, user=USER):
        def fake_query(sql, args=(), many=False):
            if "FROM users WHERE id=%s" in sql:
                return [user]
            return []
        return fake_query

    def test_public_auth_legal_pages_and_protected_home(self):
        self.assertEqual(self.client.get("/").status_code, 302)
        for path, text in (
            ("/signin", b"Sign in"),
            ("/register", b"Create an account"),
            ("/privacy", b"Privacy"),
            ("/terms", b"Terms of use"),
            ("/static/favicon.svg", b"<svg"),
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(text, response.data)
                response.close()

        self.authenticate()
        with patch.object(fraud_app, "query", side_effect=self.auth_query()):
            response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Detectorite", response.data)

    def test_registration_hashes_password_and_grants_configured_admin(self):
        connection = FakeConnection()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = CSRF
        with patch.object(fraud_app, "conn", return_value=connection):
            response = self.client.post("/register", data={
                "csrf_token": CSRF,
                "email": "abc@gmail.com",
                "password": "long test password 123",
                "confirm_password": "long test password 123",
            })

        self.assertEqual(response.status_code, 302)
        email, password_hash, role, _ = connection.user_insert
        self.assertEqual(email, "abc@gmail.com")
        self.assertEqual(role, "ADMIN")
        self.assertNotEqual(password_hash, "long test password 123")
        self.assertTrue(check_password_hash(password_hash, "long test password 123"))
        self.assertEqual(connection.attached_existing_records, 101)
        self.assertTrue(connection.committed)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_id"], 101)
            self.assertEqual(session["role"], "ADMIN")

    def test_registration_requires_provider_email_and_minimum_password_length(self):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = CSRF
        invalid_email = self.client.post("/register", data={
            "csrf_token": CSRF,
            "email": "person@example.com",
            "password": "long test password 123",
            "confirm_password": "long test password 123",
        })
        self.assertEqual(invalid_email.status_code, 400)
        short_password = self.client.post("/register", data={
            "csrf_token": CSRF,
            "email": "person@proton.me",
            "password": "short",
            "confirm_password": "short",
        })
        self.assertEqual(short_password.status_code, 400)

    def test_registration_accepts_eight_character_password(self):
        connection = FakeConnection()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = CSRF
        with patch.object(fraud_app, "conn", return_value=connection):
            response = self.client.post("/register", data={
                "csrf_token": CSRF,
                "email": "person@proton.me",
                "password": "bluebird",
                "confirm_password": "bluebird",
            })

        self.assertEqual(response.status_code, 302)
        self.assertTrue(check_password_hash(connection.user_insert[1], "bluebird"))

    def test_auth_forms_show_database_configuration_error(self):
        from mysql.connector import Error

        with self.client.session_transaction() as session:
            session["_csrf_token"] = CSRF
        with patch.object(fraud_app, "query", side_effect=Error("access denied")):
            signin = self.client.post("/signin", data={
                "csrf_token": CSRF,
                "email": "person@gmail.com",
                "password": "bluebird",
            })
        self.assertEqual(signin.status_code, 503)
        self.assertIn(b"credentials and schema", signin.data)

        with patch.object(fraud_app, "conn", side_effect=Error("access denied")):
            register = self.client.post("/register", data={
                "csrf_token": CSRF,
                "email": "person@proton.me",
                "password": "bluebird",
                "confirm_password": "bluebird",
            })
        self.assertEqual(register.status_code, 503)
        self.assertIn(b"credentials and schema", register.data)

    def test_signin_uses_password_hash_and_csrf(self):
        password_hash = generate_password_hash("long test password 123")
        with self.client.session_transaction() as session:
            session["_csrf_token"] = CSRF
        account = dict(ADMIN, password_hash=password_hash)
        with patch.object(fraud_app, "query", return_value=[account]):
            response = self.client.post("/signin", data={
                "csrf_token": CSRF,
                "email": "abc@gmail.com",
                "password": "long test password 123",
            })
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertEqual(session["user_id"], ADMIN["id"])
            self.assertIn("_csrf_token", session)

        with patch.object(fraud_app, "query", side_effect=self.auth_query(ADMIN)):
            missing_csrf = self.client.post("/logout")
        self.assertEqual(missing_csrf.status_code, 403)

    def test_signin_keeps_email_after_password_error(self):
        with self.client.session_transaction() as session:
            session["_csrf_token"] = CSRF
        account = dict(
            ADMIN,
            password_hash=generate_password_hash("correct password"),
        )
        with patch.object(fraud_app, "query", return_value=[account]):
            response = self.client.post("/signin", data={
                "csrf_token": CSRF,
                "email": "ABC@gmail.com",
                "password": "incorrect password",
            })

        self.assertEqual(response.status_code, 401)
        self.assertIn(b'value="abc@gmail.com"', response.data)
        self.assertIn(b"Email or password is incorrect.", response.data)

    def test_api_authentication_and_admin_permissions(self):
        self.assertEqual(self.client.get("/api/stats").status_code, 401)
        self.authenticate()
        with patch.object(fraud_app, "query", side_effect=self.auth_query()):
            response = self.client.post(
                "/api/patterns",
                json={"pattern_text": "new phrase", "severity": "HIGH"},
                headers={"X-CSRF-Token": CSRF},
            )
        self.assertEqual(response.status_code, 403)
        with patch.object(fraud_app, "query", side_effect=self.auth_query()):
            self.assertEqual(self.client.get("/api/users").status_code, 403)

    def test_user_api_reads_are_scoped_and_severities_normalized(self):
        self.authenticate()
        stats = {"transactions": 1, "flagged": 1, "detections": 1, "patterns": 1}
        transaction = {"id": 101, "risk_rank": 3, "account_ref": "ACC-1"}
        detection = {"transaction_id": 101, "risk_level": "Medium"}
        with patch.object(fraud_app, "query", side_effect=[
            [USER], [stats],
            [USER], [transaction],
            [USER], [detection],
            [USER], [PATTERN],
        ]) as query:
            self.assertEqual(self.client.get("/api/stats").json["transactions"], 1)
            self.assertEqual(self.client.get("/api/transactions").json[0]["risk"], "HIGH")
            self.assertEqual(self.client.get("/api/detections").json[0]["risk_level"], "MEDIUM")
            self.assertEqual(self.client.get("/api/patterns").json[0]["severity"], "HIGH")
        transaction_query = query.call_args_list[3].args
        self.assertIn("WHERE t.user_id=%s", transaction_query[0])
        self.assertEqual(transaction_query[1], (USER["id"],))

    def test_analyze_inserts_user_owned_transaction_and_detection(self):
        self.authenticate()
        connection = FakeConnection()
        with patch.object(fraud_app, "query", side_effect=self.auth_query()), patch.object(
            fraud_app, "conn", return_value=connection
        ):
            response = self.client.post("/api/analyze", json={
                "algorithm": "KMP",
                "transactions": [{
                    "account_ref": "ACC-1",
                    "amount": "500",
                    "description": "The WIRE details have changed",
                }],
            }, headers={"X-CSRF-Token": CSRF})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["results"][0]["risk"], "HIGH")
        self.assertEqual(connection.operations[1][1][0], USER["id"])
        self.assertEqual(connection.detections[0][4], "4")
        self.assertEqual(connection.detections[0][5], "HIGH")
        self.assertTrue(connection.committed)

    def test_analyze_rejects_invalid_amounts_and_malformed_csv(self):
        self.authenticate()
        with patch.object(fraud_app, "query", side_effect=self.auth_query()):
            invalid_amount = self.client.post("/api/analyze", json={
                "transactions": [{
                    "account_ref": "ACC-1",
                    "amount": "not-a-number",
                    "description": "Review this payment",
                }],
            }, headers={"X-CSRF-Token": CSRF})
            non_finite_amount = self.client.post("/api/analyze", json={
                "transactions": [{
                    "account_ref": "ACC-1",
                    "amount": "Infinity",
                    "description": "Review this payment",
                }],
            }, headers={"X-CSRF-Token": CSRF})
            malformed_csv = self.client.post("/api/analyze", data={
                "file": (BytesIO(b"account_ref,description,amount\nACC-1,\xff,1"), "scan.csv"),
            }, content_type="multipart/form-data", headers={"X-CSRF-Token": CSRF})

        self.assertEqual(invalid_amount.status_code, 400)
        self.assertIn("valid numbers", invalid_amount.json["error"])
        self.assertEqual(non_finite_amount.status_code, 400)
        self.assertIn("between 0 and", non_finite_amount.json["error"])
        self.assertEqual(malformed_csv.status_code, 400)
        self.assertIn("UTF-8", malformed_csv.json["error"])

    def test_analyze_rejects_non_object_json_and_non_string_algorithm(self):
        self.authenticate()
        with patch.object(fraud_app, "query", side_effect=self.auth_query()):
            non_object = self.client.post(
                "/api/analyze",
                json=[],
                headers={"X-CSRF-Token": CSRF},
            )
            invalid_algorithm = self.client.post(
                "/api/analyze",
                json={"algorithm": 123, "transactions": []},
                headers={"X-CSRF-Token": CSRF},
            )

        self.assertEqual(non_object.status_code, 400)
        self.assertIn("JSON object", non_object.json["error"])
        self.assertEqual(invalid_algorithm.status_code, 400)
        self.assertIn("Algorithm must be a string", invalid_algorithm.json["error"])

    def test_csv_scan_and_pattern_admin_operations(self):
        self.authenticate(ADMIN)
        connection = FakeConnection()
        with patch.object(fraud_app, "query", side_effect=[[ADMIN], [PATTERN]]), patch.object(
            fraud_app, "conn", return_value=connection
        ):
            added = self.client.post("/api/patterns", json={
                "pattern_text": "wire details have changed",
                "category": "Business email compromise",
                "severity": "HIGH",
            }, headers={"X-CSRF-Token": CSRF})
        self.assertEqual(added.status_code, 200)
        self.assertIn("INSERT IGNORE INTO suspicious_patterns", connection.operations[0][0])

        connection = FakeConnection()
        with patch.object(fraud_app, "query", side_effect=self.auth_query(ADMIN)), patch.object(
            fraud_app, "conn", return_value=connection
        ):
            deleted = self.client.delete("/api/patterns/7", headers={"X-CSRF-Token": CSRF})
        self.assertEqual(deleted.json, {"ok": True})
        self.assertIn("DELETE FROM suspicious_patterns", connection.operations[0][0])

        self.authenticate()
        connection = FakeConnection()
        with patch.object(fraud_app, "query", side_effect=self.auth_query()), patch.object(
            fraud_app, "conn", return_value=connection
        ):
            scanned = self.client.post("/api/analyze", data={
                "algorithm": "RABIN_KARP",
                "file": (BytesIO(b"account_ref,description,amount\nACC-2,gift card payment,750\n"), "scan.csv"),
            }, content_type="multipart/form-data", headers={"X-CSRF-Token": CSRF})
        self.assertEqual(scanned.status_code, 200)
        self.assertEqual(scanned.json["algorithm"], "RABIN_KARP")

    def test_admin_can_manage_users_but_not_suspend_self(self):
        self.authenticate(ADMIN)
        with patch.object(fraud_app, "query", side_effect=[[ADMIN], [USER]]):
            users = self.client.get("/api/users")
        self.assertEqual(users.status_code, 200)
        self.assertEqual(users.json[0]["id"], USER["id"])

        with patch.object(fraud_app, "query", side_effect=self.auth_query(ADMIN)):
            response = self.client.patch("/api/users/1", json={"is_active": False},
                                         headers={"X-CSRF-Token": CSRF})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
