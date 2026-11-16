import os
import tempfile
import unittest
from unittest.mock import patch

import app as fraud_app


class SQLiteIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(
            self.temporary_directory.name,
            "instance",
            "integration.sqlite3",
        )
        self.engine_patch = patch.object(fraud_app, "DB_ENGINE", "sqlite")
        self.path_patch = patch.object(fraud_app, "DB_PATH", self.database_path)
        self.admin_patch = patch.object(fraud_app, "ADMIN_EMAIL", "admin@gmail.com")
        self.engine_patch.start()
        self.path_patch.start()
        self.admin_patch.start()
        self.addCleanup(self.engine_patch.stop)
        self.addCleanup(self.path_patch.stop)
        self.addCleanup(self.admin_patch.stop)

        fraud_app.app.config.update(TESTING=True)
        self.user_client = fraud_app.app.test_client()
        self.admin_client = fraud_app.app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def register(self, client, email):
        client.get("/signin")
        with client.session_transaction() as session:
            csrf = session["_csrf_token"]
        response = client.post("/register", data={
            "csrf_token": csrf,
            "email": email,
            "password": "integration password 123",
            "confirm_password": "integration password 123",
        })
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as session:
            return session["user_id"], session["_csrf_token"]

    def test_database_creation_auth_scan_dashboard_and_admin_features(self):
        user_id, user_csrf = self.register(self.user_client, "person@gmail.com")
        self.assertTrue(os.path.isfile(self.database_path))
        denied_edit = self.user_client.patch(
            "/api/patterns/1",
            json={"pattern_text": "unauthorized edit", "severity": "HIGH"},
            headers={"X-CSRF-Token": user_csrf},
        )
        self.assertEqual(denied_edit.status_code, 403)

        scan = self.user_client.post(
            "/api/analyze",
            json={"transactions": [{
                "account_ref": "ACC-1",
                "amount": "1250.25",
                "description": "urgent wire transfer for review",
            }]},
            headers={"X-CSRF-Token": user_csrf},
        )
        self.assertEqual(scan.status_code, 200)
        self.assertEqual(scan.json["results"][0]["risk"], "HIGH")

        stats = self.user_client.get("/api/stats")
        transactions = self.user_client.get("/api/transactions")
        detections = self.user_client.get("/api/detections")
        self.assertEqual(stats.status_code, 200)
        self.assertEqual(stats.json["transactions"], 1)
        self.assertEqual(transactions.json[0]["amount"], 1250.25)
        self.assertGreater(len(detections.json), 0)

        admin_id, admin_csrf = self.register(self.admin_client, "admin@gmail.com")
        self.assertNotEqual(admin_id, user_id)
        self.assertEqual(self.admin_client.get("/api/users").status_code, 200)

        added = self.admin_client.post(
            "/api/patterns",
            json={"pattern_text": "sqlite integration phrase", "severity": "LOW"},
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(added.status_code, 200)
        patterns = self.admin_client.get("/api/patterns")
        self.assertTrue(any(
            pattern["pattern_text"] == "sqlite integration phrase"
            for pattern in patterns.json
        ))

        pattern_id = next(
            pattern["id"]
            for pattern in patterns.json
            if pattern["pattern_text"] == "sqlite integration phrase"
        )
        edited = self.admin_client.patch(
            f"/api/patterns/{pattern_id}",
            json={
                "pattern_text": "sqlite integration edited phrase",
                "category": "Integration test",
                "severity": "HIGH",
            },
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(edited.status_code, 200)

        duplicate_add = self.admin_client.post(
            "/api/patterns",
            json={"pattern_text": "sqlite integration duplicate phrase"},
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(duplicate_add.status_code, 200)
        patterns = self.admin_client.get("/api/patterns")
        duplicate_id = next(
            pattern["id"]
            for pattern in patterns.json
            if pattern["pattern_text"] == "sqlite integration duplicate phrase"
        )
        duplicate_edit = self.admin_client.patch(
            f"/api/patterns/{pattern_id}",
            json={
                "pattern_text": "sqlite integration duplicate phrase",
                "category": "Integration test",
                "severity": "HIGH",
            },
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(duplicate_edit.status_code, 409)

        patterns = self.admin_client.get("/api/patterns")
        updated_pattern = next(
            pattern for pattern in patterns.json if pattern["id"] == pattern_id
        )
        self.assertEqual(
            updated_pattern["pattern_text"],
            "sqlite integration edited phrase",
        )
        deleted = self.admin_client.delete(
            f"/api/patterns/{pattern_id}",
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(
            self.admin_client.delete(
                f"/api/patterns/{duplicate_id}",
                headers={"X-CSRF-Token": admin_csrf},
            ).status_code,
            200,
        )

        suspended = self.admin_client.patch(
            f"/api/users/{user_id}",
            json={"is_active": False},
            headers={"X-CSRF-Token": admin_csrf},
        )
        self.assertEqual(suspended.status_code, 200)
        self.assertEqual(self.user_client.get("/api/stats").status_code, 401)


if __name__ == "__main__":
    unittest.main()
