"""
Comprehensive automated test suite for JWT authentication, role authorization,
all API endpoints, statistics, CSV export, and Web routes for Student Logbook.
"""

import json
import time
import unittest
from app import app, mysql


class TestStudentLogbookJWT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.testing = True
        cls.client = app.test_client()

        # Unique suffix for test run
        cls.test_suffix = str(int(time.time()))
        cls.student_adm = f"TEST{cls.test_suffix}"
        cls.student_name = f"Test Student {cls.test_suffix}"
        cls.student_email = f"student_{cls.test_suffix}@test.com"
        cls.student_password = "password123"
        cls.supervisor_id = 1  # Existing supervisor Brian Gitau (id 1)

        # Supervisor credentials
        cls.supervisor_email = "gitaubrian@gmail.com"
        cls.supervisor_password = "supervisor123"

        with app.app_context():
            cur = mysql.connection.cursor()
            from werkzeug.security import generate_password_hash
            hashed_pw = generate_password_hash(cls.supervisor_password)
            cur.execute("UPDATE supervisor SET password=%s WHERE supervisor_id=%s", (hashed_pw, cls.supervisor_id))
            mysql.connection.commit()
            cur.close()

        cls.student_token = None
        cls.supervisor_token = None
        cls.student_id = None
        cls.created_entry_id = None

    @classmethod
    def tearDownClass(cls):
        # Clean up test entries, test students, and any created test supervisor
        with app.app_context():
            cur = mysql.connection.cursor()
            if cls.student_id:
                cur.execute("DELETE FROM logbook_entries WHERE student_id=%s", (cls.student_id,))
                cur.execute("DELETE FROM students WHERE student_id=%s", (cls.student_id,))
            cur.execute("DELETE FROM students WHERE email=%s OR adm_no=%s", (cls.student_email, cls.student_adm))
            cur.execute("DELETE FROM supervisor WHERE email LIKE 'test_sup_%@test.com'")
            mysql.connection.commit()
            cur.close()

    def test_01_healthcheck(self):
        """Test GET /api/health returns database status."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("status"), "ok")

    def test_02_get_supervisors_list(self):
        """Test GET /api/supervisors returns list for student registration."""
        res = self.client.get("/api/supervisors")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIsInstance(data.get("supervisors"), list)
        self.assertGreater(len(data["supervisors"]), 0)

    def test_03_register_supervisor(self):
        """Test POST /api/register_supervisor creates a new supervisor."""
        payload = {
            "full_name": f"Dr. Supervisor {self.test_suffix}",
            "email": f"test_sup_{self.test_suffix}@test.com",
            "password": "supervisor_pw_123",
            "department": "Computer Science"
        }
        res = self.client.post("/api/register_supervisor", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("supervisor_id", data)

    def test_04_register_student(self):
        """Test POST /api/register creates a new student."""
        payload = {
            "adm_no": self.student_adm,
            "full_name": self.student_name,
            "email": self.student_email,
            "password": self.student_password,
            "supervisor_id": self.supervisor_id
        }
        res = self.client.post("/api/register", json=payload)
        data = res.get_json()
        self.assertEqual(res.status_code, 201)
        self.assertTrue(data.get("success"))

    def test_05_register_duplicate_student_fails(self):
        """Test POST /api/register fails with duplicate email/adm_no."""
        payload = {
            "adm_no": self.student_adm,
            "full_name": self.student_name,
            "email": self.student_email,
            "password": self.student_password,
            "supervisor_id": self.supervisor_id
        }
        res = self.client.post("/api/register", json=payload)
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("success"))

    def test_06_login_student_success(self):
        """Test POST /api/login authenticates student and issues JWT."""
        payload = {
            "email": self.student_email,
            "password": self.student_password
        }
        res = self.client.post("/api/login", json=payload)
        data = res.get_json()
        self.assertEqual(res.status_code, 200)
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("role"), "student")
        self.assertIn("token", data)

        self.__class__.student_token = data["token"]
        self.__class__.student_id = data["user"]["id"]

    def test_07_login_supervisor_success(self):
        """Test POST /api/login authenticates supervisor and issues JWT."""
        payload = {
            "email": self.supervisor_email,
            "password": self.supervisor_password
        }
        res = self.client.post("/api/login", json=payload)
        data = res.get_json()
        self.assertEqual(res.status_code, 200)
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("role"), "supervisor")
        self.assertIn("token", data)

        self.__class__.supervisor_token = data["token"]

    def test_08_login_invalid_credentials_fails(self):
        """Test POST /api/login rejects invalid password."""
        payload = {
            "email": self.student_email,
            "password": "wrongpassword"
        }
        res = self.client.post("/api/login", json=payload)
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertFalse(data.get("success"))

    def test_09_me_endpoint_with_jwt(self):
        """Test GET /api/me returns user identity from JWT."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        res = self.client.get("/api/me", headers=headers)
        data = res.get_json()
        self.assertEqual(res.status_code, 200)
        self.assertTrue(data.get("success"))
        self.assertEqual(data["user"]["email"], self.student_email)
        self.assertEqual(data["user"]["role"], "student")

    def test_10_unauthorized_when_token_missing(self):
        """Test protected endpoint rejects request without token."""
        unauth_client = app.test_client()
        res = unauth_client.get("/api/view_entries")
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertFalse(data.get("success"))

    def test_11_unauthorized_when_token_invalid(self):
        """Test protected endpoint rejects request with invalid token."""
        headers = {"Authorization": "Bearer invalid.fake.token"}
        res = self.client.get("/api/view_entries", headers=headers)
        self.assertEqual(res.status_code, 401)
        data = res.get_json()
        self.assertFalse(data.get("success"))

    def test_12_role_permission_forbidden(self):
        """Test student token cannot access supervisor dashboard (403 Forbidden)."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        res = self.client.get("/api/supervisor_dashboard", headers=headers)
        self.assertEqual(res.status_code, 403)

    def test_13_supervisor_cannot_add_student_entry(self):
        """Test supervisor token cannot add logbook entry (403 Forbidden)."""
        headers = {"Authorization": f"Bearer {self.supervisor_token}"}
        payload = {
            "entry_date": "2026-08-27",
            "activity": "Supervisor trying to add entry",
            "hours_worked": 4
        }
        res = self.client.post("/api/add_entry", json=payload, headers=headers)
        self.assertEqual(res.status_code, 403)

    def test_14_student_add_entry(self):
        """Test POST /api/add_entry creates a logbook entry for student."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        payload = {
            "entry_date": "2026-08-27",
            "activity": "Implemented JWT authentication and verified API endpoints",
            "hours_worked": 6
        }
        res = self.client.post("/api/add_entry", json=payload, headers=headers)
        data = res.get_json()
        self.assertEqual(res.status_code, 201)
        self.assertTrue(data.get("success"))
        self.assertIn("entry_id", data)
        self.__class__.created_entry_id = data["entry_id"]

    def test_15_student_view_entries(self):
        """Test GET /api/view_entries returns student's entries."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        res = self.client.get("/api/view_entries", headers=headers)
        self.assertEqual(res.status_code, 200)
        entries = res.get_json()
        self.assertIsInstance(entries, list)
        self.assertTrue(any(e["entry_id"] == self.created_entry_id for e in entries))

    def test_16_student_stats(self):
        """Test GET /api/stats returns metrics for student."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        res = self.client.get("/api/stats", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertGreaterEqual(data["stats"]["total_entries"], 1)
        self.assertGreaterEqual(data["stats"]["total_hours"], 6)

    def test_17_export_entries_csv(self):
        """Test GET /api/export_entries returns CSV file."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        res = self.client.get("/api/export_entries", headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")
        csv_text = res.get_data(as_text=True)
        self.assertIn("Entry ID,Date,Activity / Work Done,Hours Worked,Status,Supervisor Comments", csv_text)
        self.assertIn("Implemented JWT authentication", csv_text)

    def test_18_student_get_single_entry(self):
        """Test GET /api/entries/<entry_id> returns entry details."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        res = self.client.get(f"/api/entries/{self.created_entry_id}", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["entry"]["entry_id"], self.created_entry_id)

    def test_19_student_edit_entry(self):
        """Test PUT /api/entries/<entry_id> updates entry."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        payload = {
            "entry_date": "2026-08-27",
            "activity": "Updated activity: Configured JWT security and tested full test suite",
            "hours_worked": 8
        }
        res = self.client.put(f"/api/entries/{self.created_entry_id}", json=payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))

    def test_20_supervisor_dashboard(self):
        """Test GET /api/supervisor_dashboard lists students assigned to supervisor."""
        headers = {"Authorization": f"Bearer {self.supervisor_token}"}
        res = self.client.get("/api/supervisor_dashboard", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("students", data)
        self.assertTrue(any(s["student_id"] == self.student_id for s in data["students"]))

    def test_21_supervisor_stats(self):
        """Test GET /api/supervisor/stats returns supervisor overview."""
        headers = {"Authorization": f"Bearer {self.supervisor_token}"}
        res = self.client.get("/api/supervisor/stats", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("total_assigned_students", data["stats"])
        self.assertIn("pending_reviews", data["stats"])

    def test_22_supervisor_view_student_entries(self):
        """Test GET /api/supervisor/student_entries/<student_id>."""
        headers = {"Authorization": f"Bearer {self.supervisor_token}"}
        res = self.client.get(f"/api/supervisor/student_entries/{self.student_id}", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("entries", data)
        self.assertTrue(any(e["entry_id"] == self.created_entry_id for e in data["entries"]))

    def test_23_supervisor_get_entry_details(self):
        """Test GET /api/supervisor/entries/<entry_id>."""
        headers = {"Authorization": f"Bearer {self.supervisor_token}"}
        res = self.client.get(f"/api/supervisor/entries/{self.created_entry_id}", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["entry"]["entry_id"], self.created_entry_id)

    def test_24_supervisor_review_entry(self):
        """Test PUT /api/supervisor/entries/<entry_id> to approve entry."""
        headers = {"Authorization": f"Bearer {self.supervisor_token}"}
        payload = {
            "supervisor_comment": "Excellent work on JWT authentication and testing!",
            "status": "approved"
        }
        res = self.client.put(f"/api/supervisor/entries/{self.created_entry_id}", json=payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))

        # Verify status was updated
        check_res = self.client.get(f"/api/supervisor/entries/{self.created_entry_id}", headers=headers)
        check_data = check_res.get_json()
        self.assertEqual(check_data["entry"]["status"], "approved")
        self.assertEqual(check_data["entry"]["supervisor_comment"], "Excellent work on JWT authentication and testing!")

    def test_25_change_password(self):
        """Test PUT /api/change_password securely updates password."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        payload = {
            "old_password": self.student_password,
            "new_password": "new_secure_password_456"
        }
        res = self.client.put("/api/change_password", json=payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))

        # Verify login works with new password
        login_res = self.client.post("/api/login", json={"email": self.student_email, "password": "new_secure_password_456"})
        self.assertEqual(login_res.status_code, 200)
        self.assertTrue(login_res.get_json().get("success"))

    def test_26_student_delete_entry(self):
        """Test DELETE /api/delete_entry/<entry_id> deletes entry."""
        headers = {"Authorization": f"Bearer {self.student_token}"}
        res = self.client.delete(f"/api/delete_entry/{self.created_entry_id}", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))

        # Verify entry no longer exists
        get_res = self.client.get(f"/api/entries/{self.created_entry_id}", headers=headers)
        self.assertEqual(get_res.status_code, 404)

    def test_27_web_template_routes(self):
        """Test HTML rendering of web routes."""
        client = app.test_client()

        # GET / redirects to login when not authenticated
        res = client.get("/")
        self.assertEqual(res.status_code, 302)

        # GET /login renders login page
        res = client.get("/login")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Student Logbook Login", res.get_data(as_text=True))

        # GET /register renders registration page with supervisors
        res = client.get("/register")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Student Registration", res.get_data(as_text=True))

    def test_28_logout(self):
        """Test POST /api/logout returns success."""
        res = self.client.post("/api/logout")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))

    def test_29_forgot_password_and_reset(self):
        """Test POST /api/forgot_password and /api/reset_password full flow."""
        # 1. Request password reset
        res = self.client.post("/api/forgot_password", json={"email": self.student_email})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        reset_token = data.get("reset_token")
        self.assertIsNotNone(reset_token)

        # 2. Reset password with valid token
        new_pwd = "new_secure_pwd_123"
        reset_res = self.client.post("/api/reset_password", json={
            "reset_token": reset_token,
            "new_password": new_pwd
        })
        self.assertEqual(reset_res.status_code, 200)
        reset_data = reset_res.get_json()
        self.assertTrue(reset_data.get("success"))

        # 3. Verify student can now login with new password
        login_res = self.client.post("/api/login", json={
            "email": self.student_email,
            "password": new_pwd
        })
        self.assertEqual(login_res.status_code, 200)
        login_data = login_res.get_json()
        self.assertTrue(login_data.get("success"))

    def test_30_forgot_password_unknown_email(self):
        """Test POST /api/forgot_password with non-existent email returns 404."""
        res = self.client.post("/api/forgot_password", json={"email": "nonexistent_user_99999@test.com"})
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertFalse(data.get("success"))


if __name__ == "__main__":
    unittest.main(verbosity=2)


