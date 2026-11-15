"""Runs the app's real data layer against a real Postgres (no mocks except the outgoing email)."""
import re
import unittest

from datetime import datetime, timedelta, timezone

from pg_fixture import SchemaTestCase, requires_pg, psycopg2  # must come first: adds tests/ to sys.path
from app_loader import load_app


PW = "Str0ng!Pass"


@requires_pg
class DatabaseIntegrationTests(SchemaTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.ns = load_app()
        cls.ns["DATABASE_URL"] = cls.url
        cls.ns["PBKDF2_ITERATIONS"] = 1000
        cls.ns["_init_db_cached"]()

    def setUp(self):
        self.sql("TRUNCATE users RESTART IDENTITY CASCADE")
        self.sent = []
        self.ns["OTP_ASYNC_DELIVERY"] = False  # deterministic: deliver inline
        self.ns["send_reset_email_brevo"] = lambda email, name, user, otp: (self.sent.append((email, otp)) or (True, "ok"))

    def make_user(self, username="aarav.s", email="aarav@example.com", pw=PW):
        ok, msg = self.ns["register_user"](username, "Aarav Sharma", email, pw)
        self.assertTrue(ok, msg)
        return self.ns["authenticate_user"](username, pw)

    # ---- schema -------------------------------------------------------------
    def test_init_is_idempotent_and_creates_tables_with_rls(self):
        self.ns["_init_db_cached"]()  # second run must not fail
        rows = self.sql(
            "SELECT c.relname, c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = %s AND c.relname IN ('users','password_resets','scans')", (self.schema,))
        self.assertEqual({r[0]: r[1] for r in rows}, {"users": True, "password_resets": True, "scans": True})

    # ---- accounts -----------------------------------------------------------
    def test_register_then_login_roundtrip(self):
        user = self.make_user()
        self.assertEqual(user[1:4], ("aarav.s", "Aarav Sharma", "aarav@example.com"))
        self.assertRegex(user[4], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
        self.assertIsNone(self.ns["authenticate_user"]("aarav.s", "wrong"))
        self.assertIsNotNone(self.ns["authenticate_user"]("AARAV.S", PW))  # case-insensitive username
        stored = self.sql("SELECT password_hash FROM users")[0][0]
        self.assertTrue(stored.startswith("pbkdf2$"))

    def test_duplicate_username_and_email_rejected(self):
        self.make_user()
        ok, msg = self.ns["register_user"]("aarav.s", "X", "other@example.com", PW)
        self.assertFalse(ok)
        ok, msg = self.ns["register_user"]("other", "X", "AARAV@EXAMPLE.COM", PW)
        self.assertFalse(ok)
        self.assertIn("email", msg.lower())
        self.assertEqual(self.sql("SELECT count(*) FROM users")[0][0], 1)

    def test_database_enforces_unique_email_even_if_app_check_is_bypassed(self):
        self.make_user()
        with self.assertRaises(psycopg2.errors.UniqueViolation):
            self.sql("INSERT INTO users (username, full_name, email, password_hash) VALUES ('b','B','AARAV@example.com','x')")

    def test_legacy_sha256_hash_is_upgraded_on_login(self):
        import hashlib
        legacy = hashlib.sha256(b"oldpass").hexdigest()
        self.sql("INSERT INTO users (username, full_name, email, password_hash) VALUES ('old','Old','old@example.com',%s)", (legacy,))
        self.assertIsNotNone(self.ns["authenticate_user"]("old", "oldpass"))
        self.assertTrue(self.sql("SELECT password_hash FROM users WHERE username='old'")[0][0].startswith("pbkdf2$"))
        self.assertIsNotNone(self.ns["authenticate_user"]("old", "oldpass"))  # still works after upgrade

    def test_profile_and_password_changes_persist(self):
        user = self.make_user()
        self.assertEqual(self.ns["update_user_profile"](user[0], "New Name", "NEW@Example.com", PW), (True, "Profile updated successfully!"))
        self.assertEqual(self.sql("SELECT full_name, email FROM users")[0], ("New Name", "new@example.com"))
        self.assertFalse(self.ns["change_user_password"](user[0], "bad", "NewStr0ng!1")[0])
        self.assertTrue(self.ns["change_user_password"](user[0], PW, "NewStr0ng!1")[0])
        self.assertIsNone(self.ns["authenticate_user"]("aarav.s", PW))
        self.assertIsNotNone(self.ns["authenticate_user"]("aarav.s", "NewStr0ng!1"))

    def test_profile_update_to_taken_email_fails(self):
        self.make_user()
        other = self.make_user("second", "second@example.com")
        ok, _ = self.ns["update_user_profile"](other[0], "Second", "aarav@example.com", PW)
        self.assertFalse(ok)

    # ---- password reset -----------------------------------------------------
    def test_full_reset_flow_by_email_and_by_username(self):
        self.make_user()
        for identifier in ("aarav@example.com", "aarav.s"):
            ok, msg = self.ns["initiate_password_reset"](identifier)
            self.assertTrue(ok, msg)
            email, otp = self.sent[-1]
            self.assertEqual(email, "aarav@example.com")  # always the registered address
            self.assertNotIn(otp, msg)
            ok, msg = self.ns["verify_otp_and_reset_password"](identifier, otp, "BrandNew!42")
            self.assertTrue(ok, msg)
            self.assertIsNotNone(self.ns["authenticate_user"]("aarav.s", "BrandNew!42"))
            self.make_pw("BrandNew!42", PW)  # reset back for next loop iteration

    def make_pw(self, old, new):
        uid = self.sql("SELECT id FROM users")[0][0]
        self.assertTrue(self.ns["change_user_password"](uid, old, new)[0])

    def test_otp_is_single_use(self):
        self.make_user()
        self.ns["initiate_password_reset"]("aarav.s")
        otp = self.sent[-1][1]
        self.assertTrue(self.ns["verify_otp_and_reset_password"]("aarav.s", otp, "BrandNew!42")[0])
        self.assertFalse(self.ns["verify_otp_and_reset_password"]("aarav.s", otp, "Another!123")[0])

    def test_new_request_invalidates_previous_otp(self):
        self.make_user()
        self.ns["initiate_password_reset"]("aarav.s")
        first = self.sent[-1][1]
        self.ns["initiate_password_reset"]("aarav.s")
        second = self.sent[-1][1]
        if first != second:
            self.assertFalse(self.ns["verify_otp_and_reset_password"]("aarav.s", first, "BrandNew!42")[0])
        self.assertTrue(self.ns["verify_otp_and_reset_password"]("aarav.s", second, "BrandNew!42")[0])

    def test_expired_otp_is_rejected(self):
        self.make_user()
        self.ns["initiate_password_reset"]("aarav.s")
        otp = self.sent[-1][1]
        self.sql("UPDATE password_resets SET expires_at = now() - interval '1 minute'")
        ok, msg = self.ns["verify_otp_and_reset_password"]("aarav.s", otp, "BrandNew!42")
        self.assertFalse(ok)
        self.assertIn("expired", msg.lower())
        self.assertIsNotNone(self.ns["authenticate_user"]("aarav.s", PW))  # password unchanged

    def test_five_wrong_guesses_lock_the_otp(self):
        self.make_user()
        self.ns["initiate_password_reset"]("aarav.s")
        otp = self.sent[-1][1]
        wrong = "000000" if otp != "000000" else "111111"
        for _ in range(5):
            self.assertFalse(self.ns["verify_otp_and_reset_password"]("aarav.s", wrong, "BrandNew!42")[0])
        ok, msg = self.ns["verify_otp_and_reset_password"]("aarav.s", otp, "BrandNew!42")  # right code, too late
        self.assertFalse(ok)
        self.assertEqual(self.sql("SELECT attempts, used FROM password_resets")[0], (5, True))

    def test_failed_email_send_leaves_no_usable_otp(self):
        self.make_user()
        self.ns["send_reset_email_brevo"] = lambda *a: (False, "BREVO_NOT_CONFIGURED")
        ok, msg = self.ns["initiate_password_reset"]("aarav.s")
        self.assertTrue(ok)  # looks identical to success: no oracle
        self.assertEqual(self.sql("SELECT count(*) FROM password_resets WHERE used = FALSE")[0][0], 0)

    def test_reset_for_unknown_account(self):
        ok, msg = self.ns["initiate_password_reset"]("ghost")
        self.assertTrue(ok)
        self.assertEqual(self.sent, [])
        self.make_user()
        self.assertEqual(self.ns["initiate_password_reset"]("aarav.s")[1], msg)  # same text as for a real account

    # ---- scans --------------------------------------------------------------
    def test_scan_save_fetch_delete_and_isolation(self):
        a, b = self.make_user(), self.make_user("second", "second@example.com")
        self.ns["save_scan_record"](a[0], "one.pdf", "Role", 40.5, 3, ["x", "y"])
        self.ns["save_scan_record"](a[0], "two.pdf", "Role", 60.0, 5, [])
        self.ns["save_scan_record"](b[0], "other.pdf", "Role", 99.0, 9, ["z"])
        df = self.ns["get_user_scans"](a[0])
        self.assertEqual(list(df["Resume File"]), ["two.pdf", "one.pdf"])  # newest first
        self.assertEqual(df.iloc[1]["Missing Keywords"], "x, y")
        self.assertRegex(df.iloc[0]["Date & Time"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
        self.ns["delete_user_scans"](a[0])
        self.assertTrue(self.ns["get_user_scans"](a[0]).empty)
        self.assertEqual(len(self.ns["get_user_scans"](b[0])), 1)  # other user untouched

    def test_deleting_a_user_cascades(self):
        user = self.make_user()
        self.ns["save_scan_record"](user[0], "one.pdf", "Role", 40.5, 3, [])
        self.ns["initiate_password_reset"]("aarav.s")
        self.sql("DELETE FROM users")
        self.assertEqual(self.sql("SELECT (SELECT count(*) FROM scans), (SELECT count(*) FROM password_resets)")[0], (0, 0))

    # ---- security (pen-test style, against real Postgres) ----------------------
    def test_account_locks_after_five_wrong_passwords_and_unlocks_later(self):
        self.make_user()
        for _ in range(5):
            self.assertIsNone(self.ns["authenticate_user"]("aarav.s", "wrong-pass"))
        with self.assertRaises(self.ns["AccountLocked"]):
            self.ns["authenticate_user"]("aarav.s", PW)  # correct password refused while locked
        self.sql("UPDATE users SET locked_until = now() - interval '1 minute'")
        self.assertIsNotNone(self.ns["authenticate_user"]("aarav.s", PW))
        self.assertEqual(self.sql("SELECT failed_logins FROM users")[0][0], 0)

    def test_failed_logins_reset_after_success(self):
        self.make_user()
        for _ in range(3):
            self.ns["authenticate_user"]("aarav.s", "wrong-pass")
        self.assertIsNotNone(self.ns["authenticate_user"]("aarav.s", PW))
        self.assertEqual(self.sql("SELECT failed_logins FROM users")[0][0], 0)

    def test_password_change_and_reset_revoke_existing_sessions(self):
        user = self.make_user()
        v0 = self.ns["get_token_version"](user[0])
        self.ns["change_user_password"](user[0], PW, "NewStr0ng!1")
        v1 = self.ns["get_token_version"](user[0])
        self.assertGreater(v1, v0)
        self.ns["initiate_password_reset"]("aarav.s")
        self.ns["verify_otp_and_reset_password"]("aarav.s", self.sent[-1][1], "BrandNew!42")
        self.assertGreater(self.ns["get_token_version"](user[0]), v1)
        self.assertIsNone(self.ns["get_token_version"](999999))  # deleted account => session invalid

    def test_reauth_prompts_cannot_be_used_to_brute_force_the_password(self):
        user = self.make_user()
        for _ in range(5):
            self.assertFalse(self.ns["change_user_password"](user[0], "wrong-pass", "NewStr0ng!1")[0])
        ok, _ = self.ns["change_user_password"](user[0], PW, "NewStr0ng!1")  # now locked: even the right one fails
        self.assertFalse(ok)
        ok, _ = self.ns["update_user_profile"](user[0], "Aarav", "x@example.com", PW)
        self.assertFalse(ok)

    def test_otp_is_stored_only_as_a_keyed_digest(self):
        self.make_user()
        self.ns["initiate_password_reset"]("aarav.s")
        otp = self.sent[-1][1]
        stored = self.sql("SELECT otp_code FROM password_resets")[0][0]
        self.assertNotEqual(stored, otp)
        self.assertRegex(stored, r"^[0-9a-f]{64}$")

    def test_reset_requests_are_rate_limited_to_three_per_hour(self):
        self.make_user()
        for _ in range(5):
            self.assertTrue(self.ns["initiate_password_reset"]("aarav.s")[0])
        self.assertEqual(len(self.sent), 3)  # 4th and 5th silently dropped (no email bombing)

    def test_email_change_needs_password_and_name_change_does_not(self):
        user = self.make_user()
        self.assertFalse(self.ns["update_user_profile"](user[0], "Aarav", "new@example.com", "")[0])
        self.assertTrue(self.ns["update_user_profile"](user[0], "Renamed", "aarav@example.com", "")[0])

    def test_sql_injection_payloads_do_nothing(self):
        self.make_user()
        for payload in ["admin' OR '1'='1", "x'; DROP TABLE users;--", "' OR 1=1 --"]:
            self.assertIsNone(self.ns["authenticate_user"](payload, payload))
            self.assertTrue(self.ns["initiate_password_reset"](payload)[0])
            self.assertFalse(self.ns["register_user"](payload, "N", "i@example.com", PW)[0])
        user = self.ns["authenticate_user"]("aarav.s", PW)
        self.ns["save_scan_record"](user[0], "x'); DROP TABLE users;--.pdf", "Role", 1.0, 1, ["'; DELETE FROM scans;--"])
        self.assertEqual(self.sql("SELECT count(*) FROM users")[0][0], 1)  # tables intact
        self.assertIn("DROP TABLE", self.ns["get_user_scans"](user[0]).iloc[0]["Resume File"])  # stored as inert text

    def test_users_cannot_read_or_delete_each_others_scans(self):
        a, b = self.make_user(), self.make_user("second", "second@example.com")
        self.ns["save_scan_record"](b[0], "secret.pdf", "Role", 9.0, 1, [])
        self.assertTrue(self.ns["get_user_scans"](a[0]).empty)
        self.ns["delete_user_scans"](a[0])
        self.assertEqual(len(self.ns["get_user_scans"](b[0])), 1)

    def test_hourly_analysis_quota_counts_only_recent_scans(self):
        user = self.make_user()
        limit = self.ns["MAX_ANALYSES_PER_HOUR"]
        self.assertEqual(self.ns["analysis_quota_remaining"](user[0]), limit)
        for _ in range(limit):
            self.ns["save_scan_record"](user[0], "a.pdf", "Role", 1.0, 1, [])
        self.assertEqual(self.ns["analysis_quota_remaining"](user[0]), 0)
        self.sql("UPDATE scans SET scanned_at = now() - interval '2 hours'")
        self.assertEqual(self.ns["analysis_quota_remaining"](user[0]), limit)

    def test_reserved_usernames_cannot_be_registered(self):
        self.assertFalse(self.ns["register_user"]("admin", "Mallory", "m@example.com", PW)[0])

    # ---- feature set: departments, admin role, anonymised analytics -------------
    def student(self, name, dept="Computer Science", scans=(), missing="docker, sql"):
        user = self.make_user(name, f"{name}@example.com")
        self.sql("UPDATE users SET department = %s WHERE id = %s", (dept, user[0]))
        for score in scans:
            self.ns["save_scan_record"](user[0], "cv.pdf", "Role", score, 3, [m for m in missing.split(", ") if m])
        return user

    def admin(self):
        user = self.make_user("boss", "boss@example.com")
        self.sql("UPDATE users SET role = 'admin' WHERE id = %s", (user[0],))
        return user[0]

    def test_department_is_stored_and_role_defaults_to_student(self):
        ok, msg = self.ns["register_user"]("dept.user", "D", "d@example.com", PW, "Civil")
        self.assertTrue(ok, msg)
        uid = self.sql("SELECT id FROM users WHERE username='dept.user'")[0][0]
        self.assertEqual(self.ns["get_session_info"](uid)["department"], "Civil")
        self.assertEqual(self.ns["get_session_info"](uid)["role"], "student")
        self.assertTrue(self.ns["update_user_profile"](uid, "D", "d@example.com", "", "Mechanical")[0])
        self.assertEqual(self.ns["get_session_info"](uid)["department"], "Mechanical")
        self.assertFalse(self.ns["update_user_profile"](uid, "D", "d@example.com", "", "Wizardry")[0])

    def test_database_rejects_an_invalid_role(self):
        self.make_user()
        with self.assertRaises(psycopg2.errors.CheckViolation):
            self.sql("UPDATE users SET role = 'superuser'")

    def test_students_cannot_read_analytics_and_admins_can(self):
        stu = self.student("stu1", scans=[50])
        with self.assertRaises(PermissionError):
            self.ns["get_admin_metrics"](stu[0])
        admin_id = self.admin()
        self.student("stu2", scans=[60]); self.student("stu3", scans=[70])
        self.assertFalse(self.ns["get_admin_metrics"](admin_id)["suppressed"])
        self.sql("UPDATE users SET role = 'student' WHERE id = %s", (admin_id,))  # demoted: access ends immediately
        with self.assertRaises(PermissionError):
            self.ns["get_admin_metrics"](admin_id)

    def test_analytics_sql_runs_and_aggregates_correctly(self):
        admin_id = self.admin()
        self.ns["save_scan_record"](admin_id, "admin.pdf", "Role", 99.0, 1, ["kubernetes"])   # admin's own scans must not count
        for n, score in (("a1", 40.0), ("a2", 60.0), ("a3", 80.0)):
            self.student(n, "Computer Science", scans=[score])
        self.student("c1", "Civil", scans=[100.0], missing="sql")
        m = self.ns["get_admin_metrics"](admin_id, 30)
        self.assertEqual(m["students"], 4); self.assertEqual(m["admins"], 1)
        self.assertEqual((m["active_7d"], m["active_30d"], m["scans_in_window"]), (4, 4, 4))
        self.assertEqual(m["avg_score"], 70.0)                                     # (40+60+80+100)/4, no admin scan
        skills = {r["Skill"]: r for r in m["top_missing"]}
        self.assertEqual(skills["docker"]["Students"], 3); self.assertEqual(skills["sql"]["Students"], 4)
        self.assertNotIn("kubernetes", skills)
        depts = {r["Department"]: r for r in m["by_department"]}
        self.assertEqual(depts["Computer Science"]["Average Score (%)"], 60.0)
        self.assertNotIn("Civil", depts)                                           # one student: hidden, never shown alone
        self.assertEqual(sum(r["Scans"] for r in m["score_distribution"]), 4)
        self.assertEqual(sum(r["Scans"] for r in m["daily_scans"]), 4)

    def test_small_populations_and_department_filters_are_suppressed(self):
        admin_id = self.admin()
        self.student("a1", scans=[50]); self.student("a2", scans=[60])
        self.assertTrue(self.ns["get_admin_metrics"](admin_id, 30)["suppressed"])          # only 2 active students
        self.student("a3", scans=[70]); self.student("c1", "Civil", scans=[10])
        self.assertFalse(self.ns["get_admin_metrics"](admin_id, 30)["suppressed"])
        civil = self.ns["get_admin_metrics"](admin_id, 30, "Civil")
        self.assertTrue(civil["suppressed"])                                               # filter can't expose one student's score
        self.assertEqual((civil["avg_score"], civil["top_missing"]), (0.0, []))
        self.assertFalse(self.ns["get_admin_metrics"](admin_id, 30, "Computer Science")["suppressed"])

    def test_skill_needs_three_distinct_students_and_respects_the_window(self):
        admin_id = self.admin()
        for n in ("a1", "a2", "a3"):
            self.student(n, scans=[50], missing="docker, rareskill" if n != "a3" else "docker")
        skills = [r["Skill"] for r in self.ns["get_admin_metrics"](admin_id, 30)["top_missing"]]
        self.assertIn("docker", skills); self.assertNotIn("rareskill", skills)       # only 2 students are missing it
        self.sql("UPDATE scans SET scanned_at = now() - interval '40 days'")
        self.assertTrue(self.ns["get_admin_metrics"](admin_id, 30)["suppressed"])    # nothing in the last 30 days
        self.assertFalse(self.ns["get_admin_metrics"](admin_id, 90)["suppressed"])

    def test_analytics_never_leak_personal_data(self):
        admin_id = self.admin()
        for n in ("a1", "a2", "a3"):
            self.student(n, scans=[50])
        blob = repr(self.ns["get_admin_metrics"](admin_id, 30)).lower()
        for secret in ("@example.com", "a1", "cv.pdf", "pbkdf2", "boss"):
            self.assertNotIn(secret, blob)


if __name__ == "__main__":
    unittest.main()
