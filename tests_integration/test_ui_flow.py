"""End-to-end UI flows: the real app.py is executed by Streamlit's AppTest against a real Postgres.
Only the outgoing HTTP call to Brevo is mocked, so we can read the emailed OTP."""
import os
import re
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from pg_fixture import SchemaTestCase, requires_pg

try:
    from streamlit.testing.v1 import AppTest
    import streamlit as st
    HAVE_APPTEST = True
except ImportError:
    HAVE_APPTEST = False

PW = "Str0ng!Pass"
APP = str(Path(__file__).resolve().parent.parent / "app.py")


def widget(at, kind, label):
    for w in at.get(kind):
        if w.label == label:
            return w
    raise AssertionError(f"No {kind} labelled {label!r}. Found: {[w.label for w in at.get(kind)]}")


def screen_text(at):
    parts = []
    for kind in ("markdown", "success", "info", "warning", "error", "caption"):
        parts += [str(getattr(e, "value", "")) for e in at.get(kind)]
    return "\n".join(parts)


@requires_pg
@unittest.skipUnless(HAVE_APPTEST, "streamlit.testing (AppTest) not available")
class UiFlowTests(SchemaTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env = mock.patch.dict(os.environ, {
            "DATABASE_URL": cls.url, "BREVO_API_KEY": "test-key", "BREVO_SENDER_EMAIL": "from@example.com"})
        cls.env.start()
        st.cache_resource.clear()  # force init_db to create tables in this schema

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        super().tearDownClass()

    def setUp(self):
        self.sql("TRUNCATE users RESTART IDENTITY CASCADE")
        self.emails = []
        patcher = mock.patch("requests.post", side_effect=self._fake_post)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _fake_post(self, url, json=None, headers=None, timeout=None):
        self.emails.append(json)
        return SimpleNamespace(status_code=201, text="")

    def app(self):
        at = AppTest.from_file(APP, default_timeout=60).run()
        self.assertFalse(at.exception, at.exception)
        return at

    def sign_up(self, at, pw=PW):
        widget(at, "text_input", "Full Name (e.g., Aarav Sharma)").set_value("Aarav Sharma")
        widget(at, "text_input", "Choose a Username").set_value("aarav.s")
        widget(at, "text_input", "Email Address").set_value("aarav@example.com")
        widget(at, "text_input", "Create Password (min 8 characters)").set_value(pw)
        widget(at, "text_input", "Confirm Password").set_value(pw)
        widget(at, "button", "Register Account").click().run()
        return at

    def log_in(self, at, pw=PW):
        widget(at, "text_input", "Username").set_value("aarav.s")
        widget(at, "text_input", "Password").set_value(pw)
        widget(at, "button", "Login").click().run()
        return at

    def wait_for_email(self, count=1, timeout=10):
        """The reset email is delivered in a background thread (by design), so poll for it."""
        deadline = time.time() + timeout
        while len(self.emails) < count and time.time() < deadline:
            time.sleep(0.05)
        self.assertGreaterEqual(len(self.emails), count, "reset email was never sent")

    def test_login_screen_shows_two_tabs_and_forgot_link(self):
        at = self.app()
        self.assertEqual([t.label for t in at.tabs], ["🔐 Login", "📝 Create Account"])  # no separate forgot tab
        widget(at, "button", "🔑 Forgot password?")

    def test_signup_then_login_reaches_dashboard(self):
        at = self.sign_up(self.app())
        self.assertIn("Account created", " ".join(e.value for e in at.success))
        at = self.log_in(self.app())
        self.assertFalse(at.exception)
        self.assertEqual(at.session_state["user"]["username"], "aarav.s")

    def test_wrong_password_shows_error_and_stays_logged_out(self):
        self.sign_up(self.app())
        at = self.log_in(self.app(), pw="wrongpass1")
        self.assertTrue(any(e.value.startswith("Invalid username or password.") for e in at.error))
        self.assertIsNone(at.session_state["user"])

    def test_duplicate_signup_is_rejected_in_ui(self):
        self.sign_up(self.app())
        at = self.sign_up(self.app())
        self.assertTrue(any("already exists" in e.value for e in at.error))

    def test_forgot_password_flow_end_to_end(self):
        self.sign_up(self.app())
        at = self.app()
        widget(at, "button", "🔑 Forgot password?").click().run()
        widget(at, "text_input", "Username or Email Address").set_value("aarav@example.com")
        widget(at, "button", "Send OTP to my registered email 📧").click().run()

        self.wait_for_email()
        self.assertEqual(len(self.emails), 1)
        self.assertEqual(self.emails[0]["to"][0]["email"], "aarav@example.com")  # registered address
        otp = re.search(r">\s*(\d{6})\s*<", self.emails[0]["htmlContent"]).group(1)
        self.assertNotIn(otp, screen_text(at))  # OTP must not be displayed in the app

        widget(at, "text_input", "Enter 6-Digit OTP Code").set_value(otp)
        widget(at, "text_input", "New Password (min 8 characters)").set_value("BrandNew!42")
        widget(at, "text_input", "Confirm New Password").set_value("BrandNew!42")
        widget(at, "button", "Reset Password ✅").click().run()
        self.assertIn("reset successfully", screen_text(at))

        widget(at, "button", "← Back to login").click().run()
        self.log_in(at, pw=PW)
        self.assertIsNone(at.session_state["user"])  # old password no longer works
        at = self.log_in(self.app(), pw="BrandNew!42")
        self.assertEqual(at.session_state["user"]["username"], "aarav.s")

    def test_forgot_password_wrong_otp_is_rejected(self):
        self.sign_up(self.app())
        at = self.app()
        widget(at, "button", "🔑 Forgot password?").click().run()
        widget(at, "text_input", "Username or Email Address").set_value("aarav.s")
        widget(at, "button", "Send OTP to my registered email 📧").click().run()
        widget(at, "text_input", "Enter 6-Digit OTP Code").set_value("000000")
        widget(at, "text_input", "New Password (min 8 characters)").set_value("BrandNew!42")
        widget(at, "text_input", "Confirm New Password").set_value("BrandNew!42")
        widget(at, "button", "Reset Password ✅").click().run()
        self.assertTrue(any("Invalid or expired OTP" in e.value for e in at.error))

    # ---- security flows -------------------------------------------------------
    def test_lockout_message_is_identical_to_unknown_user_and_wrong_password(self):
        self.sign_up(self.app())
        def failed_login(username, pw):
            at = self.app()
            widget(at, "text_input", "Username").set_value(username)
            widget(at, "text_input", "Password").set_value(pw)
            widget(at, "button", "Login").click().run()
            self.assertIsNone(at.session_state["user"])
            return [e.value for e in at.error]
        unknown = failed_login("nobody.here", "whatever1")
        wrong = failed_login("aarav.s", "wrongpass1")
        for _ in range(4):
            failed_login("aarav.s", "wrongpass1")
        locked = failed_login("aarav.s", PW)  # correct password, but the account is now locked
        self.assertEqual(unknown, wrong)
        self.assertEqual(wrong, locked)  # an attacker cannot tell a locked (= existing) account apart

    def test_session_is_revoked_when_the_password_changes_elsewhere(self):
        self.sign_up(self.app())
        at = self.log_in(self.app())
        self.assertIsNotNone(at.session_state["user"])
        self.sql("UPDATE users SET token_version = token_version + 1")  # e.g. password reset from another device
        at.run()
        self.assertIsNone(at.session_state["user"])

    def test_session_expires_when_idle(self):
        self.sign_up(self.app())
        at = self.log_in(self.app())
        at.session_state["last_active"] = time.time() - 3 * 3600
        at.run()
        self.assertIsNone(at.session_state["user"])

    def test_reserved_and_weak_credentials_are_rejected_in_the_ui(self):
        at = self.app()
        widget(at, "text_input", "Full Name (e.g., Aarav Sharma)").set_value("Mallory")
        widget(at, "text_input", "Choose a Username").set_value("admin")
        widget(at, "text_input", "Email Address").set_value("m@example.com")
        widget(at, "text_input", "Create Password (min 8 characters)").set_value("password123")
        widget(at, "text_input", "Confirm Password").set_value("password123")
        widget(at, "button", "Register Account").click().run()
        self.assertTrue(at.error)
        self.assertEqual(self.sql("SELECT count(*) FROM users")[0][0], 0)

    def test_reset_screen_gives_no_hint_whether_the_account_exists(self):
        self.sign_up(self.app())
        notices = []
        for ident in ("aarav.s", "ghost.user"):
            at = self.app()
            widget(at, "button", "🔑 Forgot password?").click().run()
            widget(at, "text_input", "Username or Email Address").set_value(ident)
            widget(at, "button", "Send OTP to my registered email 📧").click().run()
            notices.append([e.value for e in at.success])
        self.assertEqual(notices[0], notices[1])

    # ---- feature pages ----------------------------------------------------------
    STUDENT_PAGES = ["🚀 Single Resume Analyzer", "🔀 Resume A/B Compare", "🏆 Multi-Resume Batch Ranker",
                     "✍️ Resume & Cover Letter Editor", "🗓️ 30-Day Skill Roadmap", "🕒 My Scan History & Trends",
                     "⚙️ Account & Security"]

    def nav(self, at):
        return next(r for r in at.sidebar.radio if r.label == "Navigation")

    def test_every_student_page_renders_and_admin_page_is_hidden(self):
        self.sign_up(self.app())
        at = self.log_in(self.app())
        self.assertEqual(list(self.nav(at).options), self.STUDENT_PAGES)  # no admin entry for a student
        for page in self.STUDENT_PAGES:
            self.nav(at).set_value(page).run()
            self.assertFalse(at.exception, f"{page}: {at.exception}")

    def test_admin_sees_and_can_open_the_analytics_page(self):
        self.sign_up(self.app())
        self.sql("UPDATE users SET role = 'admin'")
        at = self.log_in(self.app())
        self.assertIn("📊 Admin Analytics", self.nav(at).options)
        self.nav(at).set_value("📊 Admin Analytics").run()
        self.assertFalse(at.exception, at.exception)
        self.assertTrue(any("Not enough activity" in e.value for e in at.info))  # one user only: suppressed, not leaked

    def test_demoted_admin_loses_the_page_immediately(self):
        self.sign_up(self.app())
        self.sql("UPDATE users SET role = 'admin'")
        at = self.log_in(self.app())
        self.nav(at).set_value("📊 Admin Analytics").run()
        self.sql("UPDATE users SET role = 'student'")
        at.run()
        self.assertFalse(at.exception)
        self.assertNotIn("📊 Admin Analytics", self.nav(at).options)

    def test_signup_with_department_and_roadmap_from_typed_skills(self):
        at = self.app()
        widget(at, "selectbox", "Department").set_value("Computer Science")
        self.sign_up(at)
        self.assertEqual(self.sql("SELECT department FROM users")[0][0], "Computer Science")
        at = self.log_in(self.app())
        self.nav(at).set_value("🗓️ 30-Day Skill Roadmap").run()
        widget(at, "text_input", "Skills to learn (comma-separated)").set_value("docker, kubernetes, tensorflow")
        at.run()
        self.assertFalse(at.exception)
        self.assertGreaterEqual(len(at.checkbox), 10)  # a checklist was generated

    def test_editor_updates_the_score_without_any_upload(self):
        self.sign_up(self.app())
        at = self.log_in(self.app())
        self.nav(at).set_value("✍️ Resume & Cover Letter Editor").run()
        widget(at, "text_area", "Resume text (edit freely)").set_value(
            "- Worked on websites for clients\n- Responsible for managing the database backups").run()
        self.assertFalse(at.exception, at.exception)
        self.assertTrue(any("Bullet" in e.label for e in at.expander))  # weak bullets are flagged live


if __name__ == "__main__":
    unittest.main()
