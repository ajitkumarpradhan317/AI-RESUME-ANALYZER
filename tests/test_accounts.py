"""Email verification, account deletion and remember-me tokens."""
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from app_loader import load_app
from helpers import FakeCursor, use_cursor

PW = "Str0ng!Pass"
FUTURE = lambda m=10: datetime.now(timezone.utc) + timedelta(minutes=m)
PAST = lambda m=1: datetime.now(timezone.utc) - timedelta(minutes=m)


def configured(ns, **extra):
    cfg = {"BREVO_API_KEY": "key", "BREVO_SENDER_EMAIL": "from@example.com", "OTP_PEPPER": "pepper", **extra}
    ns["get_config"] = lambda name, default="": cfg.get(name, default)
    ns["OTP_ASYNC_DELIVERY"] = False
    return cfg


class VerificationSwitchTests(unittest.TestCase):
    def test_enabled_only_when_email_service_is_configured(self):
        ns = load_app()
        ns["get_config"] = lambda n, d="": {}.get(n, d)
        self.assertFalse(ns["verification_enabled"]())                       # no Brevo keys: can't send, so don't block sign-up
        configured(ns)
        self.assertTrue(ns["verification_enabled"]())
        configured(ns, REQUIRE_EMAIL_VERIFICATION="false")
        self.assertFalse(ns["verification_enabled"]())


class SignupVerificationTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()
        configured(self.ns)
        self.sent = []
        self.ns["send_verification_email_brevo"] = lambda *a: (self.sent.append(a) or (True, "sent"))

    def register(self, cur):
        use_cursor(self.ns, cur)
        return self.ns["register_user"]("aarav.s", "Aarav", "A@Example.com", PW, "Civil")

    def test_new_account_is_unverified_and_gets_a_code_by_email(self):
        cur = FakeCursor(fetchone=[None, (42,)])
        ok, msg = self.register(cur)
        self.assertTrue(ok); self.assertIn("6-digit code", msg)
        sql, params = cur.statements("INSERT INTO users")[0]
        self.assertIn("RETURNING id", sql)
        self.assertIs(params[5], False)                                       # email_verified = False
        to_email, _, _, code = self.sent[0]
        self.assertEqual(to_email, "a@example.com"); self.assertRegex(code, r"^\d{6}$")
        stored = cur.statements("INSERT INTO email_verifications")[0][1]
        self.assertEqual(stored[1], self.ns["_otp_digest"](code)); self.assertNotEqual(stored[1], code)  # digest only
        self.assertNotIn(code, msg)

    def test_stale_unverified_signup_cannot_squat_an_address(self):
        cur = FakeCursor(fetchone=[None, (42,)])
        self.register(cur)
        self.assertIn("email_verified = FALSE", cur.statements("DELETE FROM users")[0][0])

    def test_without_email_service_accounts_are_verified_immediately(self):
        self.ns["get_config"] = lambda n, d="": d
        cur = FakeCursor(fetchone=[None, (42,)])
        ok, msg = self.register(cur)
        self.assertTrue(ok); self.assertIs(cur.statements("INSERT INTO users")[0][1][5], True)
        self.assertEqual(self.sent, []); self.assertEqual(cur.statements("DELETE FROM users"), [])

    def test_existing_verified_email_still_blocks_signup(self):
        ok, _ = self.register(FakeCursor(fetchone=[(1,)]))
        self.assertFalse(ok); self.assertEqual(self.sent, [])


class LoginVerificationTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def row(self, verified):
        return (7, "aarav.s", "Aarav", "a@example.com", "2026-01-01", self.ns["hash_password"](PW), 0, None, verified)

    def test_unverified_account_is_stopped_only_after_the_correct_password(self):
        use_cursor(self.ns, FakeCursor(fetchone=[self.row(False)]))
        with self.assertRaises(self.ns["EmailNotVerified"]) as ctx:
            self.ns["authenticate_user"]("aarav.s", PW)
        self.assertEqual(ctx.exception.user_id, 7)
        use_cursor(self.ns, FakeCursor(fetchone=[self.row(False)]))
        self.assertIsNone(self.ns["authenticate_user"]("aarav.s", "wrong"))   # wrong password: same answer as any account

    def test_verified_account_logs_in(self):
        use_cursor(self.ns, FakeCursor(fetchone=[self.row(True)]))
        self.assertEqual(self.ns["authenticate_user"]("aarav.s", PW)[0], 7)


class VerifyCodeTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()
        configured(self.ns)

    def check(self, row, code="123456"):
        if row and row[1] == "DIGEST":
            row = (row[0], self.ns["_otp_digest"]("123456")) + tuple(row[2:])
        cur = use_cursor(self.ns, FakeCursor(fetchone=[row]))
        return self.ns["verify_email_code"](7, code), cur

    def test_correct_code_verifies_the_email_once(self):
        ok, cur = self.check((1, "DIGEST", FUTURE(), 0))
        self.assertTrue(ok)
        self.assertTrue(cur.statements("SET email_verified = TRUE"))
        self.assertTrue(any("used = TRUE" in s for s, _ in cur.statements("UPDATE email_verifications")))

    def test_bad_codes_never_verify(self):
        for row, code in [((1, "DIGEST", PAST(), 0), "123456"), ((1, "DIGEST", FUTURE(), 0), "000000"),
                          (None, "123456"), ((1, "DIGEST", FUTURE(), 0), "12345"), ((1, "DIGEST", FUTURE(), 0), "١٢٣٤٥٦"),
                          ((1, "DIGEST", FUTURE(), 0), "123456; DROP TABLE users")]:
            ok, cur = self.check(row, code)
            self.assertFalse(ok, code); self.assertEqual(cur.statements("SET email_verified"), [])

    def test_fifth_wrong_guess_locks_the_code(self):
        _, cur = self.check((1, "DIGEST", FUTURE(), 4), code="000000")
        self.assertEqual(cur.statements("attempts = attempts + 1")[0][1], (True, 1))
        _, cur = self.check((1, "DIGEST", FUTURE(), 1), code="000000")
        self.assertEqual(cur.statements("attempts = attempts + 1")[0][1], (False, 1))


class ResendCodeTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()
        configured(self.ns)
        self.sent = []
        self.ns["send_verification_email_brevo"] = lambda *a: (self.sent.append(a) or (True, "sent"))

    def resend(self, user, count=0):
        use_cursor(self.ns, FakeCursor(fetchone=[user, (count,)]))
        return self.ns["send_verification_code"](7)

    def test_sends_to_the_registered_address(self):
        self.assertTrue(self.resend(("a@example.com", "Aarav", "aarav.s", False)))
        self.assertEqual(self.sent[0][0], "a@example.com")

    def test_rate_limited_and_never_for_verified_or_unknown_accounts(self):
        self.assertFalse(self.resend(("a@example.com", "Aarav", "aarav.s", False), count=3))
        self.assertFalse(self.resend(("a@example.com", "Aarav", "aarav.s", True)))
        self.assertFalse(self.resend(None))
        self.assertEqual(self.sent, [])

    def test_verification_email_is_escaped_and_not_leaking_errors(self):
        ns = load_app(); configured(ns)
        post = mock.Mock(return_value=mock.Mock(status_code=401, text="secret-details"))
        ns["requests"] = mock.Mock(post=post)
        ok, status = ns["send_verification_email_brevo"]("a@example.com", "<script>x</script>", "<b>u</b>", "123456")
        self.assertFalse(ok); self.assertNotIn("secret", status)
        body = post.call_args.kwargs["json"]["htmlContent"]
        self.assertNotIn("<script>", body); self.assertIn("123456", body)


class DeleteAccountTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def delete(self, row, password=PW):
        cur = use_cursor(self.ns, FakeCursor(fetchone=row))
        return self.ns["delete_user_account"](7, password), cur

    def pw_row(self, role="student", failures=0, locked=None):
        return (self.ns["hash_password"](PW), role, failures, locked)

    def test_correct_password_deletes_the_account(self):
        (ok, _), cur = self.delete([self.pw_row()])
        self.assertTrue(ok); self.assertEqual(cur.statements("DELETE FROM users")[0][1], (7,))

    def test_wrong_password_deletes_nothing_and_counts_toward_lockout(self):
        (ok, _), cur = self.delete([self.pw_row(failures=2)], password="wrong")
        self.assertFalse(ok); self.assertEqual(cur.statements("DELETE FROM users"), [])
        self.assertEqual(cur.statements("SET failed_logins = %s")[0][1], (3, 7))

    def test_locked_account_cannot_be_deleted(self):
        (ok, _), cur = self.delete([self.pw_row(locked=FUTURE())])
        self.assertFalse(ok); self.assertEqual(cur.statements("DELETE FROM users"), [])

    def test_the_last_administrator_cannot_delete_themselves(self):
        (ok, msg), cur = self.delete([self.pw_row("admin"), (1,)])
        self.assertFalse(ok); self.assertIn("only administrator", msg)
        (ok, _), cur = self.delete([self.pw_row("admin"), (2,)])
        self.assertTrue(ok)

    def test_unknown_user(self):
        (ok, _), _ = self.delete([None]); self.assertFalse(ok)


class RememberTokenTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()
        configured(self.ns)

    def test_token_is_random_and_stored_only_as_a_digest(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[(3,)]))
        token = self.ns["create_remember_token"](7)
        self.assertRegex(token, r"^[A-Za-z0-9_-]{40,}$")
        stored = cur.statements("INSERT INTO remember_tokens")[0][1]
        self.assertEqual(stored[1], self.ns["_otp_digest"](token)); self.assertNotEqual(stored[1], token)
        self.assertEqual(stored[2], 3)                                          # bound to the current password generation
        self.assertGreater(stored[3], datetime.now(timezone.utc) + timedelta(days=13))
        self.assertTrue(cur.statements("DELETE FROM remember_tokens"))          # old tokens trimmed to the newest five
        self.assertNotEqual(token, self.ns["create_remember_token"](7) if use_cursor(self.ns, FakeCursor(fetchone=[(3,)])) else 0)

    def test_unknown_user_gets_no_token(self):
        use_cursor(self.ns, FakeCursor(fetchone=[None]))
        self.assertIsNone(self.ns["create_remember_token"](999))

    def lookup(self, row, token="A" * 43):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[row]))
        return self.ns["user_from_remember_token"](token), cur

    def test_valid_token_restores_the_session_profile(self):
        user, _ = self.lookup((7, "aarav.s", "Aarav", "a@example.com", "2026-01-01", FUTURE(), 3, 3, True))
        self.assertEqual(user, (7, "aarav.s", "Aarav", "a@example.com", "2026-01-01"))

    def test_expired_revoked_unverified_or_unknown_tokens_are_rejected_and_purged(self):
        good = (7, "u", "N", "e@x.co", "d", FUTURE(), 3, 3, True)
        for row in [good[:5] + (PAST(),) + good[6:], good[:6] + (3, 4, True), good[:8] + (False,)]:
            user, cur = self.lookup(row)                      # expired / password changed since / email unverified
            self.assertIsNone(user); self.assertTrue(cur.statements("DELETE FROM remember_tokens"))
        user, _ = self.lookup(None); self.assertIsNone(user)

    def test_malformed_tokens_never_reach_the_database(self):
        cur = use_cursor(self.ns, FakeCursor())
        for bad in [None, "", "short", "A" * 200, "x'; DROP TABLE users;--" + "a" * 30, "a b " * 20, 12345]:
            self.assertIsNone(self.ns["user_from_remember_token"](bad))
            self.ns["revoke_remember_token"](bad)
        self.assertEqual(cur.executed, [])

    def test_logout_revokes_the_token(self):
        cur = use_cursor(self.ns, FakeCursor())
        self.ns["revoke_remember_token"]("A" * 43)
        self.assertEqual(cur.statements("DELETE FROM remember_tokens")[0][1], (self.ns["_otp_digest"]("A" * 43),))


class CookieHelperTests(unittest.TestCase):
    def test_only_token_safe_values_reach_the_script(self):
        ns = load_app()
        html_calls = []
        ns["st"].components = mock.Mock(v1=mock.Mock(html=lambda *a, **k: html_calls.append(a[0])))
        ns["set_browser_cookie"]("ats_remember", "abc_DEF-123", 3600)
        self.assertIn("SameSite=Strict", html_calls[0]); self.assertIn("max-age=3600", html_calls[0])
        for bad in ["a';alert(1);//", "<script>", "a b", "x" * 101]:
            ns["set_browser_cookie"]("ats_remember", bad, 60)
        ns["set_browser_cookie"]("bad name;", "abc", 60)
        self.assertEqual(len(html_calls), 1)                                   # nothing hostile was ever embedded
        ns["set_browser_cookie"]("ats_remember", "", 0)
        self.assertIn("max-age=0", html_calls[1])

    def test_missing_cookie_support_degrades_gracefully(self):
        ns = load_app()
        ns["st"].context = None                                                # older Streamlit: no st.context
        self.assertIsNone(ns["read_cookie"]("ats_remember"))


if __name__ == "__main__":
    unittest.main()
