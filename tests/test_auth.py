import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from app_loader import load_app
from helpers import FakeCursor, use_cursor

PW = "Str0ng!Pass"
FUTURE = lambda m=10: datetime.now(timezone.utc) + timedelta(minutes=m)
PAST = lambda m=1: datetime.now(timezone.utc) - timedelta(minutes=m)


class PasswordPolicyAndHashingTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_policy(self):
        v = self.ns["validate_password"]
        self.assertIsNone(v(PW, "aarav"))
        for bad in ["short", "password123", "12345678", "x" * 129]:
            self.assertIsNotNone(v(bad, "aarav"), bad)
        self.assertIn("username", v("Aarav.S.99", "aarav.s.99"))

    def test_hash_is_salted_and_verifiable(self):
        h1, h2 = self.ns["hash_password"](PW), self.ns["hash_password"](PW)
        self.assertNotEqual(h1, h2)
        self.assertTrue(self.ns["verify_password"](PW, h1))
        self.assertFalse(self.ns["verify_password"]("wrong", h1))

    def test_legacy_and_malformed_hashes(self):
        legacy = hashlib.sha256(b"oldpass").hexdigest()
        self.assertTrue(self.ns["verify_password"]("oldpass", legacy))
        for junk in ["pbkdf2$abc", "pbkdf2$x$y$z", "", "pbkdf2$1$a$b$c"]:
            self.assertFalse(self.ns["verify_password"](PW, junk), junk)  # never raises

    def test_non_ascii_password(self):
        h = self.ns["hash_password"]("пароль-123")
        self.assertTrue(self.ns["verify_password"]("пароль-123", h))
        self.assertFalse(self.ns["verify_password"]("пароль-124", h))


class RegisterUserTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def register(self, cur, username="aarav.s", name="Aarav", email="a@example.com", pw=PW):
        use_cursor(self.ns, cur)
        return self.ns["register_user"](username, name, email, pw)

    def test_rejects_invalid_input_without_touching_db(self):
        cases = [dict(username=u) for u in ["", "  ", "ab", "has space", "bad!char", "x" * 31, "admin", "ROOT"]]
        cases += [dict(name="   "), dict(name="x" * 101), dict(email="nope"), dict(email="a@b"), dict(pw="short"), dict(pw="password123")]
        for kw in cases:
            cur = FakeCursor()
            ok, _ = self.register(cur, **kw)
            self.assertFalse(ok, kw)
            self.assertEqual(cur.executed, [], kw)

    def test_rejects_duplicate_email(self):
        ok, msg = self.register(FakeCursor(fetchone=[(1,)]))
        self.assertFalse(ok)
        self.assertIn("email", msg.lower())

    def test_success_stores_hashed_lowercase_values_and_strips_control_chars(self):
        cur = FakeCursor()
        ok, _ = self.register(cur, username="Aarav.S", name="Aarav\nSharma\x00", email="A@Example.COM")
        self.assertTrue(ok)
        _, params = cur.statements("INSERT INTO users")[0]
        self.assertEqual(params[:3], ("aarav.s", "AaravSharma", "a@example.com"))
        self.assertTrue(params[3].startswith("pbkdf2$"))
        self.assertNotIn(PW, params[3])

    def test_unique_violation_and_unexpected_errors_are_generic(self):
        exc = self.ns["psycopg2"].errors.UniqueViolation("dup")
        ok, msg = self.register(FakeCursor(raise_on="INSERT", raise_exc=exc))
        self.assertFalse(ok); self.assertIn("already exists", msg)
        ok, msg = self.register(FakeCursor(raise_on="INSERT", raise_exc=RuntimeError("host=db.secret.internal password=hunter2")))
        self.assertFalse(ok)
        self.assertNotIn("secret", msg); self.assertNotIn("hunter2", msg)  # no internals leaked


class AuthenticateTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def row(self, pw=PW, failures=0, locked_until=None, stored=None, verified=True):
        return (7, "aarav.s", "Aarav", "a@example.com", "2026-01-01 10:00",
                stored or self.ns["hash_password"](pw), failures, locked_until, verified)

    def login(self, row, password=PW, username=" Aarav.S "):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[row] if row else []))
        return self.ns["authenticate_user"](username, password), cur

    def test_valid_login_returns_profile_and_resets_counter(self):
        user, cur = self.login(self.row(failures=3))
        self.assertEqual(user, (7, "aarav.s", "Aarav", "a@example.com", "2026-01-01 10:00"))
        self.assertEqual(cur.executed[0][1], ("aarav.s", "aarav.s"))
        self.assertTrue(cur.statements("failed_logins = 0, locked_until = NULL"))

    def test_login_works_with_email_in_any_case_and_with_spaces(self):
        user, cur = self.login(self.row(), username="  Aarav@Example.COM ")
        self.assertEqual(user[1], "aarav.s")
        sql, params = cur.executed[0]
        self.assertIn("username = %s OR LOWER(email) = %s", sql)
        self.assertEqual(params, ("aarav@example.com", "aarav@example.com"))

    def test_wrong_password_by_email_counts_against_the_same_account(self):
        user, cur = self.login(self.row(failures=4), username="aarav@example.com", password="bad")
        self.assertIsNone(user)
        self.assertTrue(cur.statements("locked_until = %s"))  # 5th failure via email locks the account too

    def test_long_valid_email_is_accepted(self):
        long_email = "a" * 64 + "@" + "b" * 63 + ".com"
        user, cur = self.login(self.row(), username=long_email)
        self.assertIsNotNone(user)

    def test_wrong_password_counts_failure(self):
        user, cur = self.login(self.row(failures=1), password="bad")
        self.assertIsNone(user)
        self.assertEqual(cur.statements("SET failed_logins = %s")[0][1], (2, 7))

    def test_fifth_failure_locks_account(self):
        user, cur = self.login(self.row(failures=4), password="bad")
        self.assertIsNone(user)
        sql, params = cur.statements("locked_until = %s")[0]
        self.assertGreater(params[0], datetime.now(timezone.utc) + timedelta(minutes=14))

    def test_locked_account_rejects_even_the_correct_password(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[self.row(locked_until=FUTURE())]))
        with self.assertRaises(self.ns["AccountLocked"]):
            self.ns["authenticate_user"]("aarav.s", PW)

    def test_expired_lock_allows_login(self):
        user, _ = self.login(self.row(locked_until=PAST()))
        self.assertIsNotNone(user)

    def test_unknown_user_returns_none_and_writes_nothing(self):
        user, cur = self.login(None)
        self.assertIsNone(user)
        self.assertEqual(cur.statements("UPDATE users"), [])

    def test_unknown_locked_and_wrong_password_all_do_equal_hashing_work(self):
        calls = []
        real = self.ns["verify_password"]
        self.ns["verify_password"] = lambda p, h: (calls.append(1), real(p, h))[1]
        self.login(None)                                             # unknown user
        self.login(self.row(), password="bad")                       # wrong password
        use_cursor(self.ns, FakeCursor(fetchone=[self.row(locked_until=FUTURE())]))
        with self.assertRaises(self.ns["AccountLocked"]):
            self.ns["authenticate_user"]("aarav.s", "whatever")      # locked
        self.assertEqual(len(calls), 3)  # one expensive hash verification each: no timing oracle

    def test_oversized_inputs_short_circuit(self):
        cur = use_cursor(self.ns, FakeCursor())
        self.assertIsNone(self.ns["authenticate_user"]("u" * 300, "x"))
        self.assertIsNone(self.ns["authenticate_user"]("user", "x" * 5000))
        self.assertEqual(cur.executed, [])

    def test_legacy_and_weak_hashes_are_upgraded(self):
        legacy = hashlib.sha256(PW.encode()).hexdigest()
        user, cur = self.login(self.row(stored=legacy))
        self.assertIsNotNone(user)
        self.assertTrue(cur.statements("SET password_hash")[0][1][0].startswith("pbkdf2$"))
        weak = f"pbkdf2$10$abcd${hashlib.pbkdf2_hmac('sha256', PW.encode(), b'abcd', 10).hex()}"
        user, cur = self.login(self.row(stored=weak))
        self.assertIsNotNone(user)
        self.assertTrue(cur.statements("SET password_hash"))


class AccountChangeTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def pw_row(self, failures=0, locked=None):
        return (self.ns["hash_password"](PW), "aarav.s", failures, locked)

    def test_change_password_wrong_current_counts_failure(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[self.pw_row(failures=2)]))
        ok, _ = self.ns["change_user_password"](1, "wrong", "NewStr0ng!1")
        self.assertFalse(ok)
        self.assertEqual(cur.statements("SET failed_logins = %s")[0][1], (3, 1))
        self.assertEqual(cur.statements("SET password_hash"), [])

    def test_change_password_blocked_while_locked(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[self.pw_row(locked=FUTURE())]))
        ok, msg = self.ns["change_user_password"](1, PW, "NewStr0ng!1")  # even the right password
        self.assertFalse(ok)
        self.assertEqual(cur.statements("SET password_hash"), [])

    def test_change_password_success_revokes_other_sessions(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[self.pw_row()]))
        ok, _ = self.ns["change_user_password"](1, PW, "NewStr0ng!1")
        self.assertTrue(ok)
        sql, params = cur.statements("SET password_hash")[0]
        self.assertIn("token_version = token_version + 1", sql)
        self.assertTrue(self.ns["verify_password"]("NewStr0ng!1", params[0]))

    def test_change_password_enforces_policy(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[self.pw_row()]))
        ok, _ = self.ns["change_user_password"](1, PW, "password123")
        self.assertFalse(ok)
        self.assertEqual(cur.statements("SET password_hash"), [])

    def profile(self, email, pw="", row=None, name="Aarav"):
        row = row or ("old@example.com", self.ns["hash_password"](PW), 0, None)
        cur = use_cursor(self.ns, FakeCursor(fetchone=[row]))
        return self.ns["update_user_profile"](1, name, email, pw), cur

    def test_email_change_requires_current_password(self):
        (ok, _), cur = self.profile("new@example.com", pw="")
        self.assertFalse(ok); self.assertEqual(cur.statements("SET full_name"), [])
        (ok, _), cur = self.profile("new@example.com", pw="wrong")
        self.assertFalse(ok); self.assertTrue(cur.statements("SET failed_logins = %s"))  # counted toward lockout
        (ok, _), cur = self.profile("NEW@example.com", pw=PW)
        self.assertTrue(ok); self.assertEqual(cur.statements("SET full_name")[0][1][1], "new@example.com")

    def test_name_only_change_needs_no_password(self):
        (ok, _), cur = self.profile("old@example.com", name="New Name")
        self.assertTrue(ok)

    def test_profile_validation_and_duplicate_email(self):
        (ok, _), _ = self.profile("not-an-email", pw=PW); self.assertFalse(ok)
        (ok, _), _ = self.profile("old@example.com", name="  "); self.assertFalse(ok)
        exc = self.ns["psycopg2"].errors.UniqueViolation("dup")
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("old@example.com", self.ns["hash_password"](PW), 0, None)],
                                             raise_on="SET full_name", raise_exc=exc))
        ok, msg = self.ns["update_user_profile"](1, "A", "taken@example.com", PW)
        self.assertFalse(ok); self.assertIn("already", msg)


class PasswordResetTests(unittest.TestCase):
    USER = (1, "aarav.s", "Aarav Sharma", "aarav@example.com")

    def setUp(self):
        self.ns = load_app()
        self.ns["OTP_ASYNC_DELIVERY"] = False
        self.ns["get_config"] = lambda name, default="": {"OTP_PEPPER": "test-pepper"}.get(name, default)

    def start(self, identifier="aarav.s", send_result=(True, "sent"), fetchone=None):
        cur = use_cursor(self.ns, FakeCursor(fetchone=fetchone if fetchone is not None else [self.USER, (0,)]))
        self.sender = mock.Mock(return_value=send_result)
        self.ns["send_reset_email_brevo"] = self.sender
        ok, msg = self.ns["initiate_password_reset"](identifier)
        return ok, msg, cur

    def test_response_is_identical_for_known_unknown_and_rate_limited_accounts(self):
        known = self.start()[1]
        unknown = self.start(fetchone=[None, (0,)])[1]
        limited = self.start(fetchone=[self.USER, (3,)])[1]
        self.assertEqual(known, unknown)
        self.assertEqual(known, limited)  # no account enumeration, no rate-limit oracle

    def test_unknown_account_sends_nothing(self):
        self.start(fetchone=[None, (0,)])
        self.sender.assert_not_called()

    def test_rate_limit_stops_after_three_requests_per_hour(self):
        _, _, cur = self.start(fetchone=[self.USER, (3,)])
        self.sender.assert_not_called()
        self.assertEqual(cur.statements("INSERT INTO password_resets"), [])

    def test_otp_goes_to_registered_email_and_is_stored_only_as_digest(self):
        ok, msg, cur = self.start(identifier="Aarav@Example.com")
        to_email, _, _, otp = self.sender.call_args[0]
        self.assertEqual(to_email, "aarav@example.com")
        self.assertRegex(otp, r"^\d{6}$")
        self.assertNotIn(otp, msg)
        stored = cur.statements("INSERT INTO password_resets")[0][1]
        self.assertNotEqual(stored[1], otp)                        # plaintext never stored
        self.assertEqual(stored[1], self.ns["_otp_digest"](otp))   # keyed digest
        self.assertAlmostEqual((stored[2] - datetime.now(timezone.utc)).total_seconds(), 15 * 60, delta=30)

    def test_lookup_is_parameterised_username_or_email(self):
        _, _, cur = self.start(identifier="Aarav@Example.com")
        sql, params = cur.executed[0]
        self.assertIn("username = %s OR LOWER(email) = %s", sql)
        self.assertEqual(params, ("aarav@example.com", "aarav@example.com"))

    def test_previous_otps_invalidated_first(self):
        _, _, cur = self.start()
        self.assertIn("SET used = TRUE", cur.statements("UPDATE password_resets")[0][0])

    def test_email_failure_invalidates_otp_and_still_looks_successful(self):
        ok, msg, cur = self.start(send_result=(False, "Brevo API Error (401)"))
        self.assertTrue(ok)
        self.assertEqual(msg, self.ns["RESET_GENERIC_MSG"])
        self.assertGreaterEqual(len(cur.statements("UPDATE password_resets")), 2)

    def test_email_delivery_runs_in_background_by_default(self):
        self.ns["OTP_ASYNC_DELIVERY"] = True
        with mock.patch.object(self.ns["threading"], "Thread") as thread:
            self.start()
        thread.assert_called_once()
        self.assertTrue(thread.call_args.kwargs["daemon"])
        thread.return_value.start.assert_called_once()
        self.sender.assert_not_called()  # the request thread never waits on the email API

    def test_empty_and_oversized_identifiers_rejected(self):
        for ident in ["", "   ", "x" * 300]:
            cur = use_cursor(self.ns, FakeCursor())
            ok, _ = self.ns["initiate_password_reset"](ident)
            self.assertFalse(ok)
            self.assertEqual(cur.executed, [])


class VerifyOtpTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()
        self.ns["get_config"] = lambda name, default="": {"OTP_PEPPER": "test-pepper"}.get(name, default)

    def verify(self, reset_row, otp="123456", user=(1,), new_pw="NewStr0ng!1"):
        digest = self.ns["_otp_digest"]("123456")
        if reset_row and reset_row[1] == "DIGEST":
            reset_row = (reset_row[0], digest) + tuple(reset_row[2:])
        cur = use_cursor(self.ns, FakeCursor(fetchone=[user, reset_row] if user else [None]))
        ok, msg = self.ns["verify_otp_and_reset_password"]("aarav.s", otp, new_pw)
        return ok, msg, cur

    def test_correct_otp_resets_password_revokes_sessions_and_burns_code(self):
        ok, msg, cur = self.verify((10, "DIGEST", FUTURE(), 0))
        self.assertTrue(ok, msg)
        sql, params = cur.statements("UPDATE users")[0]
        self.assertIn("token_version = token_version + 1", sql)
        self.assertIn("locked_until = NULL", sql)
        self.assertTrue(self.ns["verify_password"]("NewStr0ng!1", params[0]))
        self.assertTrue(any("used = TRUE" in s for s, _ in cur.statements("UPDATE password_resets")))

    def test_every_failure_mode_returns_the_same_message(self):
        msgs = set()
        for row, user, otp in [((10, "DIGEST", PAST(), 0), (1,), "123456"),     # expired
                               ((10, "DIGEST", FUTURE(), 1), (1,), "000000"),   # wrong code
                               ((10, "DIGEST", FUTURE(), 4), (1,), "000000"),   # last attempt
                               (None, (1,), "123456"),                          # no request
                               (None, None, "123456"),                          # no such user
                               ((10, "DIGEST", FUTURE(), 0), (1,), "١٢٣٤٥٦")]:  # non-ASCII
            ok, msg, cur = self.verify(row, otp=otp, user=user)
            self.assertFalse(ok)
            self.assertEqual(cur.statements("UPDATE users"), [])
            msgs.add(msg)
        self.assertEqual(len(msgs), 1)  # attacker can't tell why it failed

    def test_wrong_code_counts_attempts_and_fifth_locks(self):
        _, _, cur = self.verify((10, "DIGEST", FUTURE(), 1), otp="000000")
        self.assertEqual(cur.statements("attempts = attempts + 1")[0][1], (False, 10))
        _, _, cur = self.verify((10, "DIGEST", FUTURE(), 4), otp="000000")
        self.assertEqual(cur.statements("attempts = attempts + 1")[0][1], (True, 10))

    def test_weak_new_password_is_rejected_before_any_db_access(self):
        cur = use_cursor(self.ns, FakeCursor())
        ok, _ = self.ns["verify_otp_and_reset_password"]("aarav.s", "123456", "password123")
        self.assertFalse(ok)
        self.assertEqual(cur.executed, [])

    def test_oversized_inputs_short_circuit(self):
        cur = use_cursor(self.ns, FakeCursor())
        for ident, otp in [("x" * 300, "123456"), ("aarav.s", "1" * 50), ("aarav.s", "")]:
            ok, _ = self.ns["verify_otp_and_reset_password"](ident, otp, "NewStr0ng!1")
            self.assertFalse(ok)
        self.assertEqual(cur.executed, [])


if __name__ == "__main__":
    unittest.main()
