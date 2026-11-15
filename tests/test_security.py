"""Attack-style tests: each one tries to break the app the way a penetration tester would."""
import ast
import re
import time
import unittest
from pathlib import Path

import pandas as pd

from app_loader import load_app
from helpers import FakeCursor, use_cursor

ROOT = Path(__file__).resolve().parent.parent
SQLI = ["admin' OR '1'='1", "x'; DROP TABLE users;--", "' UNION SELECT password_hash FROM users--", "a\\' OR 1=1 #"]


class InjectionTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def assert_parameterised(self, cur, payload):
        self.assertTrue(cur.executed)
        for sql, params in cur.executed:
            self.assertNotIn(payload, sql, "user input must never be concatenated into SQL")

    def test_sql_injection_payloads_stay_in_bound_parameters(self):
        for p in SQLI:
            cur = use_cursor(self.ns, FakeCursor()); self.ns["authenticate_user"](p, "x"); self.assert_parameterised(cur, p)
            cur = use_cursor(self.ns, FakeCursor()); self.ns["initiate_password_reset"](p); self.assert_parameterised(cur, p)
            cur = use_cursor(self.ns, FakeCursor()); self.ns["verify_otp_and_reset_password"](p, "123456", "NewStr0ng!1"); self.assert_parameterised(cur, p)
            cur = use_cursor(self.ns, FakeCursor()); self.ns["save_scan_record"](1, p, p, 1.0, 1, [p]); self.assert_parameterised(cur, p)

    def test_no_dynamic_sql_in_source(self):
        """Every cursor.execute() must use a constant string (the one f-string only interpolates a hard-coded table name)."""
        tree = ast.parse((ROOT / "app.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                arg = node.args[0]
                if isinstance(arg, ast.JoinedStr):
                    names = [v.value.id for v in arg.values if isinstance(v, ast.FormattedValue)]
                    self.assertEqual(names, ["table"], f"dynamic SQL at line {node.lineno}")
                else:
                    self.assertIsInstance(arg, ast.Constant, f"non-constant SQL at line {node.lineno}")
                    self.assertNotIn("%" + "s'", arg.value)

    def test_sql_injection_username_is_not_a_valid_registration(self):
        for p in SQLI:
            ok, _ = self.ns["register_user"](p, "N", "a@example.com", "Str0ng!Pass")
            self.assertFalse(ok)


class OutputEncodingTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_html_is_escaped_in_every_rendered_helper(self):
        evil = '"><img src=x onerror=alert(1)><script>alert(2)</script>'
        for out in (self.ns["chips"]([evil]), self.ns["pill"](evil, True)):
            self.assertNotIn("<img", out); self.assertNotIn("<script", out)

    def test_csv_formula_injection_is_neutralised_for_every_string_dtype(self):
        payloads = ['=HYPERLINK("http://evil","x")', "+1+1", "-2+3", "@SUM(1)", "\t=1+1", "\r=1+1", "ok.pdf"]
        dtypes = ["object", "string"] + (["str"] if int(pd.__version__.split(".")[0]) >= 3 else [])
        for dtype in dtypes:
            df = pd.DataFrame({"a": pd.Series(payloads, dtype=dtype), "n": range(len(payloads))})
            out = self.ns["csv_safe"](df)
            for v in out["a"]:
                self.assertNotIn(v[:1], "=+-@\t\r", f"dtype={dtype}: {v!r} would execute in Excel")
            self.assertEqual(list(out["n"]), list(range(len(payloads))))  # numbers untouched
        default = pd.DataFrame({"a": ["=1+1"]})  # whatever the installed pandas' default string dtype is
        self.assertEqual(self.ns["csv_safe"](default)["a"][0], "'=1+1")

    def test_filenames_cannot_traverse_or_inject(self):
        f = self.ns["safe_filename"]
        for evil in ["../../etc/passwd", "..\\..\\win.ini", "<script>.pdf", "a\x00b\nc.pdf", "=cmd|' /C calc'!A0.pdf", "", "...."]:
            out = f(evil)
            self.assertRegex(out, r"^[A-Za-z0-9._ -]+$")
            self.assertNotIn("..", out.replace("...", "")) if "/" in evil else None
            self.assertFalse(out.startswith((".", " ")))
        self.assertLessEqual(len(f("x" * 500 + ".pdf")), 100)

    def test_email_header_injection_and_oddities_rejected(self):
        ok = self.ns["is_valid_email"]
        for bad in ["a@b.co\r\nBcc: evil@x.com", "a@b.co,evil@x.com", "a@b.co;evil@x.com", "<a@b.co>", "a b@c.co", "a@b.co\x00"]:
            self.assertFalse(ok(bad), repr(bad))


class DenialOfServiceTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_pathological_resume_text_is_processed_quickly(self):
        n = self.ns["MAX_TEXT_CHARS"]
        for payload in ["1" * n, "1-" * (n // 2), "(1" * (n // 2), "1." * (n // 2), "a@" * (n // 2),
                        "a" * 64 + "@" + "b." * (n // 4), "+1" * (n // 2), "1%" * (n // 2), "python " * (n // 7)]:
            start = time.time()
            self.ns["extract_contact_and_sections"](payload * 3)  # even beyond the cap: the function truncates
            self.assertLess(time.time() - start, 2.0, payload[:12])

    def test_text_beyond_the_cap_is_ignored(self):
        audit = self.ns["extract_contact_and_sections"]("x " * 10 + "a@b.co " + "y" * self.ns["MAX_TEXT_CHARS"] + " c@d.co")
        self.assertTrue(audit["Email"])

    def test_pdf_validation(self):
        import io
        v = self.ns["validate_pdf_upload"]
        mk = lambda b: io.BytesIO(b)
        self.assertIsNone(v(mk(b"%PDF-1.7 ok")))
        for bad in [b"", b"MZ\x90\x00 exe", b"<html>%PDF-</html>", b"GIF89a"]:
            self.assertIsNotNone(v(mk(bad)))
        self.assertIn("too large", v(mk(b"%PDF-" + b"0" * (self.ns["MAX_PDF_BYTES"] + 1))))

    def test_hourly_analysis_quota(self):
        limit = self.ns["MAX_ANALYSES_PER_HOUR"]
        use_cursor(self.ns, FakeCursor(fetchone=[(0,)])); self.assertEqual(self.ns["analysis_quota_remaining"](1), limit)
        use_cursor(self.ns, FakeCursor(fetchone=[(limit - 1,)])); self.assertEqual(self.ns["analysis_quota_remaining"](1), 1)
        use_cursor(self.ns, FakeCursor(fetchone=[(limit + 50,)])); self.assertEqual(self.ns["analysis_quota_remaining"](1), 0)


class SecretsAndConfigTests(unittest.TestCase):
    def test_no_real_secrets_committed(self):
        patterns = [r"xkeysib-[A-Za-z0-9]{20,}", r"postgres(?:ql)?://[^:\s]+:(?!YOUR-PASSWORD|test@|test\b)[^@\s]{6,}@(?!localhost)[\w.-]+",
                    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", r"sk-[A-Za-z0-9]{32,}"]
        for path in ROOT.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".toml", ".yaml", ".yml", ".md", ".txt", ".example"} and "tests" not in path.parts:
                text = path.read_text(errors="ignore")
                for p in patterns:
                    self.assertIsNone(re.search(p, text), f"possible secret in {path.name}: {p}")

    def test_secrets_file_is_git_ignored_and_xsrf_enabled(self):
        self.assertIn(".streamlit/secrets.toml", (ROOT / ".gitignore").read_text())
        cfg = (ROOT / ".streamlit/config.toml").read_text()
        self.assertRegex(cfg, r"enableXsrfProtection\s*=\s*true")
        self.assertRegex(cfg, r"maxUploadSize\s*=\s*\d+")

    def test_dependencies_have_security_floor_versions(self):
        reqs = (ROOT / "requirements.txt").read_text()
        for pkg in ["scikit-learn", "pypdf", "requests", "streamlit", "psycopg2-binary"]:
            self.assertRegex(reqs, rf"(?m)^{re.escape(pkg)}>=", f"{pkg} should declare a minimum safe version")

    def test_reset_email_is_sent_in_background_by_default(self):
        self.assertIs(load_app()["OTP_ASYNC_DELIVERY"], True)  # synchronous sending leaks account existence via latency

    def test_login_message_is_identical_for_locked_and_wrong_password(self):
        src = (ROOT / "app.py").read_text()
        self.assertEqual(src.count("st.error(LOGIN_FAILED_MSG)"), 2)
        self.assertNotIn("Too many failed attempts. Please try again in", src)


if __name__ == "__main__":
    unittest.main()
