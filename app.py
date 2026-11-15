import streamlit as st
import pypdf
import re
import os
import time
import logging
import hmac
import html
import threading
import csv
import io
import zipfile
import xml.etree.ElementTree as ET
import hashlib
import secrets
import psycopg2
import psycopg2.errors
from contextlib import contextmanager
import requests
import pandas as pd
from datetime import datetime, timedelta, timezone
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="AI ATS Resume Analyzer Enterprise", page_icon="📄", layout="wide", initial_sidebar_state="expanded")

# --- DATABASE SETUP (Supabase Postgres) ---
def get_config(name, default=""):
    """Reads a setting from environment variables (Render) or Streamlit secrets (local)."""
    value = os.environ.get(name, "").strip()
    if not value:
        try:
            value = str(st.secrets.get(name, "")).strip()
        except Exception:
            value = ""
    return value or default

DATABASE_URL = get_config("DATABASE_URL")
if not DATABASE_URL:
    st.error(
        "⚠️ `DATABASE_URL` is not configured. Add your Supabase Postgres connection string "
        "as an environment variable (Render) or in `.streamlit/secrets.toml` (local)."
    )
    st.stop()

@contextmanager
def db_cursor():
    """Opens a short-lived connection (pooler-friendly), commits on success, rolls back on error.
    SSL is required by default (Supabase); set DB_SSLMODE=disable only for a local/CI test database."""
    conn = psycopg2.connect(DATABASE_URL, connect_timeout=10, sslmode=get_config("DB_SSLMODE", "require"))
    try:
        with conn.cursor() as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

@st.cache_resource(show_spinner="Connecting to Supabase...")
def _init_db_cached():
    """Creates tables in Supabase Postgres (runs once per server process).
    Set SKIP_DB_INIT=true once the schema exists, so the app can run with a limited database role that cannot run DDL."""
    if get_config("SKIP_DB_INIT", "").lower() in ("1", "true", "yes", "on"):
        return True
    with db_cursor() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                failed_logins INTEGER NOT NULL DEFAULT 0,
                locked_until TIMESTAMPTZ,
                token_version INTEGER NOT NULL DEFAULT 0,
                role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
                department TEXT NOT NULL DEFAULT 'Unspecified'
            )
        """)
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_logins INTEGER NOT NULL DEFAULT 0")
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ")
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0")
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin'))")
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS department TEXT NOT NULL DEFAULT 'Unspecified'")
        c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE")  # existing accounts count as verified
        c.execute("""
            CREATE TABLE IF NOT EXISTS email_verifications (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                code_digest TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                used BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS remember_tokens (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                token_digest TEXT NOT NULL UNIQUE,
                token_version INTEGER NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_verifications_user ON email_verifications (user_id, id DESC)")
        c.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check")  # widen to include department administrators
        c.execute("ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('student', 'dept_admin', 'admin'))")
        c.execute("""
            CREATE TABLE IF NOT EXISTS roadmap_progress (
                user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                plan_sig TEXT NOT NULL,
                done_keys TEXT NOT NULL DEFAULT '',
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (user_id, plan_sig)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                admin_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                otp_code TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used BOOLEAN NOT NULL DEFAULT FALSE,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        c.execute("ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now()")
        c.execute("ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0")
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
                resume_name TEXT NOT NULL,
                target_role TEXT NOT NULL,
                match_score DOUBLE PRECISION NOT NULL,
                matched_count INTEGER NOT NULL,
                missing_keywords TEXT NOT NULL,
                scanned_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_user ON scans (user_id, id DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans (scanned_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets (user_id, id DESC)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_resets_user_created ON password_resets (user_id, created_at)")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users (LOWER(email))")
        # Block Supabase's public REST API from touching these tables. The direct
        # Postgres connection used by this app is unaffected.
        for table in ("users", "password_resets", "scans", "email_verifications", "remember_tokens", "roadmap_progress", "admin_audit"):
            c.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    return True

def init_db():
    """Initializes the schema, showing a friendly error instead of a raw traceback on failure."""
    try:
        _init_db_cached()
    except Exception as e:
        st.error(f"⚠️ Could not connect to the Supabase database. Check `DATABASE_URL`. ({type(e).__name__})")
        st.stop()

# --- SECURITY SETTINGS ---
logger = logging.getLogger("ats.security")
MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_PDF_PAGES = 25
MAX_TEXT_CHARS = 150000
MAX_BATCH_FILES = 20
MAX_JD_CHARS = 20000
MAX_LOGIN_FAILURES = 5
LOCKOUT_MINUTES = 15
RESET_REQUESTS_PER_HOUR = 3
OTP_MAX_ATTEMPTS = 5
OTP_VALID_MINUTES = 15
SESSION_IDLE_MINUTES = 60
SESSION_MAX_HOURS = 12                 # absolute session lifetime, regardless of activity
MAX_ANALYSES_PER_HOUR = 60             # per-user cap on resume analyses (CPU / storage abuse)
OTP_ASYNC_DELIVERY = True              # send the reset email in the background (no timing side channel)
RESERVED_USERNAMES = {"admin", "administrator", "root", "support", "system", "security", "help", "staff", "moderator", "official"}
UNSPECIFIED_DEPT = "Unspecified"
DEPARTMENTS = ["Computer Science", "Information Technology", "Electronics & Communication", "Electrical",
               "Mechanical", "Civil", "Data Science / AI", "Business / MBA", "Other"]
K_ANON_MIN_GROUP = 3                   # admin analytics never show a group smaller than this (student privacy)
ADMIN_WINDOWS = (7, 30, 90, 365)       # selectable reporting windows, in days
MAX_EDITOR_CHARS = 30000
ROADMAP_MAX_SKILLS = 8
LOGIN_FAILED_MSG = ("Invalid username/email or password. After "
                    "5 failed attempts an account is locked for 15 minutes.")
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
MAX_NAME_LEN = 100
MAX_EMAIL_LEN = 254
PBKDF2_ITERATIONS = 600_000
COMMON_PASSWORDS = {
    "password", "password1", "password12", "password123", "12345678", "123456789", "1234567890",
    "qwertyui", "qwerty123", "iloveyou", "admin123", "welcome1", "letmein1", "abc12345", "11111111",
}
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_DUMMY = {}

class AccountLocked(Exception):
    """Raised when login is attempted on a temporarily locked account."""
    def __init__(self, seconds):
        super().__init__("account locked")
        self.seconds = seconds

class EmailNotVerified(Exception):
    """Raised after a correct password on an account whose email address has not been verified yet."""
    def __init__(self, user_id):
        super().__init__("email not verified")
        self.user_id = user_id

def valid_department(value):
    """True for a known department (or the 'Unspecified' placeholder)."""
    return value == UNSPECIFIED_DEPT or value in DEPARTMENTS

def clean_line(value, max_len=None):
    """Strips control characters/newlines and surrounding whitespace from a single-line input."""
    value = CONTROL_CHARS.sub("", value or "").strip()
    return value[:max_len] if max_len else value

def validate_password(password, username=""):
    """Returns an error message if the password breaks the policy, else None."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters long."
    if len(password) > MAX_PASSWORD_LEN:
        return f"Password must be at most {MAX_PASSWORD_LEN} characters long."
    if password.lower() in COMMON_PASSWORDS:
        return "That password is too common. Please choose a stronger one."
    if username and password.lower() == username.lower():
        return "Password must not be the same as your username."
    return None

# --- PASSWORD HASHING (salted PBKDF2; legacy SHA-256 hashes are verified and upgraded on login) ---
def hash_password(password):
    """Hashes a password with a random salt using PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ITERATIONS).hex()
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt}${digest}"

def verify_password(password, stored_hash):
    """Verifies a password against a PBKDF2 hash or a legacy unsalted SHA-256 hash."""
    try:
        if stored_hash.startswith("pbkdf2$"):
            _, iterations, salt, digest = stored_hash.split("$")
            candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations)).hex()
            return hmac.compare_digest(candidate.encode(), digest.encode())
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy.encode(), stored_hash.encode())
    except (ValueError, TypeError):
        return False

def _dummy_hash():
    """A throwaway hash verified for unknown usernames so login timing doesn't reveal which usernames exist."""
    if "h" not in _DUMMY:
        _DUMMY["h"] = hash_password("dummy-password-for-timing-equalization")
    return _DUMMY["h"]

def _otp_digest(otp):
    """Keyed hash of an OTP. Only this digest is stored, so a database leak does not expose live codes."""
    key = (get_config("OTP_PEPPER") or get_config("DATABASE_URL")).encode("utf-8")
    return hmac.new(key, otp.encode("utf-8"), hashlib.sha256).hexdigest()

def _register_failed_attempt(c, user_id, previous_failures):
    """Counts a wrong-password attempt; locks the account for LOCKOUT_MINUTES after MAX_LOGIN_FAILURES."""
    failures = previous_failures + 1
    if failures >= MAX_LOGIN_FAILURES:
        c.execute("UPDATE users SET failed_logins = 0, locked_until = %s WHERE id = %s",
                  (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES), user_id))
        logger.warning("Account locked after repeated failed attempts: user_id=%s", user_id)
    else:
        c.execute("UPDATE users SET failed_logins = %s WHERE id = %s", (failures, user_id))

def register_user(username, full_name, email, password, department=UNSPECIFIED_DEPT):
    """Registers a new student account. The role is never taken from user input (admins are granted out-of-band)."""
    username = username.strip().lower()
    full_name = clean_line(full_name)
    email = email.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,30}", username):
        return False, "Username must be 3-30 characters: letters, numbers, dot, dash or underscore only."
    if username in RESERVED_USERNAMES:
        return False, "That username is reserved. Please choose another."
    if not full_name or len(full_name) > MAX_NAME_LEN:
        return False, f"Full name must be 1-{MAX_NAME_LEN} characters."
    if len(email) > MAX_EMAIL_LEN or not is_valid_email(email):
        return False, "Please enter a valid email address."
    pw_error = validate_password(password, username)
    if pw_error:
        return False, pw_error
    if not valid_department(department):
        return False, "Please choose a department from the list."
    verify = verification_enabled()
    code, new_id = None, None
    try:
        with db_cursor() as c:
            if verify:  # a sign-up that never proved it owns the address must not block the real owner
                c.execute("DELETE FROM users WHERE LOWER(email) = %s AND email_verified = FALSE", (email,))
            c.execute("SELECT 1 FROM users WHERE LOWER(email) = %s", (email,))
            if c.fetchone():
                return False, "An account with this email already exists."
            c.execute(
                "INSERT INTO users (username, full_name, email, password_hash, department, email_verified) "
                "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                (username, full_name, email, hash_password(password), department, not verify)
            )
            new_id = (c.fetchone() or (None,))[0]
            if verify and new_id:
                code = _issue_verification(c, new_id)
        if code:
            _dispatch(_deliver_verification, new_id, email, full_name, username, code)
            return True, "Account created! We emailed a 6-digit code to verify your email address. Log in to enter it."
        return True, "Account created successfully! Please log in."
    except psycopg2.errors.UniqueViolation:
        return False, "Username or email already exists. Please choose another."
    except Exception:
        logger.exception("Registration failed")
        return False, "Registration failed. Please try again later."

# ---------- email verification ----------
VERIFY_CODE_MINUTES = 30
VERIFY_MAX_ATTEMPTS = 5
VERIFY_SENDS_PER_HOUR = 3
REMEMBER_DAYS = 14
MAX_REMEMBER_TOKENS = 5
REMEMBER_COOKIE = "ats_remember"

def verification_enabled():
    """Sign-up email verification is on whenever the email service is configured (turn off with REQUIRE_EMAIL_VERIFICATION=false)."""
    if get_config("REQUIRE_EMAIL_VERIFICATION", "true").lower() in ("0", "false", "no", "off"):
        return False
    return bool(get_config("BREVO_API_KEY") and get_config("BREVO_SENDER_EMAIL"))

def _dispatch(fn, *args):
    """Runs a slow job (sending email) in the background, or inline when OTP_ASYNC_DELIVERY is off (tests)."""
    if OTP_ASYNC_DELIVERY:
        threading.Thread(target=fn, args=args, daemon=True).start()
    else:
        fn(*args)

def _issue_verification(c, user_id):
    """Invalidates older codes and stores a new keyed digest of a fresh 6-digit code. Returns the plaintext code (for the email only)."""
    c.execute("UPDATE email_verifications SET used = TRUE WHERE user_id = %s", (user_id,))
    code = f"{secrets.randbelow(900000) + 100000}"
    c.execute("INSERT INTO email_verifications (user_id, code_digest, expires_at) VALUES (%s, %s, %s)",
              (user_id, _otp_digest(code), datetime.now(timezone.utc) + timedelta(minutes=VERIFY_CODE_MINUTES)))
    return code

def send_verification_email_brevo(recipient_email, full_name, username, code):
    """Emails the sign-up verification code through the Brevo HTTPS API."""
    api_key, sender_email = get_config("BREVO_API_KEY"), get_config("BREVO_SENDER_EMAIL")
    if not api_key or not sender_email:
        return False, "BREVO_NOT_CONFIGURED"
    payload = {
        "sender": {"name": get_config("BREVO_SENDER_NAME", "AI ATS Resume Analyzer"), "email": sender_email},
        "to": [{"email": recipient_email, "name": full_name}],
        "subject": "Verify your email - AI ATS Resume Analyzer",
        "htmlContent": f"""
        <div style="font-family: Arial, sans-serif; max-width: 520px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #1f4e78;">Verify your email</h2>
            <p>Hello <strong>{html.escape(full_name)}</strong>, welcome to AI ATS Resume Analyzer (<code>@{html.escape(username)}</code>).</p>
            <p>Your 6-digit verification code is:</p>
            <div style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #0b5394; background: #f0f4f8; padding: 12px; text-align: center; border-radius: 6px; margin: 16px 0;">{code}</div>
            <p style="color: #555;">This code expires in <strong>{VERIFY_CODE_MINUTES} minutes</strong>. If you did not create this account, ignore this email.</p>
        </div>"""
    }
    try:
        response = requests.post("https://api.brevo.com/v3/smtp/email", json=payload, timeout=15,
                                 headers={"accept": "application/json", "api-key": api_key, "content-type": "application/json"})
        return (True, "sent") if response.status_code in (200, 201, 202) else (False, f"Brevo API Error ({response.status_code})")
    except Exception as exc:
        return False, f"Network Error: {type(exc).__name__}"

def _deliver_verification(user_id, email, full_name, username, code):
    try:
        sent, status = send_verification_email_brevo(email, full_name, username, code)
    except Exception as exc:
        sent, status = False, type(exc).__name__
    if not sent:
        logger.error("Verification email not delivered: user_id=%s reason=%s", user_id, status)

def send_verification_code(user_id):
    """Sends a fresh code to an unverified account (max VERIFY_SENDS_PER_HOUR per hour). Returns True if one was sent."""
    with db_cursor() as c:
        c.execute("SELECT email, full_name, username, email_verified FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
        if not row or row[3]:
            return False
        c.execute("SELECT count(*) FROM email_verifications WHERE user_id = %s AND created_at > now() - interval '1 hour'", (user_id,))
        if c.fetchone()[0] >= VERIFY_SENDS_PER_HOUR:
            return False
        code = _issue_verification(c, user_id)
    _dispatch(_deliver_verification, user_id, row[0], row[1], row[2], code)
    return True

def verify_email_code(user_id, code):
    """Checks a verification code (single use, expiring, 5 guesses). Marks the email verified on success."""
    code = (code or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        return False
    with db_cursor() as c:
        c.execute("SELECT id, code_digest, expires_at, attempts FROM email_verifications "
                  "WHERE user_id = %s AND used = FALSE ORDER BY id DESC LIMIT 1 FOR UPDATE", (user_id,))
        row = c.fetchone()
        if not row:
            return False
        if datetime.now(timezone.utc) > row[2]:
            c.execute("UPDATE email_verifications SET used = TRUE WHERE id = %s", (row[0],))
            return False
        if not hmac.compare_digest(_otp_digest(code).encode(), row[1].encode()):
            c.execute("UPDATE email_verifications SET attempts = attempts + 1, used = %s WHERE id = %s",
                      (row[3] + 1 >= VERIFY_MAX_ATTEMPTS, row[0]))
            return False
        c.execute("UPDATE email_verifications SET used = TRUE WHERE id = %s", (row[0],))
        c.execute("UPDATE users SET email_verified = TRUE WHERE id = %s", (user_id,))
    return True

# ---------- "keep me signed in" (remember-me tokens) ----------
def create_remember_token(user_id):
    """Creates a random token for the browser cookie; only a keyed digest is stored. Returns None for unknown users."""
    token = secrets.token_urlsafe(32)
    with db_cursor() as c:
        c.execute("SELECT token_version FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
        if not row:
            return None
        c.execute("INSERT INTO remember_tokens (user_id, token_digest, token_version, expires_at) VALUES (%s, %s, %s, %s)",
                  (user_id, _otp_digest(token), row[0], datetime.now(timezone.utc) + timedelta(days=REMEMBER_DAYS)))
        c.execute("DELETE FROM remember_tokens WHERE user_id = %s AND id NOT IN "
                  "(SELECT id FROM remember_tokens WHERE user_id = %s ORDER BY id DESC LIMIT %s)",
                  (user_id, user_id, MAX_REMEMBER_TOKENS))
    return token

def user_from_remember_token(token):
    """Returns (id, username, full_name, email, created_at) for a valid, unexpired token, else None.
    A token dies when the password changes (token_version), the email is unverified, or the account is deleted."""
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
        return None
    digest = _otp_digest(token)
    with db_cursor() as c:
        c.execute("SELECT u.id, u.username, u.full_name, u.email, to_char(u.created_at, 'YYYY-MM-DD HH24:MI'), "
                  "rt.expires_at, rt.token_version, u.token_version, u.email_verified "
                  "FROM remember_tokens rt JOIN users u ON u.id = rt.user_id WHERE rt.token_digest = %s", (digest,))
        row = c.fetchone()
        if not row:
            return None
        if row[5] <= datetime.now(timezone.utc) or row[6] != row[7] or not row[8]:
            c.execute("DELETE FROM remember_tokens WHERE token_digest = %s", (digest,))
            return None
        return tuple(row[:5])

def revoke_remember_token(token):
    """Deletes one remember-me token (logout)."""
    if isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
        with db_cursor() as c:
            c.execute("DELETE FROM remember_tokens WHERE token_digest = %s", (_otp_digest(token),))

# ---------- account deletion ----------
def delete_user_account(user_id, password):
    """Permanently deletes an account and (by cascade) its scans, codes and tokens, after re-checking the password."""
    with db_cursor() as c:
        c.execute("SELECT password_hash, role, failed_logins, locked_until FROM users WHERE id = %s FOR UPDATE", (user_id,))
        row = c.fetchone()
        if not row:
            return False, "Account not found."
        if row[3] and row[3] > datetime.now(timezone.utc):
            return False, "Too many failed attempts. Please try again later."
        if not verify_password(password or "", row[0]):
            _register_failed_attempt(c, user_id, row[2])
            return False, "Password is incorrect."
        if row[1] == "admin":
            c.execute("SELECT count(*) FROM users WHERE role = 'admin'")
            if c.fetchone()[0] <= 1:
                return False, "You are the only administrator. Make another administrator first."
        c.execute("DELETE FROM users WHERE id = %s", (user_id,))
    logger.info("Account deleted by its owner: user_id=%s", user_id)
    return True, "Your account and all your data have been deleted."

# ---------- staff roles, audit log, CSV import, saved roadmap progress ----------
ROLES = ("student", "dept_admin", "admin")
MAX_IMPORT_ROWS = 300
MAX_IMPORT_BYTES = 200_000

def _require_staff(c, user_id):
    """Allows administrators and department administrators. Returns (role, department)."""
    c.execute("SELECT role, department FROM users WHERE id = %s", (user_id,))
    row = c.fetchone()
    if not row or row[0] not in ("admin", "dept_admin"):
        logger.warning("Staff access denied: user_id=%s", user_id)
        raise PermissionError("Administrator access required.")
    return row[0], row[1]

def _audit(c, admin_id, action, target):
    c.execute("INSERT INTO admin_audit (admin_id, action, target) VALUES (%s, %s, %s)", (admin_id, action[:40], clean_line(target, 80)))

def list_staff(admin_id):
    """Administrators and department administrators (username, name, role, department). Full admins only."""
    with db_cursor() as c:
        _require_admin(c, admin_id)
        c.execute("SELECT username, full_name, role, department FROM users WHERE role <> 'student' ORDER BY role, username")
        return [{"Username": r[0], "Name": r[1], "Role": r[2], "Department": r[3]} for r in c.fetchall()]

def list_audit_log(admin_id, limit=25):
    """Most recent administrative actions. Full admins only."""
    with db_cursor() as c:
        _require_admin(c, admin_id)
        c.execute("SELECT to_char(a.created_at, 'YYYY-MM-DD HH24:MI'), COALESCE(u.username, '(deleted)'), a.action, a.target "
                  "FROM admin_audit a LEFT JOIN users u ON u.id = a.admin_id ORDER BY a.id DESC LIMIT %s", (max(1, min(int(limit), 100)),))
        return [{"When": r[0], "Admin": r[1], "Action": r[2], "Target": r[3]} for r in c.fetchall()]

def set_user_role(admin_id, username, new_role):
    """Promotes or demotes a user. Full admins only; the last administrator can never be removed. Returns (ok, message)."""
    username = (username or "").strip().lower()
    if new_role not in ROLES:
        return False, "Unknown role."
    if not re.fullmatch(r"[a-z0-9_.-]{3,30}", username):
        return False, "Enter a valid username."
    with db_cursor() as c:
        _require_admin(c, admin_id)
        c.execute("SELECT id, role, department, email_verified FROM users WHERE username = %s FOR UPDATE", (username,))
        target = c.fetchone()
        if not target:
            return False, "No user with that username."
        if not target[3]:
            return False, "That account's email address is not verified yet."
        if target[1] == new_role:
            return False, f"They already have the {new_role} role."
        if target[1] == "admin" and new_role != "admin":
            c.execute("SELECT count(*) FROM users WHERE role = 'admin'")
            if c.fetchone()[0] <= 1:
                return False, "At least one administrator must remain."
        if new_role == "dept_admin" and target[2] == UNSPECIFIED_DEPT:
            return False, "Set this user's department first (they can do it on their Account page)."
        c.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, target[0]))
        _audit(c, admin_id, f"role:{target[1]}->{new_role}", username)
    logger.info("Role changed: admin_id=%s target=%s new_role=%s", admin_id, username, new_role)
    return True, f"{username} is now: {new_role}."

def parse_student_csv(text):
    """Parses an uploaded CSV (columns: full_name or name, email; optional department, username).
    Returns (rows, problems); bad rows are reported, never imported."""
    if len(text.encode("utf-8", "ignore")) > MAX_IMPORT_BYTES:
        return [], ["The file is too large."]
    rows, problems, seen = [], [], set()
    try:
        reader = csv.DictReader(io.StringIO(text))
        fields = {(f or "").strip().lower().replace(" ", "_"): f for f in (reader.fieldnames or [])}
        name_key, email_key = fields.get("full_name") or fields.get("name"), fields.get("email")
        if not name_key or not email_key:
            return [], ["The CSV needs the columns full_name (or name) and email. Optional: department, username."]
        for n, raw in enumerate(reader, start=2):
            if len(rows) + len(problems) >= MAX_IMPORT_ROWS:
                problems.append(f"Stopped after {MAX_IMPORT_ROWS} rows. Import the rest in another file.")
                break
            name = clean_line(raw.get(name_key) or "", MAX_NAME_LEN)
            email = (raw.get(email_key) or "").strip().lower()
            dept = ((raw.get(fields["department"]) or "").strip() if "department" in fields else "") or UNSPECIFIED_DEPT
            uname = ((raw.get(fields["username"]) or "").strip().lower() if "username" in fields else "")
            if not name:
                problems.append(f"Row {n}: missing name")
            elif not is_valid_email(email):
                problems.append(f"Row {n}: invalid email")
            elif email in seen:
                problems.append(f"Row {n}: duplicate email in this file")
            elif not valid_department(dept):
                problems.append(f"Row {n}: unknown department")
            elif uname and (not re.fullmatch(r"[a-z0-9_.-]{3,30}", uname) or uname in RESERVED_USERNAMES):
                problems.append(f"Row {n}: invalid username")
            else:
                seen.add(email)
                rows.append({"full_name": name, "email": email, "department": dept, "username": uname})
    except csv.Error:
        problems.append("The file could not be read as CSV.")
    return rows, problems

def bulk_import_students(admin_id, rows):
    """Creates student accounts from parsed CSV rows (full admins only). The accounts have no usable password:
    each student sets their own with 'Forgot password', which proves they own the email address."""
    rows = rows[:MAX_IMPORT_ROWS]
    created = skipped = 0
    with db_cursor() as c:
        _require_admin(c, admin_id)
        c.execute("SELECT LOWER(email) FROM users WHERE LOWER(email) = ANY(%s)", ([r["email"] for r in rows],))
        existing = {r[0] for r in c.fetchall()}
        for r in rows:
            if r["email"] in existing:
                skipped += 1
                continue
            base = r["username"] or re.sub(r"[^a-z0-9_.-]", "", r["email"].split("@")[0])[:24]
            if len(base) < 3:
                base = (base + "user")[:24]
            for attempt in range(60):
                candidate = base if attempt == 0 else f"{base}{attempt}"[:30]
                if candidate in RESERVED_USERNAMES:
                    continue
                c.execute("INSERT INTO users (username, full_name, email, password_hash, department, email_verified) "
                          "VALUES (%s, %s, %s, %s, %s, TRUE) ON CONFLICT DO NOTHING RETURNING id",
                          (candidate, r["full_name"], r["email"], "disabled$" + secrets.token_urlsafe(24), r["department"]))
                if c.fetchone():
                    created += 1
                    break
            else:
                skipped += 1
        _audit(c, admin_id, "bulk_import", f"{created} created, {skipped} skipped")
    return {"created": created, "skipped": skipped}

def load_roadmap_progress(user_id, sig):
    """Returns the set of completed task ids ("week_index") saved for a roadmap."""
    if not re.fullmatch(r"[0-9a-f]{8}", sig or ""):
        return set()
    with db_cursor() as c:
        c.execute("SELECT done_keys FROM roadmap_progress WHERE user_id = %s AND plan_sig = %s", (user_id, sig))
        row = c.fetchone()
    return {k for k in (row[0].split(",") if row and row[0] else []) if re.fullmatch(r"[1-4]_\d{1,2}", k)}

def save_roadmap_progress(user_id, sig, done):
    """Saves completed task ids (validated); keeps only the user's 20 most recent roadmaps."""
    done = sorted(k for k in done if re.fullmatch(r"[1-4]_\d{1,2}", str(k)))[:60]
    if not re.fullmatch(r"[0-9a-f]{8}", sig or ""):
        return False
    with db_cursor() as c:
        c.execute("INSERT INTO roadmap_progress (user_id, plan_sig, done_keys) VALUES (%s, %s, %s) "
                  "ON CONFLICT (user_id, plan_sig) DO UPDATE SET done_keys = EXCLUDED.done_keys, updated_at = now()",
                  (user_id, sig, ",".join(done)))
        c.execute("DELETE FROM roadmap_progress WHERE user_id = %s AND plan_sig NOT IN "
                  "(SELECT plan_sig FROM roadmap_progress WHERE user_id = %s ORDER BY updated_at DESC LIMIT 20)", (user_id, user_id))
    return True

def authenticate_user(identifier, password):
    """Verifies credentials; `identifier` is the username OR the registered email.
    Returns (id, username, full_name, email, created_at) or None.
    Locks the account for LOCKOUT_MINUTES after MAX_LOGIN_FAILURES wrong passwords (raises AccountLocked)."""
    identifier = identifier.strip().lower()
    if len(password) > MAX_PASSWORD_LEN or len(identifier) > 254:  # 254 = longest valid email address
        verify_password("x", _dummy_hash())
        return None
    with db_cursor() as c:
        c.execute(
            "SELECT id, username, full_name, email, to_char(created_at, 'YYYY-MM-DD HH24:MI'), password_hash, "
            "failed_logins, locked_until, email_verified FROM users WHERE username = %s OR LOWER(email) = %s LIMIT 1 FOR UPDATE",
            (identifier, identifier)  # usernames can't contain "@", so a username never collides with an email
        )
        row = c.fetchone()
        if not row:
            verify_password(password, _dummy_hash())  # equalize timing with the real-user path
            return None
        now = datetime.now(timezone.utc)
        if row[7] and row[7] > now:
            verify_password(password, _dummy_hash())  # same cost as a real attempt: locked state isn't observable by timing
            raise AccountLocked(int((row[7] - now).total_seconds()) + 1)
        if not verify_password(password, row[5]):
            _register_failed_attempt(c, row[0], row[6])
            return None
        c.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = %s", (row[0],))
        if not row[5].startswith("pbkdf2$") or int(row[5].split("$")[1]) < PBKDF2_ITERATIONS:
            c.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hash_password(password), row[0]))
        profile, unverified = row[:5], not row[8]
    if unverified:  # raised after the transaction commits, and only once the password has been proven correct
        raise EmailNotVerified(profile[0])
    return profile

def get_token_version(user_id):
    """Current session token version for a user (None if the account no longer exists)."""
    with db_cursor() as c:
        c.execute("SELECT token_version FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
    return row[0] if row else None

def get_session_info(user_id):
    """Fresh server-side session facts (token version, role, department); None if the account no longer exists.
    The role is always re-read from the database, never trusted from the browser session."""
    with db_cursor() as c:
        c.execute("SELECT token_version, role, department FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
    return {"token_version": row[0], "role": row[1], "department": row[2]} if row else None

def update_user_profile(user_id, new_full_name, new_email, current_password="", department=None):
    """Updates profile details. Changing the email requires the current password. Returns (ok, message)."""
    name = clean_line(new_full_name)
    email = new_email.strip().lower()
    if not name or len(name) > MAX_NAME_LEN:
        return False, f"Full name must be 1-{MAX_NAME_LEN} characters."
    if len(email) > MAX_EMAIL_LEN or not is_valid_email(email):
        return False, "Please enter a valid email address."
    if department is not None and not valid_department(department):
        return False, "Please choose a department from the list."
    try:
        with db_cursor() as c:
            c.execute("SELECT email, password_hash, failed_logins, locked_until FROM users WHERE id = %s FOR UPDATE", (user_id,))
            row = c.fetchone()
            if not row:
                return False, "Account not found."
            if email != row[0]:
                if row[3] and row[3] > datetime.now(timezone.utc):
                    return False, "Too many failed attempts. Please try again later."
                if not (current_password and verify_password(current_password, row[1])):
                    logger.warning("Email change refused (bad password): user_id=%s", user_id)
                    if current_password:
                        _register_failed_attempt(c, user_id, row[2])
                    return False, "Enter your current password to change your email address."
            c.execute("UPDATE users SET full_name = %s, email = %s WHERE id = %s", (name, email, user_id))
            if department is not None:
                c.execute("UPDATE users SET department = %s WHERE id = %s", (department, user_id))
        return True, "Profile updated successfully!"
    except psycopg2.errors.UniqueViolation:
        return False, "That email is already used by another account."

def change_user_password(user_id, old_password, new_password):
    """Changes password after verifying the old one; signs out all other sessions."""
    with db_cursor() as c:
        c.execute("SELECT password_hash, username, failed_logins, locked_until FROM users WHERE id = %s FOR UPDATE", (user_id,))
        row = c.fetchone()
        if row and row[3] and row[3] > datetime.now(timezone.utc):
            return False, "Too many failed attempts. Please try again later."
        if not row or not verify_password(old_password, row[0]):
            if row:
                _register_failed_attempt(c, user_id, row[2])  # a hijacked session can't brute-force the password
            return False, "Current password is incorrect."
        pw_error = validate_password(new_password, row[1])
        if pw_error:
            return False, pw_error
        c.execute("UPDATE users SET password_hash = %s, token_version = token_version + 1 WHERE id = %s",
                  (hash_password(new_password), user_id))
    return True, "Password updated successfully!"

# --- BREVO HTTPS EMAIL API & PASSWORD RESET FUNCTIONS ---
def send_reset_email_brevo(recipient_email, full_name, username, otp_code):
    """Sends a password reset OTP email using Brevo Transactional Email HTTPS API (Port 443)."""
    brevo_api_key = get_config("BREVO_API_KEY")
    sender_email = get_config("BREVO_SENDER_EMAIL")
    sender_name = get_config("BREVO_SENDER_NAME", "AI ATS Resume Analyzer")

    if not brevo_api_key or not sender_email:
        return False, "BREVO_NOT_CONFIGURED"

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": brevo_api_key,
        "content-type": "application/json"
    }
    payload = {
        "sender": {
            "name": sender_name,
            "email": sender_email
        },
        "to": [
            {
                "email": recipient_email,
                "name": full_name
            }
        ],
        "subject": "Password Reset OTP - AI ATS Resume Analyzer",
        "htmlContent": f"""
        <div style="font-family: Arial, sans-serif; max-width: 520px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
            <h2 style="color: #1f4e78;">Password Reset Request</h2>
            <p>Hello <strong>{html.escape(full_name)}</strong>,</p>
            <p>We received a password reset request for your account (<code>@{html.escape(username)}</code>).</p>
            <p>Your 6-digit One-Time Password (OTP) is:</p>
            <div style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #0b5394; background: #f0f4f8; padding: 12px; text-align: center; border-radius: 6px; margin: 16px 0;">
                {otp_code}
            </div>
            <p style="color: #555;">This OTP will expire in <strong>15 minutes</strong>. If you did not request this reset, you can safely ignore this email.</p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="font-size: 12px; color: #888;">AI-Powered ATS Resume & Job Match Analyzer</p>
        </div>
        """
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        if response.status_code in (200, 201, 202):
            return True, "Email sent successfully via Brevo."
        else:
            return False, f"Brevo API Error ({response.status_code})"
    except Exception as e:
        return False, f"Network Error: {str(e)}"

RESET_GENERIC_MSG = (
    "If an account matches, a 6-digit OTP has been sent to its registered email address. "
    f"Check your inbox (and spam folder). It is valid for {OTP_VALID_MINUTES} minutes."
)

def _deliver_otp(user_id, email, full_name, username, otp_code):
    """Emails the OTP; if delivery fails the code is invalidated (an OTP nobody received must not stay usable)."""
    try:
        sent, status = send_reset_email_brevo(email, full_name, username, otp_code)
    except Exception as exc:
        sent, status = False, type(exc).__name__
    if not sent:
        logger.error("Reset email not delivered: user_id=%s reason=%s", user_id, status)
        try:
            with db_cursor() as c:
                c.execute("UPDATE password_resets SET used = TRUE WHERE user_id = %s", (user_id,))
        except Exception:
            logger.exception("Could not invalidate undelivered OTP: user_id=%s", user_id)

def initiate_password_reset(identifier):
    """Starts a reset for a username or email. The OTP is only ever emailed to the address registered on the
    account. The response is identical whether or not the account exists (no account enumeration), and requests
    are rate limited per account."""
    clean_id = identifier.strip().lower()
    if not clean_id or len(clean_id) > MAX_EMAIL_LEN:
        return False, "Please enter your username or email address."
    with db_cursor() as c:
        c.execute(
            "SELECT id, username, full_name, email FROM users WHERE username = %s OR LOWER(email) = %s LIMIT 1",
            (clean_id, clean_id)
        )
        user = c.fetchone()
        if not user:
            c.execute("SELECT count(*) FROM password_resets WHERE user_id = %s AND created_at > now() - interval '1 hour'", (-1,))
            c.fetchone()  # comparable DB work, so response time doesn't reveal whether the account exists
            return True, RESET_GENERIC_MSG
        user_id, username, full_name, email = user
        c.execute(
            "SELECT count(*) FROM password_resets WHERE user_id = %s AND created_at > now() - interval '1 hour'",
            (user_id,)
        )
        if c.fetchone()[0] >= RESET_REQUESTS_PER_HOUR:
            logger.warning("Password reset rate limit hit: user_id=%s", user_id)
            return True, RESET_GENERIC_MSG
        otp_code = f"{secrets.randbelow(900000) + 100000}"
        c.execute("UPDATE password_resets SET used = TRUE WHERE user_id = %s", (user_id,))
        c.execute(
            "INSERT INTO password_resets (user_id, otp_code, expires_at, used) VALUES (%s, %s, %s, FALSE)",
            (user_id, _otp_digest(otp_code), datetime.now(timezone.utc) + timedelta(minutes=OTP_VALID_MINUTES))
        )

    if OTP_ASYNC_DELIVERY:  # the slow email API call must not make existing accounts distinguishable by latency
        threading.Thread(target=_deliver_otp, args=(user_id, email, full_name, username, otp_code), daemon=True).start()
    else:
        _deliver_otp(user_id, email, full_name, username, otp_code)
    return True, RESET_GENERIC_MSG

def verify_otp_and_reset_password(identifier, otp_input, new_password):
    """Validates the OTP and sets a new password. All failures return the same message."""
    fail = (False, "Invalid or expired OTP. Please request a new one.")
    pw_error = validate_password(new_password)
    if pw_error:
        return False, pw_error
    clean_id = identifier.strip().lower()
    otp_input = otp_input.strip()
    if not clean_id or len(clean_id) > MAX_EMAIL_LEN or not otp_input or len(otp_input) > 12:
        return fail
    with db_cursor() as c:
        c.execute("SELECT id FROM users WHERE username = %s OR LOWER(email) = %s LIMIT 1", (clean_id, clean_id))
        user = c.fetchone()
        if not user:
            return fail
        user_id = user[0]
        c.execute(
            "SELECT id, otp_code, expires_at, attempts FROM password_resets "
            "WHERE user_id = %s AND used = FALSE ORDER BY id DESC LIMIT 1 FOR UPDATE",
            (user_id,)
        )
        reset_row = c.fetchone()
        if not reset_row:
            return fail
        reset_id, stored_digest, expires_at, attempts = reset_row
        if datetime.now(timezone.utc) > expires_at:
            c.execute("UPDATE password_resets SET used = TRUE WHERE id = %s", (reset_id,))
            return fail
        if not hmac.compare_digest(_otp_digest(otp_input).encode(), stored_digest.encode()):
            lock = attempts + 1 >= OTP_MAX_ATTEMPTS
            c.execute("UPDATE password_resets SET attempts = attempts + 1, used = %s WHERE id = %s", (lock, reset_id))
            if lock:
                logger.warning("OTP locked after too many wrong guesses: user_id=%s", user_id)
            return fail
        c.execute(
            "UPDATE users SET password_hash = %s, token_version = token_version + 1, failed_logins = 0, "
            "locked_until = NULL WHERE id = %s",
            (hash_password(new_password), user_id)
        )
        c.execute("UPDATE password_resets SET used = TRUE WHERE user_id = %s", (user_id,))
        logger.warning("Password reset completed: user_id=%s", user_id)
    return True, "Your password has been reset successfully! You can now log in with your new password."

def save_scan_record(user_id, resume_name, target_role, match_score, matched_count, missing_keywords):
    """Saves an ATS scan result to the database for the logged-in user."""
    with db_cursor() as c:
        c.execute(
            """INSERT INTO scans (user_id, resume_name, target_role, match_score, matched_count, missing_keywords)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (user_id, resume_name, target_role, match_score, matched_count, ", ".join(missing_keywords))
        )

def get_user_scans(user_id):
    """Fetches all past scans for a specific user."""
    with db_cursor() as c:
        c.execute(
            """SELECT id, resume_name, target_role, match_score, matched_count, missing_keywords,
                      to_char(scanned_at, 'YYYY-MM-DD HH24:MI')
               FROM scans WHERE user_id = %s ORDER BY id DESC""",
            (user_id,)
        )
        rows = c.fetchall()
    return pd.DataFrame(rows, columns=[
        "ID", "Resume File", "Target Role", "Score (%)", "Matched Keywords", "Missing Keywords", "Date & Time"
    ])

def analysis_quota_remaining(user_id):
    """How many more resumes this user may analyze in the current hour."""
    with db_cursor() as c:
        c.execute("SELECT count(*) FROM scans WHERE user_id = %s AND scanned_at > now() - interval '1 hour'", (user_id,))
        used = c.fetchone()[0]
    return max(0, MAX_ANALYSES_PER_HOUR - used)

def _require_admin(c, user_id):
    """Raises PermissionError unless this account currently holds the admin role in the database."""
    c.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    row = c.fetchone()
    if not row or row[0] != "admin":
        logger.warning("Admin analytics access denied: user_id=%s", user_id)
        raise PermissionError("Administrator access required.")

def _apply_k_anonymity(rows, k=K_ANON_MIN_GROUP):
    """rows: (department, students, scans, avg_score). Groups smaller than k are merged into 'Other departments';
    the merged group is dropped too if it is still smaller than k. Returns a list of dicts."""
    shown, small = [], []
    for dept, students, scans, avg in rows:
        (shown if students >= k else small).append((dept, int(students), int(scans), float(avg or 0)))
    out = [{"Department": d, "Students": n, "Scans": sc, "Average Score (%)": round(a, 1)} for d, n, sc, a in shown]
    if small and sum(r[1] for r in small) >= k:
        total_scans = sum(r[2] for r in small)
        weighted = sum(r[2] * r[3] for r in small) / total_scans if total_scans else 0
        out.append({"Department": "Other departments", "Students": sum(r[1] for r in small),
                    "Scans": total_scans, "Average Score (%)": round(weighted, 1)})
    return sorted(out, key=lambda r: -r["Average Score (%)"])

def get_admin_metrics(admin_id, days=30, department=None):
    """Aggregate, anonymised platform metrics for the admin dashboard. Re-checks the admin role in the database.
    Only students are counted; no names, emails or resume content are ever returned, and small groups are hidden."""
    if days not in ADMIN_WINDOWS:
        raise ValueError("Unsupported reporting window.")
    if department is not None and not valid_department(department):
        raise ValueError("Unknown department.")
    with db_cursor() as c:
        role, own_department = _require_staff(c, admin_id)
        if role == "dept_admin":
            department = own_department  # a department administrator only ever sees their own department
        c.execute(
            "SELECT count(*) FILTER (WHERE role = 'student'), count(*) FILTER (WHERE role = 'admin'), "
            "count(*) FILTER (WHERE role = 'student' AND created_at >= now() - interval '7 days'), "
            "count(*) FILTER (WHERE role = 'student' AND created_at >= now() - interval '30 days') FROM users")
        users = c.fetchone()
        c.execute(
            "SELECT count(DISTINCT s.user_id) FROM scans s JOIN users u ON u.id = s.user_id WHERE u.role = 'student' "
            "AND s.scanned_at >= now() - make_interval(days => %s) AND (%s::text IS NULL OR u.department = %s)",
            (days, department, department))
        if c.fetchone()[0] < K_ANON_MIN_GROUP:  # a department filter must not single out one or two students
            logger.info("Admin analytics suppressed (population below %s): admin_id=%s", K_ANON_MIN_GROUP, admin_id)
            return {"students": users[0], "admins": users[1], "new_7d": users[2], "new_30d": users[3],
                    "active_7d": 0, "active_30d": 0, "scans_in_window": 0, "avg_score": 0.0, "by_department": [],
                    "top_missing": [], "score_distribution": [], "daily_scans": [], "days": days,
                    "department": department, "suppressed": True}
        c.execute(
            "SELECT count(DISTINCT s.user_id) FILTER (WHERE s.scanned_at >= now() - interval '7 days'), "
            "count(DISTINCT s.user_id) FILTER (WHERE s.scanned_at >= now() - interval '30 days'), "
            "count(*) FILTER (WHERE s.scanned_at >= now() - make_interval(days => %s)), "
            "avg(s.match_score) FILTER (WHERE s.scanned_at >= now() - make_interval(days => %s)) "
            "FROM scans s JOIN users u ON u.id = s.user_id WHERE u.role = 'student' AND (%s::text IS NULL OR u.department = %s)",
            (days, days, department, department))
        scans = c.fetchone()
        c.execute(
            "SELECT u.department, count(DISTINCT s.user_id), count(*), avg(s.match_score) FROM scans s "
            "JOIN users u ON u.id = s.user_id WHERE u.role = 'student' AND s.scanned_at >= now() - make_interval(days => %s) "
            "AND (%s::text IS NULL OR u.department = %s) GROUP BY u.department", (days, department, department))
        by_dept = c.fetchall()
        c.execute(
            "SELECT kw, count(*) AS occurrences, count(DISTINCT s.user_id) AS students FROM scans s "
            "JOIN users u ON u.id = s.user_id, LATERAL unnest(string_to_array(s.missing_keywords, ', ')) AS kw "
            "WHERE u.role = 'student' AND kw <> '' AND s.scanned_at >= now() - make_interval(days => %s) "
            "AND (%s::text IS NULL OR u.department = %s) "
            "GROUP BY kw HAVING count(DISTINCT s.user_id) >= %s ORDER BY occurrences DESC, kw LIMIT 15",
            (days, department, department, K_ANON_MIN_GROUP))
        top_missing = c.fetchall()
        c.execute(
            "SELECT LEAST(floor(s.match_score / 20), 4)::int AS bucket, count(*) FROM scans s JOIN users u ON u.id = s.user_id "
            "WHERE u.role = 'student' AND s.scanned_at >= now() - make_interval(days => %s) "
            "AND (%s::text IS NULL OR u.department = %s) GROUP BY bucket ORDER BY bucket", (days, department, department))
        buckets = dict(c.fetchall())
        c.execute(
            "SELECT s.scanned_at::date AS day, count(*) FROM scans s JOIN users u ON u.id = s.user_id "
            "WHERE u.role = 'student' AND s.scanned_at >= now() - make_interval(days => %s) "
            "AND (%s::text IS NULL OR u.department = %s) GROUP BY day ORDER BY day", (days, department, department))
        daily = c.fetchall()
    logger.info("Admin analytics viewed: admin_id=%s window=%s", admin_id, days)
    labels = ["0-19", "20-39", "40-59", "60-79", "80-100"]
    return {
        "students": users[0], "admins": users[1], "new_7d": users[2], "new_30d": users[3],
        "active_7d": scans[0], "active_30d": scans[1], "scans_in_window": scans[2],
        "avg_score": round(float(scans[3] or 0), 1),
        "by_department": _apply_k_anonymity(by_dept),
        "top_missing": [{"Skill": kw, "Times missing": n, "Students": st_} for kw, n, st_ in top_missing],
        "score_distribution": [{"Score range": labels[i], "Scans": int(buckets.get(i, 0))} for i in range(5)],
        "daily_scans": [{"Day": str(d), "Scans": n} for d, n in daily],
        "days": days, "department": department, "suppressed": False,
    }

def delete_user_scans(user_id):
    """Deletes all saved scan records for a specific user."""
    with db_cursor() as c:
        c.execute("DELETE FROM scans WHERE user_id = %s", (user_id,))

init_db()

# --- UI THEME & COMPONENTS ---
CUSTOM_CSS = """
<style>
#MainMenu, footer {visibility: hidden;}
.block-container {padding-top: 1.6rem; max-width: 1150px;}
.hero {background: linear-gradient(135deg, #4f6ef7 0%, #7a4ff0 60%, #b04fe8 100%); color: #fff;
       padding: 1.5rem 1.8rem; border-radius: 18px; margin-bottom: 1.2rem; box-shadow: 0 8px 28px rgba(79,110,247,.28);}
.hero h1 {color: #fff; font-size: 1.9rem; margin: 0 0 .3rem 0; padding: 0;}
.hero p {color: rgba(255,255,255,.9); margin: 0; font-size: 1rem;}
.feat {border: 1px solid rgba(128,128,128,.25); background: rgba(128,128,128,.06); border-radius: 14px;
       padding: .9rem 1rem; height: 100%;}
.feat b {display: block; margin-bottom: .2rem;}
.feat span {opacity: .75; font-size: .87rem;}
.card {border: 1px solid rgba(128,128,128,.25); background: rgba(128,128,128,.06); border-radius: 16px; padding: 1rem 1.2rem;}
.step {display: flex; align-items: center; gap: .6rem; font-weight: 700; font-size: 1.05rem; margin: .2rem 0 .6rem 0;}
.step i {background: #4f6ef7; color: #fff; width: 1.6rem; height: 1.6rem; border-radius: 50%; display: inline-flex;
         align-items: center; justify-content: center; font-style: normal; font-size: .85rem;}
.chip {display: inline-block; padding: .18rem .7rem; margin: .15rem .2rem .15rem 0; border-radius: 99px; font-size: .82rem; font-weight: 600;}
.chip.ok {background: rgba(34,170,100,.16); color: #1f9d5c;}
.chip.bad {background: rgba(220,70,70,.15); color: #d64545;}
.chip.info {background: rgba(79,110,247,.16); color: #5b7bff;}
.pill {display: flex; justify-content: space-between; align-items: center; padding: .45rem .8rem; margin-bottom: .4rem;
       border-radius: 10px; border: 1px solid rgba(128,128,128,.25); font-size: .92rem;}
.pill.ok {border-left: 4px solid #22aa64;} .pill.bad {border-left: 4px solid #e0a020;}
.pill em {font-style: normal; opacity: .7; font-size: .82rem;}
.avatar {width: 52px; height: 52px; border-radius: 50%; background: linear-gradient(135deg,#4f6ef7,#b04fe8); color: #fff;
         display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 1.2rem; margin-bottom: .5rem;}
.gauge-wrap {text-align: center;}
.gauge-label {font-weight: 700; margin-top: -.3rem;}
div[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.25); background: rgba(128,128,128,.06);
                              border-radius: 14px; padding: .7rem 1rem;}
div[data-testid="stTabs"] button[role="tab"] {font-weight: 600;}
div.stButton > button, div[data-testid="stFormSubmitButton"] > button, div[data-testid="stDownloadButton"] > button {
    border-radius: 12px; font-weight: 600; padding: .55rem 1rem;}
div[data-testid="stForm"] {border-radius: 16px; border: 1px solid rgba(128,128,128,.25);}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

def session_fields(user_id):
    """Server-side facts stored in the browser session at login (token version, role, department)."""
    return get_session_info(user_id) or {"token_version": -1, "role": "student", "department": UNSPECIFIED_DEPT}

def start_session(user_record):
    """Signs a user in: stores the profile + fresh server-side facts and resets per-session results."""
    st.session_state.user = {
        "id": user_record[0], "username": user_record[1], "full_name": user_record[2],
        "email": user_record[3], "created_at": user_record[4], **session_fields(user_record[0]),
    }
    st.session_state.last_active = time.time()
    st.session_state.login_at = time.time()
    st.session_state.last_single_result = None
    st.session_state.last_batch_result = None
    st.session_state.last_compare_result = None

def read_cookie(name):
    """Reads a request cookie (needs Streamlit >= 1.37; returns None if unavailable)."""
    try:
        return st.context.cookies.get(name)
    except Exception:
        return None

def set_browser_cookie(name, value, max_age):
    """Sets or clears a cookie through a tiny script (Streamlit has no cookie API). Only token-safe characters are allowed."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{0,100}", value or "") or not re.fullmatch(r"[a-z_]{1,40}", name):
        return
    st.components.v1.html(
        "<script>try{const p=window.parent;const s=p.location.protocol==='https:'?'; Secure':'';"
        f"p.document.cookie='{name}={value}; max-age={int(max_age)}; path=/; SameSite=Strict'+s;}}catch(e){{}}</script>",
        height=0)

def jd_picker(prefix, last=None):
    """Role dropdown + job-description box shared by the new pages. Returns (role_title, jd_text)."""
    reuse = "📌 Same job as my last analysis"
    has_last = bool(last and last.get("jd_text"))
    options = ([reuse] if has_last else []) + list(SAMPLE_JDS.keys())
    choice = st.selectbox("Target role (or paste a custom job description):", options, key=f"{prefix}_role")
    if choice == reuse:
        with st.expander("Job description from your last analysis"):
            st.text(last["jd_text"][:1500])
        return last.get("role_title", "Custom Job Description"), last["jd_text"]
    suffix = hashlib.sha256(choice.encode()).hexdigest()[:8]   # new key per choice, so the box resets to that role's default
    jd = st.text_area("Job description", value=SAMPLE_JDS[choice], height=170, max_chars=MAX_JD_CHARS, key=f"{prefix}_jd_{suffix}")
    return (choice if choice != "Custom (Paste your own Job Description)" else "Custom Job Description"), jd

WORK_STATE_KEYS = ("editor_resume", "cover_letter_text", "editor_baseline", "editor_baseline_sig")

def wipe_work_state():
    """Removes resume/cover-letter drafts from the session (shared computers)."""
    for key in WORK_STATE_KEYS:
        st.session_state.pop(key, None)

def _load_last_resume_into_editor():
    last = st.session_state.get("last_single_result")
    if last and last.get("raw_text"):
        st.session_state["editor_resume"] = last["raw_text"]

def _fill_cover_letter(name, company, role, skills, achievement):
    st.session_state["cover_letter_text"] = build_cover_letter(name, company, role, skills, achievement)

def hero(title, subtitle):
    """Renders the gradient page header banner."""
    st.markdown(f'<div class="hero"><h1>{html.escape(title)}</h1><p>{html.escape(subtitle)}</p></div>', unsafe_allow_html=True)

def step_header(number, label):
    st.markdown(f'<div class="step"><i>{number}</i>{html.escape(label)}</div>', unsafe_allow_html=True)

def chips(words, kind="info"):
    """Colored keyword chips (kind: ok / bad / info)."""
    return "".join(f'<span class="chip {kind}">{html.escape(str(w))}</span>' for w in words)

def pill(label, ok, ok_text="Detected", bad_text="Missing"):
    """Checklist row with a colored status edge."""
    cls = "ok" if ok else "bad"
    icon = "✅" if ok else "⚠️"
    return f'<div class="pill {cls}"><span>{icon} <b>{html.escape(label)}</b></span><em>{ok_text if ok else bad_text}</em></div>'

def score_gauge(score):
    """SVG donut gauge for the ATS score, colored by match quality."""
    color = "#22aa64" if score >= 70 else "#e0a020" if score >= 45 else "#e04b4b"
    label = "Great match" if score >= 70 else "Moderate match" if score >= 45 else "Low match"
    circ = 2 * 3.14159 * 54
    dash = max(0.0, min(score, 100.0)) / 100 * circ
    return (
        f'<div class="gauge-wrap"><svg viewBox="0 0 140 140" width="190" height="190">'
        f'<circle cx="70" cy="70" r="54" fill="none" stroke="rgba(128,128,128,.22)" stroke-width="13"/>'
        f'<circle cx="70" cy="70" r="54" fill="none" stroke="{color}" stroke-width="13" stroke-linecap="round" '
        f'stroke-dasharray="{dash:.1f} {circ:.1f}" transform="rotate(-90 70 70)"/>'
        f'<text x="70" y="76" text-anchor="middle" font-size="26" font-weight="700" fill="currentColor">{score}%</text></svg>'
        f'<div class="gauge-label" style="color:{color}">{label}</div></div>'
    )

# --- SESSION STATE INITIALIZATION ---
if "user" not in st.session_state:
    st.session_state.user = None
if "last_single_result" not in st.session_state:
    st.session_state.last_single_result = None
if "last_batch_result" not in st.session_state:
    st.session_state.last_batch_result = None
    st.session_state.last_compare_result = None
if "last_compare_result" not in st.session_state:
    st.session_state.last_compare_result = None
if "otp_notice" not in st.session_state:
    st.session_state.otp_notice = None
if "show_forgot" not in st.session_state:
    st.session_state.show_forgot = False
if "reset_identifier" not in st.session_state:
    st.session_state.reset_identifier = ""

# --- PRE-LOADED SAMPLE JOB DESCRIPTIONS ---
SAMPLE_JDS = {
    "Custom (Paste your own Job Description)": "",
    "Software Engineer / Full-Stack Developer": (
        "We are looking for a Full-Stack Software Engineer skilled in Python, JavaScript, React, "
        "Node.js, REST APIs, SQL, Git, Docker, and cloud deployment on AWS. Experience with agile "
        "development, unit testing, CI/CD pipelines, and scalable microservices architecture is preferred."
    ),
    "Data Scientist / Machine Learning Engineer": (
        "Seeking a Data Scientist proficient in Python, Machine Learning, Deep Learning, NLP, "
        "Scikit-Learn, Pandas, NumPy, TensorFlow or PyTorch, SQL, and data visualization. Strong "
        "understanding of statistical modeling, feature engineering, TF-IDF, and model deployment."
    ),
    "Cloud & DevOps Engineer": (
        "Hiring a Cloud DevOps Engineer experienced in AWS, Docker, Kubernetes, Linux, Terraform, "
        "CI/CD automation, GitHub Actions, Jenkins, monitoring, networking, and Python or Bash scripting "
        "for high-availability infrastructure."
    ),
    "Data Analyst / Business Intelligence": (
        "Looking for a Data Analyst with strong expertise in SQL, Python, Excel, Power BI, Tableau, "
        "data cleaning, statistical analysis, KPI reporting, ETL pipelines, and dashboard storytelling."
    ),
    "Cybersecurity Analyst": (
        "Seeking a Cybersecurity Analyst knowledgeable in network security, SIEM tools, vulnerability "
        "assessment, penetration testing, Linux, Python scripting, incident response, firewalls, and ISO 27001."
    )
}

ACTION_VERBS = [
    "developed", "designed", "implemented", "built", "engineered", "optimized",
    "led", "managed", "automated", "deployed", "analyzed", "created", "improved",
    "reduced", "increased", "architected", "integrated", "collaborated", "spearheaded"
]

# --- NLP & AUDIT HELPER FUNCTIONS ---
def safe_filename(name):
    """Reduces an uploaded file name to a harmless display/download name (no paths, control or odd characters)."""
    base = os.path.basename((name or "").replace("\\", "/"))
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", CONTROL_CHARS.sub("", base)).strip(" .")[:100]
    return base or "resume.pdf"

def csv_safe(df):
    """Neutralizes spreadsheet formula injection: text cells starting with = + - @ are prefixed with an apostrophe."""
    out = df.copy()
    for col in out.columns:
        if not pd.api.types.is_numeric_dtype(out[col]):  # object, string and pandas 3's default "str" dtype alike
            out[col] = out[col].map(
                lambda v: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v)
    return out

def validate_pdf_upload(uploaded_file):
    """Rejects oversized files and files that are not really PDFs. Returns an error message or None."""
    uploaded_file.seek(0, 2)
    size = uploaded_file.tell()
    uploaded_file.seek(0)
    if size > MAX_PDF_BYTES:
        return f"File is too large ({size // 1024} KB). Maximum size is {MAX_PDF_BYTES // (1024 * 1024)} MB."
    if size == 0 or uploaded_file.read(5) != b"%PDF-":
        uploaded_file.seek(0)
        return "This file is not a valid PDF."
    uploaded_file.seek(0)
    return None

def extract_text_from_pdf(uploaded_file):
    """Safely extracts raw text from an uploaded PDF (size, page and text-length limits enforced)."""
    problem = validate_pdf_upload(uploaded_file)
    if problem:
        return None, problem
    try:
        reader = pypdf.PdfReader(uploaded_file)
        if reader.is_encrypted:
            return None, "The uploaded PDF is password-protected. Please upload an unlocked PDF."
        if len(reader.pages) > MAX_PDF_PAGES:
            return None, f"The PDF has too many pages ({len(reader.pages)}). Maximum is {MAX_PDF_PAGES}."
        text = ""
        for page in reader.pages:
            extracted = page.extract_text()
            if extracted:
                text += extracted + " "
            if len(text) >= MAX_TEXT_CHARS:
                text = text[:MAX_TEXT_CHARS]
                break
        if len(text.strip()) < 50:
            return None, ("Could not read any text from this PDF. It looks like a scanned image. Export your resume as a "
                          "text-based PDF from Word or Google Docs, or upload it as a Word (.docx) file instead.")
        return text, None
    except Exception:
        logger.exception("PDF parsing failed")
        return None, "Could not read this PDF. It may be corrupted or malformed."

MAX_DOCX_XML_BYTES = 10 * 1024 * 1024   # decompressed size cap for word/document.xml (zip-bomb guard)
WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

def extract_text_from_docx(uploaded_file):
    """Safely extracts text from a .docx file using only the standard library (size, zip-bomb and XML-entity guards)."""
    uploaded_file.seek(0, 2)
    size = uploaded_file.tell()
    uploaded_file.seek(0)
    if size > MAX_PDF_BYTES:
        return None, f"File is too large ({size // 1024} KB). Maximum size is {MAX_PDF_BYTES // (1024 * 1024)} MB."
    if size == 0 or uploaded_file.read(4) != b"PK\x03\x04":
        uploaded_file.seek(0)
        return None, "This file is not a valid Word (.docx) document."
    uploaded_file.seek(0)
    try:
        with zipfile.ZipFile(uploaded_file) as archive:
            if len(archive.infolist()) > 2000:
                return None, "This Word file has too many parts to be a normal resume."
            try:
                info = archive.getinfo("word/document.xml")
            except KeyError:
                return None, "This file is not a valid Word (.docx) document."
            if info.file_size > MAX_DOCX_XML_BYTES:
                return None, "This Word document is too large or complex to read."
            xml_bytes = archive.read(info)  # reading stops at the declared size, so a lying header can't inflate it
        lowered = xml_bytes.lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:  # blocks XML entity-expansion ("billion laughs") attacks
            return None, "This Word document contains unsupported content."
        root = ET.fromstring(xml_bytes)
        lines = []
        for paragraph in root.iter(WORD_NS + "p"):
            line = "".join(node.text or "" for node in paragraph.iter(WORD_NS + "t")).strip()
            if line:
                lines.append(line)
        text = "\n".join(lines)[:MAX_TEXT_CHARS]
        if len(text.strip()) < 50:
            return None, "Could not find enough text in this Word document."
        return text, None
    except (zipfile.BadZipFile, ET.ParseError):
        return None, "Could not read this Word file. It may be corrupted."
    except Exception:
        logger.exception("DOCX parsing failed")
        return None, "Could not read this Word file."

def extract_resume_text(uploaded_file):
    """Reads a resume upload (PDF or Word), choosing the parser from the file's real content, not its name."""
    head = uploaded_file.read(4)
    uploaded_file.seek(0)
    if head == b"PK\x03\x04":
        return extract_text_from_docx(uploaded_file)
    return extract_text_from_pdf(uploaded_file)

# Different spellings of the same skill are folded into one token so "ML" and "machine learning" match each other.
ALIAS_RULES = [
    (r"c\+\+", "cpp"), (r"c#", "csharp"), (r"\.net", "dotnet"), (r"node\.?\s?js", "nodejs"), (r"react\.?\s?js", "react"),
    (r"vue\.?\s?js", "vue"), (r"ci\s*[/\s-]\s*cd", "cicd"), (r"scikit[\s-]?learn|sklearn", "scikitlearn"),
    (r"machine[\s-]+learning|ml", "machinelearning"), (r"deep[\s-]+learning|dl", "deeplearning"),
    (r"natural[\s-]+language[\s-]+processing", "nlp"), (r"artificial[\s-]+intelligence", "ai"),
    (r"power[\s-]?bi", "powerbi"), (r"postgre(?:s|sql|\s?sql)", "postgresql"), (r"mongo[\s-]?db", "mongodb"),
    (r"k8s", "kubernetes"), (r"amazon[\s-]+web[\s-]+services", "aws"), (r"google[\s-]+cloud(?:[\s-]+platform)?", "gcp"),
    (r"rest(?:ful)?[\s-]+apis?", "restapi"), (r"object[\s-]+oriented[\s-]+programming", "oop"),
    (r"java[\s-]?script", "javascript"), (r"type[\s-]?script", "typescript"), (r"tensor[\s-]?flow", "tensorflow"),
]
# Words that appear in almost every job post but are not skills (kept separate from GENERIC_WORDS so real terms like "data" stay).
FILLER_WORDS = {
    "experience", "ability", "strong", "work", "working", "team", "teams", "knowledge", "skills", "skill", "years", "required",
    "requirements", "preferred", "good", "excellent", "role", "job", "candidate", "candidates", "seeking", "looking", "understanding",
    "including", "using", "use", "etc", "plus", "must", "will", "new", "high", "based", "related", "environment", "responsibilities",
    "familiarity", "proficiency", "proficient", "hands", "company", "business", "need", "needs", "needed", "want", "wanted", "able",
    "like", "ideal", "ideally", "join", "position", "opportunity", "apply", "skilled", "least", "minimum", "degree", "qualifications", "duties",
}
DISPLAY_NAMES = {
    "cpp": "c++", "csharp": "c#", "dotnet": ".net", "nodejs": "node.js", "cicd": "ci-cd", "scikitlearn": "scikit-learn",
    "machinelearning": "machine learning", "deeplearning": "deep learning", "powerbi": "power bi", "restapi": "rest api",
}

def normalize_skill_aliases(text):
    """Replaces known skill spellings (ML, k8s, C++, Node.js ...) with one canonical token."""
    for pattern, canonical in ALIAS_RULES:
        text = re.sub(rf"(?<![a-z0-9])(?:{pattern})(?![a-z0-9])", canonical, text)
    return text

def display_keyword(token):
    """Human-friendly name for a canonical keyword token."""
    return DISPLAY_NAMES.get(token, token)

def clean_text(text):
    """Cleans text: lowercases, folds skill aliases together and removes special characters."""
    text = normalize_skill_aliases(text.lower())
    text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def ats_format_checks(text):
    """Heuristic layout checks on the extracted text: things that commonly trip up real applicant tracking systems."""
    text = (text or "")[:MAX_TEXT_CHARS]
    words = len(text.split())
    lines = [ln for ln in text.splitlines() if ln.strip()]
    checks = []
    checks.append({"label": "Length (one to two pages)", "ok": 250 <= words <= 1000,
                   "tip": f"Your resume has {words} words. Aim for roughly 250-1000 words (1-2 pages)."})
    table_like = ("\t" in text) or sum(1 for ln in lines if re.search(r"\S {4,}\S", ln) or ln.count("|") >= 2) >= 3
    checks.append({"label": "Simple single-column layout", "ok": not table_like,
                   "tip": "Tabs, wide gaps or '|' separators suggest tables or columns. Many ATS read these in the wrong order. Use one column."})
    symbols = len(re.findall(r"[\u2190-\u2BFF\u2600-\u27BF\U0001F300-\U0001FAFF]", text))
    checks.append({"label": "No decorative symbols or icons", "ok": symbols <= 3,
                   "tip": "Icons, stars and arrows often turn into garbage characters. Use plain text and simple '-' or '•' bullets."})
    avg_len = (sum(len(ln) for ln in lines) / len(lines)) if lines else 0
    checks.append({"label": "Short scannable lines", "ok": avg_len <= 140 or len(lines) < 5,
                   "tip": "Long paragraphs are hard to scan. Break experience into short bullet points."})
    return checks

def extract_contact_and_sections(raw_text):
    """Checks for essential ATS contact info, standard resume sections, action verbs, and metrics."""
    raw_text = raw_text[:MAX_TEXT_CHARS]
    # Bounded quantifiers keep this linear-time (an unbounded `+` was quadratic on long text with no '@').
    email_found = "@" in raw_text and bool(re.search(r'[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,24}', raw_text))
    phone_found = bool(re.search(r'(\+?\d{1,3}[\s-]?)?(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4,6}', raw_text))
    linkedin_found = "linkedin.com" in raw_text.lower()
    github_found = "github.com" in raw_text.lower()

    lower_text = raw_text.lower()
    sections = {
        "Education": any(k in lower_text for k in ["education", "b.tech", "b.e", "bachelor", "university", "college", "degree"]),
        "Skills": any(k in lower_text for k in ["skills", "technical skills", "technologies", "tools", "programming"]),
        "Projects": any(k in lower_text for k in ["projects", "personal projects", "academic projects"]),
        "Experience / Internships": any(k in lower_text for k in ["experience", "internship", "work history", "employment"])
    }

    words_list = re.findall(r'\b[a-z]+\b', lower_text)
    found_verbs = sorted(list(set(w for w in words_list if w in ACTION_VERBS)))
    quantified_metrics = re.findall(r'\b\d+(?:\.\d+)?%|\b\d+\+\s*(?:users|projects|clients|models|apis|datasets)', lower_text)

    word_count = len(raw_text.split())
    return {
        "Email": email_found,
        "Phone": phone_found,
        "LinkedIn": linkedin_found,
        "GitHub": github_found,
        "sections": sections,
        "word_count": word_count,
        "action_verbs": found_verbs,
        "metrics_count": len(quantified_metrics)
    }

def calculate_similarity(resume_text, jd_text):
    """Calculates cosine similarity percentage using TF-IDF vectors safely."""
    try:
        documents = [resume_text, jd_text]
        tfidf = TfidfVectorizer(stop_words='english')
        tfidf_matrix = tfidf.fit_transform(documents)
        similarity_matrix = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])
        return round(float(similarity_matrix[0][0]) * 100, 2)
    except ValueError:
        return 0.0

def analyze_keywords(resume_text, jd_text):
    """Extracts top keywords from JD and compares frequency safely."""
    try:
        tfidf = TfidfVectorizer(stop_words='english', max_features=40)
        tfidf.fit([jd_text])
        # generic filler words ("ability", "team", "experience") are not skills: drop them and keep the top 20 real ones
        top_keywords = [w for w in tfidf.get_feature_names_out() if w not in FILLER_WORDS][:20]
    except ValueError:
        return [], [], pd.DataFrame()

    resume_words = resume_text.split()
    jd_words = jd_text.split()

    matched = []
    missing = []
    chart_data = []

    for kw in sorted(top_keywords):
        jd_count = jd_words.count(kw)
        res_count = resume_words.count(kw)
        shown = display_keyword(kw)
        if res_count == 0:
            missing.append(shown)
        else:
            matched.append(shown)
        chart_data.append({
            "Keyword": shown,
            "Job Description": jd_count,
            "Your Resume": res_count
        })

    df_chart = pd.DataFrame(chart_data).set_index("Keyword")
    return matched, missing, df_chart

def generate_bullet_suggestions(missing_keywords):
    """Generates sample tailored bullet points for missing skills."""
    suggestions = []
    for kw in missing_keywords[:5]:
        suggestions.append(
            f"- **[{kw.upper()}]**: Designed and implemented scalable solutions leveraging **{kw}** to improve system efficiency by 25% and deliver measurable project outcomes."
        )
    return suggestions

def generate_interview_questions(matched_keywords, missing_keywords, role_label):
    """Generates tailored technical & behavioral interview prep questions based on the resume scan."""
    questions = []
    for kw in matched_keywords[:3]:
        questions.append(
            f"**[Strength Verification - {kw.upper()}]**: You listed **{kw}** on your resume. Can you walk through a real project where you used {kw} and explain an architectural trade-off or bug you solved?"
        )
    for kw in missing_keywords[:3]:
        questions.append(
            f"**[Skill-Gap Check - {kw.upper()}]**: This **{role_label}** role requires **{kw}**, which wasn't prominent in your resume. How would you approach learning or applying {kw} in a production workflow?"
        )
    if not questions:
        questions.append(
            f"**[Role Alignment]**: Tell us about your most complex academic or internship project relevant to **{role_label}** and how you measured its success."
        )
    return questions

def build_report_text(candidate_name, filename, role_label, match_score, audit, matched, missing, questions):
    """Generates a downloadable plain-text ATS audit & interview prep report."""
    lines = [
        "====================================================",
        "    AI ATS RESUME, AUDIT & INTERVIEW PREP REPORT    ",
        "====================================================",
        f"Candidate        : {candidate_name}",
        f"Date & Time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Resume File      : {filename}",
        f"Target Role      : {role_label}",
        f"ATS Match Score  : {match_score}%",
        f"Resume Word Count: {audit['word_count']} words",
        f"Action Verbs Used: {len(audit['action_verbs'])} ({', '.join(audit['action_verbs'][:10])})",
        f"Quantified Impact: {audit['metrics_count']} metric(s) detected",
        "",
        "--- CONTACT & PROFILE CHECKLIST ---",
        f"Email Detected   : {'Yes' if audit['Email'] else 'Missing'}",
        f"Phone Detected   : {'Yes' if audit['Phone'] else 'Missing'}",
        f"LinkedIn Link    : {'Yes' if audit['LinkedIn'] else 'Missing'}",
        f"GitHub Link      : {'Yes' if audit['GitHub'] else 'Missing'}",
        "",
        "--- RESUME SECTIONS DETECTED ---",
    ]
    for sec, present in audit["sections"].items():
        lines.append(f"{sec:<25}: {'Found' if present else 'Not Found'}")

    lines.extend([
        "",
        "--- MATCHED KEYWORDS ---",
        ", ".join(matched) if matched else "None",
        "",
        "--- MISSING KEYWORDS TO ADD ---",
        ", ".join(missing) if missing else "None (All top keywords covered!)",
        "",
        "--- SUGGESTED RESUME BULLET POINTS ---"
    ])
    if missing:
        for s in generate_bullet_suggestions(missing):
            lines.append(s.replace("**", ""))
    else:
        lines.append("Your resume already covers all top keywords.")

    lines.extend([
        "",
        "--- MOCK INTERVIEW PREP QUESTIONS ---"
    ])
    for q in questions:
        lines.append("- " + q.replace("**", ""))

    return "\n".join(lines)

# --- A/B COMPARISON, SKILL ROADMAP, BULLET EDITOR & COVER LETTER (pure logic: no Streamlit, no database) ---
def compare_resume_versions(text_a, text_b, jd_text):
    """Scores two resume versions against the same job description and reports exact gains.
    Inputs are raw texts; the result lists newly matched, lost and still-missing JD keywords."""
    jd = clean_text(jd_text[:MAX_JD_CHARS])
    clean_a, clean_b = clean_text(text_a[:MAX_TEXT_CHARS]), clean_text(text_b[:MAX_TEXT_CHARS])
    score_a, score_b = calculate_similarity(clean_a, jd), calculate_similarity(clean_b, jd)
    matched_a, missing_a, _ = analyze_keywords(clean_a, jd)
    matched_b, missing_b, _ = analyze_keywords(clean_b, jd)
    delta = round(score_b - score_a, 2)
    return {
        "score_a": score_a, "score_b": score_b, "delta": delta,
        "verdict": "improved" if delta > 0.5 else "declined" if delta < -0.5 else "about the same",
        "matched_a": matched_a, "matched_b": matched_b, "missing_a": missing_a, "missing_b": missing_b,
        "newly_matched": sorted(set(matched_b) - set(matched_a)),
        "lost": sorted(set(matched_a) - set(matched_b)),
        "still_missing": sorted(set(missing_a) & set(missing_b)),
        "audit_a": extract_contact_and_sections(text_a), "audit_b": extract_contact_and_sections(text_b),
    }

GENERIC_WORDS = {
    "experience", "ability", "strong", "work", "working", "team", "teams", "knowledge", "skills", "skill", "years",
    "required", "requirements", "preferred", "good", "excellent", "role", "job", "candidate", "seeking", "looking",
    "understanding", "including", "using", "use", "etc", "plus", "must", "will", "new", "high", "based", "related",
    "environment", "responsibilities", "familiarity", "proficiency", "proficient", "hands", "solutions", "systems",
    "data", "scientist", "engineer", "developer", "analyst", "intern", "model", "models", "company", "business", "projects",
    "tools", "technologies", "technology", "software", "application", "applications", "develop", "design", "build", "manage",
    "seeking", "deploy", "deployed", "script",
}
SKILL_PROJECTS = {
    "python": "Build a command-line expense tracker with file storage and unit tests",
    "sql": "Design a small relational database (students, courses, grades) and write 15 reporting queries",
    "pandas": "Clean and analyse a messy public CSV dataset and publish your findings as a notebook",
    "numpy": "Implement linear regression from scratch with NumPy and compare it with scikit-learn",
    "scikit": "Train and compare three classifiers on a public dataset with cross-validation and a short write-up",
    "learn": "Train and compare three classifiers on a public dataset with cross-validation and a short write-up",
    "tensorflow": "Train an image classifier on a public dataset and plot accuracy and loss curves",
    "pytorch": "Fine-tune a small pretrained model on your own labelled dataset and report the metrics",
    "nlp": "Build a text classifier (for example spam or sentiment) and evaluate it with a confusion matrix",
    "machine": "Predict house prices or student grades end to end: data cleaning, model, evaluation, README",
    "deployment": "Wrap a trained model in a small web API and deploy it to a free hosting tier",
    "docker": "Containerise one of your existing projects with a Dockerfile and run it with docker compose",
    "kubernetes": "Deploy a two-service demo app to a local cluster (kind or minikube) with a readiness probe",
    "aws": "Host a static site and a small API on the AWS free tier, then document the architecture",
    "azure": "Deploy a small web app to Azure's free tier and set up a basic monitoring alert",
    "git": "Contribute a documentation fix to an open-source project through a pull request",
    "linux": "Automate a daily backup of a folder with a shell script and a cron job",
    "api": "Design and document a REST API with authentication and automated tests",
    "rest": "Design and document a REST API with authentication and automated tests",
    "flask": "Build a notes app with Flask, a database and user login",
    "django": "Build a blog with Django including admin, user accounts and tests",
    "react": "Build a dashboard in React that reads from a public API with loading and error states",
    "javascript": "Build an interactive to-do app in plain JavaScript with local storage",
    "java": "Build a library-management console app in Java with unit tests",
    "spark": "Process a multi-gigabyte public dataset with PySpark and compare timings against pandas",
    "statistics": "Run an A/B test analysis on a sample dataset and explain the result in plain language",
    "visualization": "Create an interactive dashboard that tells a story with one public dataset",
    "tableau": "Publish a Tableau Public dashboard on a topic you care about",
    "excel": "Build an Excel model with pivot tables and charts for a personal budget",
    "cloud": "Deploy one project to a cloud provider's free tier and write down the cost and architecture",
    "testing": "Add unit and integration tests to an existing project and report the coverage",
    "cicd": "Add a CI pipeline that runs tests and linting on every push to one of your repositories",
    "ci": "Add a CI pipeline that runs tests and linting on every push to one of your repositories",
}

def parse_keyword_list(value):
    """Turns 'a, b; c' (or a list) into a clean, de-duplicated list of skill keywords (generic words removed)."""
    parts = re.split(r"[,;\n]+", value) if isinstance(value, str) else list(value or [])
    out = []
    for part in parts:
        kw = re.sub(r"[^a-z0-9+#. -]", "", str(part).lower()).strip(" .-")
        if 2 <= len(kw) <= 30 and kw not in GENERIC_WORDS and kw not in out:
            out.append(kw)
    return out

def generate_roadmap(missing_keywords, hours_per_week=6):
    """Builds a 4-week learning plan (3 skill weeks + a capstone week) from the top missing keywords.
    Returns [] when there are no real skill gaps."""
    skills = parse_keyword_list(missing_keywords)[:ROADMAP_MAX_SKILLS]
    if not skills:
        return []
    groups = [skills[i::3] for i in range(3)]
    weeks = []
    for number, focus in enumerate(groups, start=1):
        deepen = not focus
        focus = focus or skills[:2]
        phrase = " and ".join(focus)
        tasks = []
        for kw in focus:
            tasks.append(f"Learn the core concepts of {kw}: read the official documentation and finish one beginner tutorial"
                         if not deepen else f"Revisit {kw}: solve harder exercises and read one real-world example project")
            tasks.append(f"Complete 5 small hands-on exercises using {kw}")
        tasks.append(f"Build the mini project below, then write a short README explaining what you built and what you learned")
        tasks.append(f"Add one honest, measurable resume bullet about {phrase} (only claim what you actually built)")
        project = SKILL_PROJECTS.get(focus[0], f"Build a small, working project that uses {focus[0]} on a real dataset or problem")
        weeks.append({"week": number, "title": ("Deepen: " if deepen else "Foundations: ") + phrase,
                      "skills": focus, "tasks": tasks, "project": project, "hours": hours_per_week})
    top = skills[:3]
    weeks.append({
        "week": 4, "title": "Capstone, portfolio and re-scan", "skills": top, "hours": hours_per_week,
        "tasks": [
            f"Combine {', '.join(top)} in one end-to-end capstone project",
            "Publish it on GitHub with a clear README (problem, approach, results, how to run it)",
            "Update your resume bullets and re-run the ATS scan (use A/B Compare: old version vs new version)",
            "Practise 5 interview questions about your new skills (see Interview Prep)",
        ],
        "project": f"One portfolio project that uses {', '.join(top)} together, with measurable results you can quote on your resume",
    })
    return weeks

def roadmap_to_text(roadmap, role_title=""):
    """Plain-text version of the roadmap (checklist format) for download."""
    lines = [f"30-DAY SKILL ROADMAP{' - ' + role_title if role_title else ''}", "=" * 50, ""]
    for w in roadmap:
        lines += [f"WEEK {w['week']}: {w['title']}  (~{w['hours']} hours)", *[f"  [ ] {t}" for t in w["tasks"]],
                  f"  Project idea: {w['project']}", ""]
    return "\n".join(lines)

WEAK_LEADS = {
    "responsible for": "Led", "worked on": "Developed", "worked with": "Collaborated with", "helped with": "Supported",
    "helped": "Supported", "assisted with": "Supported", "assisted in": "Supported", "involved in": "Contributed to",
    "participated in": "Contributed to", "tasked with": "Delivered", "duties included": "Delivered", "in charge of": "Managed",
}
BULLET_MARKER = re.compile(r"^\s*(?:[-\u2022*\u25aa\u25cf\u25e6\u2023]|\d{1,2}[.)])\s+")
METRIC_PATTERN = re.compile(
    r"\d+(?:\.\d+)?\s*(?:%|x\b|k\b|\+)|[$\u20b9\u20ac\u00a3]\s?\d|\b\d{2,}\b|"
    r"\b\d+\s+(?:users|clients|projects|models|apis|datasets|students|hours|days|members|requests|customers)\b")

def extract_bullets(text):
    """Pulls bullet-like lines (4-60 words) out of resume text, without their bullet markers."""
    bullets = []
    for line in (text or "")[:MAX_EDITOR_CHARS].splitlines():
        line = BULLET_MARKER.sub("", line).strip()
        if 4 <= len(line.split()) <= 60:
            bullets.append(line)
    return bullets[:80]

GERUND_TO_PAST = {
    "building": "Built", "developing": "Developed", "designing": "Designed", "testing": "Tested", "creating": "Created",
    "implementing": "Implemented", "writing": "Wrote", "analyzing": "Analyzed", "analysing": "Analyzed", "managing": "Managed",
    "improving": "Improved", "optimizing": "Optimized", "automating": "Automated", "deploying": "Deployed",
    "maintaining": "Maintained", "supporting": "Supported", "leading": "Led", "integrating": "Integrated",
    "researching": "Researched", "coordinating": "Coordinated", "documenting": "Documented", "reviewing": "Reviewed",
}

def suggest_rewrite(bullet):
    """A starting-point rewrite for a weak bullet, with placeholders (never invented numbers). None if no change is useful."""
    lower = bullet.lower()
    for lead, verb in sorted(WEAK_LEADS.items(), key=lambda kv: -len(kv[0])):
        if lower.startswith(lead + " "):
            rest = bullet[len(lead):].strip().rstrip(".")
            first_word, _, remainder = rest.partition(" ")
            if first_word.lower() in GERUND_TO_PAST:      # "worked on building X" -> "Built X"
                result = f"{GERUND_TO_PAST[first_word.lower()]} {remainder}".strip()
            elif first_word.lower().endswith("ing"):      # unknown gerund: don't guess the grammar
                result = f"{verb} [what you did]: {rest}"
            else:
                result = f"{verb} {rest}"
            return result + ("" if METRIC_PATTERN.search(lower) else ", resulting in [add a measurable result: %, time saved, users]")
    if not METRIC_PATTERN.search(lower):
        return bullet.rstrip(".") + ", resulting in [add a measurable result: %, time saved, users]"
    return None

def analyze_bullets(text):
    """Lints each bullet: weak lead-in, missing action verb, missing measurable result. Strength is 0-3."""
    results = []
    for bullet in extract_bullets(text):
        lower = bullet.lower()
        first = (re.findall(r"[a-z]+", lower) or [""])[0]
        weak = next((lead for lead in WEAK_LEADS if lower.startswith(lead + " ")), None)
        has_verb = first in ACTION_VERBS
        has_metric = bool(METRIC_PATTERN.search(lower))
        issues = []
        if weak:
            issues.append(f'Starts with a weak phrase ("{weak}")')
        elif not has_verb:
            issues.append("Doesn't start with a strong action verb (try Built, Developed, Optimized, Led)")
        if not has_metric:
            issues.append("No measurable result (add a number: %, time saved, users, size)")
        strength = int(has_verb) + int(has_metric) + int(len(bullet.split()) >= 8)
        results.append({"bullet": bullet, "has_verb": has_verb, "has_metric": has_metric, "weak_lead": weak,
                        "issues": issues, "strength": strength, "rewrite": suggest_rewrite(bullet) if issues else None})
    return results

def keyword_coverage(text, jd_text):
    """(coverage %, matched, missing): how many of the JD's top keywords appear in the text."""
    matched, missing, _ = analyze_keywords(clean_text(text[:MAX_EDITOR_CHARS]), clean_text(jd_text[:MAX_JD_CHARS]))
    total = len(matched) + len(missing)
    return (round(100 * len(matched) / total, 1) if total else 0.0), matched, missing

def build_cover_letter(name, company, role, skills, achievement=""):
    """Template-based cover letter draft (no AI call). Every field is sanitised to a single clean line."""
    name, company, role = clean_line(name, 80) or "Your Name", clean_line(company, 80) or "your company", clean_line(role, 80) or "the open position"
    skill_list = parse_keyword_list(skills)[:6]
    skills_phrase = ", ".join(skill_list[:-1]) + (" and " if len(skill_list) > 1 else "") + skill_list[-1] if skill_list else "the skills listed in the job description"
    achievement = clean_line(achievement, 400)
    middle = (f"One example of my work: {achievement.rstrip('.')}. " if achievement else "") + \
             "I enjoy learning quickly, working in a team and turning requirements into reliable, well-tested results."
    return (f"Dear Hiring Manager at {company},\n\n"
            f"I am excited to apply for the {role} position at {company}. My hands-on experience with {skills_phrase} "
            f"matches the requirements of this role, and I would welcome the chance to contribute from day one.\n\n"
            f"{middle}\n\n"
            f"I would be glad to discuss how my background can help {company}. Thank you for your time and consideration.\n\n"
            f"Sincerely,\n{name}")

def is_valid_email(email):
    """Validates basic email address format."""
    email = email.strip()
    return len(email) <= MAX_EMAIL_LEN and bool(re.fullmatch(r'[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,24}', email))

# =========================================================
# AUTHENTICATION VIEW (LOGIN / SIGN UP / FORGOT PASSWORD)
# =========================================================
if st.session_state.user is None:
    if st.session_state.pop("clear_cookie", False):
        set_browser_cookie(REMEMBER_COOKIE, "", 0)
    if not st.session_state.get("remember_checked"):  # one attempt per browser session, so it can never loop
        st.session_state.remember_checked = True
        _token = read_cookie(REMEMBER_COOKIE)
        if _token:
            _record = user_from_remember_token(_token)
            if _record:
                start_session(_record)
                st.rerun()
            set_browser_cookie(REMEMBER_COOKIE, "", 0)  # stale or revoked cookie: remove it
    hero("📄 AI ATS Resume Analyzer", "Beat the applicant tracking system. Score your resume, close skill gaps and prep for interviews.")
    f1, f2, f3, f4 = st.columns(4)
    for col, (ttl, desc) in zip([f1, f2, f3, f4], [
        ("🎯 ATS Match Score", "TF-IDF similarity against any job description"),
        ("🎤 Interview Prep", "Questions from your strengths and gaps"),
        ("🏆 Recruiter Mode", "Rank many resumes in one click"),
        ("📈 Progress Tracking", "Watch your score improve over time"),
    ]):
        col.markdown(f'<div class="feat"><b>{ttl}</b><span>{desc}</span></div>', unsafe_allow_html=True)
    st.write("")
    if st.session_state.get("session_notice"):
        st.warning(st.session_state.pop("session_notice"))

    auth_col1, auth_col2, auth_col3 = st.columns([1, 2, 1])
    with auth_col2:
        AUTH_LOGIN, AUTH_REGISTER = "🔐 Login", "📝 Create Account"
        if st.session_state.get("auth_goto"):  # set by a successful sign-up; applied before the widget is created
            st.session_state.auth_view = st.session_state.pop("auth_goto")
        auth_view = st.radio("Account", [AUTH_LOGIN, AUTH_REGISTER], horizontal=True,
                             label_visibility="collapsed", key="auth_view")

        if auth_view == AUTH_LOGIN:
            if st.session_state.get("verify_user_id"):
                st.markdown("#### 📧 Verify your email")
                st.caption(f"Enter the 6-digit code we emailed you. It expires in {VERIFY_CODE_MINUTES} minutes.")
                with st.form("verify_email_form"):
                    verify_code_in = st.text_input("Verification code", max_chars=6)
                    if st.form_submit_button("Verify email", use_container_width=True, type="primary"):
                        if verify_email_code(st.session_state.verify_user_id, verify_code_in):
                            st.session_state.verify_user_id = None
                            st.session_state.signup_notice = "Email verified! Please log in."
                            st.rerun()
                        else:
                            st.error("Invalid or expired code.")
                v1, v2 = st.columns(2)
                if v1.button("Resend code", use_container_width=True):
                    send_verification_code(st.session_state.verify_user_id)
                    st.info("If a new code can be sent, it is on its way.")
                if v2.button("← Back to login", use_container_width=True, key="close_verify"):
                    st.session_state.verify_user_id = None
                    st.rerun()
            elif not st.session_state.show_forgot:
                if st.session_state.get("signup_notice"):
                    st.success(st.session_state.pop("signup_notice"))
                with st.form("login_form"):
                    login_username = st.text_input("Username or Email", value=st.session_state.pop("login_prefill", ""))
                    login_password = st.text_input("Password", type="password", max_chars=MAX_PASSWORD_LEN)
                    keep_signed_in = st.checkbox(f"Keep me signed in on this device ({REMEMBER_DAYS} days)")
                    login_submitted = st.form_submit_button("Login", use_container_width=True, type="primary")

                    if login_submitted:
                        if not login_username or not login_password:
                            st.warning("Please enter your username or email, and your password.")
                        else:
                            try:
                                user_record = authenticate_user(login_username, login_password)
                            except AccountLocked:
                                st.error(LOGIN_FAILED_MSG)  # identical text to a wrong password: a lock must not reveal the account exists
                                st.stop()
                            except EmailNotVerified as unverified:
                                st.session_state.verify_user_id = unverified.user_id  # only reachable with the right password
                                st.rerun()
                            if user_record:
                                start_session(user_record)
                                if keep_signed_in:
                                    st.session_state.pending_cookie = create_remember_token(user_record[0])
                                st.rerun()
                            else:
                                st.error(LOGIN_FAILED_MSG)

                if st.button("🔑 Forgot password?", key="open_forgot"):
                    st.session_state.show_forgot = True
                    st.rerun()
            else:
                if st.button("← Back to login", key="close_forgot"):
                    st.session_state.show_forgot = False
                    st.session_state.otp_notice = None
                    st.rerun()
                st.markdown("#### Reset your password")
                st.caption("Enter your username or email. We send a 6-digit OTP to the email address registered with that account.")
                with st.form("request_otp_form"):
                    reset_id_input = st.text_input("Username or Email Address", value=st.session_state.reset_identifier, max_chars=MAX_EMAIL_LEN)
                    send_otp_btn = st.form_submit_button("Send OTP to my registered email 📧", use_container_width=True, type="primary")
                    if send_otp_btn:
                        if not reset_id_input.strip():
                            st.warning("Please enter your username or email address.")
                        else:
                            ok, msg = initiate_password_reset(reset_id_input)
                            if ok:
                                st.session_state.reset_identifier = reset_id_input.strip().lower()
                                st.session_state.otp_notice = msg
                            else:
                                st.session_state.otp_notice = None
                                st.error(msg)

                if st.session_state.otp_notice:
                    st.success(st.session_state.otp_notice)
                    with st.form("verify_otp_form"):
                        otp_code_input = st.text_input("Enter 6-Digit OTP Code", max_chars=6)
                        new_reset_pw = st.text_input("New Password (min 8 characters)", type="password", max_chars=MAX_PASSWORD_LEN)
                        confirm_reset_pw = st.text_input("Confirm New Password", type="password", max_chars=MAX_PASSWORD_LEN)
                        reset_pw_btn = st.form_submit_button("Reset Password ✅", use_container_width=True, type="primary")

                        if reset_pw_btn:
                            if not all([otp_code_input, new_reset_pw, confirm_reset_pw]):
                                st.warning("Please fill in all fields.")
                            elif len(new_reset_pw) < MIN_PASSWORD_LEN:
                                st.warning("New password must be at least 8 characters long.")
                            elif new_reset_pw != confirm_reset_pw:
                                st.error("New passwords do not match.")
                            else:
                                ok, msg = verify_otp_and_reset_password(st.session_state.reset_identifier, otp_code_input, new_reset_pw)
                                if ok:
                                    st.session_state.reset_identifier = ""
                                    st.session_state.otp_notice = None
                                    st.success(msg)
                                else:
                                    st.error(msg)

        else:
            with st.form("register_form"):
                reg_full_name = st.text_input("Full Name (e.g., Aarav Sharma)", max_chars=MAX_NAME_LEN)
                reg_username = st.text_input("Choose a Username", max_chars=30)
                reg_email = st.text_input("Email Address", max_chars=MAX_EMAIL_LEN)
                reg_dept = st.selectbox("Department", [UNSPECIFIED_DEPT] + DEPARTMENTS)
                reg_password = st.text_input("Create Password (min 8 characters)", type="password", max_chars=MAX_PASSWORD_LEN)
                reg_confirm = st.text_input("Confirm Password", type="password", max_chars=MAX_PASSWORD_LEN)
                reg_submitted = st.form_submit_button("Register Account", use_container_width=True, type="primary")

                if reg_submitted:
                    if not all([reg_full_name, reg_username, reg_email, reg_password, reg_confirm]):
                        st.warning("Please fill in all fields.")
                    elif not is_valid_email(reg_email):
                        st.warning("Please enter a valid email address.")
                    elif len(reg_password) < MIN_PASSWORD_LEN:
                        st.warning("Password must be at least 8 characters long.")
                    elif reg_password != reg_confirm:
                        st.error("Passwords do not match.")
                    else:
                        success, msg = register_user(reg_username, reg_full_name, reg_email, reg_password, reg_dept)
                        if success:
                            st.session_state.auth_goto = AUTH_LOGIN  # take the new user straight to the login page
                            st.session_state.signup_notice = msg
                            st.session_state.login_prefill = reg_username.strip().lower()
                            st.rerun()
                        else:
                            st.error(msg)

    st.divider()
    st.caption("7th Semester Engineering Project • Python, Supabase Postgres, Brevo HTTPS Email API, Scikit-Learn & Streamlit")

# =========================================================
# LOGGED-IN DASHBOARD VIEW
# =========================================================
else:
    user = st.session_state.user
    if st.session_state.get("pending_cookie"):
        set_browser_cookie(REMEMBER_COOKIE, st.session_state.pop("pending_cookie"), REMEMBER_DAYS * 86400)

    # Sign out on idle timeout, deleted account, or after a password change/reset elsewhere.
    session_info = get_session_info(user["id"])
    if (time.time() - st.session_state.get("last_active", 0) > SESSION_IDLE_MINUTES * 60
            or time.time() - st.session_state.get("login_at", 0) > SESSION_MAX_HOURS * 3600
            or session_info is None or session_info["token_version"] != user.get("token_version")):
        st.session_state.user = None
        st.session_state.last_single_result = None
        st.session_state.last_batch_result = None
        st.session_state.last_compare_result = None
        wipe_work_state()
        st.session_state.session_notice = "Your session has ended. Please log in again."
        st.rerun()
    st.session_state.last_active = time.time()
    user["role"], user["department"] = session_info["role"], session_info["department"]  # never trust a stale role

    # --- SIDEBAR NAVIGATION & ACCOUNT SUMMARY ---
    with st.sidebar:
        initials = "".join(p[0] for p in user["full_name"].split()[:2]).upper() or "?"
        st.markdown(
            f'<div class="avatar">{html.escape(initials)}</div><b>{html.escape(user["full_name"])}</b>',
            unsafe_allow_html=True
        )
        st.caption(f"@{user['username']} • {user['email']}")
        if user.get("role") == "admin":
            st.caption("🛡️ Administrator")
        st.divider()

        nav_options = [
            "🚀 Single Resume Analyzer",
            "🔀 Resume A/B Compare",
            "🏆 Multi-Resume Batch Ranker",
            "✍️ Resume & Cover Letter Editor",
            "🗓️ 30-Day Skill Roadmap",
            "🕒 My Scan History & Trends",
            "⚙️ Account & Security",
        ]
        if user.get("role") in ("admin", "dept_admin"):
            nav_options.append("📊 Admin Analytics")
        nav_page = st.radio("Navigation", nav_options)

        st.divider()
        user_scans_df = get_user_scans(user["id"])
        st.metric("Total Resumes Scanned", len(user_scans_df))
        if not user_scans_df.empty:
            avg_score = round(user_scans_df["Score (%)"].mean(), 1)
            st.metric("Average ATS Score", f"{avg_score}%")

        st.divider()
        if st.button("🚪 Logout", use_container_width=True):
            _token = read_cookie(REMEMBER_COOKIE)
            if _token:
                revoke_remember_token(_token)
            st.session_state.clear_cookie = True
            st.session_state.user = None
            st.session_state.last_single_result = None
            st.session_state.last_batch_result = None
            st.session_state.last_compare_result = None
            wipe_work_state()
            st.rerun()

    # ---------------------------------------------------------
    # PAGE 1: SINGLE RESUME ANALYZER + INTERVIEW PREP
    # ---------------------------------------------------------
    if nav_page == "🚀 Single Resume Analyzer":
        hero("🚀 Resume Analyzer", f"Welcome, {user['full_name']}! Upload a resume and a job description to get your ATS score.")

        col1, col2 = st.columns(2)

        with col1:
            step_header(1, "Upload Resume (PDF or Word)")
            uploaded_resume = st.file_uploader("Choose a PDF or Word (.docx) file", type=["pdf", "docx"])

        with col2:
            step_header(2, "Target Role / Job Description")
            selected_role = st.selectbox("Quick-Fill Sample Role (or paste custom JD below):", list(SAMPLE_JDS.keys()))
            job_description = st.text_area(
                "Job Description Text:",
                max_chars=MAX_JD_CHARS,
                value=SAMPLE_JDS[selected_role],
                height=160,
                placeholder="Paste the target job description here..."
            )

        if st.button("Analyze Match 🚀", use_container_width=True, type="primary"):
            if analysis_quota_remaining(user["id"]) < 1:
                st.error(f"Hourly limit reached ({MAX_ANALYSES_PER_HOUR} analyses). Please try again later.")
            elif uploaded_resume is not None and job_description.strip() != "":
                with st.spinner("Running NLP analysis, impact audit & interview generator..."):
                    resume_name = safe_filename(uploaded_resume.name)
                    raw_resume, pdf_error = extract_resume_text(uploaded_resume)
                    if pdf_error:
                        st.error(pdf_error)
                    else:
                        cleaned_resume = clean_text(raw_resume)
                        cleaned_jd = clean_text(job_description)

                        if not cleaned_jd:
                            st.warning("Please enter meaningful text in the job description.")
                        else:
                            match_score = calculate_similarity(cleaned_resume, cleaned_jd)
                            matched_keywords, missing_keywords, df_chart = analyze_keywords(cleaned_resume, cleaned_jd)
                            audit = extract_contact_and_sections(raw_resume)
                            role_title = selected_role if selected_role != "Custom (Paste your own Job Description)" else "Custom Job Description"
                            interview_qs = generate_interview_questions(matched_keywords, missing_keywords, role_title)

                            save_scan_record(
                                user["id"],
                                resume_name,
                                role_title,
                                match_score,
                                len(matched_keywords),
                                missing_keywords
                            )

                            st.session_state.last_single_result = {
                                "filename": resume_name,
                                "role_title": role_title,
                                "match_score": match_score,
                                "matched_keywords": matched_keywords,
                                "missing_keywords": missing_keywords,
                                "df_chart": df_chart,
                                "audit": audit,
                                "interview_qs": interview_qs,
                                "raw_text": raw_resume[:MAX_TEXT_CHARS],
                                "jd_text": job_description[:MAX_JD_CHARS]
                            }
            else:
                st.warning("Please upload a PDF resume and select or paste a job description first.")

        if st.session_state.last_single_result is not None:
            res = st.session_state.last_single_result
            st.divider()
            st.subheader(f"📊 Analysis Summary — `{res['filename']}`")

            g_col, m_col = st.columns([1, 2])
            with g_col:
                st.markdown(score_gauge(res["match_score"]), unsafe_allow_html=True)
            with m_col:
                total_kw = len(res["matched_keywords"]) + len(res["missing_keywords"])
                m1, m2, m3 = st.columns(3)
                m1.metric("Keywords Matched", f"{len(res['matched_keywords'])} / {total_kw}")
                m2.metric("Action Verbs", f"{len(res['audit']['action_verbs'])}")
                m3.metric("Quantified Metrics", f"{res['audit']['metrics_count']}")
                if res["match_score"] >= 70:
                    st.success("Great match! Your resume aligns strongly with this job description.")
                elif res["match_score"] >= 45:
                    st.warning("Moderate match. Adding the missing keywords below will boost your ATS ranking.")
                else:
                    st.error("Low match. Tailor your skills and project bullet points to this role.")

            tab1, tab2, tab3, tab4 = st.tabs([
                "📈 Skill-Gap Chart",
                "🔍 Keywords & Bullet Suggestions",
                "📋 Structure, Verbs & Impact Audit",
                "🎤 AI Mock Interview Prep"
            ])

            with tab1:
                if not res["df_chart"].empty:
                    st.write("Comparison of top job description keyword frequencies vs. your resume:")
                    st.bar_chart(res["df_chart"])
                else:
                    st.info("Not enough distinct technical keywords found to plot a chart.")

            with tab2:
                k_col1, k_col2 = st.columns(2)
                with k_col1:
                    st.markdown("#### ✅ Matched Keywords")
                    if res["matched_keywords"]:
                        st.markdown(chips(res["matched_keywords"], "ok"), unsafe_allow_html=True)
                    else:
                        st.write("No top keywords matched yet.")

                with k_col2:
                    st.markdown("#### ❌ Missing Keywords")
                    if res["missing_keywords"]:
                        st.markdown(chips(res["missing_keywords"], "bad"), unsafe_allow_html=True)
                    else:
                        st.success("None! You covered all top keywords.")

                if res["missing_keywords"]:
                    st.divider()
                    st.markdown("#### ✍️ Suggested Bullet-Point Additions")
                    for suggestion in generate_bullet_suggestions(res["missing_keywords"]):
                        st.markdown(suggestion)

            with tab3:
                c_col1, c_col2 = st.columns(2)
                with c_col1:
                    st.markdown("#### Contact & Links Check")
                    for field in ["Email", "Phone", "LinkedIn", "GitHub"]:
                        st.markdown(pill(field, res["audit"][field]), unsafe_allow_html=True)

                with c_col2:
                    st.markdown("#### Essential Sections Check")
                    for sec, present in res["audit"]["sections"].items():
                        st.markdown(pill(sec, present, "Found", "Not detected"), unsafe_allow_html=True)

                st.divider()
                st.markdown("#### 💪 Impact & Action Verb Analysis")
                st.write(f"**Word Count:** {res['audit']['word_count']} words  |  **Quantified Metrics (e.g., %, +):** {res['audit']['metrics_count']} found")
                if res["audit"]["action_verbs"]:
                    st.markdown("**Strong Action Verbs Detected:**<br>" + chips(res["audit"]["action_verbs"], "info"), unsafe_allow_html=True)
                else:
                    st.warning("No strong action verbs detected. Start bullet points with words like *Developed, Engineered, Optimized, Deployed*.")

                st.divider()
                st.markdown("#### 🧾 ATS Format Check")
                for check in ats_format_checks(res.get("raw_text", "")):
                    st.markdown(pill(check["label"], check["ok"], "Looks good", "Needs attention"), unsafe_allow_html=True)
                    if not check["ok"]:
                        st.caption(check["tip"])

            with tab4:
                st.markdown(f"#### 🎤 Tailored Interview Questions for **{res['role_title']}**")
                st.caption("Generated dynamically from your matched strengths and skill gaps:")
                for idx, q in enumerate(res["interview_qs"], 1):
                    with st.expander(f"Question {idx}", expanded=(idx == 1)):
                        st.markdown(q)

            st.divider()
            report_txt = build_report_text(
                user["full_name"],
                res["filename"],
                res["role_title"],
                res["match_score"],
                res["audit"],
                res["matched_keywords"],
                res["missing_keywords"],
                res["interview_qs"]
            )
            st.download_button(
                label="📥 Download Full ATS & Interview Prep Report (.txt)",
                data=report_txt,
                file_name=f"ATS_Report_{os.path.splitext(res['filename'])[0]}.txt",
                mime="text/plain",
                use_container_width=True,
                type="primary"
            )

    # ---------------------------------------------------------
    # PAGE 2: MULTI-RESUME BATCH RANKER (RECRUITER MODE)
    # ---------------------------------------------------------
    elif nav_page == "🏆 Multi-Resume Batch Ranker":
        hero("🏆 Batch Ranker", "Recruiter mode: upload several PDF resumes and rank candidates against one job description.")

        batch_role = st.selectbox("Select Target Role (or paste custom JD below):", list(SAMPLE_JDS.keys()), key="batch_role")
        batch_jd = st.text_area(
            "Target Job Description:",
            max_chars=MAX_JD_CHARS,
            value=SAMPLE_JDS[batch_role],
            height=140,
            key="batch_jd"
        )
        uploaded_files = st.file_uploader(
            "Upload Multiple Resumes (PDF or Word)",
            type=["pdf", "docx"],
            accept_multiple_files=True
        )

        if st.button("Rank All Candidates 🏆", use_container_width=True, type="primary"):
            if uploaded_files and len(uploaded_files) > MAX_BATCH_FILES:
                st.error(f"Please upload at most {MAX_BATCH_FILES} resumes at a time.")
            elif uploaded_files and len(uploaded_files) > analysis_quota_remaining(user["id"]):
                st.error(f"This would exceed your hourly limit of {MAX_ANALYSES_PER_HOUR} analyses. Please upload fewer files or try later.")
            elif uploaded_files and batch_jd.strip():
                cleaned_jd = clean_text(batch_jd)
                if not cleaned_jd:
                    st.warning("Please enter meaningful text in the job description.")
                else:
                    results = []
                    role_title = batch_role if batch_role != "Custom (Paste your own Job Description)" else "Batch Job Description"

                    with st.spinner(f"Evaluating {len(uploaded_files)} resumes..."):
                        for file in uploaded_files:
                            display_name = safe_filename(file.name)
                            raw_text, err = extract_resume_text(file)
                            if err:
                                results.append({
                                    "Candidate Resume": display_name,
                                    "ATS Match Score (%)": 0.0,
                                    "Matched Keywords": 0,
                                    "Missing Top Skills": f"Error: {err}"
                                })
                            else:
                                cleaned_res = clean_text(raw_text)
                                score = calculate_similarity(cleaned_res, cleaned_jd)
                                matched, missing, _ = analyze_keywords(cleaned_res, cleaned_jd)
                                save_scan_record(user["id"], display_name, role_title, score, len(matched), missing)
                                results.append({
                                    "Candidate Resume": display_name,
                                    "ATS Match Score (%)": score,
                                    "Matched Keywords": len(matched),
                                    "Missing Top Skills": ", ".join(missing[:6]) if missing else "All covered!"
                                })

                    rank_df = pd.DataFrame(results).sort_values(by="ATS Match Score (%)", ascending=False).reset_index(drop=True)
                    rank_df.insert(0, "Rank", [f"#{i+1}" for i in range(len(rank_df))])
                    st.session_state.last_batch_result = rank_df
            else:
                st.warning("Please upload at least one PDF resume and provide a job description.")

        if st.session_state.last_batch_result is not None:
            rank_df = st.session_state.last_batch_result
            st.divider()
            st.subheader("🥇 Candidate Leaderboard")
            podium = st.columns(min(3, len(rank_df)))
            for col, medal, (_, row) in zip(podium, ["🥇", "🥈", "🥉"], rank_df.head(3).iterrows()):
                col.metric(f"{medal} {row['Candidate Resume']}", f"{row['ATS Match Score (%)']}%")
            st.dataframe(
                rank_df, use_container_width=True, hide_index=True,
                column_config={"ATS Match Score (%)": st.column_config.ProgressColumn(
                    "ATS Match Score (%)", min_value=0, max_value=100, format="%.1f")}
            )

            chart_df = rank_df.copy()
            chart_df["Display Name"] = chart_df["Rank"] + " " + chart_df["Candidate Resume"]
            st.bar_chart(chart_df.set_index("Display Name")[["ATS Match Score (%)"]])

            st.download_button(
                label="📥 Download Candidate Ranking Table (.csv)",
                data=csv_safe(rank_df).to_csv(index=False),
                file_name="Candidate_ATS_Ranking.csv",
                mime="text/csv",
                use_container_width=True
            )

    # ---------------------------------------------------------
    # PAGE 3: MY SCAN HISTORY & SCORE TRENDS
    # ---------------------------------------------------------
    elif nav_page == "🕒 My Scan History & Trends":
        hero("🕒 Scan History", f"Every resume evaluation saved for {user['full_name']}, with your score progress over time.")

        scans_df = get_user_scans(user["id"])
        if scans_df.empty:
            st.info("You haven't scanned any resumes yet. Go to **Single Resume Analyzer** or **Batch Ranker** to get started!")
        else:
            s1, s2, s3 = st.columns(3)
            s1.metric("Total Scans", len(scans_df))
            s2.metric("Highest Score", f"{scans_df['Score (%)'].max()}%")
            s3.metric("Average Score", f"{round(scans_df['Score (%)'].mean(), 1)}%")

            if len(scans_df) > 1:
                st.subheader("📈 ATS Score Progression Over Time")
                trend_df = scans_df.iloc[::-1].reset_index(drop=True)
                trend_df["Scan #"] = [f"Scan {i+1}" for i in range(len(trend_df))]
                st.line_chart(trend_df.set_index("Scan #")[["Score (%)"]])

            st.divider()
            st.subheader("📋 Detailed Scan Records")
            st.dataframe(
                scans_df.drop(columns=["ID"]), use_container_width=True, hide_index=True,
                column_config={"Score (%)": st.column_config.ProgressColumn(
                    "Score (%)", min_value=0, max_value=100, format="%.1f")}
            )

            csv_data = csv_safe(scans_df.drop(columns=["ID"])).to_csv(index=False)
            col_dl, col_del = st.columns(2)
            with col_dl:
                st.download_button(
                    label="📥 Export Scan History (.csv)",
                    data=csv_data,
                    file_name=f"{user['username']}_ats_history.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            with col_del:
                if st.button("🗑️ Clear All Saved History", use_container_width=True):
                    delete_user_scans(user["id"])
                    st.session_state.last_single_result = None
                    st.session_state.last_batch_result = None
                    st.session_state.last_compare_result = None
                    st.success("All scan records deleted.")
                    st.rerun()

    # ---------------------------------------------------------
    # PAGE 4: ACCOUNT & SECURITY SETTINGS
    # ---------------------------------------------------------
    elif nav_page == "⚙️ Account & Security":
        hero("⚙️ Account & Security", "Manage your profile details and update your password.")

        st.info(f"**Username:** `{user['username']}`  |  **Member Since:** `{user['created_at']}`")

        col_prof, col_pass = st.columns(2)

        with col_prof:
            st.subheader("👤 Update Profile")
            with st.form("profile_update_form"):
                updated_name = st.text_input("Full Name", value=user["full_name"])
                updated_email = st.text_input("Email Address", value=user["email"], max_chars=MAX_EMAIL_LEN)
                dept_options = [UNSPECIFIED_DEPT] + DEPARTMENTS
                updated_dept = st.selectbox("Department", dept_options,
                                            index=dept_options.index(user.get("department")) if user.get("department") in dept_options else 0)
                profile_pw = st.text_input("Current Password (only needed to change your email)", type="password", max_chars=MAX_PASSWORD_LEN)
                save_profile = st.form_submit_button("Save Profile Changes", use_container_width=True, type="primary")

                if save_profile:
                    if not updated_name.strip() or not updated_email.strip():
                        st.warning("Name and email cannot be empty.")
                    elif not is_valid_email(updated_email):
                        st.warning("Please enter a valid email address.")
                    else:
                        ok, msg = update_user_profile(user["id"], updated_name, updated_email, profile_pw, updated_dept)
                        if ok:
                            st.session_state.user["full_name"] = clean_line(updated_name)
                            st.session_state.user["email"] = updated_email.strip().lower()
                            st.session_state.user["department"] = updated_dept
                            st.rerun()
                        else:
                            st.error(msg)

        with col_pass:
            st.subheader("🔒 Change Password")
            with st.form("password_change_form"):
                old_pw = st.text_input("Current Password", type="password", max_chars=MAX_PASSWORD_LEN)
                new_pw = st.text_input("New Password (min 8 characters)", type="password", max_chars=MAX_PASSWORD_LEN)
                confirm_pw = st.text_input("Confirm New Password", type="password", max_chars=MAX_PASSWORD_LEN)
                save_pw = st.form_submit_button("Update Password", use_container_width=True, type="primary")

                if save_pw:
                    if not all([old_pw, new_pw, confirm_pw]):
                        st.warning("Please fill in all password fields.")
                    elif len(new_pw) < MIN_PASSWORD_LEN:
                        st.warning("New password must be at least 8 characters long.")
                    elif new_pw != confirm_pw:
                        st.error("New passwords do not match.")
                    else:
                        ok, msg = change_user_password(user["id"], old_pw, new_pw)
                        if ok:
                            st.session_state.user["token_version"] = get_token_version(user["id"])
                            st.success(msg)
                        else:
                            st.error(msg)

        st.divider()
        with st.expander("🗑️ Delete my account"):
            st.warning("This permanently deletes your account, scan history and saved progress. It cannot be undone.")
            with st.form("delete_account_form"):
                del_pw = st.text_input("Confirm with your password", type="password", max_chars=MAX_PASSWORD_LEN)
                del_confirm = st.text_input("Type DELETE to confirm", max_chars=10)
                if st.form_submit_button("Permanently delete my account", use_container_width=True):
                    if del_confirm.strip() != "DELETE" or not del_pw:
                        st.warning("Enter your password and type DELETE to confirm.")
                    else:
                        ok, msg = delete_user_account(user["id"], del_pw)
                        if ok:
                            st.session_state.user = None
                            st.session_state.last_single_result = None
                            st.session_state.last_batch_result = None
                            st.session_state.last_compare_result = None
                            wipe_work_state()
                            st.session_state.clear_cookie = True
                            st.session_state.session_notice = msg
                            st.rerun()
                        else:
                            st.error(msg)

    # ---------------------------------------------------------
    # PAGE: RESUME A/B COMPARISON
    # ---------------------------------------------------------
    elif nav_page == "🔀 Resume A/B Compare":
        hero("🔀 Resume A/B Compare", "Upload two versions of your resume against the same job and see exactly what improved.")
        ab_role, ab_jd = jd_picker("ab", st.session_state.last_single_result)

        col_a, col_b = st.columns(2)
        with col_a:
            step_header("A", "Older version")
            ab_file_a = st.file_uploader("Resume version A (PDF or Word)", type=["pdf", "docx"], key="ab_file_a")
        with col_b:
            step_header("B", "Newer version")
            ab_file_b = st.file_uploader("Resume version B (PDF or Word)", type=["pdf", "docx"], key="ab_file_b")

        if st.button("Compare Versions 🔀", use_container_width=True, type="primary"):
            if analysis_quota_remaining(user["id"]) < 2:
                st.error(f"Hourly limit reached ({MAX_ANALYSES_PER_HOUR} analyses). Please try again later.")
            elif not (ab_file_a and ab_file_b and ab_jd.strip()):
                st.warning("Please upload both resume versions and choose or paste a job description.")
            elif not clean_text(ab_jd):
                st.warning("Please enter meaningful text in the job description.")
            else:
                with st.spinner("Comparing both versions..."):
                    text_a, err_a = extract_resume_text(ab_file_a)
                    text_b, err_b = (None, None) if err_a else extract_resume_text(ab_file_b)
                    if err_a:
                        st.error(f"Version A: {err_a}")
                    elif err_b:
                        st.error(f"Version B: {err_b}")
                    else:
                        cmp_res = compare_resume_versions(text_a, text_b, ab_jd)
                        name_a, name_b = safe_filename(ab_file_a.name), safe_filename(ab_file_b.name)
                        if name_a == name_b:
                            name_a, name_b = f"{name_a} (A)", f"{name_b} (B)"
                        save_scan_record(user["id"], name_a, ab_role, cmp_res["score_a"], len(cmp_res["matched_a"]), cmp_res["missing_a"])
                        save_scan_record(user["id"], name_b, ab_role, cmp_res["score_b"], len(cmp_res["matched_b"]), cmp_res["missing_b"])
                        cmp_res.update(name_a=name_a, name_b=name_b, role_title=ab_role)
                        st.session_state.last_compare_result = cmp_res

        cmp_res = st.session_state.last_compare_result
        if cmp_res:
            st.divider()
            st.subheader(f"📊 Result — {cmp_res['role_title']}")
            g1, g2, g3 = st.columns(3)
            with g1:
                st.caption(f"Version A: `{cmp_res['name_a']}`")
                st.markdown(score_gauge(cmp_res["score_a"]), unsafe_allow_html=True)
            with g2:
                st.caption(f"Version B: `{cmp_res['name_b']}`")
                st.markdown(score_gauge(cmp_res["score_b"]), unsafe_allow_html=True)
            with g3:
                st.metric("Score change (B vs A)", f"{cmp_res['score_b']}%", delta=f"{cmp_res['delta']:+.1f} points")
                if cmp_res["verdict"] == "improved":
                    st.success("Version B scores higher. Nice improvement!")
                elif cmp_res["verdict"] == "declined":
                    st.warning("Version B scores lower than version A.")
                else:
                    st.info("Both versions score about the same.")

            k1, k2, k3 = st.columns(3)
            with k1:
                st.markdown("**✅ Newly matched in B**")
                st.markdown(chips(cmp_res["newly_matched"], "ok") if cmp_res["newly_matched"] else "_None_", unsafe_allow_html=True)
            with k2:
                st.markdown("**⚠️ Lost from A**")
                st.markdown(chips(cmp_res["lost"], "bad") if cmp_res["lost"] else "_None_", unsafe_allow_html=True)
            with k3:
                st.markdown("**❌ Still missing in both**")
                st.markdown(chips(cmp_res["still_missing"], "bad") if cmp_res["still_missing"] else "_None_", unsafe_allow_html=True)

            a, b = cmp_res["audit_a"], cmp_res["audit_b"]
            rows = [
                ("Matched keywords", len(cmp_res["matched_a"]), len(cmp_res["matched_b"])),
                ("Action verbs", len(a["action_verbs"]), len(b["action_verbs"])),
                ("Quantified metrics", a["metrics_count"], b["metrics_count"]),
                ("Word count", a["word_count"], b["word_count"]),
            ]
            st.markdown("**📋 Resume audit: A vs B**")
            st.dataframe(pd.DataFrame([{"Metric": m, "A": x, "B": y, "Change": y - x} for m, x, y in rows]),
                         use_container_width=True, hide_index=True)
            st.caption("Both versions were saved to your scan history.")

    # ---------------------------------------------------------
    # PAGE: INTERACTIVE RESUME & COVER LETTER EDITOR
    # ---------------------------------------------------------
    elif nav_page == "✍️ Resume & Cover Letter Editor":
        hero("✍️ Resume & Cover Letter Editor", "Rewrite weak bullets and watch your ATS score update, with no PDF re-upload.")
        last = st.session_state.last_single_result
        ed_role, ed_jd = jd_picker("ed", last)
        cleaned_jd = clean_text(ed_jd[:MAX_JD_CHARS])
        jd_sig = hashlib.sha256(ed_jd.encode()).hexdigest()[:10]
        st.session_state.setdefault("editor_resume", "")
        st.session_state.setdefault("cover_letter_text", "")
        tab_resume, tab_letter = st.tabs(["📝 Resume Bullet Editor", "💌 Cover Letter"])

        with tab_resume:
            can_load = bool(last and last.get("raw_text"))
            st.button("📥 Load text from my last analyzed resume", disabled=not can_load,
                      on_click=lambda: (_load_last_resume_into_editor(), st.session_state.pop("editor_baseline_sig", None)),
                      help="Uses the text already extracted from your last upload. Nothing is uploaded again.")
            left, right = st.columns([3, 2])
            with left:
                st.text_area("Resume text (edit freely)", key="editor_resume", height=420, max_chars=MAX_EDITOR_CHARS,
                             placeholder="Paste your resume text here, or load it from your last analysis…")
                st.caption("Press Ctrl+Enter or click outside the box to refresh the score. Nothing is saved until you choose to.")
            text = st.session_state.editor_resume
            with right:
                if text.strip() and cleaned_jd:
                    score = calculate_similarity(clean_text(text), cleaned_jd)
                    if st.session_state.get("editor_baseline_sig") != jd_sig:
                        st.session_state.editor_baseline, st.session_state.editor_baseline_sig = score, jd_sig
                    st.markdown(score_gauge(score), unsafe_allow_html=True)
                    st.metric("Change vs baseline", f"{score}%", delta=f"{score - st.session_state.editor_baseline:+.1f} points")
                    st.button("Use current version as baseline", on_click=lambda: st.session_state.pop("editor_baseline_sig", None))
                    coverage, matched_ed, missing_ed = keyword_coverage(text, ed_jd)
                    st.progress(min(coverage / 100, 1.0), text=f"Keyword coverage: {coverage}%")
                    if missing_ed:
                        st.markdown("**Missing keywords** (add only what is true):")
                        st.markdown(chips(missing_ed, "bad"), unsafe_allow_html=True)
                else:
                    st.info("Add resume text and a job description to see your live ATS score.")

            if text.strip():
                if re.search(r"\[(?:add a measurable|what you did)[^\]]*\]", text):
                    st.warning("Your text still contains [placeholders]. Replace them with real details before using this resume.")
                bullet_report = analyze_bullets(text)
                if bullet_report:
                    weak = [b for b in bullet_report if b["issues"]]
                    st.markdown(f"#### 🔎 Bullet check: {len(bullet_report) - len(weak)} of {len(bullet_report)} bullets look strong")
                    for n, b in enumerate(weak[:15], start=1):
                        label = re.sub(r"[^\w .,%+#/&-]", "", b["bullet"])[:70]
                        with st.expander(f"{'🔴' if b['strength'] <= 1 else '🟡'} Bullet {n}: {label}"):
                            st.text(b["bullet"])
                            for issue in b["issues"]:
                                st.markdown(f"- {issue}")
                            if b["rewrite"]:
                                st.caption("Suggested starting point (fill the brackets with real facts, never invent numbers):")
                                st.code(b["rewrite"], language=None)
                st.download_button("📥 Download edited resume text (.txt)", text, file_name="edited_resume.txt", mime="text/plain")
                if text.strip() and cleaned_jd and st.button("💾 Save this version to my scan history", use_container_width=True):
                    if analysis_quota_remaining(user["id"]) < 1:
                        st.error(f"Hourly limit reached ({MAX_ANALYSES_PER_HOUR} analyses). Please try again later.")
                    else:
                        save_scan_record(user["id"], "Edited resume (editor)", ed_role,
                                         calculate_similarity(clean_text(text), cleaned_jd), len(matched_ed), missing_ed)
                        st.success("Saved. Find it under My Scan History & Trends.")

        with tab_letter:
            _, matched_c, missing_c = keyword_coverage(text if text.strip() else (last or {}).get("raw_text", ""), ed_jd) if cleaned_jd else (0, [], [])
            default_skills = ", ".join(matched_c[:6] or missing_c[:3])
            c1, c2 = st.columns(2)
            company = c1.text_input("Company", max_chars=80, key="cl_company")
            letter_role = c2.text_input("Role", value=ed_role if ed_role != "Custom Job Description" else "", max_chars=80, key=f"cl_role_{jd_sig}")
            skills_in = st.text_input("Skills to highlight (comma-separated, only ones you really have)", value=default_skills, max_chars=200, key=f"cl_skills_{jd_sig}")
            achievement = st.text_area("One real achievement to mention (optional)", max_chars=400, height=80, key="cl_achievement")
            st.button("✨ Generate draft", on_click=_fill_cover_letter,
                      args=(user["full_name"], company, letter_role, skills_in, achievement))
            st.text_area("Cover letter (edit freely)", key="cover_letter_text", height=330, max_chars=5000)
            letter = st.session_state.cover_letter_text
            if letter.strip():
                words = len(letter.split())
                m1, m2, m3 = st.columns(3)
                m1.metric("Words", words, help="Aim for 250-400 words")
                if cleaned_jd:
                    cov, got, lacking = keyword_coverage(letter, ed_jd)
                    m2.metric("JD keyword coverage", f"{cov}%")
                    m3.metric("Match to job description", f"{calculate_similarity(clean_text(letter), cleaned_jd)}%")
                    if lacking:
                        st.markdown("**Keywords not yet in your letter:**")
                        st.markdown(chips(lacking, "bad"), unsafe_allow_html=True)
                if words < 120:
                    st.info("This draft is short. Add a specific project or result to make it personal.")
                if re.search(r"your company|Your Name|the open position", letter):
                    st.warning("Fill in the company, role and your name before sending.")
                st.download_button("📥 Download cover letter (.txt)", letter, file_name="cover_letter.txt", mime="text/plain")

    # ---------------------------------------------------------
    # PAGE: 30-DAY SKILL ROADMAP
    # ---------------------------------------------------------
    elif nav_page == "🗓️ 30-Day Skill Roadmap":
        hero("🗓️ 30-Day Skill Roadmap", "Turn your missing keywords into a weekly learning checklist with project ideas.")
        last = st.session_state.last_single_result
        history = get_user_scans(user["id"]).head(20)
        sources = (["My last analysis"] if last else []) + (["A saved scan"] if not history.empty else []) + ["Type skills myself"]
        source = st.radio("Build the roadmap from:", sources, horizontal=True)
        missing, rm_role = [], ""
        if source == "My last analysis":
            missing, rm_role = last["missing_keywords"], last["role_title"]
        elif source == "A saved scan":
            labels = [f"{r['Date & Time']} • {r['Resume File']} • {r['Target Role']} ({r['Score (%)']}%)" for _, r in history.iterrows()]
            pick = st.selectbox("Choose a scan", list(range(len(labels))), format_func=lambda i: labels[i])
            missing, rm_role = history.iloc[pick]["Missing Keywords"], history.iloc[pick]["Target Role"]
        else:
            missing = st.text_input("Skills to learn (comma-separated)", max_chars=300, placeholder="docker, kubernetes, tensorflow")
        hours = st.slider("Hours per week you can study", 2, 20, 6)

        roadmap = generate_roadmap(missing, hours)
        if not roadmap:
            st.info("No skill gaps to plan for yet. Run an analysis first, or type the skills you want to learn.")
        else:
            sig = hashlib.sha256(",".join(sk for w in roadmap for sk in w["skills"]).encode()).hexdigest()[:8]
            if st.session_state.get("rm_loaded") != (user["id"], sig):  # first time this plan is shown: restore saved ticks
                saved_ids = load_roadmap_progress(user["id"], sig)
                for w in roadmap:
                    for i in range(len(w["tasks"])):
                        st.session_state[f"rm_{sig}_{w['week']}_{i}"] = f"{w['week']}_{i}" in saved_ids
                st.session_state.rm_loaded, st.session_state.rm_saved = (user["id"], sig), saved_ids
            keys = [f"rm_{sig}_{w['week']}_{i}" for w in roadmap for i in range(len(w["tasks"]))]
            done = sum(1 for k in keys if st.session_state.get(k))
            st.progress(done / len(keys), text=f"{done} of {len(keys)} tasks done")
            for w in roadmap:
                with st.expander(f"Week {w['week']}: {w['title']}  (~{w['hours']} h)", expanded=(w["week"] == 1)):
                    for i, task in enumerate(w["tasks"]):
                        st.checkbox(task, key=f"rm_{sig}_{w['week']}_{i}")
                    st.info(f"💡 **Project idea:** {w['project']}")
            now_done = {f"{w['week']}_{i}" for w in roadmap for i in range(len(w["tasks"])) if st.session_state.get(f"rm_{sig}_{w['week']}_{i}")}
            if now_done != st.session_state.get("rm_saved"):
                save_roadmap_progress(user["id"], sig, now_done)
                st.session_state.rm_saved = now_done
            st.download_button("📥 Download checklist (.txt)", roadmap_to_text(roadmap, clean_line(rm_role, 80)),
                               file_name="30_day_skill_roadmap.txt", mime="text/plain")
            st.caption("Tick tasks as you go. Your progress is saved to your account automatically.")

    # ---------------------------------------------------------
    # PAGE: ADMIN ANALYTICS (administrators only)
    # ---------------------------------------------------------
    elif nav_page == "📊 Admin Analytics":
        hero("📊 Admin Analytics", "Platform-wide, anonymised insight into how students are doing.")
        if user.get("role") not in ("admin", "dept_admin"):
            st.error("Administrator access required.")
            st.stop()
        f1, f2 = st.columns(2)
        days = f1.selectbox("Reporting window", list(ADMIN_WINDOWS), index=1, format_func=lambda d: f"Last {d} days")
        if user.get("role") == "dept_admin":
            dept_choice = user.get("department")
            f2.info(f"Your view is limited to: {dept_choice}")
        else:
            dept_choice = f2.selectbox("Department", ["All departments", UNSPECIFIED_DEPT] + DEPARTMENTS)
        try:
            m = get_admin_metrics(user["id"], days, None if dept_choice == "All departments" else dept_choice)
        except PermissionError:
            st.error("Administrator access required.")
            st.stop()

        k = st.columns(4)
        k[0].metric("Registered students", m["students"])
        k[1].metric("New this week", m["new_7d"])
        k[2].metric("Active (7 days)", m["active_7d"])
        k[3].metric("Active (30 days)", m["active_30d"])
        if m["suppressed"]:
            st.info(f"Not enough activity to show this view: at least {K_ANON_MIN_GROUP} active students are needed "
                    "so that no individual can be identified. Try a longer window or all departments.")
        else:
            k2 = st.columns(2)
            k2[0].metric(f"Scans (last {days} days)", m["scans_in_window"])
            k2[1].metric("Average ATS score", f"{m['avg_score']}%")

            st.subheader("🧩 Most commonly missing skills")
            if m["top_missing"]:
                miss_df = pd.DataFrame(m["top_missing"])
                st.bar_chart(miss_df.set_index("Skill")["Times missing"])
                st.dataframe(miss_df, use_container_width=True, hide_index=True)
                st.download_button("📥 Export missing skills (.csv)", csv_safe(miss_df).to_csv(index=False),
                                   file_name="missing_skills.csv", mime="text/csv")
            else:
                st.caption(f"Skills appear here once at least {K_ANON_MIN_GROUP} different students are missing them.")

            st.subheader("🏫 Average ATS score by department")
            if m["by_department"]:
                dept_df = pd.DataFrame(m["by_department"])
                st.dataframe(dept_df, use_container_width=True, hide_index=True,
                             column_config={"Average Score (%)": st.column_config.ProgressColumn(
                                 "Average Score (%)", min_value=0, max_value=100, format="%.1f")})
                st.download_button("📥 Export department scores (.csv)", csv_safe(dept_df).to_csv(index=False),
                                   file_name="department_scores.csv", mime="text/csv")
            else:
                st.caption(f"Departments appear here once they have at least {K_ANON_MIN_GROUP} active students.")

            c_left, c_right = st.columns(2)
            with c_left:
                st.subheader("📊 Score distribution")
                st.bar_chart(pd.DataFrame(m["score_distribution"]).set_index("Score range")["Scans"])
            with c_right:
                st.subheader("📈 Scans per day")
                if m["daily_scans"]:
                    st.line_chart(pd.DataFrame(m["daily_scans"]).set_index("Day")["Scans"])
                else:
                    st.caption("No scans in this window.")
        st.caption("🔒 Aggregate data only: no names, emails or resume content are shown, and groups smaller than "
                   f"{K_ANON_MIN_GROUP} students are hidden or merged.")

        if user.get("role") == "admin":
            st.divider()
            st.subheader("👥 Staff roles")
            st.dataframe(pd.DataFrame(list_staff(user["id"])), use_container_width=True, hide_index=True)
            with st.form("role_form"):
                r1, r2 = st.columns(2)
                role_username = r1.text_input("Username", max_chars=30)
                role_new = r2.selectbox("New role", list(ROLES), format_func=lambda r: {"student": "Student", "dept_admin": "Department admin (own department only)", "admin": "Administrator"}[r])
                if st.form_submit_button("Apply role", use_container_width=True):
                    ok, msg = set_user_role(user["id"], role_username, role_new)
                    (st.success if ok else st.error)(msg)

            st.subheader("📥 Import students (CSV)")
            st.caption("Columns: full_name (or name), email. Optional: department, username. Imported students have no password: "
                       "they open **Forgot password** and set their own, which proves they own the email address.")
            st.download_button("Download CSV template", "full_name,email,department\nAarav Sharma,aarav@example.com,Computer Science\n",
                               file_name="students_template.csv", mime="text/csv")
            csv_file = st.file_uploader("Student list", type=["csv"], key="import_csv")
            if csv_file is not None:
                import_rows, import_problems = parse_student_csv(csv_file.getvalue().decode("utf-8", "ignore"))
                st.write(f"**{len(import_rows)}** valid row(s), **{len(import_problems)}** problem(s).")
                for problem in import_problems[:10]:
                    st.caption(f"• {problem}")
                if import_rows and st.button(f"Import {len(import_rows)} students", type="primary", use_container_width=True):
                    with st.spinner("Creating accounts..."):
                        result = bulk_import_students(user["id"], import_rows)
                    st.success(f"Created {result['created']} account(s); skipped {result['skipped']} (already registered).")

            with st.expander("🧾 Recent admin activity"):
                st.dataframe(pd.DataFrame(list_audit_log(user["id"])), use_container_width=True, hide_index=True)
