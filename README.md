# AI-Powered ATS Resume & Job Match Analyzer (Enterprise Edition - Supabase Postgres)

A complete 7th-semester Natural Language Processing (NLP) & Full-Stack web application built with **Python**, **Supabase (PostgreSQL)**, **Brevo Transactional Email API**, **Scikit-Learn**, and **Streamlit**.

## Key Features
- **Brevo HTTPS Email OTP Password Reset:** Sends styled HTML password-reset OTP emails over HTTPS (Port 443) using Brevo's v3 Transactional Email API—100% compatible with Render's free tier (the OTP is only ever delivered by email and is never shown on screen).
- **User Authentication & Security:** Sign Up, Login, Logout, SHA-256 password hashing, profile editing, and password change functionality backed by Supabase Postgres (salted PBKDF2 hashing; legacy SHA-256 hashes auto-upgrade on next login).
- **Single Resume Analyzer & Mock Interview Prep:** Calculates TF-IDF Cosine Similarity, audits action verbs and quantified impact metrics, visualizes skill gaps, and generates tailored interview questions.
- **Multi-Resume Batch Ranker (Recruiter Mode):** Upload multiple PDF resumes simultaneously to rank candidates on a leaderboard and export results to CSV.
- **Scan History & Score Progression Chart:** Tracks every scan per user account and plots ATS score improvements over time on a line chart.

## How to Configure Supabase Postgres
1. Create a project at [Supabase](https://supabase.com/).
2. Click **Connect** in the project dashboard and copy the **Session pooler** connection string (works on Render's IPv4 network).
3. Set it as `DATABASE_URL` (replace `[YOUR-PASSWORD]` with your database password):
   - **Render:** Environment > add `DATABASE_URL`.
   - **Local:** create `.streamlit/secrets.toml` with `DATABASE_URL = "postgresql://..."`, or export it as an env var.
4. Tables (`users`, `password_resets`, `scans`) are created automatically on first run, with Row Level Security enabled so the public Supabase API can't read them.

## How to Configure Brevo API Key on Render (Free Plan)
1. Create a free account at [Brevo](https://www.brevo.com/) (300 free emails/day).
2. In Brevo, go to **Senders, Domains & Dedicated IPs** and verify the sender email address you want to send from (e.g., your Gmail address).
3. Go to **SMTP & API > API Keys**, click **Generate a new API key**, and copy the key (`xkeysib-...`).
4. In your **Render Web Service Dashboard**, go to **Environment** and add these two variables:
   - `BREVO_API_KEY` = `your-copied-brevo-api-key`
   - `BREVO_SENDER_EMAIL` = `your-verified-sender-email@gmail.com`
5. Click **Save Changes**. Render will redeploy automatically and send live HTML OTP emails whenever a user clicks **Forgot Password**.

## Local Setup & Running
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   streamlit run app.py
   ```

## Features
| Page | What it does |
|---|---|
| 🚀 Single Resume Analyzer | ATS score, keyword gaps, resume audit, interview questions, report download |
| 🔀 Resume A/B Compare | Upload two versions against the same job: exact score change, **newly matched**, lost and still-missing skills, audit deltas |
| 🏆 Multi-Resume Batch Ranker | Rank up to 20 resumes against one job (recruiter mode) |
| ✍️ Resume & Cover Letter Editor | Edit resume text and see the ATS score update with **no PDF re-upload**; weak-bullet detector with rewrite starters (placeholders, never invented numbers); cover-letter drafter with live keyword coverage |
| 🗓️ 30-Day Skill Roadmap | Top missing skills become a 4-week checklist (3 skill weeks + a capstone week) with a project idea per week; download as text |
| 🕒 Scan History & Trends | Past scans and score progression |
| 📊 Admin Analytics *(admins only)* | Active users, most commonly missing skills, average ATS score by department, score distribution, scans per day |

### Creating an administrator
There is deliberately **no way to become an admin from the app**. Register normally, then in the Supabase SQL editor run:
```sql
UPDATE users SET role = 'admin' WHERE username = 'your.username';
```
The role is re-read from the database on every page load and inside every analytics query, so demoting an admin (`SET role = 'student'`) takes effect immediately.

### Student privacy in the admin dashboard
Aggregate data only: no names, emails, file names or resume text are ever returned. Administrators' own scans are excluded. Any view covering fewer than 3 active students is suppressed (including a department filter that would single out one or two students), departments with fewer than 3 students are merged into "Other departments" (or hidden), and a skill is listed only if at least 3 different students are missing it.

### Accounts and sign-in
- **Email verification at sign-up** (on automatically when Brevo is configured; `REQUIRE_EMAIL_VERIFICATION=false` turns it off). A 6-digit code is emailed; accounts must verify before they can log in. A never-verified sign-up cannot block the real owner of an email address.
- **Keep me signed in** (14 days) via a random token stored hashed in the database; it is revoked on logout, password change/reset and account deletion.
- **Delete my account** on the Account page: removes the account and all its data (scans, saved roadmap progress, codes, tokens). The last administrator cannot delete themselves.
- Uploads: **PDF or Word (.docx)**. Scanned-image PDFs get a clear message explaining what to do.
- **Smarter keyword matching:** `ML` = `machine learning`, `k8s` = `Kubernetes`, `C++`, `Node.js`, `CI/CD` etc. are treated as one skill, and generic filler words ("ability", "team") are no longer reported as missing skills.
- **ATS format check** in the audit tab (length, tables/columns, decorative symbols, wall-of-text lines).

### Administration
- **Roles:** `student`, `dept_admin` (sees analytics for their own department only) and `admin`. Admins manage roles from the Admin Analytics page (every change is written to an audit log; the last admin can never be removed).
- **Bulk import:** upload a CSV (`full_name,email,department`). Imported students have no password: they use **Forgot password**, which proves they own the email. Max 300 rows per file.

## Configuration reference
| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | yes | Supabase **Session pooler** connection string |
| `BREVO_API_KEY`, `BREVO_SENDER_EMAIL` | for email | password-reset and verification emails (sender must be verified in Brevo) |
| `OTP_PEPPER` | recommended | long random secret for hashing codes and tokens (`render.yaml` generates one) |
| `REQUIRE_EMAIL_VERIFICATION` | no | `false` disables sign-up verification (default: on when Brevo is configured) |
| `DB_SSLMODE` | no | `disable` only for a local Docker Postgres |
| `SKIP_DB_INIT` | no | `true` once the schema exists, so a limited database role can be used |

More: **docs/DEPLOYMENT.md** (Render, backups, least-privilege role), **docs/ARCHITECTURE.md**, **docs/LIMITATIONS.md**, **docs/MANUAL_TEST_CHECKLIST.md**.

## Running the Unit Tests
The tests need no database, Brevo account or Streamlit server (they use fakes and mocks):
```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```
They cover password hashing, sign-up validation, login, the OTP reset flow (OTP only emailed to the registered address, expiry, 5-attempt lock), the Brevo email call, config loading, ATS scoring/keyword analysis, resume audit, report generation, UI helpers and scan-history queries.

## Running the Integration Tests
These run the real data layer (and the real Streamlit UI flows) against a real Postgres. Use a **throwaway** database, never your production Supabase project.
```bash
docker compose -f docker-compose.test.yml up -d
export TEST_DATABASE_URL=postgresql://test:test@localhost:5433/ats_test
export DB_SSLMODE=disable          # local Postgres has no SSL (the app defaults to `require` for Supabase)
python -m unittest discover -s tests_integration -v
```
Each test class creates its own schema and drops it afterwards. Without `TEST_DATABASE_URL` the integration tests are skipped. GitHub Actions (`.github/workflows/tests.yml`) runs both unit and integration tests on every push.

## Security
Penetration-test findings and the controls in place. Run `python -m unittest discover -s tests -v` to re-check them (`tests/test_security.py` contains the attack-style tests).

| Area | Attack tried | Control |
|---|---|---|
| Login | Password guessing | 5 failures lock the account 15 min; PBKDF2-SHA256 (600k iterations); policy: 8-128 chars, no common passwords |
| Login | Account enumeration (message, lock state, timing) | One identical error text for unknown / wrong password / locked; equal hashing work on every path |
| Password reset | OTP brute force | Single-use, 15 min expiry, 5 guesses per code, 3 requests per account per hour, OTP stored only as a keyed digest |
| Password reset | Enumeration via response or latency | Identical response for every case; the email is sent in a background thread |
| Sessions | Stolen / stale sessions | 60 min idle and 12 h absolute timeout; password change/reset revokes every session (`token_version`) |
| Account page | Brute-forcing the current password from a hijacked session | Wrong current-password attempts count toward the same lockout; email change needs the password |
| SQL | Injection | Every query is parameterised (a test fails the build if SQL is ever concatenated) |
| Output | XSS / HTML injection | All user data is `html.escape`d before any `unsafe_allow_html` |
| Exports | CSV formula injection (incl. pandas 3 `str` dtype) | Cells starting with `= + - @ TAB CR` are neutralised |
| Uploads | Fake PDFs, huge files, PDF bombs, ReDoS | Magic-byte check, 5 MB / 25 pages / 150k chars caps, linear-time regexes, `pypdf>=5.1` |
| Abuse | Resource exhaustion | 20 files per batch, 60 analyses per user per hour |
| Data | Cross-user access | Every query is scoped to the session's user id; RLS on all tables |
| Secrets | Leaks | Only env vars / git-ignored `secrets.toml`; a test scans the repo for keys |

**Residual risks (not fixable in app code):**
- Sign-up still reveals that a username or email is taken, and emails are not verified at sign-up (someone can register with another person's address). Email verification is the proper fix.
- Per-account lockout means an attacker who knows a username can lock that user out for 15 minutes. Put Cloudflare / a WAF with IP rate limiting in front of Render to blunt this and credential stuffing.
- Streamlit cannot set HTTP security headers (CSP, X-Frame-Options); set them at the proxy/CDN.
- Use a dedicated least-privilege database role instead of the Supabase `postgres` superuser (see **docs/DEPLOYMENT.md**).
- Set `OTP_PEPPER` to a long random string so stored OTP digests don't depend on the database password.
