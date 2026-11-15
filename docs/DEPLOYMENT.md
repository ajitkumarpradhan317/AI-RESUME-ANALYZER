# Deployment notes

## Render
`render.yaml` already sets the build/start commands, a health check (`/_stcore/health`), Python 3.12 and a generated `OTP_PEPPER`. You enter `DATABASE_URL`, `BREVO_API_KEY` and `BREVO_SENDER_EMAIL` in the Render dashboard (no quotes).

**Free plan sleeps** after about 15 minutes without traffic (first visit then takes ~30-60 s). Options: upgrade to the *Starter* plan (always on), or ping `https://YOUR-APP.onrender.com/_stcore/health` every 5 minutes with a free monitor such as UptimeRobot. Sessions are kept in memory, so each restart/deploy signs users out.

## Backups (Supabase)
- Dashboard -> **Database -> Backups**: free projects get daily backups for a short period; paid plans add longer retention and point-in-time recovery.
- Manual export from your computer (uses the *direct* or pooler connection string, password URL-encoded):
  ```bash
  pg_dump "$DATABASE_URL" --no-owner --format=custom --file=ats_backup_$(date +%F).dump
  # restore into an empty database:
  pg_restore --no-owner --dbname "$TARGET_DATABASE_URL" ats_backup_2026-01-01.dump
  ```
- Keep at least one export outside Supabase and test a restore once. Backups contain password hashes and emails: store them privately.

## Least-privilege database role
The app normally creates its tables at start-up, which needs more rights than day-to-day use. So: run the app once as the owner (`postgres`), then create a limited role and switch to it:
```sql
CREATE ROLE ats_app LOGIN PASSWORD 'use-a-long-random-password';
GRANT USAGE ON SCHEMA public TO ats_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  users, scans, password_resets, email_verifications, remember_tokens, roadmap_progress, admin_audit TO ats_app;
```
Then set `DATABASE_URL` to the `ats_app` connection string and add `SKIP_DB_INIT=true` (the limited role cannot run the schema statements). When a new version adds tables, run it once as `postgres` again (without `SKIP_DB_INIT`) and add the new table to the `GRANT`.

## Screenshots for your report
Put them in `docs/screenshots/` (login, analysis, A/B compare, editor, roadmap, admin analytics). They are not included because they must be taken from your running site.
