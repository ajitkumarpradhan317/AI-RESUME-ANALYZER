# Manual test checklist (run once on your deployed site)

Use two browsers (or one normal + one private window) and two email addresses.

## Accounts
- [ ] Sign up -> you land on the Login page with your username filled in.
- [ ] (Brevo configured) A 6-digit code arrives by email; login shows the verification screen; wrong code is rejected; correct code lets you in.
- [ ] Log in with username, then log out and log in with email.
- [ ] Wrong password 5 times -> account locks; message is the same as for a wrong password.
- [ ] Forgot password: OTP arrives only by email (never on screen); reset works; old password stops working; other browser is signed out.
- [ ] "Keep me signed in": refresh the page -> still signed in. Logout -> refresh -> signed out.
- [ ] Account page: change name, change department, change email (needs password), change password.
- [ ] Delete my account (wrong password refuses; correct one deletes and signs out).

## Analysis
- [ ] Upload a text PDF and a .docx -> score, keywords, audit, ATS format check, interview questions.
- [ ] Upload a scanned PDF -> clear "scanned image" message.
- [ ] Resume saying "ML" matches a job description saying "machine learning".
- [ ] A/B Compare with two versions -> newly matched skills listed; both saved to history.
- [ ] Editor: load last resume, edit a bullet, score changes without re-upload; weak bullets flagged; cover letter draft + download.
- [ ] Roadmap: tick tasks, refresh/re-login -> ticks are still there; download works.
- [ ] Batch ranker with 3 resumes; CSV downloads open safely in Excel.

## Admin (promote yourself with the SQL in the README)
- [ ] Admin Analytics shows "not enough activity" until 3 students have scans, then numbers.
- [ ] Department admin sees only their department and no role/import tools.
- [ ] Role change works and appears in "Recent admin activity"; the last admin cannot be demoted.
- [ ] CSV import creates accounts; an imported student can set a password through Forgot password.

## Hosting
- [ ] `/_stcore/health` returns OK; the app wakes within about a minute after idle on the free plan.
