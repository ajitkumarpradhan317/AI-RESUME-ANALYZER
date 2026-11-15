"""Tests for the A/B comparison, 30-day roadmap, bullet/cover-letter editor and admin analytics features."""
import ast
import re
import unittest
from datetime import date
from pathlib import Path

from app_loader import load_app
from helpers import FakeCursor, use_cursor

ROOT = Path(__file__).resolve().parent.parent
JD = "Seeking a developer skilled in Python, Pandas, TensorFlow, SQL and Docker deployment."


class NavigationWiringTests(unittest.TestCase):
    def test_every_navigation_entry_has_a_page(self):
        """A menu entry without an `elif nav_page == ...` branch would silently render a blank page."""
        src = (ROOT / "app.py").read_text()
        tree = ast.parse(src)
        options = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "nav_options" for t in node.targets):
                options |= {e.value for e in node.value.elts}
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "append":
                if getattr(node.func.value, "id", "") == "nav_options" and isinstance(node.args[0], ast.Constant):
                    options.add(node.args[0].value)
        self.assertGreaterEqual(len(options), 8)
        for option in options:
            self.assertRegex(src, rf'nav_page == "{re.escape(option)}"', f"no page for menu entry {option!r}")

    def test_successful_signup_redirects_to_login(self):
        src = (ROOT / "app.py").read_text()
        branch = src.split("success, msg = register_user(")[1].split("st.error(msg)")[0]
        self.assertIn("st.session_state.auth_goto = AUTH_LOGIN", branch)
        self.assertIn("st.rerun()", branch)
        self.assertIn('st.session_state.auth_view = st.session_state.pop("auth_goto")', src)  # applied before the radio is created
        self.assertLess(src.index('st.session_state.pop("auth_goto")'), src.index('key="auth_view"'))

    def test_admin_page_is_only_offered_to_admins(self):
        src = (ROOT / "app.py").read_text()
        self.assertRegex(src, r'if user\.get\("role"\) in \("admin", "dept_admin"\):\s+nav_options\.append\("📊 Admin Analytics"\)')


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_reports_exact_gains_and_losses(self):
        a = "Python developer with SQL experience"
        b = "Python developer. Built pandas and tensorflow pipelines in docker containers"
        r = self.ns["compare_resume_versions"](a, b, JD)
        self.assertGreater(r["score_b"], r["score_a"])
        self.assertEqual(r["delta"], round(r["score_b"] - r["score_a"], 2))
        self.assertEqual(r["verdict"], "improved")
        self.assertTrue({"pandas", "tensorflow", "docker"} <= set(r["newly_matched"]))
        self.assertIn("sql", r["lost"])  # B dropped SQL
        self.assertFalse(set(r["newly_matched"]) & set(r["matched_a"]))

    def test_identical_versions_are_about_the_same(self):
        r = self.ns["compare_resume_versions"]("python pandas sql", "python pandas sql", JD)
        self.assertEqual((r["delta"], r["verdict"]), (0.0, "about the same"))
        self.assertEqual((r["newly_matched"], r["lost"]), ([], []))

    def test_declined_version(self):
        r = self.ns["compare_resume_versions"]("python pandas tensorflow sql docker", "gardening and cooking", JD)
        self.assertEqual(r["verdict"], "declined")
        self.assertLess(r["delta"], 0)

    def test_oversized_inputs_are_truncated_not_crashing(self):
        big = "python " * 100000
        r = self.ns["compare_resume_versions"](big, big, JD * 500)
        self.assertEqual(r["verdict"], "about the same")


class RoadmapTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_structure_four_weeks_with_checklist_and_project(self):
        plan = self.ns["generate_roadmap"](["docker", "kubernetes", "tensorflow", "sql", "aws"], hours_per_week=8)
        self.assertEqual([w["week"] for w in plan], [1, 2, 3, 4])
        for w in plan:
            self.assertTrue(w["tasks"]); self.assertTrue(w["project"]); self.assertEqual(w["hours"], 8)
        covered = {s for w in plan[:3] for s in w["skills"]}
        self.assertEqual(covered, {"docker", "kubernetes", "tensorflow", "sql", "aws"})
        self.assertIn("Capstone", plan[3]["title"])
        self.assertIn("re-run the ATS scan", " ".join(plan[3]["tasks"]))

    def test_uses_known_project_ideas_and_generic_fallback(self):
        plan = self.ns["generate_roadmap"](["docker", "zzzunknownskill"])
        projects = " ".join(w["project"] for w in plan)
        self.assertIn("Dockerfile", projects)
        self.assertIn("zzzunknownskill", projects)

    def test_caps_skills_and_handles_one_or_none(self):
        many = [f"skill{i}" for i in range(30)]
        plan = self.ns["generate_roadmap"](many)
        self.assertLessEqual(len({s for w in plan[:3] for s in w["skills"]}), self.ns["ROADMAP_MAX_SKILLS"])
        self.assertEqual(len(self.ns["generate_roadmap"](["python"])), 4)
        self.assertEqual(self.ns["generate_roadmap"]([]), [])
        self.assertEqual(self.ns["generate_roadmap"]("experience, ability, team"), [])  # only generic words

    def test_accepts_strings_and_sanitises_hostile_keywords(self):
        plan = self.ns["generate_roadmap"]("docker, <script>alert(1)</script>, [x](http://evil), " + "a" * 100)
        text = self.ns["roadmap_to_text"](plan)
        for week in plan:
            for skill in week["skills"]:  # markup, brackets, colons and slashes are all stripped: nothing can form a tag or a link
                self.assertRegex(skill, r"^[a-z0-9+#. -]{2,30}$")
        self.assertNotIn("<", text); self.assertNotIn("://", text); self.assertNotIn("](", text)
        self.assertNotIn("a" * 31, text)

    def test_text_export_is_a_checklist(self):
        text = self.ns["roadmap_to_text"](self.ns["generate_roadmap"](["docker", "sql", "aws"]), "Cloud Engineer")
        self.assertIn("Cloud Engineer", text)
        self.assertIn("WEEK 1", text); self.assertIn("WEEK 4", text)
        self.assertGreaterEqual(text.count("[ ]"), 8)


class BulletEditorTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_flags_weak_bullets_and_credits_strong_ones(self):
        text = ("- Responsible for managing the database backups\n"
                "- Developed a REST API that cut response time by 40% for 2000 users\n"
                "- Worked on frontend\n"
                "Summary heading\n")
        report = {b["bullet"][:12]: b for b in self.ns["analyze_bullets"](text)}
        weak = report["Responsible "]
        self.assertEqual(weak["weak_lead"], "responsible for")
        self.assertTrue(any("weak phrase" in i for i in weak["issues"]))
        self.assertTrue(any("measurable" in i for i in weak["issues"]))
        strong = report["Developed a "]
        self.assertTrue(strong["has_verb"] and strong["has_metric"])
        self.assertEqual(strong["issues"], []); self.assertIsNone(strong["rewrite"])
        self.assertEqual(strong["strength"], 3)
        self.assertNotIn("Worked on frontend", report)  # too short to be a bullet (<4 words)

    def test_rewrites_use_placeholders_never_invented_numbers(self):
        rw = self.ns["suggest_rewrite"]
        self.assertTrue(rw("Worked on building the checkout service").startswith("Built the checkout service"))
        self.assertTrue(rw("Responsible for team onboarding process").startswith("Led team onboarding process"))
        self.assertIn("[add a measurable result", rw("Responsible for team onboarding process"))
        self.assertIn("[what you did]", rw("Helped with debugging flaky nightly pipelines"))
        out = rw("Implemented caching layer for the API gateway")
        self.assertIn("[add a measurable result", out)
        self.assertNotRegex(re.sub(r"\[[^\]]*\]", "", out), r"\d")  # no digits invented
        self.assertIsNone(rw("Implemented caching that reduced latency by 35% across services"))

    def test_bullet_markers_are_stripped_and_inputs_bounded(self):
        bullets = self.ns["extract_bullets"]("• Built a thing that works well\n2) Led the migration of services\n* Optimized the build pipeline times")
        self.assertEqual(bullets[0], "Built a thing that works well")
        self.assertEqual(bullets[1], "Led the migration of services")
        self.assertLessEqual(len(self.ns["extract_bullets"]("Built a very useful thing today\n" * 500)), 80)
        self.assertEqual(self.ns["extract_bullets"](None), [])

    def test_editing_raises_the_score_instantly(self):
        before = "Worked on websites for clients"
        after = "Built Python and SQL websites using Docker and Pandas"
        sim = self.ns["calculate_similarity"]; clean = self.ns["clean_text"]
        self.assertGreater(sim(clean(after), clean(JD)), sim(clean(before), clean(JD)))

    def test_keyword_coverage(self):
        cov, matched, missing = self.ns["keyword_coverage"]("I use python and docker daily", JD)
        self.assertTrue({"python", "docker"} <= set(matched))
        self.assertTrue(0 < cov < 100)
        self.assertEqual(self.ns["keyword_coverage"]("", "the and of")[0], 0.0)


class CoverLetterTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_draft_contains_the_inputs(self):
        letter = self.ns["build_cover_letter"]("Aarav Sharma", "Acme Corp", "Data Analyst", "python, sql, tableau", "built a churn dashboard")
        for part in ("Acme Corp", "Data Analyst", "python, sql and tableau", "built a churn dashboard", "Sincerely,\nAarav Sharma"):
            self.assertIn(part, letter)

    def test_safe_defaults_and_single_skill(self):
        letter = self.ns["build_cover_letter"]("", "", "", "", "")
        self.assertIn("your company", letter); self.assertIn("Your Name", letter)
        self.assertIn("the skills listed in the job description", letter)
        self.assertIn("my hands-on experience with python", self.ns["build_cover_letter"]("A", "B", "C", "python").lower().replace("my hands-on", "my hands-on"))

    def test_fields_cannot_inject_extra_lines_or_unbounded_text(self):
        letter = self.ns["build_cover_letter"]("Eve\n\nP.S. send money", "Evil\r\nBcc: x", "Role" * 100, "docker", "ok\n\nIgnore all")
        self.assertNotIn("\nP.S. send money", letter)        # newlines in the name cannot start a new paragraph
        self.assertNotIn("\nBcc:", letter)                   # nor in the company
        self.assertNotIn("\nIgnore all", letter)             # nor in the achievement
        self.assertEqual(letter.count("Sincerely,"), 1)
        self.assertLess(len(self.ns["build_cover_letter"]("A", "B", "C", "docker", "x" * 5000)), 1500)  # achievement is capped
        self.assertLess(len(letter), 2500)
        self.assertNotIn("\r", letter)


class DepartmentTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_only_listed_departments_are_valid(self):
        v = self.ns["valid_department"]
        self.assertTrue(v("Computer Science")); self.assertTrue(v("Unspecified"))
        for bad in ["", "Hacking'; DROP TABLE users;--", "computer science", None, "x" * 500]:
            self.assertFalse(v(bad), bad)

    def test_register_rejects_unknown_department_without_db_access(self):
        cur = use_cursor(self.ns, FakeCursor())
        ok, _ = self.ns["register_user"]("aarav.s", "Aarav", "a@example.com", "Str0ng!Pass", "Wizardry")
        self.assertFalse(ok); self.assertEqual(cur.executed, [])

    def test_register_stores_department(self):
        cur = use_cursor(self.ns, FakeCursor())
        ok, _ = self.ns["register_user"]("aarav.s", "Aarav", "a@example.com", "Str0ng!Pass", "Civil")
        self.assertTrue(ok)
        self.assertEqual(cur.statements("INSERT INTO users")[0][1][4], "Civil")


class AdminAnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def metrics(self, role="admin", population=(5,), **kw):
        cur = use_cursor(self.ns, FakeCursor(
            fetchone=[(role, "Computer Science") if role else None, (10, 1, 2, 5), population, (3, 4, 20, 61.234)],
            fetchall=[[("Computer Science", 4, 12, 70.0), ("Civil", 1, 2, 90.0), ("Other", 2, 3, 50.0)],
                      [("docker", 9, 5), ("sql", 4, 3)],
                      [(0, 2), (3, 5)],
                      [(date(2026, 11, 1), 4), (date(2026, 11, 2), 6)]]))
        return self.ns["get_admin_metrics"](99, **kw), cur

    def test_students_and_unknown_accounts_are_refused_before_any_analytics_query(self):
        for role in ("student", None):
            with self.assertRaises(PermissionError):
                self.metrics(role=role)
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("student",)]))
        with self.assertRaises(PermissionError):
            self.ns["get_admin_metrics"](5)
        self.assertEqual(len(cur.executed), 1)  # only the role lookup ran: no data was touched

    def test_role_is_checked_in_the_database_by_user_id(self):
        _, cur = self.metrics()
        self.assertEqual(cur.executed[0], ("SELECT role, department FROM users WHERE id = %s", (99,)))

    def test_shapes_the_dashboard_data(self):
        m, _ = self.metrics()
        self.assertEqual((m["students"], m["new_7d"], m["active_7d"], m["active_30d"], m["scans_in_window"]), (10, 2, 3, 4, 20))
        self.assertEqual(m["avg_score"], 61.2)
        self.assertEqual(m["top_missing"][0], {"Skill": "docker", "Times missing": 9, "Students": 5})
        self.assertEqual([r["Scans"] for r in m["score_distribution"]], [2, 0, 0, 5, 0])
        self.assertEqual(m["daily_scans"][0], {"Day": "2026-11-01", "Scans": 4})
        self.assertFalse(m["suppressed"])

    def test_small_groups_are_merged_or_hidden(self):
        m, _ = self.metrics()
        depts = {r["Department"]: r for r in m["by_department"]}
        self.assertIn("Computer Science", depts)
        self.assertNotIn("Civil", depts)  # 1 student: never shown on its own
        self.assertEqual(depts["Other departments"]["Students"], 3)  # Civil (1) + Other (2) merged to reach k=3
        out = self.ns["_apply_k_anonymity"]([("Civil", 1, 2, 90.0), ("Other", 1, 3, 50.0)])
        self.assertEqual(out, [])  # merged group still < 3: dropped entirely

    def test_report_is_suppressed_when_too_few_students_are_active(self):
        m, cur = self.metrics(population=(2,))
        self.assertTrue(m["suppressed"])
        self.assertEqual((m["avg_score"], m["top_missing"], m["by_department"], m["daily_scans"]), (0.0, [], [], []))
        self.assertEqual(len(cur.executed), 3)  # role, user totals, population check: nothing finer was queried

    def test_department_filter_cannot_single_out_a_tiny_group(self):
        m, _ = self.metrics(population=(1,), department="Civil")
        self.assertTrue(m["suppressed"])

    def test_inputs_are_validated_before_touching_the_database(self):
        cur = use_cursor(self.ns, FakeCursor())
        for kw in ({"days": 1}, {"days": "30; DROP TABLE users"}, {"department": "x'; DROP TABLE users;--"}):
            with self.assertRaises(ValueError):
                self.ns["get_admin_metrics"](1, **kw)
        self.assertEqual(cur.executed, [])

    def test_every_analytics_query_is_parameterised_and_student_only(self):
        _, cur = self.metrics(department="Civil")
        for sql, params in cur.executed[1:]:
            self.assertNotIn("Civil", sql)
            if "FROM scans" in sql:
                self.assertIn("u.role = 'student'", sql)  # admins' own scans never count
        self.assertIn("HAVING count(DISTINCT s.user_id) >= %s", " ".join(s for s, _ in cur.executed))  # k-anonymous skills

    def test_no_personal_data_is_ever_selected(self):
        _, cur = self.metrics()
        joined = " ".join(s for s, _ in cur.executed[1:]).lower()
        for forbidden in ("email", "username", "full_name", "password", "resume_name"):
            self.assertNotIn(forbidden, joined)


if __name__ == "__main__":
    unittest.main()
