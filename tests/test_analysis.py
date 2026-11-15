import unittest
from datetime import datetime

from app_loader import load_app
from helpers import FakeCursor, use_cursor


class TextAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_clean_text(self):
        self.assertEqual(self.ns["clean_text"]("  Hello,   WORLD!! C++/Node.js "), "hello world cpp nodejs")  # aliases folded, nothing lost

    def test_is_valid_email(self):
        ok = self.ns["is_valid_email"]
        self.assertTrue(ok(" a.b+c@example.co.in "))
        for bad in ["", "plain", "a@b", "@example.com", "a b@example.com"]:
            self.assertFalse(ok(bad), bad)

    def test_similarity_bounds(self):
        sim = self.ns["calculate_similarity"]
        self.assertAlmostEqual(sim("python machine learning", "python machine learning"), 100.0, places=1)
        self.assertEqual(sim("python pandas", "kubernetes docker"), 0.0)
        mid = sim("python pandas sql", "python tensorflow docker")
        self.assertTrue(0 < mid < 100)

    def test_similarity_with_only_stop_words_returns_zero(self):
        self.assertEqual(self.ns["calculate_similarity"]("the and of", "the and of"), 0.0)

    def test_analyze_keywords_splits_matched_and_missing(self):
        resume = "experienced python developer using pandas"
        jd = "python pandas tensorflow tensorflow deployment"
        matched, missing, df = self.ns["analyze_keywords"](resume, jd)
        self.assertEqual(matched, ["pandas", "python"])
        self.assertEqual(missing, ["deployment", "tensorflow"])
        self.assertEqual(list(df.columns), ["Job Description", "Your Resume"])
        self.assertEqual(df.loc["tensorflow", "Job Description"], 2)
        self.assertEqual(df.loc["tensorflow", "Your Resume"], 0)

    def test_analyze_keywords_empty_job_description(self):
        matched, missing, df = self.ns["analyze_keywords"]("python", "the and of")
        self.assertEqual((matched, missing), ([], []))
        self.assertTrue(df.empty)

    def test_audit_detects_contacts_sections_and_metrics(self):
        verb = self.ns["ACTION_VERBS"][0]
        text = (f"Aarav Sharma aarav@example.com linkedin.com/in/aarav github.com/aarav 555-123-4567\n"
                f"Education: B.Tech University\nSkills: Python\nProjects\nExperience\n"
                f"{verb} a model, improving accuracy by 25% and serving 10+ users.")
        audit = self.ns["extract_contact_and_sections"](text)
        for key in ("Email", "Phone", "LinkedIn", "GitHub"):
            self.assertTrue(audit[key], key)
        self.assertTrue(all(audit["sections"].values()))
        self.assertIn(verb, audit["action_verbs"])
        self.assertEqual(audit["metrics_count"], 2)
        self.assertEqual(audit["word_count"], len(text.split()))

    def test_audit_on_empty_resume(self):
        audit = self.ns["extract_contact_and_sections"]("hello world")
        self.assertFalse(audit["Email"] or audit["LinkedIn"] or audit["GitHub"])
        self.assertFalse(any(audit["sections"].values()))
        self.assertEqual(audit["metrics_count"], 0)


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_bullet_suggestions_capped_at_five(self):
        out = self.ns["generate_bullet_suggestions"]([f"kw{i}" for i in range(9)])
        self.assertEqual(len(out), 5)
        self.assertIn("[KW0]", out[0])
        self.assertEqual(self.ns["generate_bullet_suggestions"]([]), [])

    def test_interview_questions(self):
        q = self.ns["generate_interview_questions"]
        qs = q(["a", "b", "c", "d"], ["x", "y", "z", "w"], "Data Scientist")
        self.assertEqual(len(qs), 6)  # 3 strengths + 3 gaps
        self.assertTrue(qs[0].startswith("**[Strength"))
        self.assertTrue(qs[3].startswith("**[Skill-Gap"))
        self.assertIn("Data Scientist", qs[3])

    def test_interview_questions_fallback(self):
        qs = self.ns["generate_interview_questions"]([], [], "DevOps")
        self.assertEqual(len(qs), 1)
        self.assertIn("Role Alignment", qs[0])

    def test_report_text_contains_key_fields(self):
        audit = self.ns["extract_contact_and_sections"]("Skills python 90% a@b.com")
        report = self.ns["build_report_text"]("Aarav", "cv.pdf", "Data Scientist", 58.4,
                                              audit, ["python"], ["tensorflow"], ["Q1?"])
        for fragment in ("Aarav", "cv.pdf", "Data Scientist", "58.4%", "python", "tensorflow", "Q1?"):
            self.assertIn(fragment, report)


class UiHelperTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_chips_escape_html(self):
        out = self.ns["chips"](["<b>x</b>", "ok"], "bad")
        self.assertNotIn("<b>x</b>", out)
        self.assertIn("&lt;b&gt;", out)
        self.assertEqual(out.count('class="chip bad"'), 2)

    def test_pill_states(self):
        self.assertIn("pill ok", self.ns["pill"]("Email", True))
        self.assertIn("Detected", self.ns["pill"]("Email", True))
        self.assertIn("pill bad", self.ns["pill"]("Email", False))
        self.assertIn("Not detected", self.ns["pill"]("Skills", False, "Found", "Not detected"))

    def test_gauge_color_thresholds(self):
        g = self.ns["score_gauge"]
        self.assertIn("#22aa64", g(70)); self.assertIn("Great match", g(85))
        self.assertIn("#e0a020", g(45)); self.assertIn("Moderate match", g(58.4))
        self.assertIn("#e04b4b", g(44.9)); self.assertIn("Low match", g(10))
        self.assertIn('stroke-dasharray="339.3 339.3"', g(250))  # clamped at 100%


class ScanHistoryTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_save_scan_joins_missing_keywords(self):
        cur = use_cursor(self.ns, FakeCursor())
        self.ns["save_scan_record"](3, "cv.pdf", "Role", 58.4, 8, ["a", "b"])
        self.assertEqual(cur.statements("INSERT INTO scans")[0][1], (3, "cv.pdf", "Role", 58.4, 8, "a, b"))

    def test_get_user_scans_builds_dataframe(self):
        rows = [(2, "cv.pdf", "Role", 58.4, 8, "a, b", "2026-11-12 10:00")]
        use_cursor(self.ns, FakeCursor(fetchall=[rows]))
        df = self.ns["get_user_scans"](3)
        self.assertEqual(list(df.columns)[:3], ["ID", "Resume File", "Target Role"])
        self.assertEqual(len(df), 1)
        use_cursor(self.ns, FakeCursor(fetchall=[[]]))
        self.assertTrue(self.ns["get_user_scans"](3).empty)

    def test_delete_scans_scoped_to_user(self):
        cur = use_cursor(self.ns, FakeCursor())
        self.ns["delete_user_scans"](9)
        sql, params = cur.executed[0]
        self.assertIn("DELETE FROM scans WHERE user_id", sql)
        self.assertEqual(params, (9,))


if __name__ == "__main__":
    unittest.main()
