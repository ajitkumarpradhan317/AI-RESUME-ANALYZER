"""Staff roles, department administrators, CSV import, audit log and saved roadmap progress."""
import unittest
from datetime import date

from app_loader import load_app
from helpers import FakeCursor, use_cursor

SIG = "0123abcd"


class RoleManagementTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def change(self, target, role="dept_admin", me=("admin",), others=(2,)):
        queue = [me, target] + ([others] if others is not None else [])
        cur = use_cursor(self.ns, FakeCursor(fetchone=queue))
        return self.ns["set_user_role"](1, "Student.One", role), cur

    def test_only_full_admins_may_change_roles(self):
        for role in ("student", "dept_admin", None):
            cur = use_cursor(self.ns, FakeCursor(fetchone=[(role,) if role else None]))
            with self.assertRaises(PermissionError):
                self.ns["set_user_role"](5, "student.one", "admin")
            self.assertEqual(len(cur.executed), 1)  # refused before any lookup or write

    def test_promote_to_department_admin_writes_role_and_audit(self):
        (ok, msg), cur = self.change((9, "student", "Civil", True))
        self.assertTrue(ok, msg)
        self.assertEqual(cur.statements("UPDATE users SET role")[0][1], ("dept_admin", 9))
        audit = cur.statements("INSERT INTO admin_audit")[0][1]
        self.assertEqual(audit[1:], ("role:student->dept_admin", "student.one"))

    def test_guard_rails(self):
        cases = [((9, "student", "Unspecified", True), "dept_admin", "department first"),
                 ((9, "student", "Civil", False), "admin", "not verified"),
                 ((9, "admin", "Civil", True), "admin", "already"),
                 (None, "admin", "No user")]
        for target, role, expect in cases:
            (ok, msg), cur = self.change(target, role, others=None)
            self.assertFalse(ok); self.assertIn(expect, msg)
            self.assertEqual(cur.statements("UPDATE users SET role"), [])

    def test_the_last_administrator_can_never_be_demoted(self):
        (ok, msg), cur = self.change((9, "admin", "Civil", True), "student", others=(1,))
        self.assertFalse(ok); self.assertIn("At least one administrator", msg)
        self.assertEqual(cur.statements("UPDATE users SET role"), [])
        (ok, _), _ = self.change((9, "admin", "Civil", True), "student", others=(2,))
        self.assertTrue(ok)

    def test_invalid_input_never_reaches_the_database(self):
        cur = use_cursor(self.ns, FakeCursor())
        for user, role in [("x'; DROP TABLE users;--", "admin"), ("", "admin"), ("ab", "admin"), ("student.one", "superuser")]:
            ok, _ = self.ns["set_user_role"](1, user, role)
            self.assertFalse(ok)
        self.assertEqual(cur.executed, [])

    def test_listings_are_admin_only_and_never_include_emails(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("student",)]))
        for fn in ("list_staff", "list_audit_log"):
            with self.assertRaises(PermissionError):
                self.ns[fn](5)
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("admin",)], fetchall=[[("boss", "Boss", "admin", "Civil")]]))
        self.assertEqual(self.ns["list_staff"](1), [{"Username": "boss", "Name": "Boss", "Role": "admin", "Department": "Civil"}])
        self.assertNotIn("email", cur.executed[1][0].lower())


class DepartmentAdminTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def metrics(self, role, own_dept, requested):
        cur = use_cursor(self.ns, FakeCursor(
            fetchone=[(role, own_dept), (10, 1, 2, 5), (5,), (3, 4, 20, 61.0)],
            fetchall=[[("Civil", 5, 12, 70.0)], [("docker", 9, 5)], [(0, 2)], [(date(2026, 11, 1), 4)]]))
        return self.ns["get_admin_metrics"](7, 30, requested), cur

    def test_department_admin_is_forced_to_their_own_department(self):
        for requested in (None, "Mechanical", "Computer Science"):          # whatever they ask for...
            m, cur = self.metrics("dept_admin", "Civil", requested)
            self.assertEqual(m["department"], "Civil")                      # ...they only ever see Civil
            for sql, params in cur.executed[1:]:
                if "department" in sql:
                    self.assertIn("Civil", params)

    def test_department_filter_also_applies_to_the_department_breakdown(self):
        _, cur = self.metrics("dept_admin", "Civil", None)
        by_dept_sql = next(s for s, _ in cur.executed if "GROUP BY u.department" in s)
        self.assertIn("u.department = %s", by_dept_sql)                     # other departments' averages are not leaked

    def test_full_admin_keeps_free_choice_and_students_are_refused(self):
        m, _ = self.metrics("admin", "Civil", "Mechanical")
        self.assertEqual(m["department"], "Mechanical")
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("student", "Civil")]))
        with self.assertRaises(PermissionError):
            self.ns["get_admin_metrics"](7, 30, None)


class CsvImportTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    GOOD = "full_name,email,department\nAarav Sharma,Aarav@Example.com,Computer Science\nMeera N,meera@example.com,\n"

    def test_parses_valid_rows_and_normalises(self):
        rows, problems = self.ns["parse_student_csv"](self.GOOD)
        self.assertEqual(problems, [])
        self.assertEqual(rows[0], {"full_name": "Aarav Sharma", "email": "aarav@example.com", "department": "Computer Science", "username": ""})
        self.assertEqual(rows[1]["department"], "Unspecified")

    def test_accepts_name_column_alias_and_odd_header_case(self):
        rows, _ = self.ns["parse_student_csv"]("Name , EMAIL\nA B,a@example.com\n")
        self.assertEqual(len(rows), 1)

    def test_reports_bad_rows_without_importing_them(self):
        csv_text = ("full_name,email,department,username\n"
                    ",x@example.com,,\n"                              # no name
                    "A,not-an-email,,\n"                              # bad email
                    "B,b@example.com,Wizardry,\n"                     # unknown department
                    "C,c@example.com,,admin\n"                        # reserved username
                    "D,d@example.com,,bad name!\n"                    # invalid username
                    "E,e@example.com,,\nE2,e@example.com,,\n")        # duplicate email
        rows, problems = self.ns["parse_student_csv"](csv_text)
        self.assertEqual([r["email"] for r in rows], ["e@example.com"])
        self.assertEqual(len(problems), 6)

    def test_missing_columns_oversized_and_row_cap(self):
        self.assertIn("needs the columns", self.ns["parse_student_csv"]("a,b\n1,2\n")[1][0])
        self.assertEqual(self.ns["parse_student_csv"]("x" * 300_000), ([], ["The file is too large."]))
        big = "full_name,email\n" + "".join(f"S{i},s{i}@example.com\n" for i in range(500))
        rows, problems = self.ns["parse_student_csv"](big)
        self.assertLessEqual(len(rows), self.ns["MAX_IMPORT_ROWS"])
        self.assertTrue(any("Stopped after" in p for p in problems))

    def test_hostile_cell_content_is_neutralised(self):
        rows, _ = self.ns["parse_student_csv"]('full_name,email\n"Eve\x00\nP.S. x",e@example.com\n')
        self.assertNotIn("\n", rows[0]["full_name"]); self.assertNotIn("\x00", rows[0]["full_name"])
        self.assertEqual(self.ns["parse_student_csv"]("")[0], [])             # empty file: no crash

    def test_import_is_admin_only(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("dept_admin",)]))
        with self.assertRaises(PermissionError):
            self.ns["bulk_import_students"](5, [{"full_name": "A", "email": "a@example.com", "department": "Civil", "username": ""}])
        self.assertEqual(len(cur.executed), 1)

    def test_import_creates_accounts_nobody_can_log_into_and_skips_existing(self):
        rows = [{"full_name": "A", "email": "a@example.com", "department": "Civil", "username": ""},
                {"full_name": "B", "email": "taken@example.com", "department": "Civil", "username": ""},
                {"full_name": "C", "email": "c@example.com", "department": "Civil", "username": "chosen.name"}]
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("admin",), (1,), (2,)], fetchall=[[("taken@example.com",)]]))
        result = self.ns["bulk_import_students"](1, rows)
        self.assertEqual(result, {"created": 2, "skipped": 1})
        inserts = cur.statements("INSERT INTO users")
        self.assertEqual([i[1][0] for i in inserts], ["auser", "chosen.name"])  # from the email (padded to 3+ chars), or as given
        for sql, params in inserts:
            self.assertIn("ON CONFLICT DO NOTHING", sql)
            self.assertTrue(params[3].startswith("disabled$"))                  # not a valid hash: no password works
            self.assertFalse(self.ns["verify_password"]("anything", params[3]))
        self.assertEqual(cur.statements("INSERT INTO admin_audit")[0][1][1], "bulk_import")

    def test_username_collisions_get_a_numeric_suffix(self):
        rows = [{"full_name": "A", "email": "sam@example.com", "department": "Civil", "username": ""}]
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("admin",), None, None, (5,)], fetchall=[[]]))
        self.assertEqual(self.ns["bulk_import_students"](1, rows)["created"], 1)
        self.assertEqual([i[1][0] for i in cur.statements("INSERT INTO users")], ["sam", "sam1", "sam2"])

    def test_reserved_and_short_names_are_never_used(self):
        rows = [{"full_name": "A", "email": "admin@example.com", "department": "Civil", "username": ""},
                {"full_name": "B", "email": "x@example.com", "department": "Civil", "username": ""}]
        cur = use_cursor(self.ns, FakeCursor(fetchone=[("admin",), (1,), (2,)], fetchall=[[]]))
        self.ns["bulk_import_students"](1, rows)
        names = [i[1][0] for i in cur.statements("INSERT INTO users")]
        self.assertNotIn("admin", names); self.assertTrue(all(len(n) >= 3 for n in names))


class RoadmapProgressTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_load_returns_only_valid_task_ids(self):
        use_cursor(self.ns, FakeCursor(fetchone=[("1_0,2_3,9_9,x,1_0;DROP,4_12",)]))
        self.assertEqual(self.ns["load_roadmap_progress"](7, SIG), {"1_0", "2_3", "4_12"})
        use_cursor(self.ns, FakeCursor(fetchone=[None]))
        self.assertEqual(self.ns["load_roadmap_progress"](7, SIG), set())

    def test_save_upserts_validated_ids_and_trims_old_plans(self):
        cur = use_cursor(self.ns, FakeCursor())
        self.assertTrue(self.ns["save_roadmap_progress"](7, SIG, {"2_1", "1_0", "bad", "5_5"}))
        sql, params = cur.statements("INSERT INTO roadmap_progress")[0]
        self.assertIn("ON CONFLICT (user_id, plan_sig) DO UPDATE", sql)
        self.assertEqual(params, (7, SIG, "1_0,2_1"))                          # sorted, junk dropped
        self.assertIn("LIMIT 20", cur.statements("DELETE FROM roadmap_progress")[0][0])

    def test_bad_signatures_never_reach_the_database(self):
        cur = use_cursor(self.ns, FakeCursor())
        for sig in ["", None, "short", "ZZZZZZZZ", "0123abcd'; DROP TABLE users;--"]:
            self.assertFalse(self.ns["save_roadmap_progress"](7, sig, {"1_0"}))
            self.assertEqual(self.ns["load_roadmap_progress"](7, sig), set())
        self.assertEqual(cur.executed, [])

    def test_progress_is_scoped_to_the_user(self):
        cur = use_cursor(self.ns, FakeCursor(fetchone=[None]))
        self.ns["load_roadmap_progress"](7, SIG)
        self.assertEqual(cur.executed[0][1], (7, SIG))


if __name__ == "__main__":
    unittest.main()
