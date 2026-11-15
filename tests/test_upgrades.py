"""Skill-alias matching, Word (.docx) uploads and ATS format checks."""
import io
import unittest
import zipfile

from app_loader import load_app

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


def make_docx(paragraphs, extra_xml_prefix="", extra_files=None):
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    xml = f'{extra_xml_prefix}<w:document {W}><w:body>{body}</w:body></w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", xml)
        for name, data in (extra_files or {}).items():
            z.writestr(name, data)
    buf.seek(0)
    return buf


class SkillAliasTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def test_spellings_of_one_skill_become_one_token(self):
        clean = self.ns["clean_text"]
        for variants, token in [(["ML", "machine learning", "Machine-Learning"], "machinelearning"),
                                (["k8s", "Kubernetes"], "kubernetes"), (["Node.js", "NodeJS", "node js"], "nodejs"),
                                (["C++"], "cpp"), (["C#"], "csharp"), (["scikit-learn", "sklearn"], "scikitlearn"),
                                (["CI/CD", "ci cd"], "cicd"), (["Postgres", "PostgreSQL", "postgre sql"], "postgresql"),
                                (["REST API", "RESTful APIs"], "restapi"), (["Tensor Flow", "TensorFlow"], "tensorflow")]:
            for v in variants:
                self.assertEqual(clean(f"I know {v} well"), f"i know {token} well", v)

    def test_aliases_do_not_fire_inside_other_words(self):
        clean = self.ns["clean_text"]
        self.assertEqual(clean("html and xml documents"), "html and xml documents")   # "ml" inside words untouched
        self.assertEqual(clean("model models"), "model models")
        self.assertEqual(clean("download"), "download")                                 # "dl" inside a word untouched

    def test_resume_saying_ml_now_matches_a_jd_saying_machine_learning(self):
        jd = self.ns["clean_text"]("We need machine learning and Kubernetes experience with Python")
        good = self.ns["clean_text"]("Built ML pipelines on k8s using Python")
        matched, missing, _ = self.ns["analyze_keywords"](good, jd)
        self.assertTrue({"machine learning", "kubernetes", "python"} <= set(matched))
        self.assertEqual(missing, [])

    def test_keywords_are_shown_with_readable_names(self):
        jd = self.ns["clean_text"]("Strong C++ and Node.js and scikit-learn skills")
        _, missing, df = self.ns["analyze_keywords"]("nothing relevant here", jd)
        for shown in ("c++", "node.js", "scikit-learn"):
            self.assertIn(shown, missing)
            self.assertIn(shown, list(df.index) + list(df.get("Keyword", [])))
        self.assertNotIn("cpp", missing)

    def test_generic_filler_words_are_not_reported_as_skills(self):
        jd = self.ns["clean_text"]("Strong ability and experience working in a team. Python and Docker required.")
        matched, missing, _ = self.ns["analyze_keywords"]("", jd)
        for filler in ("ability", "experience", "team", "strong", "working"):
            self.assertNotIn(filler, matched + missing)
        self.assertTrue({"python", "docker"} <= set(missing))

    def test_alias_processing_is_fast_on_large_input(self):
        import time
        big = ("machine learning k8s c++ node.js " * 8000)[: self.ns["MAX_TEXT_CHARS"]]
        start = time.time()
        self.ns["clean_text"](big)
        self.assertLess(time.time() - start, 1.5)


class DocxTests(unittest.TestCase):
    TEXT = ["Aarav Sharma aarav@example.com", "Built Python pipelines that cut processing time by 40 percent",
            "Skills: Python, SQL, Docker, Machine Learning"]

    def setUp(self):
        self.ns = load_app()

    def test_extracts_paragraphs_as_lines(self):
        text, err = self.ns["extract_text_from_docx"](make_docx(self.TEXT))
        self.assertIsNone(err)
        self.assertEqual(text.splitlines(), self.TEXT)

    def test_dispatcher_picks_parser_from_content_not_filename(self):
        f = make_docx(self.TEXT); f.name = "resume.pdf"          # lying extension
        text, err = self.ns["extract_resume_text"](f)
        self.assertIsNone(err); self.assertIn("Built Python", text)

    def test_rejects_non_word_files(self):
        for data in [b"", b"%PDF-1.4 hi", b"not a zip at all", b"PK\x03\x04" + b"garbage" * 50]:
            text, err = self.ns["extract_text_from_docx"](io.BytesIO(data))
            self.assertIsNone(text); self.assertTrue(err)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("hello.txt", "x" * 100)
        buf.seek(0)
        self.assertIn("not a valid Word", self.ns["extract_text_from_docx"](buf)[1])

    def test_blocks_xml_entity_expansion_attacks(self):
        bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
        text, err = self.ns["extract_text_from_docx"](make_docx(self.TEXT, extra_xml_prefix=bomb))
        self.assertIsNone(text); self.assertIn("unsupported", err)

    def test_blocks_zip_bombs_and_oversized_files(self):
        self.ns["MAX_DOCX_XML_BYTES"] = 10_000
        text, err = self.ns["extract_text_from_docx"](make_docx(["x" * 20000]))
        self.assertIsNone(text); self.assertIn("too large", err)
        self.ns["MAX_PDF_BYTES"] = 100
        text, err = self.ns["extract_text_from_docx"](make_docx(self.TEXT))
        self.assertIn("too large", err)

    def test_too_many_archive_members_rejected(self):
        files = {f"junk{i}.txt": "x" for i in range(2100)}
        text, err = self.ns["extract_text_from_docx"](make_docx(self.TEXT, extra_files=files))
        self.assertIsNone(text); self.assertIn("too many parts", err)

    def test_empty_document_and_text_cap(self):
        self.assertIn("enough text", self.ns["extract_text_from_docx"](make_docx(["hi"]))[1])
        self.ns["MAX_TEXT_CHARS"] = 100
        text, _ = self.ns["extract_text_from_docx"](make_docx(["word " * 100]))
        self.assertLessEqual(len(text), 100)


class FormatCheckTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_app()

    def checks(self, text):
        return {c["label"]: c for c in self.ns["ats_format_checks"](text)}

    def test_clean_resume_passes_everything(self):
        text = "\n".join(f"- Built service number {i} that improved reliability for users" for i in range(40))
        self.assertTrue(all(c["ok"] for c in self.checks(text).values()))

    def test_flags_tables_symbols_length_and_walls_of_text(self):
        c = self.checks("Skills\tPython\tSQL\nName |  Role | Year\nA | B | C\nX | Y | Z\nP | Q | R")
        self.assertFalse(c["Simple single-column layout"]["ok"])
        self.assertFalse(c["Length (one to two pages)"]["ok"])                 # far too short
        self.assertFalse(self.checks("★ ☎ ✉ ➤ ✔ " * 5)["No decorative symbols or icons"]["ok"])
        wall = "\n".join(["lorem ipsum dolor " * 20] * 8)
        self.assertFalse(self.checks(wall)["Short scannable lines"]["ok"])
        self.assertFalse(self.checks("word " * 1500)["Length (one to two pages)"]["ok"])

    def test_every_failed_check_explains_how_to_fix_it(self):
        for c in self.ns["ats_format_checks"]("★ ☎ ✉ ➤ ✔ \t"):
            self.assertTrue(c["tip"])
        self.assertEqual(len(self.ns["ats_format_checks"](None)), 4)  # never crashes on empty input


class SkipInitTests(unittest.TestCase):
    def test_skip_db_init_runs_no_ddl(self):
        from helpers import FakeCursor, use_cursor
        ns = load_app()
        cur = use_cursor(ns, FakeCursor())
        ns["get_config"] = lambda n, d="": "true" if n == "SKIP_DB_INIT" else d
        self.assertTrue(ns["_init_db_cached"]())
        self.assertEqual(cur.executed, [])                              # a limited database role never sees CREATE/ALTER
        ns["get_config"] = lambda n, d="": d
        ns["_init_db_cached"]()
        self.assertTrue(any("CREATE TABLE" in sql for sql, _ in cur.executed))


if __name__ == "__main__":
    unittest.main()
