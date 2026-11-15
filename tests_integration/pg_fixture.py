"""Shared setup for integration tests: a throwaway Postgres schema per test class.

Point TEST_DATABASE_URL at a THROWAWAY Postgres (e.g. `docker compose -f docker-compose.test.yml up -d`),
as a URI: postgresql://user:pass@host:port/dbname. Never use your production Supabase database.
Each test class creates its own schema and drops it afterwards.
"""
import os
import sys
import unittest
import uuid
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))  # reuse app_loader

os.environ.setdefault("DB_SSLMODE", "disable")  # local/CI Postgres has no SSL
TEST_URL = os.environ.get("TEST_DATABASE_URL", "").strip()

try:
    import psycopg2
    HAVE_PG = True
except ImportError:
    psycopg2, HAVE_PG = None, False

requires_pg = unittest.skipUnless(
    TEST_URL.startswith("postgres") and HAVE_PG,
    "set TEST_DATABASE_URL (throwaway Postgres URI) and install psycopg2-binary to run integration tests")


def schema_url(schema):
    sep = "&" if "?" in TEST_URL else "?"
    return f"{TEST_URL}{sep}options={quote('-csearch_path=' + schema)}"


def run_sql(url, query, params=None):
    """Runs one statement (autocommit) and returns rows if the statement produces any."""
    conn = psycopg2.connect(url, sslmode=os.environ["DB_SSLMODE"])
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall() if cur.description else None
    finally:
        conn.close()


class SchemaTestCase(unittest.TestCase):
    """Creates an isolated schema, installs the app's tables into it, and wipes data before each test."""

    @classmethod
    def setUpClass(cls):
        cls.schema = "it_" + uuid.uuid4().hex[:8]
        run_sql(TEST_URL, f"CREATE SCHEMA {cls.schema}")
        cls.url = schema_url(cls.schema)

    @classmethod
    def tearDownClass(cls):
        run_sql(TEST_URL, f"DROP SCHEMA IF EXISTS {cls.schema} CASCADE")

    def sql(self, query, params=None):
        return run_sql(self.url, query, params)
