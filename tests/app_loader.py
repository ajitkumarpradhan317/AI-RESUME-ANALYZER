"""Loads the testable (non-UI) definitions from app.py without running the Streamlit script.

app.py is a single Streamlit script, so importing it would render the UI and need a database.
Instead we parse it, execute only its imports, constants and function definitions into an
isolated namespace, and stub out streamlit / psycopg2 / PyPDF2 so the tests need no services.
"""
import ast
import sys
import types
from pathlib import Path

APP_PATH = Path(__file__).resolve().parent.parent / "app.py"


def _stub_modules():
    st = types.ModuleType("streamlit")
    st.secrets = {}
    st.cache_resource = lambda *a, **k: (lambda f: f)
    sys.modules["streamlit"] = st

    try:
        import psycopg2  # noqa: F401
        import psycopg2.errors  # noqa: F401
    except ImportError:
        pg = types.ModuleType("psycopg2")
        errors = types.ModuleType("psycopg2.errors")
        errors.UniqueViolation = type("UniqueViolation", (Exception,), {})
        pg.errors = errors
        pg.connect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no database in unit tests"))
        sys.modules["psycopg2"], sys.modules["psycopg2.errors"] = pg, errors

    try:
        import pypdf  # noqa: F401
    except ImportError:
        sys.modules["pypdf"] = types.ModuleType("pypdf")


_cache = None


def load_app():
    """Returns a fresh namespace dict of app.py's functions and constants."""
    _stub_modules()
    tree = ast.parse(APP_PATH.read_text(encoding="utf-8"))
    ns = {"__name__": "app_under_test"}
    for node in tree.body:
        keep = isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
        if isinstance(node, ast.Assign):
            # constants may call re.compile(); any other call (config, st.*, db) is skipped
            has_call = any(isinstance(n, ast.Call) and not (isinstance(n.func, ast.Attribute) and n.func.attr == "compile")
                           for n in ast.walk(node.value))
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            keep = bool(names) and ((all(n.isupper() for n in names) and not has_call) or names == ["logger"])
        if keep:
            exec(compile(ast.Module([node], []), str(APP_PATH), "exec"), ns)
    ns["PBKDF2_ITERATIONS"] = 1000  # fast hashing for tests; production uses the value in app.py
    return ns
