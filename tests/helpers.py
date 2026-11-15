import contextlib


class FakeCursor:
    """Scriptable stand-in for a psycopg2 cursor. Records every executed statement."""

    def __init__(self, fetchone=(), fetchall=(), raise_on=None, raise_exc=None):
        self._one = list(fetchone)
        self._all = list(fetchall)
        self.executed = []
        self._raise_on, self._raise_exc = raise_on, raise_exc

    def execute(self, sql, params=None):
        sql = " ".join(sql.split())
        self.executed.append((sql, params))
        if self._raise_on and self._raise_on in sql:
            raise self._raise_exc

    def fetchone(self):
        return self._one.pop(0) if self._one else None

    def fetchall(self):
        return self._all.pop(0) if self._all else []

    def statements(self, keyword):
        return [e for e in self.executed if keyword in e[0]]


def use_cursor(ns, cursor):
    """Makes the app's db_cursor() yield the given fake cursor."""
    ns["db_cursor"] = lambda: contextlib.nullcontext(cursor)
    return cursor
