"""SQLite-backed analysis database for per-APK alias/annotation records."""
from __future__ import annotations

import sqlite3
import os
from typing import Any


class AnalysisDB:
    """Holds a per-APK SQLite database for alias records.

    One instance per server process; open() is a one-shot operation.
    """

    def __init__(self) -> None:
        self._conn: sqlite3.Connection | None = None
        self.path: str = ""

    @property
    def loaded(self) -> bool:
        return self._conn is not None

    def open(self, path: str, create_if_missing: bool = False) -> None:
        if self._conn is not None:
            raise RuntimeError("DB already loaded")
        if not os.path.exists(path):
            if not create_if_missing:
                raise FileNotFoundError(f"DB not found: {path}")
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self.path = path
        self._init_schema()

    def _init_schema(self) -> None:
        assert self._conn is not None
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS aliases (
                original TEXT PRIMARY KEY,
                alias    TEXT NOT NULL,
                note     TEXT
            )
        """)
        self._conn.commit()

    def set_alias(self, original: str, alias: str, note: str = "") -> None:
        assert self._conn is not None
        self._conn.execute(
            "INSERT OR REPLACE INTO aliases (original, alias, note) VALUES (?, ?, ?)",
            (original, alias, note or None),
        )
        self._conn.commit()

    def get_alias(self, original: str) -> tuple[str, str] | None:
        assert self._conn is not None
        row = self._conn.execute(
            "SELECT alias, note FROM aliases WHERE original = ?", (original,)
        ).fetchone()
        return (row[0], row[1] or "") if row else None

    def list_aliases(self, pattern: str = "") -> list[dict[str, Any]]:
        assert self._conn is not None
        if pattern:
            rows = self._conn.execute(
                "SELECT original, alias, note FROM aliases "
                "WHERE original LIKE ? OR alias LIKE ? ORDER BY original",
                (f"%{pattern}%", f"%{pattern}%"),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT original, alias, note FROM aliases ORDER BY original"
            ).fetchall()
        return [{"original": r[0], "alias": r[1], "note": r[2] or ""} for r in rows]

    def delete_alias(self, original: str) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            "DELETE FROM aliases WHERE original = ?", (original,)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def get_all_aliases(self) -> dict[str, str]:
        assert self._conn is not None
        rows = self._conn.execute(
            "SELECT original, alias FROM aliases"
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    def alias_count(self) -> int:
        assert self._conn is not None
        return self._conn.execute("SELECT COUNT(*) FROM aliases").fetchone()[0]


db = AnalysisDB()
