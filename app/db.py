"""
ForensiX Database Layer.
Provides SQLite connection management, WAL mode, foreign keys,
and parameterized execution helpers.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, List, Optional
from flask import current_app, g


def get_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """
    Retrieve or create a database connection for the current request context.
    Configures WAL mode, busy timeout, foreign key enforcement, and Row factory.
    """
    if "db" not in g:
        if db_path is None:
            if current_app:
                db_path = Path(current_app.config["DATABASE_PATH"])
            else:
                db_path = Path("data/db/forensix.sqlite")

        db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(
            str(db_path),
            timeout=5.0,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.row_factory = sqlite3.Row

        # Execute PRAGMA statements
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA foreign_keys = ON;")

        g.db = conn

    return g.db


def close_db(e: Optional[BaseException] = None) -> None:
    """Close the database connection if open at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(database_path: Optional[Path] = None) -> None:
    """Initialize database schema from schema.sql."""
    if database_path is None:
        if current_app:
            database_path = Path(current_app.config["DATABASE_PATH"])
        else:
            database_path = Path("data/db/forensix.sqlite")

    database_path.parent.mkdir(parents=True, exist_ok=True)
    schema_path = Path(__file__).parent / "schema.sql"

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    conn = sqlite3.connect(str(database_path), timeout=5.0)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.executescript(schema_sql)
        conn.commit()

        # Schema migrations for existing databases
        cursor = conn.execute("PRAGMA table_info(custody_log);")
        custody_cols = [row[1] for row in cursor.fetchall()]
        if "entry_hmac" not in custody_cols and len(custody_cols) > 0:
            conn.execute("ALTER TABLE custody_log ADD COLUMN entry_hmac TEXT;")
            conn.commit()
    finally:
        conn.close()


def query_db(
    query: str,
    args: tuple = (),
    one: bool = False,
    db: Optional[sqlite3.Connection] = None,
) -> Any:
    """
    Execute a parameterized SQL query and return results.
    Never uses string concatenation to prevent SQL injection.
    """
    conn = db or get_db()
    cursor = conn.cursor()
    cursor.execute(query, args)
    rows = cursor.fetchall()
    cursor.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute_db(
    query: str,
    args: tuple = (),
    commit: bool = True,
    db: Optional[sqlite3.Connection] = None,
) -> int:
    """
    Execute a parameterized DML statement (INSERT, UPDATE, DELETE).
    Returns cursor.lastrowid on INSERT, or cursor.rowcount.
    """
    conn = db or get_db()
    cursor = conn.cursor()
    cursor.execute(query, args)
    if commit:
        conn.commit()
    result_id = cursor.lastrowid if cursor.lastrowid else cursor.rowcount
    cursor.close()
    return result_id
