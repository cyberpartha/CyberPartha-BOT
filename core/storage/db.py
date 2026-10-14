"""
StateDB: lightweight SQLite manager for CyberPartha BOT state.
Manages: program metadata, host inventory, approval log, suggestions,
         request budget persistence, recon checkpoints.
"""
from __future__ import annotations
import json, os, sqlite3, tempfile
from pathlib import Path
from typing import Any, Optional

class StateDB:
    """Context-manager wrapper around a program-specific SQLite database."""

    SCHEMA = [
        '''CREATE TABLE IF NOT EXISTS meta (
               key   TEXT PRIMARY KEY,
               value TEXT NOT NULL
           )''',
        '''CREATE TABLE IF NOT EXISTS hosts (
               host   TEXT PRIMARY KEY,
               source TEXT NOT NULL,
               added  TEXT NOT NULL DEFAULT (datetime('now'))
           )''',
        '''CREATE TABLE IF NOT EXISTS suggestions (
               id           INTEGER PRIMARY KEY AUTOINCREMENT,
               category     TEXT NOT NULL,
               title        TEXT NOT NULL,
               method       TEXT NOT NULL DEFAULT 'PLAN ONLY',
               max_requests INTEGER NOT NULL DEFAULT 1,
               priority     INTEGER NOT NULL DEFAULT 0,
               status       TEXT NOT NULL DEFAULT 'pending',
               evidence     TEXT,
               created      TEXT NOT NULL DEFAULT (datetime('now')),
               updated      TEXT
           )''',
        '''CREATE TABLE IF NOT EXISTS approval_log (
               token_id     TEXT PRIMARY KEY,
               program      TEXT NOT NULL,
               target_url   TEXT NOT NULL,
               http_method  TEXT NOT NULL,
               approved_at  TEXT NOT NULL DEFAULT (datetime('now')),
               consumed     INTEGER NOT NULL DEFAULT 0,
               outcome      TEXT
           )''',
        '''CREATE TABLE IF NOT EXISTS budget_log (
               id           INTEGER PRIMARY KEY AUTOINCREMENT,
               program      TEXT NOT NULL,
               operation    TEXT NOT NULL,
               consumed_at  TEXT NOT NULL DEFAULT (datetime('now'))
           )''',
    ]

    def __init__(self, db_path: Path | str) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    def _ensure_connected(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self._path)
            self._conn.execute('PRAGMA journal_mode=WAL')
            self._conn.execute('PRAGMA foreign_keys=ON')
            for ddl in self.SCHEMA:
                self._conn.execute(ddl)
            self._conn.commit()
            if os.path.exists(self._path):
                try: os.chmod(self._path, 0o600)
                except OSError: pass
        return self._conn

    def __enter__(self) -> 'StateDB':
        self._ensure_connected()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._conn:
            if exc_type is None:
                self._conn.commit()
            else:
                self._conn.rollback()
            self._conn.close()
            self._conn = None
        return False

    @property
    def conn(self) -> sqlite3.Connection:
        return self._ensure_connected()

    # ── meta key/value store ─────────────────────────────────────────────────

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.conn.execute(
            'SELECT value FROM meta WHERE key=?', (key,)
        ).fetchone()
        return row[0] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            'INSERT OR REPLACE INTO meta (key,value) VALUES (?,?)', (key, str(value))
        )
        self.conn.commit()

    def clear_meta_prefix(self, prefix: str) -> None:
        self.conn.execute('DELETE FROM meta WHERE key LIKE ?', (f'{prefix}%',))
        self.conn.commit()

    def is_paused(self) -> bool:
        return self.get_meta('paused', '0') == '1'

    def set_paused(self, paused: bool) -> None:
        self.set_meta('paused', '1' if paused else '0')

    # ── hosts ─────────────────────────────────────────────────────────────────

    def add_host(self, host: str, source: str) -> bool:
        cur = self.conn.execute(
            'INSERT OR IGNORE INTO hosts (host,source) VALUES (?,?)', (host, source)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def count_hosts(self) -> int:
        return self.conn.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]

    def all_hosts(self, limit: int = 500) -> list[str]:
        return [r[0] for r in self.conn.execute(
            'SELECT host FROM hosts ORDER BY host LIMIT ?', (limit,)
        ).fetchall()]

    def get_all_hosts(self, limit: int = 500) -> list[dict]:
        return [{"hostname": r[0], "source": r[1]} for r in self.conn.execute(
            'SELECT host, source FROM hosts ORDER BY host LIMIT ?', (limit,)
        ).fetchall()]

    # ── suggestions ───────────────────────────────────────────────────────────

    def add_suggestion(
        self,
        category: str,
        title: str,
        method: str = 'PLAN ONLY',
        max_requests: int = 1,
        priority: int = 0,
        evidence: Optional[str] = None,
    ) -> int:
        cur = self.conn.execute(
            '''INSERT INTO suggestions
                   (category, title, method, max_requests, priority, evidence)
                   VALUES (?,?,?,?,?,?)''',
            (category, title, method, max_requests, priority, evidence),
        )
        self.conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def get_suggestion(self, suggestion_id: int) -> Optional[dict]:
        row = self.conn.execute(
            'SELECT * FROM suggestions WHERE id=?', (suggestion_id,)
        ).fetchone()
        if not row:
            return None
        cols = [d[0] for d in self.conn.description]
        return dict(zip(cols, row))

    def update_suggestion_status(self, suggestion_id: int, status: str) -> None:
        self.conn.execute(
            "UPDATE suggestions SET status=?, updated=datetime('now') WHERE id=?",
            (status, suggestion_id),
        )
        self.conn.commit()

    def next_pending(self) -> Optional[tuple]:
        """Return the next pending suggestion in legacy tuple format."""
        return self.conn.execute(
            "SELECT id, category, title, method, max_requests, priority, status "
            "FROM suggestions WHERE status='pending' ORDER BY priority DESC, id ASC LIMIT 1"
        ).fetchone()

    def suggestion_exists(self, category: str) -> bool:
        """Whether a suggestion exists for this category, regardless of status."""
        return self.conn.execute(
            'SELECT 1 FROM suggestions WHERE category=? LIMIT 1', (category,)
        ).fetchone() is not None

    def pending_suggestions(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM suggestions WHERE status='pending' ORDER BY priority DESC"
        ).fetchall()
        cols = [d[0] for d in self.conn.description]
        return [dict(zip(cols, r)) for r in rows]
