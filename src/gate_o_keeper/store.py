import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from uuid import uuid4

from .config import Policy
from .hardware import Scan


class Denied(Exception):
    """A user-facing refusal; contains no secret material."""


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    subject TEXT PRIMARY KEY, directory_key TEXT NOT NULL,
    allowed INTEGER NOT NULL DEFAULT 0, checked INTEGER NOT NULL DEFAULT 0,
    online INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL REFERENCES users(subject),
    expires INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires);
CREATE TABLE IF NOT EXISTS tags (
    tag TEXT PRIMARY KEY, last_open INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS visits (
    id TEXT PRIMARY KEY, door TEXT NOT NULL, tag TEXT NOT NULL,
    counter INTEGER NOT NULL, expires INTEGER NOT NULL,
    UNIQUE(tag, counter)
);
CREATE TABLE IF NOT EXISTS attempts (
    id TEXT PRIMARY KEY, tag TEXT NOT NULL, counter INTEGER NOT NULL,
    door TEXT NOT NULL, subject TEXT NOT NULL, created INTEGER NOT NULL,
    outcome TEXT NOT NULL, UNIQUE(tag, counter)
);
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


@dataclass(frozen=True)
class Attempt:
    id: str
    door: str
    tag: str
    counter: int


class Store:
    def __init__(self, path, policy: Policy, namespace: str, clock=time.time):
        self.path = path
        self.policy = policy
        self.clock = clock
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
        with self.transaction() as db:
            previous = db.execute(
                "SELECT value FROM settings WHERE name='authority'"
            ).fetchone()
            if previous and previous["value"] != namespace:
                db.execute("DELETE FROM sessions")
                db.execute("DELETE FROM users")
                # Retain seen scans and their original deadlines across config changes.
                db.execute("UPDATE visits SET expires=0")
            db.execute(
                "INSERT OR REPLACE INTO settings VALUES ('authority',?)", (namespace,)
            )

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()

    def begin_check(self, subject, directory_key=None):
        with self.transaction() as db:
            if directory_key is not None:
                previous = db.execute(
                    "SELECT directory_key FROM users WHERE subject=?", (subject,)
                ).fetchone()
                if previous and previous[0] != directory_key:
                    db.execute("DELETE FROM sessions WHERE subject=?", (subject,))
                    db.execute(
                        "UPDATE users SET allowed=0,checked=0,directory_key=? WHERE subject=?",
                        (directory_key, subject),
                    )
                db.execute(
                    "INSERT OR IGNORE INTO users(subject,directory_key) VALUES (?,?)",
                    (subject, directory_key),
                )
            return db.execute(
                """UPDATE users SET revision=revision+1,online=0 WHERE subject=?
                RETURNING revision,directory_key""",
                (subject,),
            ).fetchone()

    def finish_check(self, subject, revision, allowed, *, sign_in=False):
        now = int(self.clock())
        with self.transaction() as db:
            applied = db.execute(
                """UPDATE users SET allowed=?,online=1,checked=?
                WHERE subject=? AND revision=?""",
                (allowed, now, subject, revision),
            ).rowcount
            if not applied:
                return None
            if not allowed:
                db.execute("DELETE FROM sessions WHERE subject=?", (subject,))
            elif sign_in:
                token = secrets.token_urlsafe(32)
                expiry = now + min(
                    self.policy.session_seconds, self.policy.offline_seconds
                )
                db.execute(
                    "INSERT INTO sessions VALUES (?,?,?)",
                    (digest(token), subject, expiry),
                )
                return token, expiry
        return None

    def revoke(self, subject):
        with self.transaction() as db:
            db.execute(
                "UPDATE users SET allowed=0,online=0,revision=revision+1 WHERE subject=?",
                (subject,),
            )
            db.execute("DELETE FROM sessions WHERE subject=?", (subject,))

    def active_subjects(self):
        with self.transaction() as db:
            db.execute("DELETE FROM sessions WHERE expires<=?", (int(self.clock()),))
            return [r[0] for r in db.execute("SELECT DISTINCT subject FROM sessions")]

    def logout(self, token):
        with self.transaction() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (digest(token),))

    def _session(self, db, token, now):
        return db.execute(
            """SELECT subject,expires,checked,online FROM sessions JOIN users USING(subject)
            WHERE token_hash=? AND expires>? AND allowed=1 AND checked+?>?""",
            (digest(token), now, self.policy.offline_seconds, now),
        ).fetchone()

    def member(self, token):
        with self.connection() as db:
            return self._session(db, token, int(self.clock())) is not None

    def register_scan(self, door: str, scan: Scan, visit: str):
        with self.transaction() as db:
            now = int(self.clock())
            high = db.execute(
                "SELECT last_open FROM tags WHERE tag=?", (scan.tag,)
            ).fetchone()
            if high and scan.counter <= high[0]:
                raise Denied("这次扫描已失效，请重新扫描门口贴纸。")
            db.execute(
                """INSERT OR IGNORE INTO visits VALUES (?,?,?,?,?)""",
                (
                    digest(visit),
                    door,
                    scan.tag,
                    scan.counter,
                    now + self.policy.scan_seconds,
                ),
            )
            self._visit(db, visit, now)

    @staticmethod
    def _visit(db, visit, now):
        row = db.execute(
            """SELECT v.* FROM visits v LEFT JOIN tags t USING(tag)
            WHERE v.id=? AND v.expires>? AND v.counter>coalesce(t.last_open,-1)
            AND NOT EXISTS(SELECT 1 FROM attempts a WHERE a.tag=v.tag AND a.counter=v.counter)
            """,
            (digest(visit), now),
        ).fetchone()
        if row is None:
            raise Denied("这次扫描已过期或已处理，请重新扫描门口贴纸。")
        return row

    def visit(self, visit):
        with self.connection() as db:
            return self._visit(db, visit, int(self.clock()))

    def claim(self, visit, token):
        with self.transaction() as db:
            now = int(self.clock())
            member = self._session(db, token, now)
            if member is None:
                raise Denied("请使用有开门权限的社团账号登录。")
            row = self._visit(db, visit, now)
            attempt = Attempt(uuid4().hex, row["door"], row["tag"], row["counter"])
            db.execute(
                "INSERT INTO attempts VALUES (?,?,?,?,?,?, 'dispatching')",
                (
                    attempt.id,
                    attempt.tag,
                    attempt.counter,
                    attempt.door,
                    member["subject"],
                    now,
                ),
            )
            return attempt

    def finish_attempt(self, attempt, outcome, token):
        with self.transaction() as db:
            changed = db.execute(
                "UPDATE attempts SET outcome=? WHERE id=? AND outcome='dispatching'",
                (outcome, attempt.id),
            ).rowcount
            if not changed or outcome not in {"confirmed", "simulated"}:
                return None
            db.execute(
                """INSERT INTO tags VALUES (?,?) ON CONFLICT(tag) DO UPDATE
                SET last_open=max(tags.last_open,excluded.last_open)""",
                (attempt.tag, attempt.counter),
            )
            db.execute(
                "DELETE FROM visits WHERE tag=? AND counter<=?",
                (attempt.tag, attempt.counter),
            )
            now = int(self.clock())
            member = self._session(db, token, now)
            if (
                member
                and member["online"]
                and now - member["checked"] <= self.policy.poll_seconds * 2
            ):
                expiry = min(
                    now + self.policy.session_seconds,
                    member["checked"] + self.policy.offline_seconds,
                )
                if expiry > member["expires"]:
                    db.execute(
                        "UPDATE sessions SET expires=? WHERE token_hash=?",
                        (expiry, digest(token)),
                    )
                    return expiry
        return None
