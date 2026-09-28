"""Database access: SQLite for local/demo use, PostgreSQL for production.

Set DATABASE_URL=postgresql://user:pass@host/db to use Postgres; otherwise the
app uses a SQLite file. Application code writes SQL with `?` placeholders and
reads rows by column name (row["state"]) or position (row[0]) on either engine.
"""
from __future__ import annotations

import sqlite3
import time

from .rbac import DEFAULT_ROLE_PERMS

DAY, MIN = 86400, 60


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------
_COMMON_TABLES = """
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, dept TEXT);
CREATE TABLE IF NOT EXISTS assignments(
  id {serial}, uid TEXT NOT NULL REFERENCES users(id),
  role TEXT NOT NULL, expires {ts}, certified {ts});
CREATE TABLE IF NOT EXISTS role_perms(
  role TEXT NOT NULL, perm TEXT NOT NULL, PRIMARY KEY(role, perm));
CREATE TABLE IF NOT EXISTS incidents(
  id TEXT PRIMARY KEY, descr TEXT NOT NULL, priority INTEGER NOT NULL CHECK (priority BETWEEN 1 AND 4),
  state TEXT NOT NULL, caller TEXT REFERENCES users(id), assignee TEXT REFERENCES users(id), opened {ts});
CREATE TABLE IF NOT EXISTS changes(
  id TEXT PRIMARY KEY, title TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('Standard','Normal','Emergency')),
  risk TEXT NOT NULL CHECK (risk IN ('Low','Moderate','High')),
  state TEXT NOT NULL, requested_by TEXT REFERENCES users(id), implementer TEXT REFERENCES users(id),
  win TEXT, release_id TEXT);
CREATE TABLE IF NOT EXISTS votes(
  change_id TEXT NOT NULL REFERENCES changes(id), uid TEXT NOT NULL REFERENCES users(id),
  decision TEXT NOT NULL CHECK (decision IN ('approved','rejected')), at {ts},
  PRIMARY KEY(change_id, uid));
CREATE TABLE IF NOT EXISTS releases(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, stage INTEGER NOT NULL CHECK (stage BETWEEN 0 AND 4),
  built_by TEXT REFERENCES users(id), change_id TEXT REFERENCES changes(id), items TEXT);
CREATE TABLE IF NOT EXISTS gates(
  release_id TEXT NOT NULL REFERENCES releases(id), gate TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pass','fail','pending')), signed_by TEXT, note TEXT,
  PRIMARY KEY(release_id, gate));
CREATE TABLE IF NOT EXISTS access_requests(
  id TEXT PRIMARY KEY, uid TEXT NOT NULL REFERENCES users(id), role TEXT NOT NULL,
  days INTEGER NOT NULL, why TEXT, state TEXT NOT NULL, requested {ts},
  decided_by TEXT REFERENCES users(id), exception INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(
  id {serial}, at {ts} NOT NULL, uid TEXT, roles TEXT, action TEXT, record TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied')), detail TEXT, channel TEXT DEFAULT 'web');
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS api_tokens(
  id {serial}, uid TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE, created {ts} NOT NULL, last_used {ts}, revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_assignments_uid ON assignments(uid);
CREATE INDEX IF NOT EXISTS ix_audit_at ON audit(at);
CREATE INDEX IF NOT EXISTS ix_changes_state ON changes(state);
"""

SQLITE_SCHEMA = _COMMON_TABLES.format(serial="INTEGER PRIMARY KEY AUTOINCREMENT", ts="REAL") + """
-- The audit log is append-only. Deletes are allowed only during a demo reset.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
WHEN (SELECT value FROM settings WHERE key='allow_reset') IS NOT '1'
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""

POSTGRES_SCHEMA = _COMMON_TABLES.format(serial="BIGSERIAL PRIMARY KEY", ts="DOUBLE PRECISION") + """
-- The audit log is append-only. Deletes are allowed only during a demo reset.
CREATE OR REPLACE FUNCTION audit_guard() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' AND COALESCE((SELECT value FROM settings WHERE key = 'allow_reset'), '0') = '1' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit log is append-only';
END $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_append_only ON audit;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit
  FOR EACH ROW EXECUTE FUNCTION audit_guard();
DROP TRIGGER IF EXISTS audit_no_truncate ON audit;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit
  FOR EACH STATEMENT EXECUTE FUNCTION audit_guard();
"""

TABLES = ["audit", "api_tokens", "gates", "votes", "releases", "changes", "incidents",
          "access_requests", "role_perms", "assignments", "users", "settings"]


# --------------------------------------------------------------------------
# Connection wrapper
# --------------------------------------------------------------------------
class Row(dict):
    """A dict that also supports positional access: row["state"] and row[0]."""

    def __init__(self, cols, values):
        super().__init__(zip(cols, values))
        self._values = tuple(values)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return dict.__getitem__(self, key)


def _sqlite_row(cursor, values):
    return Row([d[0] for d in cursor.description], values)


def _pg_row_factory(cursor):
    cols = [d.name for d in cursor.description] if cursor.description else []
    return lambda values: Row(cols, values)


class Database:
    def __init__(self, raw, dialect: str):
        self.raw = raw
        self.dialect = dialect

    def _sql(self, sql):
        return sql.replace("?", "%s") if self.dialect == "postgres" else sql

    def execute(self, sql, params=()):
        cur = self.raw.cursor()
        cur.execute(self._sql(sql), params)
        return cur

    def executemany(self, sql, rows):
        cur = self.raw.cursor()
        cur.executemany(self._sql(sql), rows)
        return cur

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


def is_postgres(url: str) -> bool:
    return url.startswith(("postgres://", "postgresql://"))


def connect(url: str) -> Database:
    """Open a connection. `url` is a Postgres URL or a SQLite file path."""
    if is_postgres(url):
        import psycopg  # imported lazily so SQLite users don't need the driver
        raw = psycopg.connect(url.replace("postgres://", "postgresql://", 1), row_factory=_pg_row_factory)
        return Database(raw, "postgres")
    raw = sqlite3.connect(url)
    raw.row_factory = _sqlite_row
    raw.execute("PRAGMA foreign_keys=ON")
    return Database(raw, "sqlite")


# --------------------------------------------------------------------------
# Setup and seed data
# --------------------------------------------------------------------------
def init(db: Database) -> None:
    """Create tables if needed and seed demo data into an empty database."""
    if db.dialect == "postgres":
        db.execute(POSTGRES_SCHEMA)
        db.commit()
    else:
        db.raw.executescript(SQLITE_SCHEMA)
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        seed(db)


def _set(db, key, value):
    db.execute("INSERT INTO settings(key, value) VALUES (?, ?) "
               "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))


def reset(db: Database) -> None:
    """Wipe and re-seed (demo only)."""
    _set(db, "allow_reset", "1")
    for t in TABLES:
        db.execute(f"DELETE FROM {t}")
    db.commit()
    seed(db)


def seed(db: Database) -> None:
    now = time.time()
    x = db.executemany
    x("INSERT INTO users(id, name, dept) VALUES (?,?,?)", [
        ("u1", "Priya Nair", "Finance Operations"),
        ("u2", "Marcus Lee", "Service Desk"),
        ("u3", "Raj Patel", "Payments Engineering"),
        ("u4", "Elena Petrova", "Change Management"),
        ("u5", "David Okafor", "Release Engineering"),
        ("u6", "Sofia Alvarez", "Risk & Compliance"),
        ("u7", "Tom Becker", "Identity & Access"),
    ])
    old = now - 40 * DAY
    x("INSERT INTO assignments(uid, role, expires, certified) VALUES (?,?,?,?)", [
        ("u1", "requester", None, old), ("u2", "agent", None, old), ("u3", "developer", None, old),
        ("u4", "change_mgr", None, old), ("u4", "cab", None, old), ("u5", "release_mgr", None, old),
        ("u6", "cab", None, old), ("u7", "admin", None, old), ("u2", "cab", now + 12 * DAY, None),
    ])
    x("INSERT INTO role_perms(role, perm) VALUES (?,?)",
      [(r, p) for r, ps in DEFAULT_ROLE_PERMS.items() for p in ps])
    x("INSERT INTO incidents(id, descr, priority, state, caller, assignee, opened) VALUES (?,?,?,?,?,?,?)", [
        ("INC0041187", "Card authorization latency above 2s on EU gateway", 1, "In Progress", "u1", "u2", now - 95 * MIN),
        ("INC0041190", "SAR case report fails to export to PDF", 3, "New", "u1", None, now - 40 * MIN),
        ("INC0041176", "Chargeback queue not refreshing in ops dashboard", 2, "New", "u6", None, now - 180 * MIN),
        ("INC0041172", "VPN token not syncing after phone replacement", 4, "Resolved", "u5", "u2", now - DAY),
    ])
    x("INSERT INTO changes(id, title, type, risk, state, requested_by, implementer, win, release_id) "
      "VALUES (?,?,?,?,?,?,?,?,?)", [
        ("CHG0030412", "Deploy Payments API v4.2 to production", "Normal", "Moderate", "Authorize", "u3", "u3",
         "Oct 1, 22:00–23:30 ET", "REL-26.10"),
        ("CHG0030418", "Add velocity rule for cross-border P2P transfers", "Normal", "Moderate", "Assess", "u3", "u3",
         "Oct 8, 21:00–22:00 ET", "REL-26.11"),
        ("CHG0030415", "Rotate TLS certificates on card vault", "Standard", "Low", "Scheduled", "u5", "u3",
         "Sep 29, 06:00–06:30 ET", None),
        ("CHG0030409", "Hotfix: sanctions list sync job failing", "Emergency", "High", "Implement", "u3", "u3", "Now", None),
        ("CHG0030401", "Upgrade Kafka brokers to 3.8", "Normal", "High", "Closed", "u5", "u3", "Sep 21", "REL-26.09"),
    ])
    x("INSERT INTO votes(change_id, uid, decision, at) VALUES (?,?,?,?)", [
        ("CHG0030412", "u4", "approved", now - 60 * MIN),
        ("CHG0030409", "u4", "approved", now - 300 * MIN),
        ("CHG0030401", "u4", "approved", now - 9 * DAY),
        ("CHG0030401", "u6", "approved", now - 9 * DAY),
    ])
    x("INSERT INTO releases(id, name, stage, built_by, change_id, items) VALUES (?,?,?,?,?,?)", [
        ("REL-26.10", "Payments API v4.2", 3, "u3", "CHG0030412",
         "Idempotency keys on payment retries\nISO 20022 pacs.008 mapping\nRetire v3 auth endpoint"),
        ("REL-26.11", "AML rules engine 2.3", 1, "u3", "CHG0030418",
         "Cross-border P2P velocity rule\nStructuring detection threshold tuning\nAlert de-duplication"),
        ("REL-26.09", "Merchant portal 1.18", 4, "u3", "CHG0030401", "Dispute evidence upload\nPayout schedule view"),
    ])
    x("INSERT INTO gates(release_id, gate, status, signed_by, note) VALUES (?,?,?,?,?)", [
        ("REL-26.10", "build", "pass", "CI", None), ("REL-26.10", "sec", "pass", "SAST/DAST", None),
        ("REL-26.10", "uat", "pass", "u6", None), ("REL-26.10", "rollback", "pending", None, None),
        ("REL-26.11", "build", "pass", "CI", None), ("REL-26.11", "sec", "fail", "SAST/DAST", "2 high findings"),
        ("REL-26.11", "uat", "pending", None, None), ("REL-26.11", "rollback", "pending", None, None),
        ("REL-26.09", "build", "pass", "CI", None), ("REL-26.09", "sec", "pass", "SAST/DAST", None),
        ("REL-26.09", "uat", "pass", "u6", None), ("REL-26.09", "rollback", "pass", "u5", None),
    ])
    x("INSERT INTO access_requests(id, uid, role, days, why, state, requested, decided_by, exception) "
      "VALUES (?,?,?,?,?,?,?,?,?)", [
        ("RITM0010051", "u3", "release_mgr", 30, "Cover release on-call during quarter-end while David is out",
         "Pending", now - 180 * MIN, None, 0),
        ("RITM0010053", "u1", "agent", 14, "Help triage SAR export tickets this sprint", "Pending", now - 50 * MIN, None, 0),
        ("RITM0010047", "u2", "cab", 30, "Represent service desk at CAB during Q4", "Approved", now - 18 * DAY, "u7", 0),
    ])
    _set(db, "freeze", "0")
    _set(db, "allow_reset", "0")
    x("INSERT INTO audit(at, uid, roles, action, record, outcome, detail) VALUES (?,?,?,?,?,?,?)", [
        (now - 300 * MIN, "u4", "Change Manager, CAB Member", "Authorized emergency change", "CHG0030409", "allowed", None),
        (now - 95 * MIN, "u2", "Service Desk Agent, CAB Member", "Assign to me", "INC0041187", "allowed", None),
        (now - 80 * MIN, "u3", "Developer", "Deploy to Production", "REL-26.10", "denied",
         "Needs “Deploy to Production” permission. Your roles: Developer."),
        (now - 60 * MIN, "u4", "Change Manager, CAB Member", "CAB vote: approve", "CHG0030412", "allowed", None),
    ])
    db.commit()
