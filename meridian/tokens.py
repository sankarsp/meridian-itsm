"""API tokens: random secrets shown once, stored only as SHA-256 hashes."""
from __future__ import annotations

import hashlib
import secrets
import time

PREFIX = "mrd_"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(db, uid: str, name: str) -> str:
    if not db.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
        raise LookupError(f"No user {uid}")
    token = PREFIX + secrets.token_urlsafe(32)
    db.execute("INSERT INTO api_tokens(uid, name, token_hash, created) VALUES (?,?,?,?)",
               (uid, name, _hash(token), time.time()))
    db.commit()
    return token


def resolve(db, token: str | None) -> str | None:
    """Return the user id for a valid, unrevoked token."""
    if not token or not token.startswith(PREFIX):
        return None
    row = db.execute("SELECT id, uid FROM api_tokens WHERE token_hash=? AND revoked=0", (_hash(token),)).fetchone()
    if not row:
        return None
    db.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (time.time(), row["id"]))
    db.commit()
    return row["uid"]


def revoke(db, token_id: int) -> bool:
    cur = db.execute("UPDATE api_tokens SET revoked=1 WHERE id=?", (token_id,))
    db.commit()
    return cur.rowcount > 0


def list_for(db, uid: str | None = None):
    sql = "SELECT id, uid, name, created, last_used, revoked FROM api_tokens"
    args = ()
    if uid:
        sql += " WHERE uid=?"
        args = (uid,)
    return db.execute(sql + " ORDER BY id", args).fetchall()
