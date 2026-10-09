"""Hash-bound local human review for public synthetic export; no automatic posting."""

import json
import time
from pathlib import Path

from .intelligence import analyze, public_ioc, validate_ioc
from .policy import Rejected, canonical, digest_identifier, fields, identifier, plan_hash
from .storage import checkpoint, connect


class Review:
    def __init__(self, path: Path, clock=None):
        self.clock = clock or (lambda: int(time.time()))
        self.db = connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS reviews (
              hash TEXT PRIMARY KEY, kind TEXT NOT NULL, content TEXT NOT NULL,
              owner TEXT NOT NULL, expires INTEGER NOT NULL, approved INTEGER NOT NULL DEFAULT 0,
              consumed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS review_audit (
              sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL,
              hash TEXT NOT NULL, action TEXT NOT NULL
            );
        """)

    def close(self):
        self.db.close()

    def prepare(self, kind: str, content: dict, owner: str) -> dict:
        identifier(owner)
        now = checkpoint(self.db, self.clock)
        if kind == "ioc":
            validate_ioc(content, now)
        elif kind == "report":
            analyze(content)
        else:
            raise Rejected("unsupported review kind")
        expires = min(now + 300, content["expires_at"]) if kind == "ioc" else now + 300
        envelope = {
            "kind": kind,
            "content": content,
            "owner": owner,
            "created_at": now,
            "expires_at": expires,
        }
        digest = plan_hash(envelope)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("SELECT count(*) FROM reviews").fetchone()[0] >= 10000:
                raise Rejected("review quota exceeded")
            self.db.execute(
                "INSERT OR IGNORE INTO reviews(hash, kind, content, owner, expires)"
                " VALUES (?, ?, ?, ?, ?)",
                (digest, kind, canonical(envelope), owner, expires),
            )
        return {"review_hash": digest, "review": envelope, "requires_review": True}

    def approve(self, digest: str, owner: str):
        digest_identifier(digest)
        identifier(owner)
        now = checkpoint(self.db, self.clock)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._verify_stored(digest, owner)
            changed = self.db.execute(
                """UPDATE reviews SET approved=1
                WHERE hash=? AND owner=? AND expires>? AND approved=0 AND consumed=0""",
                (digest, owner, now),
            ).rowcount
            if changed != 1:
                raise Rejected("invalid or expired review approval")
            self.db.execute(
                "INSERT INTO review_audit(at, hash, action) VALUES (?, ?, 'approved')",
                (now, digest),
            )

    def export(self, digest: str, owner: str) -> dict:
        digest_identifier(digest)
        identifier(owner)
        now = checkpoint(self.db, self.clock)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            envelope = self._verify_stored(digest, owner)
            row = self.db.execute(
                "SELECT kind, content FROM reviews WHERE hash=? AND owner=?"
                " AND approved=1 AND consumed=0 AND expires>?",
                (digest, owner, now),
            ).fetchone()
            if not row:
                raise Rejected("missing, expired or consumed export review")
            content = envelope["content"]
            if row[0] == "ioc":
                output = public_ioc(content, now)
            else:
                analyze(content)
                output = content
            self.db.execute("UPDATE reviews SET consumed=1 WHERE hash=?", (digest,))
            self.db.execute(
                "INSERT INTO review_audit(at, hash, action) VALUES (?, ?, 'exported')",
                (now, digest),
            )
        return {"review_hash": digest, "reviewed": True, "export": output}

    def _verify_stored(self, digest, owner):
        row = self.db.execute(
            "SELECT kind, content, owner, expires FROM reviews WHERE hash=?", (digest,)
        ).fetchone()
        if not row or row[2] != owner:
            raise Rejected("review outside owner scope")
        try:
            envelope = fields(
                json.loads(row[1]), {"kind", "content", "owner", "created_at", "expires_at"}
            )
            if (
                plan_hash(envelope) != digest
                or envelope["owner"] != row[2]
                or envelope["expires_at"] != row[3]
                or envelope["kind"] != row[0]
            ):
                raise Rejected("review integrity mismatch")
        except (ValueError, TypeError) as exc:
            raise Rejected("invalid stored review") from exc
        return envelope
