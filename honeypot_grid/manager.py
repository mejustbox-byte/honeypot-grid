"""Transactional SQLite mock lifecycle and audit. Local operator is trusted."""

import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

from .policy import Config, Rejected, canonical, fields, identifier, integer, plan, plan_hash


class Manager:
    def __init__(self, database: Path, clock: Callable[[], int] | None = None):
        self.clock = clock or (lambda: int(time.time()))
        self.db = sqlite3.connect(database)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
              hash TEXT PRIMARY KEY, owner TEXT NOT NULL, plan TEXT NOT NULL,
              expires INTEGER NOT NULL, state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approvals (
              hash TEXT PRIMARY KEY REFERENCES runs(hash), operator TEXT NOT NULL,
              expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit (
              sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL, hash TEXT NOT NULL,
              action TEXT NOT NULL
            );
        """)
        self.db.execute("PRAGMA foreign_keys = ON")

    def close(self):
        self.db.close()

    def _audit(self, digest: str, action: str):
        self.db.execute(
            "INSERT INTO audit(at, hash, action) VALUES (?, ?, ?)", (self.clock(), digest, action)
        )

    def prepare(self, raw: dict, scope: dict) -> dict:
        config = Config.parse(raw, scope)
        value = plan(config, self.clock())
        digest = plan_hash(value)
        with self.db:
            inserted = self.db.execute(
                "INSERT OR IGNORE INTO runs VALUES (?, ?, ?, ?, 'awaiting-approval')",
                (digest, config.owner, canonical(value), value["expires_at"]),
            ).rowcount
            if inserted:
                self._audit(digest, "planned")
        return {"plan": value, "plan_hash": digest, "dry_run": True}

    def approve(self, digest: str, operator: str, ttl: int = 300):
        identifier(operator)
        integer(ttl, 1, 300)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT owner, expires, state FROM runs WHERE hash=?", (digest,)
            ).fetchone()
            if not row or row[0] != operator or row[1] <= self.clock():
                raise Rejected("approval outside owner or time scope")
            if row[2] != "awaiting-approval":
                raise Rejected("run cannot be approved")
            try:
                self.db.execute(
                    "INSERT INTO approvals(hash, operator, expires) VALUES (?, ?, ?)",
                    (digest, operator, min(row[1], self.clock() + ttl)),
                )
            except sqlite3.IntegrityError as exc:
                raise Rejected("approval already issued") from exc
            self._audit(digest, "approved")

    def apply(self, value: dict, scope: dict, operator: str) -> dict:
        identifier(operator)
        fields(value, {"version", "adapter", "config", "isolation", "created_at", "expires_at"})
        if type(value["version"]) is not int or value["version"] != 1 or value["adapter"] != "mock":
            raise Rejected("unsupported plan")
        if type(value["config"]) is not dict:
            raise Rejected("invalid plan configuration")
        raw = dict(value["config"])
        raw["isolation"] = value["isolation"]
        config = Config.parse(raw, scope)
        created = integer(value["created_at"], 0, 2**53)
        if value != plan(config, created) or created > self.clock():
            raise Rejected("invalid plan lifetime")
        digest = plan_hash(value)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT plan, expires, state FROM runs WHERE hash=?", (digest,)
            ).fetchone()
            if not row or row[0] != canonical(value) or row[1] <= self.clock():
                raise Rejected("unknown or expired plan")
            if operator != config.owner:
                raise Rejected("operator outside scope")
            if row[2] == "observing":
                return {"plan_hash": digest, "state": "observing", "changed": False}
            if row[2] != "awaiting-approval":
                raise Rejected("run is terminal")
            approval = self.db.execute(
                "SELECT operator, expires, consumed FROM approvals WHERE hash=?",
                (digest,),
            ).fetchone()
            if (
                not approval
                or approval[0] != operator
                or approval[1] <= self.clock()
                or approval[2]
            ):
                raise Rejected("missing, expired or consumed approval")
            # The mock effect is only this transaction. Audit failure rolls it back.
            self.db.execute("UPDATE approvals SET consumed=1 WHERE hash=?", (digest,))
            self.db.execute("UPDATE runs SET state='observing' WHERE hash=?", (digest,))
            self._audit(digest, "mock-provisioned")
        return {"plan_hash": digest, "state": "observing", "changed": True}

    def stop(self, digest: str, operator: str):
        identifier(operator)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT owner, state FROM runs WHERE hash=?", (digest,)
            ).fetchone()
            if not row or row[0] != operator:
                raise Rejected("stop outside scope")
            if row[1] != "destroyed":
                self.db.execute("UPDATE runs SET state='destroyed' WHERE hash=?", (digest,))
                self._audit(digest, "stopped")

    def expire(self) -> int:
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            rows = self.db.execute(
                "SELECT hash FROM runs WHERE expires<=? AND state!='destroyed'", (self.clock(),)
            ).fetchall()
            for (digest,) in rows:
                self.db.execute("UPDATE runs SET state='destroyed' WHERE hash=?", (digest,))
                self._audit(digest, "ttl-expired")
        return len(rows)

    def status(self) -> list[dict]:
        return [
            dict(zip(("plan_hash", "state", "expires_at"), row, strict=True))
            for row in self.db.execute("SELECT hash, state, expires FROM runs ORDER BY hash")
        ]

    def audit(self) -> list[dict]:
        return [
            dict(zip(("sequence", "at", "plan_hash", "action"), row, strict=True))
            for row in self.db.execute(
                "SELECT sequence, at, hash, action FROM audit ORDER BY sequence"
            )
        ]
