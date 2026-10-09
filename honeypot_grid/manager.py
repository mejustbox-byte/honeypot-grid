"""Transactional SQLite mock lifecycle and audit. Local operator is trusted."""

import sqlite3
import time
from collections.abc import Callable
from pathlib import Path

from .policy import (
    Config,
    Rejected,
    canonical,
    digest_identifier,
    fields,
    identifier,
    integer,
    plan,
    plan_hash,
)
from .storage import connect


class Manager:
    def __init__(self, database: Path, clock: Callable[[], int] | None = None, runtime=None):
        self.clock = clock or (lambda: int(time.time()))
        self.runtime = runtime
        self.adapter = runtime.name if runtime else "mock"
        self.db = connect(database)
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
            CREATE TABLE IF NOT EXISTS clock_state (
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), highwater INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO clock_state VALUES (1, 0);
        """)
        self.db.execute("PRAGMA foreign_keys = ON")

    def close(self):
        self.db.close()

    def _now(self, allow_rollback=False):
        now = integer(self.clock(), 0, 2**53)
        previous = self.db.execute(
            "SELECT highwater FROM clock_state WHERE singleton=1"
        ).fetchone()[0]
        if now < previous and not allow_rollback:
            raise Rejected("clock rollback detected")
        now = max(now, previous)
        self.db.execute("UPDATE clock_state SET highwater=? WHERE singleton=1", (now,))
        return now

    def _checkpoint(self, allow_rollback=False):
        # Persist observed time even when a later policy decision rolls back.
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            return self._now(allow_rollback)

    def _audit(self, digest: str, action: str):
        self.db.execute(
            "INSERT INTO audit(at, hash, action) VALUES (?, ?, ?)",
            (self._now(allow_rollback=action in {"stopped", "ttl-expired"}), digest, action),
        )

    def prepare(self, raw: dict, scope: dict) -> dict:
        self._checkpoint()
        config = Config.parse(raw, scope)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("SELECT count(*) FROM runs").fetchone()[0] >= 10000:
                raise Rejected("run storage quota exceeded")
            value = plan(config, self._now(), self.adapter)
            digest = plan_hash(value)
            inserted = self.db.execute(
                "INSERT OR IGNORE INTO runs VALUES (?, ?, ?, ?, 'awaiting-approval')",
                (digest, config.owner, canonical(value), value["expires_at"]),
            ).rowcount
            if inserted:
                self._audit(digest, "planned")
        return {"plan": value, "plan_hash": digest, "dry_run": True}

    def approve(self, digest: str, operator: str, ttl: int = 300):
        digest_identifier(digest)
        self._checkpoint()
        identifier(operator)
        integer(ttl, 1, 300)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT owner, expires, state FROM runs WHERE hash=?", (digest,)
            ).fetchone()
            if not row or row[0] != operator or row[1] <= self._now():
                raise Rejected("approval outside owner or time scope")
            if row[2] != "awaiting-approval":
                raise Rejected("run cannot be approved")
            try:
                self.db.execute(
                    "INSERT INTO approvals(hash, operator, expires) VALUES (?, ?, ?)",
                    (digest, operator, min(row[1], self._now() + ttl)),
                )
            except sqlite3.IntegrityError as exc:
                raise Rejected("approval already issued") from exc
            self._audit(digest, "approved")

    def apply(self, value: dict, scope: dict, operator: str) -> dict:
        self._checkpoint()
        identifier(operator)
        fields(value, {"version", "adapter", "config", "isolation", "created_at", "expires_at"})
        if (
            type(value["version"]) is not int
            or value["version"] != 1
            or value["adapter"] != self.adapter
        ):
            raise Rejected("unsupported plan")
        if type(value["config"]) is not dict:
            raise Rejected("invalid plan configuration")
        raw = dict(value["config"])
        raw["isolation"] = value["isolation"]
        config = Config.parse(raw, scope)
        created = integer(value["created_at"], 0, 2**53)
        integer(value["expires_at"], 0, 2**53)
        if value != plan(config, created, self.adapter) or created > self.clock():
            raise Rejected("invalid plan lifetime")
        digest = plan_hash(value)
        if self.runtime:
            return self._apply_runtime(value, digest, config, operator)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT plan, expires, state FROM runs WHERE hash=?", (digest,)
            ).fetchone()
            if not row or row[0] != canonical(value) or row[1] <= self._now():
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
            if not approval or approval[0] != operator or approval[1] <= self._now() or approval[2]:
                raise Rejected("missing, expired or consumed approval")
            # The mock effect is only this transaction. Audit failure rolls it back.
            self.db.execute("UPDATE approvals SET consumed=1 WHERE hash=?", (digest,))
            self.db.execute("UPDATE runs SET state='observing' WHERE hash=?", (digest,))
            self._audit(digest, "mock-provisioned")
        return {"plan_hash": digest, "state": "observing", "changed": True}

    def _apply_runtime(self, value, digest, config, operator):
        self.runtime.preflight(config)
        already = False
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            now = self._now()
            row = self.db.execute(
                "SELECT plan, expires, state FROM runs WHERE hash=?", (digest,)
            ).fetchone()
            if not row or row[0] != canonical(value) or row[1] <= now or operator != config.owner:
                raise Rejected("runtime action outside approval scope")
            if row[2] == "observing":
                already = True
            elif row[2] != "awaiting-approval":
                raise Rejected("runtime run cannot be applied")
            else:
                approval = self.db.execute(
                    "SELECT operator, expires, consumed FROM approvals WHERE hash=?", (digest,)
                ).fetchone()
                if not approval or approval[0] != operator or approval[1] <= now or approval[2]:
                    raise Rejected("invalid runtime approval")
                self.db.execute("UPDATE approvals SET consumed=1 WHERE hash=?", (digest,))
                self.db.execute("UPDATE runs SET state='provisioning' WHERE hash=?", (digest,))
                # Durable audit precedes every external action. This is a saga, not a DB rollback.
                self._audit(digest, "runtime-provisioning")
        try:
            if already:
                if not self.runtime.verify(digest, config):
                    raise Rejected("runtime disappeared")
                return {"plan_hash": digest, "state": "observing", "changed": False}
            self.runtime.start(digest, config)
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                # Another process may stop/expire while the external start is running.
                row = self.db.execute(
                    "SELECT state, expires FROM runs WHERE hash=?", (digest,)
                ).fetchone()
                if row[0] != "provisioning" or row[1] <= self._now():
                    raise Rejected("runtime plan stopped or expired during provisioning")
                self.db.execute("UPDATE runs SET state='observing' WHERE hash=?", (digest,))
                self._audit(digest, "runtime-observing")
        except BaseException as exc:
            try:
                self.runtime.stop(digest)
            finally:
                with self.db:
                    self.db.execute("UPDATE runs SET state='quarantined' WHERE hash=?", (digest,))
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise Rejected("runtime failed; reconciliation required") from exc
        return {"plan_hash": digest, "state": "observing", "changed": True}

    def stop(self, digest: str, operator: str):
        digest_identifier(digest)
        self._checkpoint(allow_rollback=True)
        identifier(operator)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT owner, state, plan FROM runs WHERE hash=?", (digest,)
            ).fetchone()
            if not row or row[0] != operator:
                raise Rejected("stop outside scope")
            import json

            if json.loads(row[2])["adapter"] != self.adapter:
                raise Rejected("wrong runtime for stop")
            if row[1] != "destroyed":
                if self.runtime:
                    self.runtime.stop(digest)
                self.db.execute("UPDATE runs SET state='destroyed' WHERE hash=?", (digest,))
                self._audit(digest, "stopped")

    def expire(self) -> int:
        self._checkpoint(allow_rollback=True)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            rows = self.db.execute(
                "SELECT hash, plan FROM runs WHERE state!='destroyed'"
                " AND (expires<=? OR state IN ('provisioning', 'quarantined'))",
                (self._now(allow_rollback=True),),
            ).fetchall()
            import json

            managed = [
                (digest, value)
                for digest, value in rows
                if json.loads(value)["adapter"] == self.adapter
            ]
            for digest, _ in managed:
                if self.runtime:
                    self.runtime.stop(digest)
                self.db.execute("UPDATE runs SET state='destroyed' WHERE hash=?", (digest,))
                self._audit(digest, "ttl-expired")
        if self.runtime:
            for digest in self.runtime.inventory():
                row = self.db.execute("SELECT state FROM runs WHERE hash=?", (digest,)).fetchone()
                if row is None or row[0] == "destroyed":
                    self.runtime.stop(digest)
        return len(managed)

    def status(self) -> list[dict]:
        return [
            dict(zip(("plan_hash", "state", "expires_at"), row, strict=True))
            for row in self.db.execute("SELECT hash, state, expires FROM runs ORDER BY hash")
        ]

    def collect(self, digest, scope, operator, store, key, epoch):
        """Read a verified finite Docker snapshot, then atomically ingest deliveries."""
        import io

        from .transport import collect

        config = self._observed_config(digest, scope, operator)
        output = self.runtime.delivery_snapshot(digest, config)
        result = collect(io.BytesIO(output), store, key, epoch, config.lab_id, config.service)
        with self.db:
            self._audit(digest, "delivery-collected")
        return result

    def _observed_config(self, digest, scope, operator):
        import json

        digest_identifier(digest)
        identifier(operator)
        self._checkpoint()
        if self.runtime is None:
            raise Rejected("Docker runtime required for delivery")
        row = self.db.execute(
            "SELECT plan, owner, state FROM runs WHERE hash=?", (digest,)
        ).fetchone()
        if not row or row[1] != operator or row[2] != "observing":
            raise Rejected("delivery outside observed owner scope")
        value = json.loads(row[0])
        if plan_hash(value) != digest or value["adapter"] != self.adapter:
            raise Rejected("invalid stored delivery plan")
        return Config.parse(value["config"] | {"isolation": value["isolation"]}, scope)

    def lab_probe(self, digest, scope, operator):
        config = self._observed_config(digest, scope, operator)
        result = self.runtime.lab_probe(digest, config)
        with self.db:
            self._audit(digest, "lab-probed")
        return result

    def audit(self) -> list[dict]:
        return [
            dict(zip(("sequence", "at", "plan_hash", "action"), row, strict=True))
            for row in self.db.execute(
                "SELECT sequence, at, hash, action FROM audit ORDER BY sequence"
            )
        ]
