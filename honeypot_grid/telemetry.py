"""Private bounded normalized telemetry with keyed pseudonyms and explicit retention."""

import hashlib
import hmac
import ipaddress
import time
from pathlib import Path

from .policy import Rejected, canonical, fields, identifier, integer
from .privacy import aggregate
from .storage import checkpoint, connect


class Telemetry:
    def __init__(self, path: Path, clock=None, quota=10000, retention=86400):
        self.clock = clock or (lambda: int(time.time()))
        self.quota = integer(quota, 1, 10000)
        self.retention = integer(retention, 60, 604800)
        self.db = connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
              id TEXT PRIMARY KEY, epoch TEXT NOT NULL, sensor TEXT NOT NULL,
              source TEXT NOT NULL, timestamp INTEGER NOT NULL,
              service TEXT NOT NULL, category TEXT NOT NULL, expires INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS telemetry_audit (
              sequence INTEGER PRIMARY KEY, at INTEGER NOT NULL,
              action TEXT NOT NULL, count INTEGER NOT NULL
            );
        """)

    def close(self):
        self.db.close()

    def ingest(self, batch: object, key: bytes, epoch: str) -> int:
        identifier(epoch)
        if type(key) is not bytes or len(key) != 32:
            raise Rejected("32-byte pseudonym key required")
        if type(batch) is not list or not 1 <= len(batch) <= 100:
            raise Rejected("invalid telemetry batch")
        now = checkpoint(self.db, self.clock)
        normalized = []
        for event in batch:
            fields(
                event,
                {
                    "schema_version",
                    "event_id",
                    "sensor_id",
                    "source_ip",
                    "timestamp",
                    "service",
                    "category",
                },
            )
            if type(event["schema_version"]) is not int or event["schema_version"] != 1:
                raise Rejected("unsupported telemetry schema")
            event_id = identifier(event["event_id"])
            sensor = identifier(event["sensor_id"])
            stamp = integer(event["timestamp"], max(0, now - self.retention + 1), now + 5)
            try:
                if type(event["source_ip"]) is not str or len(event["source_ip"]) > 64:
                    raise ValueError
                source = str(ipaddress.ip_address(event["source_ip"]))
            except ValueError as exc:
                raise Rejected("invalid source address") from exc
            # Reuse exact normalized enum and type validation; no unknown text survives.
            aggregate(
                [
                    {
                        k: event[k]
                        for k in ("schema_version", "sensor_id", "timestamp", "service", "category")
                    }
                ]
            )

            def pseudonym(domain, value):
                message = canonical([epoch, domain, value]).encode()
                return hmac.new(key, message, hashlib.sha256).hexdigest()

            normalized.append(
                (
                    pseudonym("event", event_id),
                    epoch,
                    pseudonym("sensor", sensor),
                    pseudonym("source", source),
                    stamp,
                    event["service"],
                    event["category"],
                    stamp + self.retention,
                )
            )
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            # Do not silently erase rows: retention is explicit and auditable.
            count = self.db.execute("SELECT count(*) FROM events").fetchone()[0]
            if count + len(normalized) > self.quota:
                raise Rejected("telemetry quota exceeded")
            self.db.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)", normalized)
            self.db.execute(
                "INSERT INTO telemetry_audit(at, action, count) VALUES (?, 'ingested', ?)",
                (now, len(normalized)),
            )
        return len(normalized)

    def purge(self) -> int:
        now = checkpoint(self.db, self.clock, allow_rollback=True)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            count = self.db.execute("DELETE FROM events WHERE expires<=?", (now,)).rowcount
            if count:
                self.db.execute(
                    "INSERT INTO telemetry_audit(at, action, count) VALUES (?, 'purged', ?)",
                    (now, count),
                )
        return count

    def report(self, minimum_group=5) -> dict:
        integer(minimum_group, 5, 1000)
        now = checkpoint(self.db, self.clock)
        rows = self.db.execute(
            """SELECT timestamp / 86400 AS day, service, category, count(*)
            FROM events WHERE expires>? GROUP BY day, service, category
            HAVING count(*)>=? ORDER BY day, service, category""",
            (now, minimum_group),
        ).fetchall()
        # No IDs, source pseudonyms, epochs, fine-grained times or raw values.
        return {
            "schema_version": 1,
            "requires_review": True,
            "groups": [
                dict(zip(("day", "service", "category", "count"), row, strict=True)) for row in rows
            ],
        }
