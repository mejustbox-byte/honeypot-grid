"""Offline pipeline CLI commands. No external posting or LLM network requests."""

import os
import secrets
import time
from pathlib import Path

from .intelligence import analyze, validate_proposal
from .policy import fields, load_json
from .quarantine import purge_samples, quarantine, sandbox_plan
from .review import Review
from .storage import private_parent, read_key
from .telemetry import Telemetry

COMMANDS = {
    "keygen",
    "telemetry-ingest",
    "telemetry-report",
    "telemetry-purge",
    "review-plan",
    "review-approve",
    "export",
    "analyze",
    "quarantine",
    "sandbox-plan",
    "demo-ioc",
    "quarantine-purge",
}


def configure(commands):
    keygen = commands.add_parser("keygen", help="create a new private local pseudonym key")
    keygen.add_argument("--output", type=Path, required=True)
    ingest = commands.add_parser("telemetry-ingest")
    ingest.add_argument("--events", type=Path, required=True)
    ingest.add_argument("--key-file", type=Path, required=True)
    ingest.add_argument("--epoch", required=True)
    commands.add_parser("telemetry-report")
    commands.add_parser("telemetry-purge")
    review = commands.add_parser("review-plan")
    review.add_argument("--kind", choices=("ioc", "report"), required=True)
    review.add_argument("--input", type=Path, required=True)
    review.add_argument("--operator", required=True)
    for name in ("review-approve", "export"):
        command = commands.add_parser(name)
        command.add_argument("--review-hash", required=True)
        command.add_argument("--operator", required=True)
    analysis = commands.add_parser("analyze")
    analysis.add_argument("--report", type=Path, required=True)
    analysis.add_argument("--proposal", type=Path)
    sample = commands.add_parser("quarantine")
    sample.add_argument("--file", type=Path, required=True)
    sample.add_argument("--directory", type=Path, required=True)
    purge = commands.add_parser("quarantine-purge")
    purge.add_argument("--directory", type=Path, required=True)
    purge.add_argument("--older-than", type=int, default=86400)
    sandbox = commands.add_parser("sandbox-plan")
    sandbox.add_argument("--receipt", type=Path, required=True)
    commands.add_parser("demo-ioc", help="generate a time-valid synthetic .invalid IoC")


def execute(args):
    if args.command == "keygen":
        private_parent(args.output)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(secrets.token_bytes(32))
        return {"created": True}
    if args.command.startswith("telemetry-"):
        store = Telemetry(args.database)
        try:
            if args.command == "telemetry-ingest":
                events = fields(load_json(args.events), {"events"})["events"]
                return {"ingested": store.ingest(events, read_key(args.key_file), args.epoch)}
            if args.command == "telemetry-purge":
                return {"purged": store.purge()}
            return store.report()
        finally:
            store.close()
    if args.command in ("review-plan", "review-approve", "export"):
        store = Review(args.database)
        try:
            if args.command == "review-plan":
                return store.prepare(args.kind, load_json(args.input), args.operator)
            if args.command == "review-approve":
                store.approve(args.review_hash, args.operator)
                return {"approved": True}
            return store.export(args.review_hash, args.operator)
        finally:
            store.close()
    if args.command == "analyze":
        report = load_json(args.report)
        if args.proposal:
            return validate_proposal(report, load_json(args.proposal))
        return analyze(report)
    if args.command == "quarantine-purge":
        return {"purged": purge_samples(args.directory, args.older_than)}
    if args.command == "quarantine":
        return quarantine(args.file, args.directory)
    if args.command == "sandbox-plan":
        return sandbox_plan(load_json(args.receipt))
    now = int(time.time())
    return {
        "kind": "domain",
        "value": "sensor.example.invalid",
        "source_ref": "demo-event",
        "method": "synthetic-observation",
        "confidence": 10,
        "first_seen": now,
        "last_seen": now,
        "expires_at": now + 3600,
    }
