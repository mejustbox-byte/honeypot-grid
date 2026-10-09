"""Explicit local CLI. All provisioning is SQLite mock state only."""

import argparse
import sqlite3
import sys
from pathlib import Path

from .manager import Manager
from .policy import Rejected, canonical, fields, load_json
from .privacy import aggregate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline mock-only Honeypot Grid manager")
    parser.add_argument("--database", type=Path, default=Path("honeypot-grid.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("plan", help="validate and produce a dry-run plan")
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--scope", type=Path, required=True)
    approve = commands.add_parser("approve", help="trusted local owner approves one plan")
    approve.add_argument("--plan-hash", required=True)
    approve.add_argument("--operator", required=True)
    approve.add_argument("--ttl", type=int, default=300)
    apply = commands.add_parser("apply", help="apply approved plan to mock state only")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--scope", type=Path, required=True)
    apply.add_argument("--operator", required=True)
    stop = commands.add_parser("stop")
    stop.add_argument("--plan-hash", required=True)
    stop.add_argument("--operator", required=True)
    commands.add_parser("expire", help="reconcile expired mock runs; no background scheduler")
    commands.add_parser("status")
    commands.add_parser("audit", help="read metadata-only local audit")
    privacy = commands.add_parser("aggregate", help="aggregate synthetic events for manual review")
    privacy.add_argument("--events", type=Path, required=True)
    args = parser.parse_args(argv)
    manager = None
    try:
        if args.command == "aggregate":
            batch = fields(load_json(args.events), {"events"})
            result = aggregate(batch["events"])
        else:
            manager = Manager(args.database)
            if args.command == "plan":
                result = manager.prepare(load_json(args.config), load_json(args.scope))
            elif args.command == "approve":
                manager.approve(args.plan_hash, args.operator, args.ttl)
                result = {"approved": True}
            elif args.command == "apply":
                envelope = fields(load_json(args.plan), {"plan", "plan_hash", "dry_run"})
                from .policy import plan_hash

                if (
                    envelope["plan_hash"] != plan_hash(envelope["plan"])
                    or envelope["dry_run"] is not True
                ):
                    raise Rejected("plan envelope mismatch")
                result = manager.apply(envelope["plan"], load_json(args.scope), args.operator)
            elif args.command == "stop":
                manager.stop(args.plan_hash, args.operator)
                result = {"state": "destroyed"}
            elif args.command == "expire":
                result = {"expired": manager.expire()}
            elif args.command == "audit":
                result = {"audit": manager.audit()}
            else:
                result = {"runs": manager.status()}
        print(canonical(result))
        return 0
    except Rejected, OSError, sqlite3.Error, TypeError, KeyError, OverflowError:
        # Do not echo filenames, database paths, raw input or exception values.
        print("REJECTED: invalid input, policy or unavailable state store", file=sys.stderr)
        return 2
    finally:
        if manager:
            manager.close()


if __name__ == "__main__":
    raise SystemExit(main())
