"""Explicit local CLI with mock default and opt-in dedicated-lab runtime."""

import argparse
import sqlite3
import sys
import time
from pathlib import Path

from .manager import Manager
from .operations import COMMANDS, configure, execute
from .policy import Rejected, canonical, fields, load_json
from .privacy import aggregate
from .runtime import DockerRuntime
from .storage import private_file


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Honeypot Grid laboratory manager")
    parser.add_argument("--database", type=Path, default=Path("honeypot-grid.sqlite3"))
    parser.add_argument("--runtime", choices=("mock", "docker-none"), default="mock")
    parser.add_argument("--vm-attestation", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("plan", help="validate and produce a dry-run plan")
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--scope", type=Path, required=True)
    approve = commands.add_parser("approve", help="trusted local owner approves one plan")
    approve.add_argument("--plan-hash", required=True)
    approve.add_argument("--operator", required=True)
    approve.add_argument("--ttl", type=int, default=300)
    apply = commands.add_parser("apply", help="apply approved plan to selected runtime")
    apply.add_argument("--plan", type=Path, required=True)
    apply.add_argument("--scope", type=Path, required=True)
    apply.add_argument("--operator", required=True)
    stop = commands.add_parser("stop")
    stop.add_argument("--plan-hash", required=True)
    stop.add_argument("--operator", required=True)
    commands.add_parser("expire", help="reconcile expired runs; no background scheduler")
    commands.add_parser("status")
    commands.add_parser("audit", help="read metadata-only local audit")
    reconcile = commands.add_parser("reconcile", help="bounded TTL and crash recovery loop")
    reconcile.add_argument("--iterations", type=int, default=1)
    reconcile.add_argument("--interval", type=int, default=1)
    privacy = commands.add_parser("aggregate", help="aggregate synthetic events for manual review")
    privacy.add_argument("--events", type=Path, required=True)
    configure(commands)
    args = parser.parse_args(argv)
    manager = None
    try:
        if args.command in COMMANDS:
            result = execute(args)
        elif args.command == "aggregate":
            batch = fields(load_json(args.events), {"events"})
            result = aggregate(batch["events"])
        else:
            runtime = None
            if args.runtime == "docker-none":
                if args.vm_attestation is None:
                    raise Rejected("private VM attestation required")
                import os

                fd = private_file(args.vm_attestation)
                os.close(fd)
                runtime = DockerRuntime(load_json(args.vm_attestation))
            manager = Manager(args.database, runtime=runtime)
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
            elif args.command == "reconcile":
                from .policy import integer

                integer(args.iterations, 1, 3600)
                integer(args.interval, 1, 60)
                expired = 0
                for index in range(args.iterations):
                    expired += manager.expire()
                    if index + 1 < args.iterations:
                        time.sleep(args.interval)
                result = {"reconciled": expired}
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
