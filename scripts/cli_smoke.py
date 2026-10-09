"""Installed CLI end-to-end smoke with private temporary state and synthetic inputs."""

import json
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="hpg-smoke-") as directory:
        work = Path(directory)

        def call(*args, accepted=True):
            result = subprocess.run(
                ["honeypot-grid", "--database", str(work / "state.sqlite3"), *args],
                cwd=work,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            assert result.returncode == (0 if accepted else 2), result.stderr
            return json.loads(result.stdout) if accepted else None

        def save(name, content):
            path = work / name
            path.write_text(json.dumps(content), encoding="utf-8")
            return str(path)

        scope = str(ROOT / "examples/scope.json")
        envelope = call("plan", "--config", str(ROOT / "examples/lab.json"), "--scope", scope)
        plan_file = save("plan.json", envelope)
        digest = envelope["plan_hash"]
        call(
            "apply",
            "--plan",
            plan_file,
            "--scope",
            scope,
            "--operator",
            "lab-operator",
            accepted=False,
        )
        call("approve", "--plan-hash", digest, "--operator", "lab-operator")
        assert call("apply", "--plan", plan_file, "--scope", scope, "--operator", "lab-operator")[
            "changed"
        ]
        assert not call(
            "apply", "--plan", plan_file, "--scope", scope, "--operator", "lab-operator"
        )["changed"]
        call("stop", "--plan-hash", digest, "--operator", "lab-operator")
        call("reconcile")
        ioc = save("ioc.json", call("demo-ioc"))
        review = call("review-plan", "--kind", "ioc", "--input", ioc, "--operator", "lab-operator")
        review_hash = review["review_hash"]
        call("export", "--review-hash", review_hash, "--operator", "lab-operator", accepted=False)
        call("review-approve", "--review-hash", review_hash, "--operator", "lab-operator")
        assert call("export", "--review-hash", review_hash, "--operator", "lab-operator")[
            "reviewed"
        ]
        call("export", "--review-hash", review_hash, "--operator", "lab-operator", accepted=False)
        sample = work / "harmless.txt"
        sample.write_bytes(b"synthetic fixture")
        receipt = call("quarantine", "--file", str(sample), "--directory", str(work / "samples"))
        assert (
            call("sandbox-plan", "--receipt", save("receipt.json", receipt))["executor_available"]
            is False
        )
        call("keygen", "--output", str(work / "telemetry.key"))
        from honeypot_grid.transport import envelope

        events = [
            envelope(
                {
                    "schema_version": 1,
                    "sensor_id": "sensor-smoke",
                    "timestamp": int(time.time()),
                    "service": "http-mock",
                    "category": "connection",
                }
            )
            for _ in range(5)
        ]
        snapshot = work / "delivery.ndjson"
        snapshot.write_text("\n".join(json.dumps(item) for item in events) + "\n")
        snapshot.chmod(0o600)
        args = (
            "telemetry-collect",
            "--input",
            str(snapshot),
            "--key-file",
            str(work / "telemetry.key"),
            "--epoch",
            "epoch-smoke",
            "--sensor-id",
            "sensor-smoke",
            "--service",
            "http-mock",
        )
        assert call(*args)["ingested"] == 5
        assert call(*args)["duplicates"] == 5
        assert call("telemetry-report")["groups"][0]["count"] == 5
        for name in ("kernel", "initrd"):
            artifact = work / name
            artifact.write_bytes(b"harmless boot fixture, not a real image")
            artifact.chmod(0o600)
        sample.chmod(0o600)
        import hashlib

        manifest = {
            "operator": "lab-operator",
            "authorization_ref": "smoke-only",
            "dedicated_lab_vm": True,
            "no_production_routes": True,
            "no_host_credentials": True,
        }
        for name in ("kernel", "initrd"):
            manifest[name] = str(work / name)
            manifest[name + "_sha256"] = hashlib.sha256((work / name).read_bytes()).hexdigest()
        vm_scope = {
            name: manifest[name]
            for name in ("operator", "authorization_ref", "kernel_sha256", "initrd_sha256")
        }
        job = call(
            "vm-plan",
            "--sample",
            str(sample),
            "--manifest",
            save("vm.json", manifest),
            "--scope",
            save("vm-scope.json", vm_scope),
        )
        call("vm-run", "--job-hash", job["job_hash"], "--operator", "lab-operator", accepted=False)
        assert call("vm-approve", "--job-hash", job["job_hash"], "--operator", "lab-operator")[
            "approved"
        ]
        # Never boot a VM/image fixture on the developer host.
    print(
        "PASS: CLI lifecycle/review/quarantine, delivery retry/report, VM plan/approval; no VM boot"
    )


if __name__ == "__main__":
    main()
