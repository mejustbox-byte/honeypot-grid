"""Installed CLI end-to-end smoke with private temporary state and synthetic inputs."""

import json
import subprocess
import tempfile
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
    print(
        "PASS: installed CLI lifecycle, review/replay protection, quarantine; no external runtime"
    )


if __name__ == "__main__":
    main()
