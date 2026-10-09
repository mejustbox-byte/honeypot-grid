import copy
import json

import pytest

from honeypot_grid.manager import Manager
from honeypot_grid.policy import ISOLATION, Config, Rejected
from honeypot_grid.runtime import DockerRuntime


@pytest.fixture
def settings():
    scope = {
        "lab_id": "lab-demo",
        "owner": "lab-operator",
        "authorization_ref": "demo-only",
        "services": ["http-mock"],
        "image_digests": ["sha256:" + "0" * 64],
    }
    config = {k: scope[k] for k in ("lab_id", "owner", "authorization_ref")} | {
        "service": "http-mock",
        "image_digest": scope["image_digests"][0],
        "ttl_seconds": 600,
        "memory_mib": 128,
        "cpu_millicores": 250,
        "isolation": dict(ISOLATION),
    }
    return config, scope


class FakeRuntime:
    name = "docker-none"

    def __init__(self):
        self.live = set()
        self.starts = 0
        self.fail_cleanup = False

    def preflight(self, config):
        pass

    def start(self, digest, config):
        self.starts += 1
        self.live.add(digest)

    def verify(self, digest, config):
        return digest in self.live

    def stop(self, digest):
        if self.fail_cleanup:
            raise Rejected("synthetic cleanup failure")
        self.live.discard(digest)

    def inventory(self):
        return list(self.live)


def test_runtime_saga_idempotency_ttl_and_orphans(tmp_path, settings):
    config, scope = settings
    now, runtime = [1000], FakeRuntime()
    manager = Manager(tmp_path / "runtime.sqlite3", lambda: now[0], runtime)
    try:
        item = manager.prepare(config, scope)
        assert item["plan"]["adapter"] == "docker-none"
        with pytest.raises(Rejected):
            manager.apply(item["plan"], scope, "lab-operator")
        manager.approve(item["plan_hash"], "lab-operator")
        assert manager.apply(item["plan"], scope, "lab-operator")["changed"] is True
        assert manager.apply(item["plan"], scope, "lab-operator")["changed"] is False
        assert runtime.starts == 1
        runtime.live.add("f" * 64)
        assert manager.expire() == 0
        assert "f" * 64 not in runtime.live
        now[0] = 1600
        assert manager.expire() == 1
        assert runtime.live == set()
    finally:
        manager.close()


def test_runtime_final_audit_failure_compensates_then_recovers(tmp_path, settings):
    config, scope = settings
    runtime = FakeRuntime()
    manager = Manager(tmp_path / "runtime.sqlite3", lambda: 1000, runtime)
    try:
        item = manager.prepare(config, scope)
        manager.approve(item["plan_hash"], "lab-operator")
        manager.db.execute("""CREATE TRIGGER fail_final BEFORE INSERT ON audit
            WHEN NEW.action='runtime-observing'
            BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END""")
        with pytest.raises(Rejected):
            manager.apply(item["plan"], scope, "lab-operator")
        assert runtime.live == set()
        assert manager.status()[0]["state"] == "quarantined"
        assert manager.db.execute("SELECT consumed FROM approvals").fetchone() == (1,)
        assert manager.expire() == 1
        assert manager.status()[0]["state"] == "destroyed"
    finally:
        manager.close()


def test_runtime_cleanup_failure_retains_recoverable_record(tmp_path, settings):
    config, scope = settings
    runtime = FakeRuntime()
    manager = Manager(tmp_path / "runtime.sqlite3", lambda: 1000, runtime)
    try:
        item = manager.prepare(config, scope)
        manager.approve(item["plan_hash"], "lab-operator")
        manager.apply(item["plan"], scope, "lab-operator")
        runtime.fail_cleanup = True
        with pytest.raises(Rejected):
            manager.stop(item["plan_hash"], "lab-operator")
        assert manager.status()[0]["state"] == "observing"
        runtime.fail_cleanup = False
        manager.stop(item["plan_hash"], "lab-operator")
        assert runtime.live == set()
    finally:
        manager.close()


def test_clock_rollback_after_rejection_does_not_revive_approval(tmp_path, settings):
    config, scope = settings
    now = [1000]
    manager = Manager(tmp_path / "clock.sqlite3", lambda: now[0])
    try:
        item = manager.prepare(config, scope)
        manager.approve(item["plan_hash"], "lab-operator", 10)
        now[0] = 1011
        with pytest.raises(Rejected):
            manager.apply(item["plan"], scope, "lab-operator")
        now[0] = 1005
        with pytest.raises(Rejected):
            manager.apply(item["plan"], scope, "lab-operator")
        manager.stop(item["plan_hash"], "lab-operator")
        assert manager.status()[0]["state"] == "destroyed"
    finally:
        manager.close()


class DockerRunner:
    def __init__(self, config, mutation=None):
        self.config = config
        self.mutation = mutation
        self.value = None
        self.calls = []
        self.logs = ""
        self.after_logs = None

    def __call__(self, argv):
        self.calls.append(argv)
        args = argv[3:]
        if args[0] == "info":
            return json.dumps(
                {
                    "OSType": "linux",
                    "CgroupVersion": "2",
                    "CgroupDriver": "systemd",
                    "SecurityOptions": ["name=seccomp", "name=apparmor"],
                }
            )
        if args[:2] == ["image", "inspect"]:
            return json.dumps(
                [
                    {
                        "Id": self.config.image_digest,
                        "Config": {
                            "Labels": {"org.honeypot-grid.synthetic": "true"},
                            "Volumes": None,
                        },
                    }
                ]
            )
        if args[:2] == ["container", "ls"]:
            return "" if self.value is None else self.value["Name"] + "\n"
        if args[:2] == ["container", "create"]:
            labels = {}
            for i, argument in enumerate(args):
                if argument == "--label":
                    key, value = args[i + 1].split("=", 1)
                    labels[key] = value
            self.value = {
                "Name": args[args.index("--name") + 1],
                "Image": self.config.image_digest,
                "Config": {"Labels": labels, "User": "65532:65532"},
                "State": {"Running": False},
                "Mounts": [],
                "HostConfig": {
                    "NetworkMode": "none",
                    "Privileged": False,
                    "ReadonlyRootfs": True,
                    "Binds": [],
                    "PortBindings": {},
                    "PidMode": "",
                    "IpcMode": "private",
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges"],
                    "PidsLimit": 32,
                    "Memory": self.config.memory_mib * 1024 * 1024,
                    "MemorySwap": self.config.memory_mib * 1024 * 1024,
                    "NanoCpus": self.config.cpu_millicores * 1000000,
                    "RestartPolicy": {"Name": "no"},
                },
            }
            if self.mutation:
                self.value["HostConfig"].update(self.mutation)
            return "synthetic-container-id"
        if args[:2] == ["container", "inspect"]:
            return json.dumps([self.value])
        if args[:2] == ["container", "start"]:
            self.value["State"]["Running"] = True
            return ""
        if args[:2] == ["container", "logs"]:
            if self.after_logs:
                self.after_logs(self.value)
            return self.logs
        if args[:2] == ["container", "exec"]:
            from honeypot_grid.lab_probe import PROBE

            assert args[-1] == PROBE
            assert args[2:4] == ["--user", "65532:65532"]
            return json.dumps(
                {"version": 1, "only_loopback": True, "blocked_attempts": 30, "unprivileged": True}
            )
        if args[:2] == ["container", "rm"]:
            self.value = None
            return ""
        raise AssertionError("unexpected Docker argv")


def attestation():
    return {
        "dedicated_lab_vm": True,
        "no_production_routes": True,
        "no_host_credentials": True,
        "operator": "lab-operator",
        "authorization_ref": "demo-only",
    }


def test_docker_fixed_argv_and_verified_cleanup(settings):
    raw, scope = settings
    config = Config.parse(raw, scope)
    runner = DockerRunner(config)
    runtime = DockerRuntime(attestation(), runner)
    runtime.start("a" * 64, config)
    assert runtime.verify("a" * 64, config) is True
    runtime.start("a" * 64, config)
    assert sum(call[3:5] == ["container", "create"] for call in runner.calls) == 1
    for argv in runner.calls:
        assert argv[:3] == ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
        assert "--publish" not in argv and "--privileged" not in argv
        assert "--volume" not in argv and "--network=host" not in argv
    runtime.stop("a" * 64)
    assert runner.value is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"NetworkMode": "host"},
        {"Privileged": True},
        {"ReadonlyRootfs": False},
        {"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]},
        {"PidsLimit": 0},
        {"CapAdd": ["SYS_ADMIN"]},
        {"SecurityOpt": ["no-new-privileges", "seccomp=unconfined"]},
        {"Memory": 0},
        {"NanoCpus": 0},
        {"PortBindings": {"8080/tcp": []}},
    ],
)
def test_docker_rejects_enforcement_drift_and_cleans(settings, mutation):
    raw, scope = settings
    config = Config.parse(raw, scope)
    runner = DockerRunner(config, mutation)
    runtime = DockerRuntime(attestation(), runner)
    with pytest.raises(Rejected):
        runtime.start("a" * 64, config)
    assert runner.value is None


def test_docker_does_not_remove_foreign_label(settings):
    raw, scope = settings
    config = Config.parse(raw, scope)
    runner = DockerRunner(config)
    runtime = DockerRuntime(attestation(), runner)
    runtime.start("a" * 64, config)
    runner.value = copy.deepcopy(runner.value)
    runner.value["Config"]["Labels"]["org.honeypot-grid.owner"] = "another-owner"
    with pytest.raises(Rejected):
        runtime.stop("a" * 64)
    assert runner.value is not None


def test_docker_delivery_scope_retry_and_security_drift(tmp_path, settings):
    from honeypot_grid.policy import canonical
    from honeypot_grid.telemetry import Telemetry
    from honeypot_grid.transport import envelope

    raw, scope = settings
    config = Config.parse(raw, scope)
    runner = DockerRunner(config)
    runtime = DockerRuntime(attestation(), runner)
    manager = Manager(tmp_path / "manager.sqlite3", lambda: 1000, runtime)
    store = Telemetry(tmp_path / "events.sqlite3", lambda: 1000)
    try:
        plan = manager.prepare(raw, scope)
        manager.approve(plan["plan_hash"], "lab-operator")
        manager.apply(plan["plan"], scope, "lab-operator")
        runner.logs = (
            canonical(
                envelope(
                    {
                        "schema_version": 1,
                        "sensor_id": config.lab_id,
                        "timestamp": 1000,
                        "service": config.service,
                        "category": "connection",
                    }
                )
            )
            + "\n"
        )
        with pytest.raises(Rejected):
            manager.collect(plan["plan_hash"], scope, "wrong-owner", store, b"k" * 32, "epoch-test")
        assert (
            manager.collect(
                plan["plan_hash"], scope, "lab-operator", store, b"k" * 32, "epoch-test"
            )["ingested"]
            == 1
        )
        assert (
            manager.collect(plan["plan_hash"], scope, "lab-operator", store, b"r" * 32, "rotated")[
                "duplicates"
            ]
            == 1
        )
        assert manager.lab_probe(plan["plan_hash"], scope, "lab-operator")["blocked_attempts"] == 30
        runner.after_logs = lambda value: value["HostConfig"].update(NetworkMode="host")
        with pytest.raises(Rejected):
            manager.collect(
                plan["plan_hash"], scope, "lab-operator", store, b"k" * 32, "epoch-test"
            )
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (1,)
    finally:
        manager.close()
        store.close()
