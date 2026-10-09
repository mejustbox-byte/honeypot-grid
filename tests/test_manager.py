import copy
import sqlite3

import pytest

from honeypot_grid.__main__ import main
from honeypot_grid.manager import Manager
from honeypot_grid.policy import ISOLATION, Config, Rejected, canonical, load_json
from honeypot_grid.privacy import aggregate


@pytest.fixture
def scope():
    return {
        "lab_id": "lab-demo",
        "owner": "lab-operator",
        "authorization_ref": "demo-only",
        "services": ["http-mock"],
        "image_digests": ["sha256:" + "0" * 64],
    }


@pytest.fixture
def config(scope):
    return {k: scope[k] for k in ("lab_id", "owner", "authorization_ref")} | {
        "service": "http-mock",
        "image_digest": scope["image_digests"][0],
        "ttl_seconds": 600,
        "memory_mib": 128,
        "cpu_millicores": 250,
        "isolation": dict(ISOLATION),
    }


@pytest.fixture
def managed(tmp_path):
    now = [1000]
    manager = Manager(tmp_path / "state.sqlite3", lambda: now[0])
    yield manager, now
    manager.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("lab_id", "another-lab"),
        ("owner", "another-owner"),
        ("authorization_ref", "another-permit"),
        ("image_digest", "sha256:" + "1" * 64),
        ("service", "shell"),
        ("ttl_seconds", True),
        ("ttl_seconds", 3601),
        ("memory_mib", 0),
        ("cpu_millicores", "250"),
        ("unknown", "secret-canary"),
    ],
)
def test_policy_rejects_unapproved_values(config, scope, field, value):
    config[field] = value
    with pytest.raises(Rejected):
        Config.parse(config, scope)


@pytest.mark.parametrize("field", list(ISOLATION))
def test_isolation_fail_closed(config, scope, field):
    config["isolation"][field] = "allow" if field.startswith("egress") else not ISOLATION[field]
    with pytest.raises(Rejected):
        Config.parse(config, scope)


def test_approval_and_restart_idempotency(managed, config, scope, tmp_path):
    manager, _ = managed
    result = manager.prepare(config, scope)
    assert result["dry_run"] is True
    value, digest = result["plan"], result["plan_hash"]
    with pytest.raises(Rejected):
        manager.apply(value, scope, "lab-operator")
    manager.approve(digest, "lab-operator")
    assert manager.apply(value, scope, "lab-operator")["changed"] is True
    restarted = Manager(tmp_path / "state.sqlite3", manager.clock)
    try:
        assert restarted.apply(value, scope, "lab-operator")["changed"] is False
        assert restarted.db.execute("SELECT consumed FROM approvals").fetchone() == (1,)
        assert restarted.db.execute(
            "SELECT count(*) FROM audit WHERE action='mock-provisioned'"
        ).fetchone() == (1,)
    finally:
        restarted.close()


def test_owner_expiry_and_no_renewal(managed, config, scope):
    manager, now = managed
    result = manager.prepare(config, scope)
    with pytest.raises(Rejected):
        manager.approve(result["plan_hash"], "another-owner")
    manager.approve(result["plan_hash"], "lab-operator", 10)
    now[0] += 10
    with pytest.raises(Rejected):
        manager.apply(result["plan"], scope, "lab-operator")
    with pytest.raises(Rejected):
        manager.approve(result["plan_hash"], "lab-operator")


def test_mutation_and_scope_change(managed, config, scope):
    manager, _ = managed
    result = manager.prepare(config, scope)
    manager.approve(result["plan_hash"], "lab-operator")
    mutated = copy.deepcopy(result["plan"])
    mutated["config"]["memory_mib"] = 256
    with pytest.raises(Rejected):
        manager.apply(mutated, scope, "lab-operator")
    scope["image_digests"] = ["sha256:" + "1" * 64]
    with pytest.raises(Rejected):
        manager.apply(result["plan"], scope, "lab-operator")
    assert manager.status()[0]["state"] == "awaiting-approval"


def test_ttl_and_stop_are_terminal(managed, config, scope):
    manager, now = managed
    result = manager.prepare(config, scope)
    manager.approve(result["plan_hash"], "lab-operator")
    manager.apply(result["plan"], scope, "lab-operator")
    now[0] += 600
    assert manager.expire() == 1
    assert manager.expire() == 0
    manager.stop(result["plan_hash"], "lab-operator")
    with pytest.raises(Rejected):
        manager.apply(result["plan"], scope, "lab-operator")
    assert manager.status()[0]["state"] == "destroyed"


def test_stop_blocks_unexpired_plan(managed, config, scope):
    manager, _ = managed
    result = manager.prepare(config, scope)
    manager.approve(result["plan_hash"], "lab-operator")
    manager.stop(result["plan_hash"], "lab-operator")
    with pytest.raises(Rejected):
        manager.apply(result["plan"], scope, "lab-operator")


def test_audit_failure_rolls_back_effect_and_approval(managed, config, scope):
    manager, _ = managed
    result = manager.prepare(config, scope)
    manager.approve(result["plan_hash"], "lab-operator")
    manager.db.execute("""CREATE TRIGGER audit_failure BEFORE INSERT ON audit
        BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END""")
    with pytest.raises(sqlite3.Error):
        manager.apply(result["plan"], scope, "lab-operator")
    assert manager.status()[0]["state"] == "awaiting-approval"
    assert manager.db.execute("SELECT consumed FROM approvals").fetchone() == (0,)


@pytest.mark.parametrize(
    "text", ['{"a":1,"a":2}', '{"a":NaN}', "[]", "{" * 2000, '{"a":"' + "x" * 16384 + '"}']
)
def test_bounded_json(tmp_path, text):
    path = tmp_path / "input.json"
    path.write_text(text)
    with pytest.raises(Rejected):
        load_json(path)


def test_privacy_no_raw_fields_or_rare_groups():
    event = {
        "schema_version": 1,
        "sensor_id": "synthetic-canary",
        "timestamp": 1000,
        "service": "http-mock",
        "category": "connection",
    }
    assert aggregate([event] * 4)["groups"] == []
    result = aggregate([event] * 5)
    assert "synthetic-canary" not in canonical(result)
    assert result["groups"][0] == {
        "day": 0,
        "service": "http-mock",
        "category": "connection",
        "count": 5,
    }
    for field in ("password", "source_ip", "payload", "headers", "url"):
        with pytest.raises(Rejected):
            aggregate([event | {field: "synthetic-secret-canary"}] * 5)


def test_cli_workflow(tmp_path, config, scope, capsys):
    args = ["--database", str(tmp_path / "cli.sqlite3")]
    config_path, scope_path, plan_path = (tmp_path / p for p in ("config", "scope", "plan"))
    config_path.write_text(canonical(config))
    scope_path.write_text(canonical(scope))
    assert main(args + ["plan", "--config", str(config_path), "--scope", str(scope_path)]) == 0
    output = capsys.readouterr().out
    plan_path.write_text(output)
    result = load_json(plan_path)
    apply = args + [
        "apply",
        "--plan",
        str(plan_path),
        "--scope",
        str(scope_path),
        "--operator",
        "lab-operator",
    ]
    assert main(apply) == 2
    assert (
        main(args + ["approve", "--plan-hash", result["plan_hash"], "--operator", "lab-operator"])
        == 0
    )
    assert main(apply) == 0
