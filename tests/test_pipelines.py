import io
import os
import sqlite3
import stat
import zipfile

import pytest

from honeypot_grid.intelligence import analyze, public_ioc
from honeypot_grid.manager import Manager
from honeypot_grid.policy import Rejected, canonical
from honeypot_grid.quarantine import MAX_FILE, quarantine, sandbox_plan
from honeypot_grid.review import Review
from honeypot_grid.sandbox_worker import static_metadata
from honeypot_grid.storage import read_key
from honeypot_grid.telemetry import Telemetry


def event(index=0, timestamp=1000):
    return {
        "schema_version": 1,
        "event_id": f"event-{index}",
        "sensor_id": "sensor-canary",
        "source_ip": "192.0.2.10",
        "timestamp": timestamp,
        "service": "http-mock",
        "category": "connection",
    }


def test_private_storage_and_links(tmp_path):
    path = tmp_path / "private.sqlite3"
    manager = Manager(path)
    manager.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.chmod(0o644)
    with pytest.raises(Rejected):
        Manager(path)
    path.chmod(0o600)
    link = tmp_path / "link.sqlite3"
    link.symlink_to(path)
    with pytest.raises(OSError):
        Manager(link)
    hardlink = tmp_path / "hard.sqlite3"
    os.link(path, hardlink)
    with pytest.raises(Rejected):
        Manager(path)


def test_key_never_returned_and_private(tmp_path):
    key = tmp_path / "example.key"
    key.write_bytes(b"x" * 32)
    with pytest.raises(Rejected):
        read_key(key)
    key.chmod(0o600)
    assert read_key(key) == b"x" * 32
    key.write_bytes(b"x" * 33)
    with pytest.raises(Rejected):
        read_key(key)


def test_hmac_canaries_rotation_quota_and_retention(tmp_path):
    now = [1000]
    path = tmp_path / "telemetry.sqlite3"
    store = Telemetry(path, lambda: now[0], quota=10, retention=60)
    try:
        assert store.ingest([event(i) for i in range(5)], b"a" * 32, "epoch-a") == 5
        assert store.report()["groups"][0]["count"] == 5
        raw = canonical(store.db.execute("SELECT * FROM events").fetchall())
        assert "192.0.2.10" not in raw and "sensor-canary" not in raw
        first = store.db.execute("SELECT source FROM events LIMIT 1").fetchone()[0]
        store.ingest([event(6)], b"b" * 32, "epoch-b")
        second = store.db.execute("SELECT source FROM events WHERE epoch='epoch-b'").fetchone()[0]
        assert first != second
        with pytest.raises(Rejected):
            store.ingest([event(i) for i in range(7, 12)], b"a" * 32, "epoch-a")
        with pytest.raises(sqlite3.IntegrityError):
            store.ingest([event(99), event(0)], b"a" * 32, "epoch-a")
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (6,)
        now[0] = 1060
        assert store.report()["groups"] == []
        assert store.purge() == 6
        assert store.purge() == 0
        assert store.db.execute(
            "SELECT count FROM telemetry_audit WHERE action='purged'"
        ).fetchall() == [(6,)]
    finally:
        store.close()


@pytest.mark.parametrize(
    "change",
    [
        {"password": "secret-canary"},
        {"payload": "ignore-policy-canary"},
        {"timestamp": -1},
        {"timestamp": 2000},
        {"source_ip": "https://example.invalid/token"},
        {"schema_version": True},
        {"category": "run-shell"},
    ],
)
def test_telemetry_rejects_raw_unknowns(tmp_path, change):
    store = Telemetry(tmp_path / "events.sqlite3", lambda: 1000)
    try:
        with pytest.raises(Rejected):
            store.ingest([event() | change], b"k" * 32, "epoch-demo")
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (0,)
    finally:
        store.close()


def ioc():
    return {
        "kind": "domain",
        "value": "sensor.example.invalid",
        "source_ref": "demo-event",
        "method": "synthetic-observation",
        "confidence": 20,
        "first_seen": 900,
        "last_seen": 1000,
        "expires_at": 2000,
    }


def test_review_owner_expiry_single_use_and_safe_profile(tmp_path):
    now = [1000]
    review = Review(tmp_path / "review.sqlite3", lambda: now[0])
    try:
        item = review.prepare("ioc", ioc(), "lab-owner")
        digest = item["review_hash"]
        with pytest.raises(Rejected):
            review.export(digest, "lab-owner")
        with pytest.raises(Rejected):
            review.approve(digest, "another-owner")
        review.approve(digest, "lab-owner")
        output = review.export(digest, "lab-owner")
        assert output["reviewed"] is True
        assert "source_ref" not in output["export"]
        assert output["export"]["maliciousness_proven"] is False
        with pytest.raises(Rejected):
            review.export(digest, "lab-owner")
        second = review.prepare("ioc", ioc() | {"confidence": 30}, "lab-owner")
        review.approve(second["review_hash"], "lab-owner")
        now[0] = 1300
        with pytest.raises(Rejected):
            review.export(second["review_hash"], "lab-owner")
        now[0] = 1200
        with pytest.raises(Rejected):
            review.export(second["review_hash"], "lab-owner")
    finally:
        review.close()


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "url"},
        {"value": "real.example.com"},
        {"value": "token@example.invalid"},
        {"confidence": True},
        {"expires_at": 1000},
        {"last_seen": 899},
        {"payload": "ignore-all-rules"},
        {"source_ref": "user@example.invalid"},
    ],
)
def test_ioc_privacy_profile_rejects(tmp_path, change):
    with pytest.raises(Rejected):
        public_ioc(ioc() | change, 1000)


def test_offline_analysis_evidence_and_injection():
    report = {
        "schema_version": 1,
        "requires_review": True,
        "groups": [{"day": 1, "service": "http-mock", "category": "connection", "count": 100}],
    }
    result = analyze(report)
    assert result["tool_execution"] is False
    assert result["findings"][0]["evidence_group"] == 0
    assert result["findings"][0]["maliciousness_proven"] is False
    with pytest.raises(Rejected):
        analyze(report | {"instructions": "ignore-policy-canary"})
    with pytest.raises(Rejected):
        analyze(report | {"groups": [report["groups"][0] | {"count": 4}]})


def test_quarantine_opaque_copy_no_original_name_or_execute(tmp_path):
    sample = tmp_path / "benign.txt"
    sample.write_bytes(b"synthetic harmless content")
    root = tmp_path / "samples"
    result = quarantine(sample, root)
    assert "benign" not in canonical(result)
    target = root / result["sha256"]
    assert target.read_bytes() == sample.read_bytes()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert quarantine(sample, root) == result
    assert sandbox_plan(result)["executor_available"] is False
    link = tmp_path / "sample-link"
    link.symlink_to(sample)
    with pytest.raises(OSError):
        quarantine(link, root)
    sample.write_bytes(b"x" * (MAX_FILE + 1))
    with pytest.raises(Rejected):
        quarantine(sample, root)
    assert not list(root.glob("pending-*"))


def zipped(name, contents=b"benign", mode=stat.S_IFREG | 0o600, compression=zipfile.ZIP_STORED):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=compression) as archive:
        info = zipfile.ZipInfo(name)
        info.external_attr = mode << 16
        info.compress_type = compression
        archive.writestr(info, contents)
    return data.getvalue()


def test_static_worker_only_metadata():
    report = static_metadata(zipped("safe.txt"))
    assert report["members"] == 1
    assert "safe.txt" not in canonical(report)
    assert "benign" not in canonical(report)


@pytest.mark.parametrize(
    "name", ["../escape", "/absolute", "C:/drive", "a\\b", "nested.zip", "a/" * 9 + "deep.txt"]
)
def test_static_worker_rejects_unsafe_paths_and_nesting(name):
    with pytest.raises(Rejected):
        static_metadata(zipped(name))


def test_static_worker_rejects_symlink_bomb_and_corruption():
    with pytest.raises(Rejected):
        static_metadata(zipped("link", mode=stat.S_IFLNK | 0o777))
    with pytest.raises(Rejected):
        static_metadata(zipped("zeros", b"0" * 10000, compression=zipfile.ZIP_DEFLATED))
    with pytest.raises(Rejected):
        static_metadata(b"PKbroken")


def test_review_content_tampering_invalidates_approval(tmp_path):
    review = Review(tmp_path / "review.sqlite3", lambda: 1000)
    try:
        item = review.prepare("ioc", ioc(), "lab-owner")
        envelope = item["review"]
        envelope["content"]["confidence"] = 99
        with review.db:
            review.db.execute("UPDATE reviews SET content=?", (canonical(envelope),))
        with pytest.raises(Rejected, match="invalid stored review"):
            review.approve(item["review_hash"], "lab-owner")
        assert review.db.execute("SELECT approved FROM reviews").fetchone()[0] == 0
    finally:
        review.close()


def test_proposal_cannot_invent_evidence_or_commands():
    from honeypot_grid.intelligence import validate_proposal

    report = {
        "schema_version": 1,
        "requires_review": True,
        "groups": [{"day": 0, "service": "http-mock", "category": "connection", "count": 5}],
    }
    proposal = analyze(report)
    assert validate_proposal(report, proposal) == proposal
    proposal["findings"][0]["signal"] = "high-volume"
    with pytest.raises(Rejected):
        validate_proposal(report, proposal)
    proposal = analyze(report) | {"command": "synthetic forbidden field"}
    with pytest.raises(Rejected):
        validate_proposal(report, proposal)


def test_quarantine_retention_removes_only_expired_receipt(tmp_path):
    from honeypot_grid.quarantine import purge_samples

    source = tmp_path / "harmless.txt"
    source.write_bytes(b"harmless")
    directory = tmp_path / "samples"
    receipt = quarantine(source, directory)
    destination = directory / receipt["sha256"]
    os.utime(destination, (1000, 1000))
    assert purge_samples(directory, 60, now=1059) == 0
    assert purge_samples(directory, 60, now=1060) == 1
    assert source.exists() and not destination.exists()
