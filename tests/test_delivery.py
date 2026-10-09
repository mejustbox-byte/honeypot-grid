import asyncio
import copy
import io
import time

import pytest

from honeypot_grid.policy import Rejected, canonical
from honeypot_grid.sensor import Sensor
from honeypot_grid.telemetry import Telemetry
from honeypot_grid.transport import MAX_LINE, collect, envelope, parse_line


def delivery(index=0):
    item = envelope(
        {
            "schema_version": 1,
            "sensor_id": "sensor-test",
            "timestamp": 1000,
            "service": "http-mock",
            "category": "connection",
        }
    )
    item["delivery_id"] = f"{index:064x}"
    return item


def ingest(store, values, key=b"k" * 32, epoch="epoch-test"):
    return store.ingest_deliveries(values, key, epoch, "sensor-test", "http-mock")


def test_delivery_retry_after_restart_rotation_and_minimization(tmp_path):
    path = tmp_path / "events.sqlite3"
    store = Telemetry(path, lambda: 1000)
    items = [delivery(i) for i in range(5)]
    assert ingest(store, items) == {"ingested": 5, "duplicates": 0}
    store.close()
    store = Telemetry(path, lambda: 1000)
    try:
        assert ingest(store, items, b"r" * 32, "rotated") == {"ingested": 0, "duplicates": 5}
        assert store.report()["groups"][0]["count"] == 5
        raw = canonical(store.db.execute("SELECT * FROM events").fetchall())
        assert "sensor-test" not in raw and "127.0.0.1" not in raw
        assert store.db.execute("SELECT count(*) FROM deliveries").fetchone() == (5,)
    finally:
        store.close()


def test_delivery_conflicting_replay_and_audit_failure_are_atomic(tmp_path):
    store = Telemetry(tmp_path / "events.sqlite3", lambda: 1000)
    try:
        ingest(store, [delivery(1)])
        changed = copy.deepcopy(delivery(1))
        changed["event"]["category"] = "probe"
        with pytest.raises(Rejected):
            ingest(store, [delivery(2), changed])
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (1,)
        store.db.execute("""CREATE TRIGGER fail_delivery BEFORE INSERT ON telemetry_audit
           WHEN NEW.action='delivered' BEGIN SELECT RAISE(ABORT, 'synthetic'); END""")
        import sqlite3

        with pytest.raises(sqlite3.IntegrityError):
            ingest(store, [delivery(3)])
        assert store.db.execute("SELECT count(*) FROM deliveries").fetchone() == (1,)
        store.db.execute("DROP TRIGGER fail_delivery")
        assert ingest(store, [delivery(3)])["ingested"] == 1
    finally:
        store.close()


@pytest.mark.parametrize(
    "mutation",
    [
        {"transport_version": True},
        {"transport_version": 2},
        {"delivery_id": "bad"},
        {"payload": "canary-secret"},
        {"event": {"instructions": "ignore-policy"}},
    ],
)
def test_delivery_rejects_invalid_envelope(tmp_path, mutation):
    store = Telemetry(tmp_path / "events.sqlite3", lambda: 1000)
    try:
        with pytest.raises(Rejected):
            ingest(store, [delivery() | mutation])
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (0,)
    finally:
        store.close()


@pytest.mark.parametrize(
    "change",
    [
        {"sensor_id": "other"},
        {"service": "ssh-mock"},
        {"source_ip": "192.0.2.1"},
        {"timestamp": 1006},
    ],
)
def test_delivery_scope_and_privacy(tmp_path, change):
    item = delivery()
    item["event"].update(change)
    store = Telemetry(tmp_path / "events.sqlite3", lambda: 1000)
    try:
        with pytest.raises(Rejected):
            ingest(store, [item])
    finally:
        store.close()


@pytest.mark.parametrize(
    "line", [b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":1}', b"x" * (MAX_LINE + 1), b"\xff\n"]
)
def test_transport_framing(line):
    with pytest.raises(Rejected):
        parse_line(line)


def test_delivery_quota_duplicates_and_retention(tmp_path):
    now = [1000]
    store = Telemetry(tmp_path / "events.sqlite3", lambda: now[0], quota=1, retention=60)
    try:
        assert ingest(store, [delivery(), delivery()]) == {"ingested": 1, "duplicates": 1}
        assert ingest(store, [delivery()])["duplicates"] == 1
        with pytest.raises(Rejected):
            ingest(store, [delivery(1)])
        now[0] = 1060
        assert store.purge() == 1
        assert store.db.execute("SELECT count(*) FROM deliveries").fetchone() == (0,)
        with pytest.raises(Rejected):
            ingest(store, [delivery()])  # An expired receipt cannot revive an old event.
    finally:
        store.close()


def test_committed_prefix_can_recover_from_truncated_snapshot(tmp_path):
    items = [delivery(i) for i in range(101)]
    lines = b"".join((canonical(item) + "\n").encode() for item in items)
    store = Telemetry(tmp_path / "events.sqlite3", lambda: 1000)
    try:
        with pytest.raises(Rejected):
            collect(
                io.BytesIO(lines[:-1]), store, b"k" * 32, "epoch-test", "sensor-test", "http-mock"
            )
        assert store.db.execute("SELECT count(*) FROM events").fetchone() == (100,)
        assert collect(
            io.BytesIO(lines), store, b"k" * 32, "epoch-test", "sensor-test", "http-mock"
        ) == {"ingested": 1, "duplicates": 100}
    finally:
        store.close()


def test_real_localhost_sensor_to_report_pipeline(tmp_path):
    store = Telemetry(tmp_path / "events.sqlite3")
    items = []

    async def exercise():
        sensor = Sensor("http-mock", "sensor-test", lambda event: items.append(envelope(event)))
        server = await asyncio.start_server(sensor.handle, "127.0.0.1", 0)
        try:
            for _ in range(5):
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", server.sockets[0].getsockname()[1]
                )
                writer.write(
                    b"GET /canary-secret HTTP/1.1\r\nAuthorization: canary-password\r\n\r\n"
                )
                await writer.drain()
                assert b"canary" not in await reader.read(1024)
                writer.close()
                await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    try:
        asyncio.run(exercise())
        assert int(time.time()) - items[0]["event"]["timestamp"] < 5
        data = ("\n".join(canonical(item) for item in items) + "\n").encode()
        assert b"canary" not in data
        assert (
            collect(io.BytesIO(data), store, b"k" * 32, "epoch-test", "sensor-test", "http-mock")[
                "ingested"
            ]
            == 5
        )
        assert store.report()["groups"][0]["count"] == 5
    finally:
        store.close()
