"""Bounded local NDJSON transport. No sockets, raw addresses or remote auth."""

import json
import secrets

from .policy import Rejected, canonical
from .privacy import aggregate

MAX_LINE = 1024
MAX_DELIVERIES = 1000


def envelope(event):
    aggregate([event])
    return {"transport_version": 1, "delivery_id": secrets.token_hex(32), "event": event}


def emit(event):
    print(canonical(envelope(event)), flush=True)


def parse_line(data):
    if type(data) is not bytes or not data.endswith(b"\n") or len(data) > MAX_LINE:
        raise Rejected("invalid delivery framing")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Rejected("duplicate transport field")
            result[key] = value
        return result

    def invalid(_):
        raise Rejected("invalid transport number")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Rejected("invalid delivery JSON") from exc


def collect(stream, store, key, epoch, sensor_id, service):
    """Commit bounded batches; failed replay can retry already committed prefixes.

    A finite file or completed Docker log snapshot is required. An arbitrary
    blocking stream is deliberately not exposed by the CLI.
    """
    counts = {"ingested": 0, "duplicates": 0}
    batch = []
    lines = 0
    while data := stream.readline(MAX_LINE + 1):
        lines += 1
        if lines > MAX_DELIVERIES:
            raise Rejected("delivery snapshot limit exceeded")
        batch.append(parse_line(data))
        if len(batch) == 100:
            result = store.ingest_deliveries(batch, key, epoch, sensor_id, service)
            for name in counts:
                counts[name] += result[name]
            batch = []
    if batch:
        result = store.ingest_deliveries(batch, key, epoch, sensor_id, service)
        for name in counts:
            counts[name] += result[name]
    return counts
