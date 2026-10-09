"""Bounded synthetic event aggregation; no raw values in public output."""

from collections import Counter

from .policy import Rejected, fields, identifier, integer


def aggregate(events: object, minimum_group: int = 5) -> dict:
    integer(minimum_group, 5, 1000)
    if type(events) is not list or len(events) > 1000:
        raise Rejected("invalid event batch")
    counts = Counter()
    for event in events:
        fields(event, {"schema_version", "sensor_id", "timestamp", "service", "category"})
        if type(event["schema_version"]) is not int or event["schema_version"] != 1:
            raise Rejected("unsupported event schema")
        identifier(event["sensor_id"])
        integer(event["timestamp"], 0, 2**53)
        if type(event["service"]) is not str or event["service"] not in ("http-mock", "ssh-mock"):
            raise Rejected("unsupported event service")
        if type(event["category"]) is not str or event["category"] not in ("connection", "probe"):
            raise Rejected("unsupported event category")
        counts[(event["timestamp"] // 86400, event["service"], event["category"])] += 1
    return {
        "schema_version": 1,
        "groups": [
            {"day": day, "service": service, "category": category, "count": count}
            for (day, service, category), count in sorted(counts.items())
            if count >= minimum_group
        ],
    }
