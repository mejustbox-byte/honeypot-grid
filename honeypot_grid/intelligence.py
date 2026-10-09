"""Structured synthetic IoCs and evidence-bound offline analysis, no tools or network."""

import re

from .policy import Rejected, fields, identifier, integer, plan_hash

HASH = re.compile(r"[0-9a-f]{64}\Z")
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+invalid\Z")


def validate_ioc(value: dict, now: int) -> dict:
    fields(
        value,
        {
            "kind",
            "value",
            "source_ref",
            "method",
            "confidence",
            "first_seen",
            "last_seen",
            "expires_at",
        },
    )
    if type(value["kind"]) is not str or value["kind"] not in ("sha256", "domain"):
        raise Rejected("unsupported IoC kind")
    pattern = HASH if value["kind"] == "sha256" else DOMAIN
    if (
        type(value["value"]) is not str
        or len(value["value"]) > 253
        or not pattern.fullmatch(value["value"])
    ):
        raise Rejected("unsafe synthetic IoC value")
    identifier(value["source_ref"])
    if value["method"] not in ("static-metadata", "synthetic-observation"):
        raise Rejected("unsupported IoC method")
    integer(value["confidence"], 0, 100)
    first = integer(value["first_seen"], 0, now)
    last = integer(value["last_seen"], first, now)
    integer(value["expires_at"], max(now + 1, last), now + 604800)
    return dict(value)


def public_ioc(value: dict, now: int) -> dict:
    value = validate_ioc(value, now)
    return {
        "profile": "synthetic-ioc-v1",
        "kind": value["kind"],
        "value": value["value"],
        "confidence": value["confidence"],
        "last_seen_day": value["last_seen"] // 86400,
        "expires_at": value["expires_at"],
        "maliciousness_proven": False,
    }


def analyze(report: dict) -> dict:
    fields(report, {"schema_version", "requires_review", "groups"})
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["requires_review"] is not True
        or type(report["groups"]) is not list
        or len(report["groups"]) > 1000
    ):
        raise Rejected("invalid privacy report")
    findings = []
    for index, group in enumerate(report["groups"]):
        fields(group, {"day", "service", "category", "count"})
        integer(group["day"], 0, 2**53 // 86400)
        count = integer(group["count"], 5, 10000)
        if group["service"] not in ("http-mock", "ssh-mock") or group["category"] not in (
            "connection",
            "probe",
        ):
            raise Rejected("invalid report enums")
        findings.append(
            {
                "evidence_group": index,
                "signal": "high-volume" if count >= 100 else "observed-activity",
                "confidence": "low",
                "maliciousness_proven": False,
            }
        )
    return {
        "provider": "offline-rules-v1",
        "report_hash": plan_hash(report),
        "findings": findings,
        "requires_review": True,
        "tool_execution": False,
    }


def validate_proposal(report: dict, proposal: dict) -> dict:
    baseline = analyze(report)
    fields(proposal, {"provider", "report_hash", "findings", "requires_review", "tool_execution"})
    identifier(proposal["provider"])
    if (
        proposal["report_hash"] != baseline["report_hash"]
        or proposal["requires_review"] is not True
        or proposal["tool_execution"] is not False
        or type(proposal["findings"]) is not list
        or len(proposal["findings"]) > len(report["groups"])
    ):
        raise Rejected("invalid analysis proposal")
    seen = set()
    for finding in proposal["findings"]:
        fields(finding, {"evidence_group", "signal", "confidence", "maliciousness_proven"})
        index = integer(finding["evidence_group"], 0, len(report["groups"]) - 1)
        if index in seen:
            raise Rejected("duplicate analysis evidence")
        seen.add(index)
        if (
            finding["signal"] not in ("high-volume", "observed-activity")
            or finding["confidence"] != "low"
            or finding["maliciousness_proven"] is not False
            or (finding["signal"] == "high-volume" and report["groups"][index]["count"] < 100)
        ):
            raise Rejected("unsupported analysis assertion")
    return proposal
