"""Strict bounded input and immutable policy plans; never runtime enforcement."""

import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

MAX_INPUT = 16_384
ID = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
ISOLATION = {
    "dedicated_vm": True,
    "egress_ipv4": "deny",
    "egress_ipv6": "deny",
    "dns": False,
    "metadata": False,
    "privileged": False,
    "host_namespaces": False,
    "host_mounts": False,
    "runtime_socket": False,
}


class Rejected(ValueError):
    """A safe, payload-free rejection reason."""


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fields(value: object, expected: set[str]) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise Rejected("invalid schema fields")
    return value


def identifier(value: object) -> str:
    if type(value) is not str or not ID.fullmatch(value):
        raise Rejected("invalid identifier")
    return value


def integer(value: object, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise Rejected("integer outside policy bounds")
    return value


def load_json(path: Path) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Rejected("duplicate JSON field")
            result[key] = value
        return result

    def invalid_constant(_):
        raise Rejected("non-finite JSON constant")

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT:
        os.close(fd)
        raise Rejected("bounded regular JSON file required")
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise Rejected("input size limit exceeded")
    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Rejected("invalid JSON") from exc
    if type(value) is not dict:
        raise Rejected("JSON object required")
    return value


def digest_identifier(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Rejected("invalid object hash")
    return value


@dataclass(frozen=True)
class Config:
    lab_id: str
    owner: str
    authorization_ref: str
    service: str
    image_digest: str
    ttl_seconds: int
    memory_mib: int
    cpu_millicores: int

    @classmethod
    def parse(cls, raw: dict, scope: dict) -> Config:
        fields(scope, {"lab_id", "owner", "authorization_ref", "services", "image_digests"})
        for name in ("lab_id", "owner", "authorization_ref"):
            identifier(scope[name])
        if type(scope["services"]) is not list or not scope["services"]:
            raise Rejected("invalid service allowlist")
        if any(s not in ("http-mock", "ssh-mock") for s in scope["services"]):
            raise Rejected("unsupported service allowlist")
        digests = scope["image_digests"]
        if type(digests) is not list or not digests:
            raise Rejected("invalid image allowlist")
        if any(type(d) is not str or not DIGEST.fullmatch(d) for d in digests):
            raise Rejected("invalid digest allowlist")
        fields(raw, set(cls.__dataclass_fields__) | {"isolation"})
        for name in ("lab_id", "owner", "authorization_ref"):
            identifier(raw[name])
            if raw[name] != scope[name]:
                raise Rejected("configuration outside authorized scope")
        if type(raw["service"]) is not str or raw["service"] not in scope["services"]:
            raise Rejected("service outside allowlist")
        if type(raw["image_digest"]) is not str or raw["image_digest"] not in digests:
            raise Rejected("image outside allowlist")
        isolation = fields(
            raw["isolation"],
            {
                "dedicated_vm",
                "egress_ipv4",
                "egress_ipv6",
                "dns",
                "metadata",
                "privileged",
                "host_namespaces",
                "host_mounts",
                "runtime_socket",
            },
        )
        required = ISOLATION
        if any(type(isolation[k]) is not type(v) or isolation[k] != v for k, v in required.items()):
            raise Rejected("unsafe isolation declaration")
        integer(raw["ttl_seconds"], 1, 3600)
        integer(raw["memory_mib"], 64, 1024)
        integer(raw["cpu_millicores"], 100, 2000)
        return cls(**{k: raw[k] for k in cls.__dataclass_fields__})


def plan(config: Config, now: int, adapter="mock") -> dict:
    return {
        "version": 1,
        "adapter": adapter,
        "config": asdict(config),
        "isolation": dict(ISOLATION),
        "created_at": now,
        "expires_at": now + config.ttl_seconds,
    }


def plan_hash(value: dict) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()
