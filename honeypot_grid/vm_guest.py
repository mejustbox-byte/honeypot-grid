"""Guest-only worker entrypoint. Never invoke with untrusted input on the host."""

import hashlib
import os
from pathlib import Path

from .policy import Rejected, canonical
from .quarantine import MAX_FILE
from .sandbox_worker import limits, static_metadata
from .vm import INPUT_HEADER, MAGIC


def read_frame(stream):
    header = stream.read(INPUT_HEADER.size)
    if len(header) != INPUT_HEADER.size:
        raise Rejected("invalid VM input frame")
    magic, size, digest, nonce = INPUT_HEADER.unpack(header)
    if magic != MAGIC or size > MAX_FILE:
        raise Rejected("invalid VM input frame")
    data = stream.read(size)
    if len(data) != size or hashlib.sha256(data).digest() != digest:
        raise Rejected("invalid VM input integrity")
    return data, nonce.hex()


def main():
    # A reviewed initramfs must mount sysfs and expose virtio /dev/vda first.
    if os.getpid() == 1 or not Path("/sys/class/net/lo").exists():
        return 2
    nonce = None
    try:
        if set(os.listdir("/sys/class/net")) != {"lo"}:
            raise Rejected("unexpected guest NIC")
        limits()
        with open("/dev/vda", "rb", buffering=0) as stream:
            data, nonce = read_frame(stream)
        result = {
            "version": 1,
            "nonce": nonce,
            "status": "ok",
            "metadata": static_metadata(data),
            "network_devices": 0,
        }
    except Rejected, OSError:
        if nonce is None:
            return 2
        result = {
            "version": 1,
            "nonce": nonce,
            "status": "rejected",
            "metadata": None,
            "network_devices": 0,
        }
    print("HPG/1 " + canonical(result), flush=True)
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
