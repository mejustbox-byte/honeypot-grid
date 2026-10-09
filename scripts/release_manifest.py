"""Write an artifact inventory for the first alpha release (not an SBOM)."""

import hashlib
import json
import os
import re
import tomllib
from pathlib import Path


def main():
    version = tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    commit = os.environ["GITHUB_SHA"]
    if version != "0.1.0a1" or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Unexpected release version or commit")
    paths = [
        Path("dist/honeypot_grid-0.1.0a1-py3-none-any.whl"),
        Path("dist/honeypot_grid-0.1.0a1.tar.gz"),
    ]
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    manifest = {
        "tag": "v0.1.0-alpha.1",
        "version": version,
        "commit": commit,
        "runtime_dependencies": [],
        "artifacts_sha256": hashes,
        "checks": ["pytest", "ruff", "documentation links", "CLI smoke", "package build"],
        "unverified": ["real Docker isolation", "real QEMU guest", "external ingress"],
        "inventory_only": "This is not an SBOM or a vulnerability assessment.",
    }
    target = Path("dist/RELEASE-MANIFEST.json")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    hashes[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    Path("dist/SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in hashes.items())
    )


if __name__ == "__main__":
    main()
