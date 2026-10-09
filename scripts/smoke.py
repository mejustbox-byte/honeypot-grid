"""Offline bootstrap: validates documentation; does not deploy or access the network."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "README.md", "ROADMAP.md", "INSTALL.md", "CHANGELOG.md", "LICENSE",
    "SECURITY.md", "ARCHITECTURE.md", "THREAT-MODEL.md",
    "CONTRIBUTING.md", "TECH-STACK.md",
)


def main():
    checked_links = 0
    for name in REQUIRED:
        path = ROOT / name
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            raise ValueError(f"Missing or empty required document: {name}")
    for name in REQUIRED:
        if not name.endswith(".md"):
            continue
        content = (ROOT / name).read_text(encoding="utf-8")
        if content.count("```") % 2:
            raise ValueError(f"Unbalanced code fences: {name}")
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
            if target.startswith(("https://", "http://", "#")):
                continue
            local = (ROOT / target.split("#", 1)[0]).resolve()
            if not local.is_relative_to(ROOT) or not local.is_file():
                raise ValueError(f"Invalid local link in {name}")
            checked_links += 1
    print(f"PASS: {len(REQUIRED)} documents, {checked_links} local links; offline smoke.")
    print(f"Runtime: Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    if sys.version_info[:2] != (3, 14):
        print("NOTE: target Cloud runtime 3.14 has not been verified by this run.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
