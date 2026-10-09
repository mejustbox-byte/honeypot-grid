#!/usr/bin/env bash
# Development verification only. No Docker services or untrusted samples.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export UV_CACHE_DIR="$PWD/.cloud-env/cache"
export UV_PYTHON_INSTALL_DIR="$PWD/.cloud-env/python"
export UV_PYTHON_BIN_DIR="$PWD/.cloud-env/bin"
if [ -d .cloud-env/wheels ]; then
  export UV_FIND_LINKS="$PWD/.cloud-env/wheels"
fi
export UV_OFFLINE=1
export PATH="$PWD/.venv/bin:/usr/bin:/bin"
read -r tool_name tool_version _ <<< "$(uv --version)"
test "$tool_name $tool_version" = 'uv 0.12.19'
python -c 'import sys; assert sys.version_info[:3] == (3, 14, 7)'
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -q
uv run --locked python scripts/smoke.py
uv run --locked python scripts/cli_smoke.py
uv build --offline
uv run --locked python scripts/cloud_capabilities.py
printf '%s\n' 'PASS: offline development checks; lab containment acceptance is separate'
