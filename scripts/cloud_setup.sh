#!/usr/bin/env bash
# Run only during approved dependency installation; no infrastructure is provisioned.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "$(git remote get-url origin)" in
  https://github.com/mejustbox-byte/honeypot-grid.git|git@github.com:mejustbox-byte/honeypot-grid.git) ;;
  *) printf '%s\n' 'REJECTED: unexpected repository' >&2; exit 2 ;;
esac
read -r tool_name tool_version _ <<< "$(uv --version)"
test "$tool_name $tool_version" = 'uv 0.12.19'
export UV_CACHE_DIR="$PWD/.cloud-env/cache"
export UV_PYTHON_INSTALL_DIR="$PWD/.cloud-env/python"
export UV_PYTHON_BIN_DIR="$PWD/.cloud-env/bin"
if [ -d .cloud-env/wheels ]; then
  export UV_FIND_LINKS="$PWD/.cloud-env/wheels"
fi
uv sync --locked --python 3.14.7
# Populate the build cache before offline verification.
uv build
bash scripts/cloud_check.sh
