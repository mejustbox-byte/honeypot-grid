#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_SHA:?}" "${GH_REPO:?}" "${GH_TOKEN:?}"
[[ "$GH_REPO" == mejustbox-byte/honeypot-grid ]]
[[ "$GITHUB_SHA" =~ ^[0-9a-f]{40}$ ]]
tag=v0.1.0-alpha.2
# Publish only the commit checked by this workflow.
release_commit="$GITHUB_SHA"
# A rerun may finish a draft, but never moves a tag or overwrites an asset.
if gh api "repos/$GH_REPO/git/ref/tags/$tag" > tag-ref.json 2> tag-error.txt; then
  existing=$(python -c 'import json; print(json.load(open("tag-ref.json"))["object"]["sha"])')
  [[ "$existing" == "$release_commit" ]]
else
  # A permission/network error is not proof that a tag is absent.
  grep -q 'HTTP 404' tag-error.txt
fi
if gh release view "$tag" --json isDraft > release-state.json 2> release-error.txt; then
  if [[ $(python -c 'import json; print(json.load(open("release-state.json"))["isDraft"])') != True ]]; then
    echo 'Release already published; verifying its assets.'
  fi
else
  grep -qi 'release not found\|HTTP 404' release-error.txt
  [[ "$GITHUB_SHA" == "$release_commit" ]]
  gh release create "$tag" --target "$release_commit" --draft --prerelease \
    --title 'Honeypot Grid v0.1.0-alpha.2' --notes-file RELEASE-NOTES.md
fi
mkdir -p release-download
for asset in honeypot_grid-0.1.0a2-py3-none-any.whl honeypot_grid-0.1.0a2.tar.gz RELEASE-MANIFEST.json SHA256SUMS; do
  gh release view "$tag" --json assets --jq '.assets[].name' > release-assets.txt
  if grep -Fxq "$asset" release-assets.txt; then
    gh release download "$tag" --pattern "$asset" --dir release-download
    # Existing draft assets are verified together against their manifest below.
  else
    [[ $(gh release view "$tag" --json isDraft --jq .isDraft) == true ]]
    gh release upload "$tag" "dist/$asset"
    gh release download "$tag" --pattern "$asset" --dir release-download
    cmp "dist/$asset" "release-download/$asset"
  fi
done
(cd release-download && sha256sum --check SHA256SUMS)
target=$(gh release view "$tag" --json targetCommitish --jq .targetCommitish)
[[ "$target" == "$release_commit" ]]
python - "$release_commit" <<'PYVERIFY'
import json, sys
from pathlib import Path
manifest = json.loads(Path("release-download/RELEASE-MANIFEST.json").read_text())
assert manifest["commit"] == sys.argv[1]
assert manifest["tag"] == "v0.1.0-alpha.2"
assert manifest["version"] == "0.1.0a2"
PYVERIFY
if ! gh api "repos/$GH_REPO/git/ref/tags/$tag" > tag-ref.json 2> tag-error.txt; then
  grep -q 'HTTP 404' tag-error.txt
  gh api --method POST "repos/$GH_REPO/git/refs" -f ref="refs/tags/$tag" -f sha="$release_commit"
fi
actual=$(gh api "repos/$GH_REPO/git/ref/tags/$tag" --jq .object.sha)
[[ "$actual" == "$release_commit" ]]
if [[ $(gh release view "$tag" --json isDraft --jq .isDraft) == true ]]; then
  gh release edit "$tag" --draft=false --prerelease --latest=false
fi
gh release view "$tag" --json url,isDraft,isPrerelease,targetCommitish
