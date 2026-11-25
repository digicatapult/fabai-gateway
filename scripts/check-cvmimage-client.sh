#!/usr/bin/env bash
# Checks that cvmimage's own collateral client accepts fabai-collateral's
# response. The client is an internal package of cvmimage's tinfoil module,
# so a test is added to a scratch checkout of fabai-cvmimage at the pinned
# commit and run against fabai-collateral's handler over a synthetic cache.
#
#   scripts/check-cvmimage-client.sh [existing fabai-cvmimage checkout]
set -euo pipefail

# cvmimage v0.14.19, the runtime image the deployments pin.
readonly CVMIMAGE_COMMIT="58d570cca75ed207edfd9a2a56f6846dd80de2bf"
readonly CVMIMAGE_REPO="https://github.com/digicatapult/fabai-cvmimage"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

checkout="$work/cvmimage"
if [[ $# -gt 0 ]]; then
  git clone --quiet --no-checkout "$1" "$checkout"
else
  git clone --quiet --no-checkout --filter=blob:none "$CVMIMAGE_REPO" "$checkout"
fi
git -C "$checkout" -c advice.detachedHead=false checkout --quiet --detach "${CVMIMAGE_COMMIT}^{commit}"
if [[ "$(git -C "$checkout" rev-parse HEAD)" != "$CVMIMAGE_COMMIT" ]]; then
  printf 'the checkout is not cvmimage commit %s\n' "$CVMIMAGE_COMMIT" >&2
  exit 1
fi

(cd "$root" && go build -o "$work/conformance" ./internal/collateral/conformance)
"$work/conformance" -addr-file "$work/addr" &
pid=$!
for _ in $(seq 100); do
  [[ -s "$work/addr" ]] && break
  sleep 0.1
done
if [[ ! -s "$work/addr" ]]; then
  printf 'the conformance service did not start\n' >&2
  exit 1
fi

cp "$root/internal/collateral/conformance/testdata/fabai_conformance_test.go" \
  "$checkout/tinfoil/internal/attestationmaterial/"
cd "$checkout/tinfoil"
FABAI_COLLATERAL_URL="http://$(cat "$work/addr")" \
  go test -count=1 -run '^TestFabAICollateralService$' -v ./internal/attestationmaterial/
