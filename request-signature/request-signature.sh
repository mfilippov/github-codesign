#!/usr/bin/env bash
# Submit a signing request to the sign-pending spool and wait for the result.
# Env: ARTIFACT, SPOOL, plus the standard GITHUB_* variables.
# Writes the signed files to $RUNNER_TEMP/signed and its path to $GITHUB_OUTPUT (dir=...).
set -euo pipefail

[[ $ARTIFACT =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$ ]] ||
    { echo "::error::artifact name must match [A-Za-z0-9][A-Za-z0-9._-]{0,99}"; exit 1; }

# Run IDs are unique across GitHub, so this is unique per request.
id="$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$ARTIFACT"
result="$SPOOL/results/$id"

printf '{"repo":"%s","run_id":%s,"run_attempt":%s,"artifact":"%s"}\n' \
    "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$ARTIFACT" \
    >"$SPOOL/requests/.$id.tmp"
mv "$SPOOL/requests/.$id.tmp" "$SPOOL/requests/$id.json"

echo "Request $id submitted. Approve it on the signing host: sudo -u signer sign-pending"
until [[ -f $result/status.json ]]; do sleep 10; done
cat "$result/status.json"
grep -q '"status": "signed"' "$result/status.json" ||
    { echo "::error::signing request was not signed (see status above)"; exit 1; }

# The runner is persistent; RUNNER_TEMP is emptied by the runner before every job, the
# workspace is not.
out="$RUNNER_TEMP/signed"
rm -rf "$out"
cp -r "$result" "$out"
rm "$out/status.json"
echo "dir=$out" >>"$GITHUB_OUTPUT"
