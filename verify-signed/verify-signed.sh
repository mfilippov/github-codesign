#!/usr/bin/env bash
# Check signed PE files against the attested unsigned build. For every file:
#   1. the unsigned file has build provenance from SIGNER_WORKFLOW at GITHUB_SHA, built on a
#      GitHub-hosted runner;
#   2. the signed file has a valid Authenticode signature + timestamp from the certificate
#      with LEAF_HASH;
#   3. the signed file without its signature equals the unsigned file, except the PE CheckSum
#      (recomputed on signing, not covered by Authenticode).
# Both directories must contain the same set of files.
# Env: SIGNED, UNSIGNED, LEAF_HASH, SIGNER_WORKFLOW (optional), GH_TOKEN, GITHUB_*.
set -euo pipefail

workflow=${SIGNER_WORKFLOW:-${GITHUB_WORKFLOW_REF%@*}}
ca=/etc/ssl/certs/ca-certificates.crt
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! command -v osslsigncode >/dev/null; then
    sudo apt-get install -y -qq osslsigncode >/dev/null
fi

list() { (cd "$1" && find . -type f | sort); }
if ! diff <(list "$SIGNED") <(list "$UNSIGNED") >/dev/null; then
    echo "::error::signed and unsigned directories differ:"
    diff <(list "$SIGNED") <(list "$UNSIGNED") || true
    exit 1
fi

# SHA256 of a PE file with the 4-byte CheckSum field (optional header + 64) zeroed.
pe_digest() {
    local copy=$tmp/pe off
    cp "$1" "$copy"
    off=$(od -An -tu4 -j60 -N4 "$copy" | tr -d ' ')
    printf '\0\0\0\0' | dd of="$copy" bs=1 seek=$((off + 88)) conv=notrunc status=none
    sha256sum "$copy" | cut -d' ' -f1
}

while read -r f; do
    f=${f#./}
    case ${f,,} in
    *.exe | *.dll) ;;
    *) echo "::error::$f: only PE files (.exe, .dll) are supported"; exit 1 ;;
    esac

    gh attestation verify "$UNSIGNED/$f" --repo "$GITHUB_REPOSITORY" \
        --signer-workflow "$workflow" --source-digest "$GITHUB_SHA" \
        --deny-self-hosted-runners >"$tmp/log" 2>&1 ||
        { cat "$tmp/log"; echo "::error::$f: unsigned build has no valid provenance"; exit 1; }

    osslsigncode verify -in "$SIGNED/$f" -CAfile "$ca" -TSA-CAfile "$ca" \
        -require-leaf-hash "$LEAF_HASH" >"$tmp/log" 2>&1 ||
        { cat "$tmp/log"; echo "::error::$f: signature check failed"; exit 1; }

    osslsigncode remove-signature -in "$SIGNED/$f" -out "$tmp/stripped" >/dev/null
    a=$(pe_digest "$tmp/stripped")
    b=$(pe_digest "$UNSIGNED/$f")
    [[ $a == "$b" ]] ||
        { echo "::error::$f: signed file is not the attested build plus a signature"; exit 1; }
    rm "$tmp/stripped"
    echo "✓ $f"
done < <(list "$SIGNED")
