#!/usr/bin/env bash
# Onboard a repository for signing. Runs on your machine with gh logged in as the repository
# admin; the signing host itself never gets an admin token.
#
#   CODESIGN_HOST=<host> scripts/onboard-repo.sh <owner/repo> [workflow]
#
# 1. Repository settings: fork PR workflows need approval for all external contributors;
#    environment "codesign" with you as required reviewer, deployments from tags "v*" only.
# 2. Signing host, over SSH (asks for your sudo password): codesign-add-repo adds the
#    allowlist entry and, if the repository has no codesign runner yet, registers one. The
#    single-use registration token is fetched here and copied to the clipboard for its prompt.
# Safe to re-run.
set -euo pipefail

usage() { sed -n '5s/^#   //p' "$0" >&2; exit 2; }
[[ $# -ge 1 && $# -le 2 ]] || usage
repo=$1 workflow=${2:-.github/workflows/release.yml}
: "${CODESIGN_HOST:?set CODESIGN_HOST to the signing host}"

# Git Bash ships its own ssh, which does not see keys in the Windows OpenSSH agent.
ssh=ssh
if [[ $(uname -s) == MINGW* && -x /c/Windows/System32/OpenSSH/ssh.exe ]]; then
    ssh=/c/Windows/System32/OpenSSH/ssh.exe
fi

gh api "repos/$repo" --jq .full_name >/dev/null

gh api -X PUT "repos/$repo/actions/permissions/fork-pr-contributor-approval" \
    -f approval_policy=all_external_contributors
echo "✓ fork PR workflows need approval for all external contributors"

me=$(gh api user --jq .id)
gh api -X PUT "repos/$repo/environments/codesign" --input - >/dev/null <<EOF
{
  "reviewers": [{"type": "User", "id": $me}],
  "prevent_self_review": false,
  "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}
}
EOF
if ! gh api "repos/$repo/environments/codesign/deployment-branch-policies" \
        --jq '.branch_policies[] | select(.type == "tag" and .name == "v*")' | grep -q .; then
    gh api -X POST "repos/$repo/environments/codesign/deployment-branch-policies" \
        -f name='v*' -f type=tag >/dev/null
fi
echo "✓ environment codesign: you as required reviewer, tags v* only"

args=()
if gh api "repos/$repo/actions/runners" \
        --jq '.runners[] | select(any(.labels[]; .name == "codesign")) | .name' | grep -q .; then
    echo "✓ codesign runner already registered"
    args=(--no-runner)
else
    token=$(gh api -X POST "repos/$repo/actions/runners/registration-token" --jq .token)
    if command -v clip.exe >/dev/null; then
        printf %s "$token" | clip.exe
    elif command -v pbcopy >/dev/null; then
        printf %s "$token" | pbcopy
    elif command -v wl-copy >/dev/null; then
        printf %s "$token" | wl-copy
    else
        echo "Registration token (single use, 1 h): $token"
    fi
    echo "Runner registration token is in the clipboard; paste it at the \"Registration token\" prompt."
fi

"$ssh" -t "$CODESIGN_HOST" sudo codesign-add-repo "${args[@]}" "$repo" "$workflow"
