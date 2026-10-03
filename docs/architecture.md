# Architecture

Authenticode signing of Windows binaries built in GitHub Actions. The code signing key lives on a
YubiKey (PIV) attached to a signing host (a Raspberry Pi 5 running Ubuntu).

```
GitHub-hosted runner
   │ build, attest-build-provenance, upload artifact "unsigned"
   ▼
signing host
┌───────────────────────────────────────────────────────┐
│ github-runner: codesign runner (rootless Podman)       │
│   ↓  request: repo, run_id, run_attempt, artifact      │
│ /var/spool/codesign (requests/, results/)              │
│   ↓                                                    │
│ signer: sign-pending — the only user with PC/SC access │
│   ↓  osslsigncode + pkcs11-provider + ykcs11           │
│ YubiKey PIV                                            │
└───────────────────────────────────────────────────────┘
   ▲ SSH: sudo -u signer sign-pending → approve, PIN, touch
 human
   │
   ▼ signed files back through the runner
GitHub-hosted runner: verify-signed, attest signed files, draft release
```

## Threat model

Goal: full control over a workflow, over the codesign runner, or over the `github-runner` user
must not be enough to get an arbitrary file signed, or to publish something other than the
attested build as the signed release. A signature requires, at the same time:

1. A human approving specific files in `sign-pending`.
2. The YubiKey PIN.
3. A physical touch (touch policy `CACHED`: one touch covers ~15 s).

Out of scope: a malicious commit pushed with the maintainer's GitHub account. It gets valid
provenance; the defense is the human checking the commit on the approval screen. Root on the
signing host is equivalent to key access (e.g. ptrace `sign-pending` for the PIN, then sign
within the touch window), so the host runs nothing else, and must be physically controlled.

## Rules

- **Only `signer` can reach the YubiKey.** polkit rule `deploy/polkit/50-pcsc-signer.rules`:
  pcscd accepts only `signer`. SSH sessions are `Remote=yes`, so the default `allow_active`
  policy never applies to them.
- **The runner is untrusted input.** It submits only `(repo, run_id, run_attempt, artifact)`.
  `sign-pending` resolves everything else through the GitHub API with its own read-only token:
  workflow name and path, commit, ref, actor, event. It downloads the artifact itself and
  checks the API `digest`.
- **Build provenance.** With `require_attestation`, every file must pass
  `gh attestation verify --signer-workflow <allowed workflow> --source-digest <run commit>
  --deny-self-hosted-runners`. The artifact store trusts any job in the run, including the one
  on the codesign runner, which could overwrite the artifact; provenance binds the bytes to a
  GitHub-hosted build of the allowed workflow at that commit.
- **No TOCTOU.** `sign-pending` works on its own copy in a 0700 directory, hashes it, shows the
  hash and re-checks it right before signing.
- **Verify before returning.** Each signed file passes `osslsigncode verify` (chain and
  timestamp) before the result is published.
- **Verify before releasing** (`verify-signed`, GitHub-hosted). Signed files come back through
  the codesign runner. The release job checks that each unsigned file has provenance, each
  signed file has a valid signature from the pinned certificate (`-require-leaf-hash`), and
  the signed file without its signature is byte-identical to the unsigned build (except the PE
  CheckSum, which signing recomputes and Authenticode does not cover). Only then are the
  signed files attested and released.
- **Approval input.** Answers are read from `/dev/tty` only; typed-ahead input is flushed
  before each prompt; only `y`/`n`/`s` are accepted.
- **Repository settings.** Fork PR workflows need approval for all external contributors. The
  sign job uses environment `codesign` (required reviewer, deployment tags `v*`). An environment
  only gates jobs that declare it and does not bind the runner label, so the fork PR setting is
  what keeps foreign code off the codesign runner; if it gets there anyway, it still cannot get
  anything signed (allowlist, provenance, human approval) nor released (`verify-signed`).

## Runners

Builds run on GitHub-hosted runners. The signing host only runs codesign runners, one per
repository, whose job writes a request and waits. No build/CI runners on the host: persistent
runners keep state between jobs, and every extra job is untrusted code next to the key.

- **Rootless Podman.** A container escape lands in `github-runner`, which is not in the polkit
  rule. Never mount the Podman socket, `/dev/bus/usb` or the pcscd socket into containers.
- **Persistent runners, no PAT on the host.** Each runner is registered once with the single-use
  registration token, fetched with the admin's own `gh` by `scripts/onboard-repo.sh` and typed
  into `gh-runner register` on the host (via `codesign-add-repo`),
  and runs in its own container and volume (`deploy/runner/gh-runner`, user unit
  `gh-runner@<instance>`). Container uid 1001 (`runner`) is mapped to `github-runner`
  (`--userns=keep-id`), so it can write `requests/` and read `results/`. The job's workspace is
  not cleaned between runs; `request-signature` works in `RUNNER_TEMP`.
- **Only the label `codesign`** (`--no-default-labels`), so `runs-on: self-hosted` jobs never
  land there.
- Rejected: ephemeral JIT runners. On a personal account `generate-jitconfig` needs a PAT with
  repository **Administration: write** (which can add deploy keys, i.e. push code), stored on
  the host next to untrusted code. Organizations have the narrower "Self-hosted runners"
  permission; free organizations only have the Default runner group.
- Personal accounts only have per-repository runners: one instance per repository (~180 MB
  idle).

## sign-pending

Runs as `signer`: `sudo -u signer sign-pending` (`-list` to list, `-local <file>` to test the
signing path without GitHub). Config `~signer/.config/github-codesign/config.json` (example:
`deploy/signer/config.json`); next to it `token` (fine-grained PAT, Actions: read, mode 600;
may cover all repositories, the allowlist decides) and `chain.pem` (leaf from the key + the
intermediate CA). Audit log: `~signer/.local/state/github-codesign/audit.jsonl`.

```json
{
  "slot": "9a",
  "repos": [
    {
      "repo": "owner/name",
      "workflows": [".github/workflows/release.yml"],
      "branches": ["v*"],
      "require_attestation": true
    }
  ]
}
```

Other settings (defaults): `spool` (`/var/spool/codesign`), `pkcs11_module`
(`/usr/lib/aarch64-linux-gnu/libykcs11.so`), `key_uri` (derived from `slot`, e.g.
`pkcs11:id=%01;type=private`), `tsa_url` (`http://ts.ssl.com`), `ca_bundle`, `certs`,
`token_file`, `max_artifact_bytes`.

Approval screen:

```
━━━ Signing request 1 of 1: 36318774321-1-unsigned

Repository:   mfilippov/caps-lang
Workflow:     Release (.github/workflows/release.yml)
Run:          #4, attempt 1 — Add build provenance, pin actions, keep a single task XML
              https://github.com/mfilippov/caps-lang/actions/runs/36318774321
Event:        push
Ref:          v0.0.0-test.4
Commit:       cdd3b94ac314bf06876714909d9c660d4aeb8a98
Actor:        mfilippov (triggered by mfilippov)
Artifact:     unsigned, sha256:f5cfd5b9…
Provenance:   ✓ all files: .github/workflows/release.yml at this commit, GitHub-hosted runner

File:         capslang-x64.exe
Size:         102.5 KiB
SHA256:       4c4c414e…

Approve signing? [y=yes/n=reject/s=skip] y
PIN tries remaining: 3 of 3
YubiKey PIN:
Signing capslang-x64.exe — touch the YubiKey when it blinks
✓ Signature and timestamp verified
✓ Signed files returned to the runner
```

### Spool protocol

```
/var/spool/codesign/requests/<id>.json   github-runner writes (tmp + rename)
    {"repo": "owner/name", "run_id": 123, "run_attempt": 1, "artifact": "unsigned"}
/var/spool/codesign/results/<id>/        signer writes (assembled under a tmp name, renamed)
    status.json   {"status": "signed|rejected", "reason": …, "files": [{name, size, sha256}]}
    <files>       signed files, same relative paths as in the artifact
```

`<id>` matches `[A-Za-z0-9][A-Za-z0-9._-]{0,127}` (`request-signature` uses
`<run_id>-<attempt>-<artifact>`). A request is pending while `results/<id>` does not exist.
Request files are opened with `O_NOFOLLOW`, size-limited and strictly parsed. Entries older
than 7 days are removed by systemd-tmpfiles.

Checks before the approval screen (failure → `rejected`, the job fails fast):

- repository in the allowlist; the run belongs to it and `head_repository` is the same (no
  forks); workflow path and `head_branch` match the rule; the run is `in_progress` at the
  requested attempt;
- exactly one artifact with that name in the run, not expired, `workflow_run` matches; the
  download matches the API `digest`;
- the zip contains only `.exe/.dll/.msi` with safe relative paths, no duplicates, size limits
  counted on real data; nothing is already signed;
- provenance for every file (if required).

Network or YubiKey errors and "skip" leave the request pending for a retry.

## Key policies

The PIV key's PIN and touch policies are fixed when the key is generated. With PIN policy
`ONCE` and touch policy `CACHED`:

- Every `osslsigncode` run is a new PKCS#11 session, so it needs the PIN; `sign-pending` asks
  once and passes it to each run through an inherited pipe (`pin-source=file:/dev/fd/3`), never
  via argv, environment or disk.
- One touch covers ~15 s, enough for several files of one request.
- PIV allows only 3 PIN attempts: `sign-pending` shows the remaining tries and refuses to ask
  with fewer than 2 left.

## Stack

- `pcscd` + `libccid`, access via polkit
- `ykcs11` — PKCS#11 module for the YubiKey PIV applet
- `pkcs11-provider` — OpenSSL 3 provider (instead of the deprecated `libengine-pkcs11-openssl`)
- `osslsigncode` with `-provider` support (tested with 2.13)
- `gh` ≥ 2.49 for `gh attestation verify` (from cli.github.com)
- RFC 3161 timestamps from the certificate's CA
