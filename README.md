# github-codesign

Authenticode signing for Windows binaries built in GitHub Actions, with the private key on a
YubiKey (PIV) attached to a small Linux box (a Raspberry Pi 5 here) that you control.

- Builds run on GitHub-hosted runners and get [build provenance attestations][attest].
- A self-hosted runner on the signing host only drops a request into a spool and waits.
- `sign-pending`, run by a human over SSH, resolves the request through the GitHub API, checks
  the provenance, shows what exactly will be signed and asks for approval, the YubiKey PIN and
  a touch.
- Before the release is created, a GitHub-hosted job proves that the signed files are the
  attested build plus a valid signature by the pinned certificate.

Nothing that runs in GitHub Actions or on the runner can get an arbitrary file signed.
Details and threat model: [docs/architecture.md](docs/architecture.md).

```
GitHub-hosted: build → attest → upload "unsigned"
                                      │
signing host   codesign runner ── request ──► spool ◄── sign-pending (signer, human: y + PIN + touch)
                                      │                     │ GitHub API, gh attestation verify,
                                      ◄──── signed files ───┘ osslsigncode + PKCS#11 → YubiKey
GitHub-hosted: verify-signed → attest signed files → draft release
```

## Repository

| Path | What |
|---|---|
| `cmd/sign-pending` | Approval and signing tool for the `signer` user (Go, stdlib only) |
| `request-signature/` | Composite action for the codesign runner: submit a request, wait for the result |
| `verify-signed/` | Composite action for the release job: signed files = attested build + our signature |
| `deploy/` | polkit rule, spool (tmpfiles.d), example `sign-pending` config, runner script and unit |
| `scripts/install-badger.sh` | Sets up a signing host (Ubuntu) |
| `scripts/onboard-repo.sh` | Onboards a repository: settings, allowlist entry, codesign runner |

## Signing host setup

Requirements: Ubuntu (tested on 26.04, arm64), a YubiKey with the code signing key and
certificate in a PIV slot, physical control over the box.

```bash
# on your machine
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o sign-pending ./cmd/sign-pending
scp -r sign-pending deploy scripts/install-badger.sh host:setup/
# on the host
cd setup && sudo SLOT=9a ./install-badger.sh
```

The script installs the packages (`pcscd`, `ykcs11`, `pkcs11-provider`, `osslsigncode`, `gh`,
rootless Podman), creates the users `signer` (the only one allowed to use the YubiKey, via
polkit) and `github-runner`, the spool `/var/spool/codesign`, builds the certificate chain from
the key and prints the certificate hash for `verify-signed`. It then lists the manual steps:
the `signer` token (fine-grained PAT, Actions: read) and, per repository, the allowlist entry,
repository settings and the codesign runner.

## Using it in a repository

Repository settings: fork PR workflow approval for all external contributors, an environment
`codesign` with you as required reviewer and deployment tags `v*`, a codesign runner and an
entry in the `sign-pending` allowlist with `require_attestation`. All of it in one go, from
your machine with `gh` logged in as the repository admin:

```bash
CODESIGN_HOST=<signing host> scripts/onboard-repo.sh owner/repo [.github/workflows/release.yml]
```

It asks for your sudo password on the host and, for a new runner, for the registration token
it copied to the clipboard. Safe to re-run.

```yaml
on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: windows-latest
    permissions: { contents: read, id-token: write, attestations: write }
    steps:
      # ... build app.exe ...
      - uses: actions/attest-build-provenance@<sha>
        with: { subject-path: app.exe }
      - uses: actions/upload-artifact@<sha>
        with: { name: unsigned, path: app.exe }

  sign:
    needs: build
    runs-on: codesign
    environment: codesign
    timeout-minutes: 60
    steps:
      - id: sign
        uses: mfilippov/github-codesign/request-signature@<sha>
      - uses: actions/upload-artifact@<sha>
        with: { name: signed, path: '${{ steps.sign.outputs.dir }}' }

  release:
    needs: sign
    runs-on: ubuntu-latest
    permissions: { contents: write, id-token: write, attestations: write }
    steps:
      - uses: actions/download-artifact@<sha>
        with: { name: signed, path: signed }
      - uses: actions/download-artifact@<sha>
        with: { name: unsigned, path: unsigned }
      - uses: mfilippov/github-codesign/verify-signed@<sha>
        with: { signed: signed, unsigned: unsigned }
      - uses: actions/attest-build-provenance@<sha>
        with: { subject-path: signed/* }
      # ... gh release create ...
```

A complete example: [mfilippov/caps-lang release.yml][caps-lang].

`verify-signed` pins the signing certificate by hash (`leaf-hash`, defaults to the maintainer's
certificate); set it to yours, as printed by the installer.

On the signing host, approve with:

```
$ sudo -u signer sign-pending
```

[attest]: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations
[caps-lang]: https://github.com/mfilippov/caps-lang/blob/master/.github/workflows/release.yml
