# github-codesign

Authenticode signing of Windows binaries from GitHub Actions with a key on a YubiKey attached to
a signing host. Overview: `README.md`; design and threat model: `docs/architecture.md`.
Machine-specific details (host, YubiKey, current state): `CLAUDE.local.md` (not committed).

## Layout

- `cmd/sign-pending` — Go, stdlib only; Linux-only at runtime, tests also run on Windows
  (`open_other.go`, `flush_other.go` are stubs for that)
- `request-signature/`, `verify-signed/` — composite actions; logic lives in the `.sh` files
  next to `action.yml`, keep YAML thin
- `deploy/` — files installed on the signing host, by destination; `scripts/install-badger.sh`
  installs them

## Build and test

```powershell
go vet ./...; go test ./...
$env:GOOS='linux'; $env:GOARCH='arm64'; $env:CGO_ENABLED='0'
go build -trimpath -o build/sign-pending ./cmd/sign-pending
```

Test the signing path on the host without GitHub (costs no PIN attempt if you answer `n`):
`sudo -u signer sign-pending -local /tmp/some.exe`.

## YubiKey and certificate

- PIV, **3 PIN attempts** — never guess; `sign-pending` refuses with fewer than 2 left.
- Key in slot 9A (`"slot"` in the config), ECC P-256, generated on the key.
  PIN policy `ONCE`, touch policy `CACHED` (~15 s); cannot be changed.
- Certificate: SSL.com OV code signing, `CN=Mikhail Filippov`, valid 2026-09-03 … 2027-09-03.
  On renewal update `chain.pem` on the host and the `leaf-hash` default in
  `verify-signed/action.yml` (`openssl x509 -in chain.pem -outform DER | sha256sum`).

## Gotchas

- **udev and the `pcscd` group.** If udevd loads `92-libccid.rules` before the pcscd package
  creates its group (`Failed to resolve group 'pcscd'`), the reader stays `root:root` and pcscd
  logs `LIBUSB_ERROR_ACCESS`. `udevadm control --reload` does not help (rules unchanged);
  `systemctl restart systemd-udevd && udevadm trigger` or a reboot does.
- **polkit and SSH.** pcscd allows only `allow_active` by default; SSH sessions are
  `Remote=yes` → `is NOT authorized for action: access_pcsc`. Hence the explicit rule.
- **Windows verification.** Don't test with binaries from System32: `Get-AuthenticodeSignature`
  shows their catalog signature.
- **Windows PowerShell from PowerShell 7** inherits `PSModulePath` and fails to load
  `Get-AuthenticodeSignature`; clear `PSModulePath` first.
- **Persistent runner workspace** is not cleaned between runs; use `RUNNER_TEMP`.
- **gh from Ubuntu** is too old for `gh attestation`; install from cli.github.com (deb822
  `.sources` file — a long one-line `.list` entry breaks when pasted).

## Useful commands

```bash
journalctl -u pcscd -b --no-pager | tail     # polkit / libusb denials
ykman piv info                                # slots, PIN tries
opensc-tool -l                                # readers
loginctl show-session $XDG_SESSION_ID -p Remote -p Active
```

## Conventions

- Commits GPG-signed, no `Co-Authored-By`
- Documentation and comments in English
- Python scripts only via `uv run` (inline dependencies, PEP 723)
