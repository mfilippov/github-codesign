#!/usr/bin/env bash
# Set up a signing host (Ubuntu, arm64 or amd64) with the YubiKey attached:
# packages, users, polkit rule, spool, sign-pending, certificate chain and the runner tooling.
# Run as root from a directory that contains sign-pending (built for this machine) and deploy/:
#   sudo SLOT=9a ./install-badger.sh
# Idempotent; an existing signer config is kept. Tokens and runner registration are manual,
# see the message at the end.
set -euo pipefail

SLOT=${SLOT:-9a}
src=$(cd "$(dirname "$0")" && pwd)
[[ -f $src/sign-pending && -d $src/deploy ]] ||
    { echo "need sign-pending and deploy/ next to this script" >&2; exit 1; }
case ${SLOT,,} in
9a) id=01 ;; 9c) id=02 ;; 9d) id=03 ;; 9e) id=04 ;;
*) echo "SLOT must be 9a, 9c, 9d or 9e" >&2; exit 1 ;;
esac
arch=$(dpkg --print-architecture)

# gh from cli.github.com: the distribution's gh may be too old for `gh attestation verify`.
install -d -m 755 /etc/apt/keyrings
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    -o /etc/apt/keyrings/githubcli-archive-keyring.gpg
cat >/etc/apt/sources.list.d/github-cli.sources <<SOURCES
Types: deb
URIs: https://cli.github.com/packages
Suites: stable
Components: main
Architectures: $arch
Signed-By: /etc/apt/keyrings/githubcli-archive-keyring.gpg
SOURCES
apt-get update
apt-get install -y pcscd yubikey-manager ykcs11 opensc osslsigncode pkcs11-provider \
    podman uidmap passt crun systemd-container gh
# The libccid udev rule may have been loaded before the pcscd group existed; reload udev so
# the reader gets the right group (otherwise pcscd logs LIBUSB_ERROR_ACCESS).
systemctl restart systemd-udevd
udevadm trigger --subsystem-match=usb
ykcs11=$(dpkg -L ykcs11 | grep -m1 '/libykcs11.so$')

# signer: the only user allowed to use the YubiKey (polkit rule).
id signer &>/dev/null || useradd --system --create-home --shell /bin/bash signer
install -m 644 "$src/deploy/polkit/50-pcsc-signer.rules" /etc/polkit-1/rules.d/

# github-runner: codesign runners in rootless Podman. A regular (non-system) user, so that
# useradd allocates subuid/subgid ranges.
id github-runner &>/dev/null || useradd --create-home --shell /usr/sbin/nologin github-runner
grep -q '^github-runner:' /etc/subuid || { echo "no subuid range for github-runner" >&2; exit 1; }
loginctl enable-linger github-runner

install -m 644 "$src/deploy/tmpfiles.d/codesign.conf" /etc/tmpfiles.d/
systemd-tmpfiles --create /etc/tmpfiles.d/codesign.conf

install -m 755 "$src/sign-pending" /usr/local/bin/

conf=/home/signer/.config/github-codesign
runuser -u signer -- mkdir -p "$conf"
if [[ ! -f $conf/config.json ]]; then
    install -m 644 -o signer -g signer "$src/deploy/signer/config.json" "$conf/"
    sed -i -e "s|\"slot\": \"9a\"|\"slot\": \"${SLOT,,}\",\n  \"pkcs11_module\": \"$ykcs11\"|" \
        "$conf/config.json"
fi
if [[ ! -f $conf/chain.pem ]]; then
    # Leaf from the YubiKey + intermediate from the certificate's AIA "CA Issuers" URL.
    tmp=$(mktemp -d)
    runuser -u signer -- env PKCS11_PROVIDER_MODULE="$ykcs11" \
        openssl storeutl -provider pkcs11 -provider default -certs "pkcs11:id=%$id;type=cert" |
        openssl x509 >"$tmp/leaf.pem"
    url=$(openssl x509 -in "$tmp/leaf.pem" -noout -ext authorityInfoAccess |
        sed -n 's/.*CA Issuers - URI:\(.*\)/\1/p' | head -1)
    curl -fsS "$url" | openssl x509 -inform DER >"$tmp/intermediate.pem"
    openssl verify -partial_chain -CAfile "$tmp/intermediate.pem" "$tmp/leaf.pem"
    cat "$tmp/leaf.pem" "$tmp/intermediate.pem" >"$conf/chain.pem"
    chown signer:signer "$conf/chain.pem"
    rm -r "$tmp"
    echo "Leaf certificate hash (verify-signed leaf-hash):"
    echo "  sha256:$(openssl x509 -in "$conf/chain.pem" -outform DER | sha256sum | cut -d' ' -f1)"
fi

runuser -u github-runner -- mkdir -p /home/github-runner/.local/bin /home/github-runner/.config/systemd/user
install -m 755 -o github-runner -g github-runner "$src/deploy/runner/gh-runner" \
    /home/github-runner/.local/bin/
install -m 644 -o github-runner -g github-runner "$src/deploy/runner/gh-runner@.service" \
    /home/github-runner/.config/systemd/user/
systemctl --user -M github-runner@ daemon-reload

cat <<'MSG'

Done. Remaining manual steps:

1. signer token: fine-grained PAT, Actions: read (all repos is fine: the allowlist in
   config.json decides what gets signed). Paste, Enter, Ctrl-D:
     sudo runuser -u signer -- sh -c 'umask 077; cat > /home/signer/.config/github-codesign/token'

2. Per repository <repo>:
   - add it to /home/signer/.config/github-codesign/config.json
   - repo settings: fork PR workflow approval "all external contributors";
     environment "codesign" with you as required reviewer, deployment tags "v*"
   - register a codesign runner (token from Settings → Actions → Runners → New runner):
       sudo machinectl shell github-runner@ /bin/bash -l
       ~/.local/bin/gh-runner register --no-default-labels <repo>-codesign \
           https://github.com/<owner>/<repo> codesign \
           /var/spool/codesign/requests:/spool/requests /var/spool/codesign/results:/spool/results:ro
       systemctl --user enable --now gh-runner@<repo>-codesign
MSG
