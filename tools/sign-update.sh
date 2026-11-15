#!/bin/sh
# Signs a published release for the self-updater (core update.rs). Run on the owner's machine after CI
# has published the release: the private key never leaves ~/.config/typeon-signing, so a GitHub or CI
# compromise alone cannot ship an update. Until SHA256SUMS.sig is uploaded, apps treat the release as
# not published yet.
#   tools/sign-update.sh v7.4.6
# Key (once): openssl genpkey -algorithm ed25519 -out ~/.config/typeon-signing/update-ed25519.pem
# Its public half is UPDATE_KEY in update.rs:
#   openssl pkey -in KEY -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'
set -eu
TAG=$1
KEY="${TYPEON_SIGNING:-$HOME/.config/typeon-signing}/update-ed25519.pem"
cd "$(dirname "$0")/.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
gh release download "$TAG" -p SHA256SUMS -D "$T"
cat "$T/SHA256SUMS"
printf 'Sign these hashes for %s? [y/N] ' "$TAG"; read -r ok; [ "$ok" = y ]
# Must match update::signed_message: header, tag, then SHA256SUMS verbatim.
{ printf 'typeon-update v1\n%s\n' "$TAG"; cat "$T/SHA256SUMS"; } > "$T/msg"
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$T/msg" | od -An -tx1 | tr -d ' \n' > "$T/SHA256SUMS.sig"
gh release upload "$TAG" --clobber "$T/SHA256SUMS.sig"
cp "$T/SHA256SUMS.sig" dist/ 2>/dev/null || true
echo "signed $TAG"
