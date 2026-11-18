#!/bin/sh
# Signs a published release for the self-updater (core update.rs). Run on the owner's machine after CI
# has published the release: the private key never leaves ~/.config/typeon-signing. Until SHA256SUMS.sig
# is uploaded, apps treat the release as not published yet.
#   tools/sign-update.sh v7.4.6
# The signature only says "the owner approved these hashes". CI builds the artifacts, so before signing
# this script refuses when:
#   - the tag on GitHub points at another commit than the owner's local tag,
#   - SHA256SUMS lists a file the release does not have, or an asset differs from its listed hash,
#   - a file of the same name in the local dist/ differs (artifacts the owner built or checked),
#   - an APK is not signed with the owner's release certificate.
# It cannot catch a build CI itself poisoned from a clean commit (builds are not reproducible).
# Key (once): openssl genpkey -algorithm ed25519 -out ~/.config/typeon-signing/update-ed25519.pem
# Its public half is UPDATE_KEY in update.rs:
#   openssl pkey -in KEY -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'
# Release certificate SHA-256 (hex): TYPEON_RELEASE_CERT_SHA256, else read from the release keystore.
set -eu
TAG=$1
SIGN="${TYPEON_SIGNING:-$HOME/.config/typeon-signing}"
KEY="$SIGN/update-ed25519.pem"
cd "$(dirname "$0")/.."
die() { echo "REFUSED: $*" >&2; exit 1; }
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

local_sha=$(git rev-parse --verify "$TAG^{commit}") || die "no local tag $TAG"
remote_sha=$(gh api "repos/{owner}/{repo}/commits/$TAG" --jq .sha) || die "tag $TAG not found on GitHub"
[ "$local_sha" = "$remote_sha" ] || die "GitHub tag $TAG is $remote_sha, local tag is $local_sha"

gh release download "$TAG" -D "$T/a"
[ -f "$T/a/SHA256SUMS" ] || die "release has no SHA256SUMS"
mv "$T/a/SHA256SUMS" "$T/SHA256SUMS"
rm -f "$T/a/SHA256SUMS.sig"
# Every asset is listed and matches; nothing listed is missing.
(cd "$T/a" && sha256sum -c --strict --quiet ../SHA256SUMS) || die "assets do not match SHA256SUMS"
for f in "$T/a"/*; do
    cut -c67- "$T/SHA256SUMS" | grep -qxF "$(basename "$f")" || die "asset $(basename "$f") is not in SHA256SUMS"
done

# Local copies the owner built or checked must be identical.
matched=0
while read -r h name; do
    [ -f "dist/$name" ] || { echo "no local copy: $name"; continue; }
    [ "$(sha256sum "dist/$name" | cut -d' ' -f1)" = "$h" ] || die "dist/$name differs from the release"
    matched=$((matched + 1))
done < "$T/SHA256SUMS"
echo "$matched file(s) match dist/"

CERT=${TYPEON_RELEASE_CERT_SHA256:-}
if [ -z "$CERT" ]; then
    KT=$(command -v keytool || echo "${JAVA_HOME:-}/bin/keytool")
    CERT=$("$KT" -list -v -keystore "$SIGN/typeon-release.jks" -alias typeon -storepass:file "$SIGN/pass.txt" \
        | sed -n 's/^[[:space:]]*SHA256: *//p' | tr -d ':') || true
fi
CERT=$(printf %s "$CERT" | tr 'A-F' 'a-f')
[ -n "$CERT" ] || die "release certificate digest unknown (set TYPEON_RELEASE_CERT_SHA256)"
B="$(ls -d "${ANDROID_HOME:-$HOME/Android/Sdk}"/build-tools/*/ | sort -V | tail -1)"
for apk in "$T/a"/*.apk; do
    [ -f "$apk" ] || continue
    certs=$("$B/apksigner" verify --print-certs "$apk") || die "$(basename "$apk") does not verify"
    printf %s "$certs" | tr 'A-F' 'a-f' | grep -q "$CERT" || die "$(basename "$apk") is not signed with the release key"
done

cat "$T/SHA256SUMS"
printf 'Sign these hashes for %s (commit %s)? [y/N] ' "$TAG" "$local_sha"; read -r ok; [ "$ok" = y ]
# Must match update::signed_message: header, tag, then SHA256SUMS verbatim.
{ printf 'typeon-update v1\n%s\n' "$TAG"; cat "$T/SHA256SUMS"; } > "$T/msg"
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$T/msg" | od -An -tx1 | tr -d ' \n' > "$T/SHA256SUMS.sig"
gh release upload "$TAG" --clobber "$T/SHA256SUMS.sig"
cp "$T/SHA256SUMS.sig" dist/ 2>/dev/null || true
echo "signed $TAG"
