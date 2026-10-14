#!/bin/sh
# Re-signs a release APK with the private key through the v3 rotation lineage.
# Gradle signs with the tracked debug key (old signer); Android 9+ then accepts
# only the private key for updates. Usage: sign-release.sh in.apk out.apk
set -eu
K="${TYPEON_SIGNING:-$HOME/.config/typeon-signing}"
B="$HOME/Android/Sdk/build-tools/36.0.0"
D="$(dirname "$0")/p2p_messenger_android/app/debug.keystore"
"$B/apksigner" sign --out "$2" \
  --ks "$D" --ks-key-alias androiddebugkey --ks-pass pass:android \
  --next-signer --ks "$K/typeon-release.jks" --ks-key-alias typeon --ks-pass "file:$K/pass.txt" \
  --lineage "$K/lineage.bin" "$1"
"$B/apksigner" verify --print-certs "$2"
