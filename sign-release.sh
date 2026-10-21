#!/bin/sh
# Re-signs a release APK with the private key through the v3 rotation lineage.
# Gradle leaves release unsigned; the tracked debug key is only the OLD signer
# of the lineage (installs from before the rotation), Android 9+ then accepts
# only the private key for updates. Client and server app alike.
# Usage: sign-release.sh in.apk out.apk
set -eu
K="${TYPEON_SIGNING:-$HOME/.config/typeon-signing}"
# H113: the newest installed build-tools.
B="$(ls -d "${ANDROID_HOME:-$HOME/Android/Sdk}"/build-tools/*/ | sort -V | tail -1)"
D="$(dirname "$0")/p2p_messenger_android/app/debug.keystore"
# --rotation-min-sdk-version 28: the default (33) left Android 9-12 on the
# tracked debug key.
"$B/apksigner" sign --out "$2" --rotation-min-sdk-version 28 --v4-signing-enabled false \
  --ks "$D" --ks-key-alias androiddebugkey --ks-pass pass:android \
  --next-signer --ks "$K/typeon-release.jks" --ks-key-alias typeon --ks-pass "file:$K/pass.txt" \
  --lineage "$K/lineage.bin" "$1"
"$B/apksigner" verify --print-certs "$2"
