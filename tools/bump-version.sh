#!/bin/sh
# One version for every app, so the self-updater (core update.rs) compares like with like:
#   tools/bump-version.sh 7.4.0        (Android versionCodes go up by one)
# Release tags must be v<version>; a tag with "-" (v7.4.0-beta.1) is a beta / GitHub pre-release.
set -eu
V=$1
cd "$(dirname "$0")/.."
for g in p2p_messenger_android/app/build.gradle p2p_messenger_android_server/app/build.gradle; do
    code=$(sed -n 's/^ *versionCode \([0-9]*\)/\1/p' "$g")
    sed -i "s/^\( *versionCode\) $code/\1 $((code + 1))/; s/^\( *versionName\) \".*\"/\1 \"$V\"/" "$g"
done
for c in Linux typeon-server; do
    sed -i "0,/^version = \".*\"/s//version = \"$V\"/" "$c/Cargo.toml"
    name=$(sed -n 's/^name = "\(.*\)"/\1/p' "$c/Cargo.toml" | head -n1)
    # Lock file: the version line right after this package's name.
    sed -i "/^name = \"$name\"$/{n;s/^version = \".*\"/version = \"$V\"/}" "$c/Cargo.lock"
done
grep -H 'versionName\|versionCode' p2p_messenger_android*/app/build.gradle
grep -H -m1 '^version' Linux/Cargo.toml typeon-server/Cargo.toml
