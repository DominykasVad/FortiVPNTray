#!/bin/bash
# Builds and signs the daemon and the three clients into dist/. No root needed.
#   FVT_SIGN_IDENTITY  required: name of the local code-signing identity
#   FVT_SIGN_KEYCHAIN  optional: keychain that holds it
#   SPIKE_BUILD_NOTE   optional: text compiled into client A, to force a different binary
source "$(dirname "$0")/common.sh"
identity="${FVT_SIGN_IDENTITY:?set FVT_SIGN_IDENTITY to the local signing identity (docs/signing.md)}"
sign_args=(--force --sign "$identity")
[[ -n "${FVT_SIGN_KEYCHAIN:-}" ]] && sign_args+=(--keychain "$FVT_SIGN_KEYCHAIN")

mkdir -p "$dist_dir"
swiftc_args=(-swift-version 6 -O -target arm64-apple-macos13.0)
swiftc "${swiftc_args[@]}" -o "$dist_dir/daemon" "$spike_dir/Sources/Protocol.swift" "$spike_dir/Sources/daemon/main.swift"

# Client A carries a build note so that a rebuild can produce a different cdhash on demand.
note_file="$dist_dir/BuildNote.swift"
printf 'let buildNote = "%s"\n' "${SPIKE_BUILD_NOTE:-first build}" > "$note_file"
swiftc "${swiftc_args[@]}" -o "$dist_dir/client-a" "$spike_dir/Sources/Protocol.swift" "$spike_dir/Sources/client/main.swift" "$note_file"
cp "$dist_dir/client-a" "$dist_dir/client-b"
cp "$dist_dir/client-a" "$dist_dir/client-c"

codesign "${sign_args[@]}" --identifier "$label" "$dist_dir/daemon"
codesign "${sign_args[@]}" --identifier "$client_id" "$dist_dir/client-a"   # A: right identity, right identifier
codesign --force --sign - --identifier "$client_id" "$dist_dir/client-b"    # B: ad-hoc, right identifier
codesign "${sign_args[@]}" --identifier "$other_id" "$dist_dir/client-c"    # C: right identity, wrong identifier

for name in daemon client-a client-b client-c; do
  codesign --verify --strict "$dist_dir/$name"
  printf '%-9s cdhash=%s  %s\n' "$name" "$(cdhash "$dist_dir/$name")" \
    "$(codesign --display --requirements - "$dist_dir/$name" 2>/dev/null | sed -E 's/^designated => //; s/H"[0-9a-fA-F]+"/H"<sha1>"/')"
done
echo "client-a leaf certificate SHA-1: $(cert_sha1 "$dist_dir/client-a" leaf)"
