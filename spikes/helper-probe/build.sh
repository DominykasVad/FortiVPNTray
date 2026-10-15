#!/bin/bash
# Builds the helper probe into dist/ twice, signed differently. No root needed.
#   probe-signed  the local identity, identifier eu.dvad.fortivpntray: what the helper requires
#   probe-adhoc   ad-hoc, the same identifier
# Environment:
#   FVT_SIGN_IDENTITY  name of the local code-signing identity (docs/signing.md); without it
#                      only probe-adhoc is built
#   FVT_SIGN_KEYCHAIN  optional: keychain that holds it
# Also writes dist/samples/oversized.json, a connect request over the helper's 16 KiB limit.
set -euo pipefail
spike_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$spike_dir/../.." && pwd)"
dist_dir="$spike_dir/dist"
shared="$repo_dir/native/Sources/FortiVPNShared"
identifier="eu.dvad.fortivpntray"

mkdir -p "$dist_dir/samples"
# The protocol and the service name come from the app's own sources, so they cannot drift.
swiftc -swift-version 6 -O -target arm64-apple-macos13.0 -o "$dist_dir/probe" \
  "$shared/AppIdentity.swift" "$shared/HelperTransport.swift" "$spike_dir/Sources/main.swift"

cp "$dist_dir/probe" "$dist_dir/probe-adhoc"
codesign --force --sign - --identifier "$identifier" "$dist_dir/probe-adhoc"
built=(probe-adhoc)

identity="${FVT_SIGN_IDENTITY:-}"
if [[ -n "$identity" && "$identity" != "-" ]]; then
  sign_args=(--force --sign "$identity" --identifier "$identifier")
  [[ -n "${FVT_SIGN_KEYCHAIN:-}" ]] && sign_args+=(--keychain "$FVT_SIGN_KEYCHAIN")
  cp "$dist_dir/probe" "$dist_dir/probe-signed"
  codesign "${sign_args[@]}" "$dist_dir/probe-signed"
  built+=(probe-signed)
else
  rm -f "$dist_dir/probe-signed"
  echo "probe-signed not built: set FVT_SIGN_IDENTITY (and FVT_SIGN_KEYCHAIN) as for native/scripts/build.sh" >&2
fi
rm "$dist_dir/probe"

for name in "${built[@]}"; do
  codesign --verify --strict "$dist_dir/$name"
  # A signed build has an explicit designated requirement; an ad-hoc one only an implied cdhash ("# designated").
  printf '%-13s %s; %s\n' "$name" \
    "$(codesign --display --verbose=2 "$dist_dir/$name" 2>&1 | grep -E '^(Identifier|Signature)=' | paste -sd ' ' -)" \
    "$(codesign --display --requirements - "$dist_dir/$name" 2>/dev/null | sed -nE 's/^(# )?designated => /designated: /p')"
done
if [[ -f "$dist_dir/probe-signed" ]]; then
  work="$(mktemp -d)"
  codesign --display --extract-certificates="$work/cert-" "$dist_dir/probe-signed" 2>/dev/null
  echo "probe-signed leaf certificate SHA-1: $(shasum -a 1 "$work/cert-0" | awk '{ print toupper($1) }')"
  rm -rf "$work"
fi

# A valid request padded past ConnectRequest.maxEncodedSize (16 KiB) with spaces, which
# JSON allows: refused for its size before it is parsed.
{
  printf '{"host": "vpn.example.com", "port": 443, "auth": {"method": "saml", "listenPort": 8020}, '
  printf '"trustedCerts": [], "useSystemDNSFallback": true%*s}\n' 17000 ''
} > "$dist_dir/samples/oversized.json"
echo "dist/samples/oversized.json: $(wc -c < "$dist_dir/samples/oversized.json" | tr -d ' ') bytes"
