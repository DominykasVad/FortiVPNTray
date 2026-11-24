#!/bin/bash
# Checks a signed FortiVPNTray.app; sign.sh runs it after signing, and it can be run by
# hand on any build (docs/signing.md). The helper's caller check trusts whatever runs
# inside a process with the app's signature, so a build is refused unless the bundle
# verifies strictly (the bundled helper is a sealed resource), the app and the helper
# carry the hardened runtime, and neither has entitlements, which could switch its
# protections off again.
set -euo pipefail
app_path="${1:?usage: check-signature.sh <path to .app>}"
helper_path="$app_path/Contents/Resources/FortiVPNHelper"

fail() { echo "error: $*" >&2; exit 1; }

[[ -d "$app_path" ]] || fail "$app_path is not an app bundle."
[[ -f "$helper_path" ]] || fail "$helper_path is missing."
codesign --verify --deep --strict "$app_path" || fail "$app_path does not verify."

# CS_RUNTIME in the CodeDirectory flags, read as a number so the check does not depend on
# how codesign spells the flag names.
runtime_flag=0x10000
for target in "$app_path" "$helper_path"; do
  flags="$(codesign --display --verbose "$target" 2>&1 | sed -nE 's/^CodeDirectory .* flags=(0x[0-9a-fA-F]+).*/\1/p')"
  [[ "$flags" =~ ^0x[0-9a-fA-F]+$ ]] || fail "cannot read the code-signing flags of $target."
  (( flags & runtime_flag )) || fail "$target is signed without the hardened runtime (flags $flags). Sign with native/scripts/sign.sh."
  entitlements="$(codesign --display --entitlements - --xml "$target" 2>/dev/null || true)"
  [[ -z "$entitlements" ]] || fail "$target is signed with entitlements; FortiVPNTray uses none."
done
echo "Signature check passed: hardened runtime, no entitlements."
