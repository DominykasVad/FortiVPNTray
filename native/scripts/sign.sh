#!/bin/bash
# Signs a built FortiVPNTray.app and its bundled helpers.
#   FVT_SIGN_IDENTITY  name of the local code-signing identity; unset or "-" = ad-hoc
#   FVT_SIGN_KEYCHAIN  optional keychain that holds it
# See docs/signing.md.
set -euo pipefail
app_path="${1:?usage: sign.sh <path to .app>}"
identity="${FVT_SIGN_IDENTITY:--}"
keychain="${FVT_SIGN_KEYCHAIN:-}"
helper_paths=("$app_path/Contents/Resources/FortiVPNHelper" "$app_path/Contents/Resources/openvpngui-helper")

sign_args=(--force --sign "$identity")
if [[ "$identity" == "-" ]]; then
  if [[ -n "$keychain" ]]; then
    echo "error: FVT_SIGN_KEYCHAIN is set but FVT_SIGN_IDENTITY is not." >&2
    exit 1
  fi
  cat >&2 <<'WARNING'
************************************************************************
WARNING: FVT_SIGN_IDENTITY is not set. This build is AD-HOC signed.
The helper cannot verify an ad-hoc signed app and will run in UID-ONLY
mode: any process of the logged-in user can talk to it.
For daily use, build with the local identity (docs/signing.md).
************************************************************************
WARNING
elif [[ -n "$keychain" ]]; then
  sign_args+=(--keychain "$keychain")
fi

# Inside-out: the bundled helpers first, then the bundle that seals them.
targets=()
for helper_path in "${helper_paths[@]}"; do
  if [[ -f "$helper_path" ]]; then targets+=("$helper_path"); fi
done
targets+=("$app_path")
for target in "${targets[@]}"; do
  codesign "${sign_args[@]}" "$target"
done
codesign --verify --deep --strict "$app_path"

[[ "$identity" == "-" ]] && exit 0

# Read the leaf certificate back from what was actually signed, so it can be
# compared with the identity. It is never stored or typed by hand.
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
leaf_sha1() {
  local prefix="$work_dir/$2-"
  codesign --display --extract-certificates="$prefix" "$1" 2>/dev/null
  if [[ ! -s "${prefix}0" ]]; then
    echo "error: $1 carries no signing certificate after signing with \"$identity\"." >&2
    exit 1
  fi
  shasum -a 1 "${prefix}0" | awk '{ print toupper($1) }'
}
app_leaf="$(leaf_sha1 "$app_path" app)"
for target in "${targets[@]}"; do
  [[ "$target" == "$app_path" ]] && continue
  target_leaf="$(leaf_sha1 "$target" helper)"
  if [[ "$target_leaf" != "$app_leaf" ]]; then
    echo "error: $target is signed with a different certificate ($target_leaf) than the app ($app_leaf)." >&2
    exit 1
  fi
done
echo "Signed with: $identity"
echo "Leaf certificate SHA-1: $app_leaf"
