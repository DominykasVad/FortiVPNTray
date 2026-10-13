# Shared by the spike's scripts. Sourced, not run.
set -euo pipefail
spike_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dist_dir="$spike_dir/dist"

label="eu.dvad.fortivpntray.spike.xpc"
client_id="eu.dvad.fortivpntray.spike.client"
other_id="eu.dvad.fortivpntray.spike.other"
daemon_path="/Library/PrivilegedHelperTools/$label"
plist_path="/Library/LaunchDaemons/$label.plist"
log_path="/var/log/$label.log"

# SHA-1 of a certificate in a signed file's chain: 0 is the leaf, the last one is the root.
cert_sha1() {
  local file="$1" which="$2" work prefix count
  work="$(mktemp -d)"
  prefix="$work/cert-"
  codesign --display --extract-certificates="$prefix" "$file" 2>/dev/null
  count="$(find "$work" -name 'cert-*' | wc -l | tr -d ' ')"
  if [[ "$count" -eq 0 ]]; then
    rm -rf "$work"
    return 1
  fi
  [[ "$which" == root ]] && which=$((count - 1)) || which=0
  shasum -a 1 "${prefix}${which}" | awk '{ print toupper($1) }'
  rm -rf "$work"
}

cdhash() { codesign --display --verbose=4 "$1" 2>&1 | awk -F= '/^CDHash=/{ print $2 }'; }
