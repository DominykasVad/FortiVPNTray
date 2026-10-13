#!/bin/bash
# Installs the spike daemon as a root launchd job. Run by the maintainer:
#   sudo spikes/xpc-codesign/install.sh [leaf|root|uid-only]      (default: leaf)
# The certificate hash is read from dist/client-a, never typed.
source "$(dirname "$0")/common.sh"
mode="${1:-leaf}"
[[ "$mode" == leaf || "$mode" == root || "$mode" == uid-only ]] || { echo "usage: sudo install.sh [leaf|root|uid-only]" >&2; exit 64; }
[[ "$(id -u)" -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
allowed_uid="${SUDO_UID:?run with sudo from the account that will run the clients}"
[[ -x "$dist_dir/daemon" && -x "$dist_dir/client-a" ]] || { echo "run build.sh first" >&2; exit 1; }

arguments=("$daemon_path" --mach-service "$label" --allowed-uid "$allowed_uid" --mode "$mode")
if [[ "$mode" != uid-only ]]; then
  hash="$(cert_sha1 "$dist_dir/client-a" "$mode")" || { echo "dist/client-a carries no certificate" >&2; exit 1; }
  arguments+=(--client-id "$client_id" --cert-sha1 "$hash")
fi

launchctl bootout "system/$label" 2>/dev/null || true
mkdir -p /Library/PrivilegedHelperTools
install -o root -g wheel -m 755 "$dist_dir/daemon" "$daemon_path"
: > "$log_path"

plist="$(mktemp)"
plutil -create xml1 "$plist"
plutil -insert Label -string "$label" "$plist"
plutil -insert RunAtLoad -bool true "$plist"
plutil -insert StandardErrorPath -string "$log_path" "$plist"
plutil -insert MachServices -dictionary "$plist"
/usr/libexec/PlistBuddy -c "Add :MachServices:$label bool true" "$plist"
plutil -insert ProgramArguments -array "$plist"
for argument in "${arguments[@]}"; do
  plutil -insert ProgramArguments -string "$argument" -append "$plist"
done
install -o root -g wheel -m 644 "$plist" "$plist_path"
rm -f "$plist"

launchctl bootstrap system "$plist_path"
echo "Installed $label in mode $mode for uid $allowed_uid."
echo "Now run, without sudo: spikes/xpc-codesign/run.sh"
