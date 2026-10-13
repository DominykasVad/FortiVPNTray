#!/bin/bash
# Removes everything install.sh put on the system. Run by the maintainer:
#   sudo spikes/xpc-codesign/uninstall.sh
source "$(dirname "$0")/common.sh"
[[ "$(id -u)" -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
launchctl bootout "system/$label" 2>/dev/null || true
rm -f "$daemon_path" "$plist_path" "$log_path"
echo "Removed $label."
