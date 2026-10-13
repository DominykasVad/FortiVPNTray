#!/bin/bash
# Removes the root-owned copy made by `sudo copy.sh`. Run by the maintainer:
#   sudo spikes/openfortivpn-copy/remove.sh
source "$(dirname "$0")/common.sh"
[[ "$(id -u)" -eq 0 ]] || die "run with sudo"
rm -rf "$default_dest"
echo "Removed $default_dest"
