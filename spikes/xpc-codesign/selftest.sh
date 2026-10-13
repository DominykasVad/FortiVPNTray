#!/bin/bash
# Unprivileged check: the daemon binary talks to itself over an anonymous XPC listener
# with the same delegate and requirement code. No root, nothing installed.
# This is not the spike's verdict; only install.sh + run.sh test a real launchd Mach service.
source "$(dirname "$0")/common.sh"
[[ -x "$dist_dir/daemon" ]] || { echo "run build.sh first" >&2; exit 1; }
hash="$(cert_sha1 "$dist_dir/daemon" leaf)" || { echo "dist/daemon carries no certificate" >&2; exit 1; }
"$dist_dir/daemon" --self-test --client-id "$label" --cert-sha1 "$hash" 2>/dev/null
