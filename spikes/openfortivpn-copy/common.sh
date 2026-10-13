# Shared by the spike's scripts. Sourced, not run.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

label="eu.dvad.fortivpntray.spike.openfortivpn"
default_dest="/Library/PrivilegedHelperTools/$label.d"
brew_prefix="/opt/homebrew"
source_binary="$brew_prefix/bin/openfortivpn"

die() { echo "error: $*" >&2; exit 1; }

# Load commands of a Mach-O file that are not system libraries, one per line.
non_system_libraries() {
  otool -L "$1" | tail -n +2 | awk '{ print $1 }' | grep -Ev '^(/usr/lib/|/System/)' || true
}

sha256_of() { shasum -a 256 "$1" | awk '{ print $1 }'; }

# "owner:group mode" of a path, without following a final symlink.
owner_and_mode() { stat -f '%Su:%Sg %Lp' "$1"; }
