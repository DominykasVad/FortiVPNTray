#!/bin/bash
# Checks a copy made by copy.sh. No root needed.
#   spikes/openfortivpn-copy/verify.sh [directory]
source "$(dirname "$0")/common.sh"
dest="${1:-$default_dest}"
[[ -f "$dest/manifest.json" ]] || die "no manifest in $dest: run copy.sh first"
failures=0
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
pass() { echo "ok    $*"; }

files=("$dest/openfortivpn")
while IFS= read -r library; do files+=("$library"); done < <(find "$dest/lib" -type f | sort)

echo "== Load commands (otool -L)"
for file in "${files[@]}"; do
  otool -L "$file" | tail -n +2 | sed 's/^[[:space:]]*/        /'
  outside="$(non_system_libraries "$file" | grep -v "^$dest/" || true)"
  if [[ -z "$outside" ]]; then pass "${file#"$dest"/} loads only system libraries and $dest"; else fail "${file#"$dest"/} still loads: $outside"; fi
  if otool -l "$file" | grep -q LC_RPATH; then fail "${file#"$dest"/} has an LC_RPATH"; fi
done

echo "== Signatures"
for file in "${files[@]}"; do
  if codesign --verify --strict "$file" 2>/dev/null; then pass "${file#"$dest"/} signature valid"; else fail "${file#"$dest"/} signature invalid"; fi
done

echo "== Manifest"
for file in "${files[@]}"; do
  relative="${file#"$dest"/}"
  recorded="$(grep -F "\"file\": \"$relative\"" "$dest/manifest.json" | sed -E 's/.*"sha256": "([0-9a-f]{64})".*/\1/')"
  if [[ "$recorded" == "$(sha256_of "$file")" ]]; then pass "$relative matches the manifest"; else fail "$relative does not match the manifest"; fi
done
listed="$(grep -c '"file":' "$dest/manifest.json")"
if [[ "$listed" -eq ${#files[@]} ]]; then pass "manifest lists exactly the ${#files[@]} files present"; else fail "manifest lists $listed files, ${#files[@]} present"; fi

echo "== Ownership (the file and every parent directory)"
check_owner() { # <path>
  local info mode
  [[ -L "$1" ]] && { fail "$1 is a symlink"; return; }
  info="$(owner_and_mode "$1")"
  mode="${info##* }"
  if [[ "${info%% *}" != root:wheel && "${info%% *}" != root:admin ]]; then fail "$1 is owned by ${info%% *}"; return; fi
  if (( (8#$mode & 8#022) != 0 )); then
    # A sticky, root-owned directory such as /Library is the system default; report it, do not hide it.
    if [[ -d "$1" && $(( 8#$mode & 8#1000 )) -ne 0 ]]; then echo "note  $1 is group/other writable but sticky ($info)"; return; fi
    fail "$1 is group/other writable ($info)"; return
  fi
  pass "$1 ($info)"
}
path="$dest"
parents=()
while [[ "$path" != "/" ]]; do parents=("$path" ${parents[@]+"${parents[@]}"}); path="$(dirname "$path")"; done
for path in / "${parents[@]}" "$dest/lib" "${files[@]}" "$dest/manifest.json"; do check_owner "$path"; done

echo "== Runs from the copy"
if version="$("$dest/openfortivpn" --version 2>&1)"; then pass "openfortivpn --version: $version"; else fail "openfortivpn --version failed: $version"; fi

echo
if [[ $failures -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL ($failures check(s))"; exit 1; fi
