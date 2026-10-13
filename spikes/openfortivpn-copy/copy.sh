#!/bin/bash
# Copies Homebrew's openfortivpn and every non-system dylib it loads into one
# directory, rewrites the load paths to that directory, re-signs ad-hoc and
# writes a manifest.
#
#   sudo spikes/openfortivpn-copy/copy.sh            root-owned copy in the default place
#   spikes/openfortivpn-copy/copy.sh <directory>     unprivileged dry run somewhere else
#
# Each file is copied first and only the copy is inspected, so a file that
# changes under /opt/homebrew during the run cannot differ from what was checked.
source "$(dirname "$0")/common.sh"
dest="${1:-$default_dest}"
[[ "$dest" == /* ]] || die "the destination must be an absolute path"
[[ "$(uname -m)" == arm64 ]] || die "Apple Silicon only"
[[ -e "$source_binary" ]] || die "$source_binary not found: brew install openfortivpn"
as_root=0
[[ "$(id -u)" -eq 0 ]] && as_root=1
if [[ "$dest" == "$default_dest" && $as_root -eq 0 ]]; then
  die "the default destination needs sudo; pass another directory for a dry run"
fi
if [[ "$dest" != "$default_dest" && $as_root -eq 1 ]]; then
  die "as root only the default destination is allowed; the script deletes the destination first"
fi

rm -rf "$dest"
mkdir -p "$dest/lib"
chmod 755 "$dest" "$dest/lib"

# file-in-dest <tab> original path it was copied from <tab> sha256 of the unmodified copy
sources_list="$(mktemp)"
trap 'rm -f "$sources_list"' EXIT

copy_in() { # <resolved source> <destination>
  [[ -f "$1" ]] || die "not a regular file: $1"
  cp "$1" "$2"
  chmod u+w "$2"
  printf '%s\t%s\t%s\n' "$2" "$1" "$(sha256_of "$2")" >> "$sources_list"
}

binary_real="$(realpath "$source_binary")"
copy_in "$binary_real" "$dest/openfortivpn"

# Breadth-first over the copies: every non-system load command must end up in $dest/lib.
queue=("$dest/openfortivpn")
while [[ ${#queue[@]} -gt 0 ]]; do
  current="${queue[0]}"
  queue=("${queue[@]:1}")
  while IFS= read -r reference; do
    [[ -n "$reference" ]] || continue
    case "$reference" in
      "$dest"/*) continue ;;
      @*) die "$current loads $reference; @rpath/@loader_path references are not handled" ;;
      /*) ;;
      *) die "$current loads a relative path: $reference" ;;
    esac
    real="$(realpath "$reference")" || die "cannot resolve $reference"
    target="$dest/lib/$(basename "$real")"
    if [[ -e "$target" ]]; then
      known="$(awk -F'\t' -v t="$target" '$1 == t { print $2 }' "$sources_list")"
      [[ "$known" == "$real" ]] || die "two different libraries are both called $(basename "$real"): $known and $real"
    else
      copy_in "$real" "$target"
      install_name_tool -id "$target" "$target" 2>/dev/null
      queue+=("$target")
    fi
    install_name_tool -change "$reference" "$target" "$current" 2>/dev/null
  done < <(non_system_libraries "$current")
done

# Rewriting load commands invalidates the signature; arm64 will not run unsigned code.
files=("$dest/openfortivpn")
while IFS= read -r library; do files+=("$library"); done < <(find "$dest/lib" -type f | sort)
for file in "${files[@]}"; do
  codesign --force --sign - "$file" 2>/dev/null
  if [[ "$file" == "$dest/openfortivpn" ]]; then chmod 755 "$file"; else chmod 644 "$file"; fi
done

# Versions. The Homebrew receipt is the user's file; it is recorded, not trusted.
openfortivpn_version="$("$dest/openfortivpn" --version 2>&1 | head -1)"
openssl_version="$(strings -a "$dest"/lib/libcrypto.*.dylib 2>/dev/null | grep -m1 -E '^OpenSSL [0-9]+\.[0-9]+\.[0-9]+' || true)"
receipt="$(dirname "$(dirname "$binary_real")")/INSTALL_RECEIPT.json"
receipt_version="$(basename "$(dirname "$(dirname "$binary_real")")")"

json_string() { printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"; }
set_hash="$(for file in "${files[@]}"; do printf '%s  %s\n' "$(sha256_of "$file")" "${file#"$dest"/}"; done | shasum -a 256 | awk '{ print $1 }')"
# Hash of the set as Homebrew shipped it: what an update check compares against /opt/homebrew.
source_set_hash="$(for file in "${files[@]}"; do awk -F'\t' -v t="$file" '$1 == t { print $3 "  " $2 }' "$sources_list"; done | shasum -a 256 | awk '{ print $1 }')"
{
  printf '{\n'
  printf '  "openfortivpn_version": %s,\n' "$(json_string "$openfortivpn_version")"
  printf '  "openssl_version": %s,\n' "$(json_string "$openssl_version")"
  printf '  "homebrew_keg": %s,\n' "$(json_string "$receipt_version")"
  printf '  "set_sha256": %s,\n' "$(json_string "$set_hash")"
  printf '  "source_set_sha256": %s,\n' "$(json_string "$source_set_hash")"
  printf '  "files": [\n'
  last=$((${#files[@]} - 1))
  for index in "${!files[@]}"; do
    file="${files[$index]}"
    origin="$(awk -F'\t' -v t="$file" '$1 == t { print $2 }' "$sources_list")"
    origin_hash="$(awk -F'\t' -v t="$file" '$1 == t { print $3 }' "$sources_list")"
    printf '    { "file": %s, "sha256": %s, "source": %s, "source_sha256": %s }' \
      "$(json_string "${file#"$dest"/}")" "$(json_string "$(sha256_of "$file")")" \
      "$(json_string "$origin")" "$(json_string "$origin_hash")"
    [[ $index -lt $last ]] && printf ','
    printf '\n'
  done
  printf '  ]\n}\n'
} > "$dest/manifest.json"
chmod 644 "$dest/manifest.json"

if [[ $as_root -eq 1 ]]; then
  chown -R root:wheel "$dest"
fi

echo "Copied to $dest"
echo "openfortivpn: $openfortivpn_version (Homebrew keg $receipt_version)"
echo "OpenSSL:      ${openssl_version:-unknown}"
[[ -f "$receipt" ]] && echo "Receipt:      $receipt"
echo
"$(dirname "$0")/verify.sh" "$dest"
