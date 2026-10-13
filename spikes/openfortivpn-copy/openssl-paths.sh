#!/bin/bash
# Shows which files the copied OpenSSL libraries read, and that an OpenSSL config
# file can make them load arbitrary code. No root: works on a dry-run copy in a
# temporary directory and does not touch /opt/homebrew.
source "$(dirname "$0")/common.sh"
spike_dir="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
copy="$work/copy"
"$spike_dir/copy.sh" "$copy" >/dev/null 2>&1 || true   # the dry run fails only its ownership checks
[[ -x "$copy/openfortivpn" ]] || die "dry-run copy failed"

cc -o "$work/probe" "$spike_dir/probe/probe.c" "$copy"/lib/libssl.*.dylib "$copy"/lib/libcrypto.*.dylib
cc -dynamiclib -o "$work/trace.dylib" "$spike_dir/probe/trace.c"
cc -dynamiclib -o "$work/marker.dylib" "$spike_dir/probe/marker.c"
cat > "$work/hostile.cnf" <<CONFIG
openssl_conf = init
[init]
providers = provs
[provs]
default = def
marker = mk
[def]
activate = 1
[mk]
module = $work/marker.dylib
activate = 1
CONFIG

run() { # <title> [VAR=value ...]
  local title="$1"; shift
  rm -f "$work/marker.out"
  echo "== $title"
  env -i PATH="$PATH" SPIKE_MARKER="$work/marker.out" DYLD_INSERT_LIBRARIES="$work/trace.dylib" "$@" "$work/probe" 2>&1 \
    | grep -v "TRACE open $work" | sed "s#$work#<tmp>#g" | sort -u
  if [[ -f "$work/marker.out" ]]; then echo "ARBITRARY LIBRARY LOADED: $(cat "$work/marker.out")"; else echo "no extra library loaded"; fi
}

run "Environment cleared, PATH only (PLAN.md 2.3 as written)"
run "OPENSSL_CONF points at a hostile config" OPENSSL_CONF="$work/hostile.cnf"
run "OPENSSL_CONF=/dev/null, OPENSSL_MODULES in the copy, SSL_CERT_FILE=/etc/ssl/cert.pem" \
  OPENSSL_CONF=/dev/null OPENSSL_MODULES="$copy/lib/ossl-modules" SSL_CERT_FILE=/etc/ssl/cert.pem SSL_CERT_DIR="$copy/certs"
