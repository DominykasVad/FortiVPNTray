# S2 — Root-owned copy of Homebrew's openfortivpn

Throwaway spike for PLAN.md phase 1, task 1.2. Not part of the app.

**Question:** can Homebrew's `openfortivpn` and the libraries it loads be copied into a
root-owned directory so that root never executes or loads anything under `/opt/homebrew`?

**Answer:** yes, with one addition. The binary and its dylibs copy cleanly, but
OpenSSL also reads a configuration file and a CA bundle from paths compiled into the
library, both under `/opt/homebrew`, and the configuration file can load code. The
helper therefore also pins three OpenSSL environment variables; see
[Finding](#finding-openssl-reads-user-writable-files-that-are-not-dylibs) and
[Result](#result).

## What is here

| File | Purpose |
|---|---|
| `copy.sh` | Copies the binary and every non-system dylib it loads, rewrites load paths, re-signs ad-hoc, writes `manifest.json`, then runs `verify.sh` |
| `verify.sh` | Checks a copy: `otool -L`, signatures, manifest hashes, ownership of every file and parent directory, `--version` |
| `remove.sh` | **sudo.** Deletes the root-owned copy |
| `openssl-paths.sh` | Shows which files the copied OpenSSL reads and that a config file can load arbitrary code (no root) |
| `probe/` | Three small C files used by `openssl-paths.sh` |

`sudo copy.sh` writes only to
`/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.spike.openfortivpn.d/`
(`openfortivpn`, `lib/*.dylib`, `manifest.json`). `remove.sh` deletes that directory.
With a directory argument and no sudo, `copy.sh` does a dry run there.

## How the copy is made

1. Resolve `/opt/homebrew/bin/openfortivpn` to its real file and copy it.
2. Read the **copy's** load commands. For each one outside `/usr/lib` and `/System`:
   resolve it, copy the real file to `lib/`, set its id (`install_name_tool -id`) and
   point the referrer at it (`install_name_tool -change`). Repeat for each copied
   library until nothing outside the directory is left.
3. Re-sign every file ad-hoc, because rewriting load commands breaks the signature.
4. Write the manifest and, as root, `chown -R root:wheel`.

Only copies are inspected, so a file that changes under `/opt/homebrew` during the
run cannot differ from what was checked. `@rpath` and `@loader_path` references and
two different libraries with the same file name stop the script; neither occurs today.

## Dry-run evidence (agent, no root)

`copy.sh <scratch directory>` on macOS 15.7.9, openfortivpn 1.24.1 (keg `1.24.1_1`),
OpenSSL 4.0.3:

```
== Load commands (otool -L)
        <dest>/lib/libssl.4.dylib (compatibility version 4.0.0, current version 4.0.0)
        <dest>/lib/libcrypto.4.dylib (compatibility version 4.0.0, current version 4.0.0)
        /usr/lib/libutil.dylib (compatibility version 1.0.0, current version 1.0.0)
        /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
ok    openfortivpn loads only system libraries and <dest>
        <dest>/lib/libcrypto.4.dylib (compatibility version 4.0.0, current version 4.0.0)
        /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
ok    lib/libcrypto.4.dylib loads only system libraries and <dest>
        <dest>/lib/libssl.4.dylib (compatibility version 4.0.0, current version 4.0.0)
        <dest>/lib/libcrypto.4.dylib (compatibility version 4.0.0, current version 4.0.0)
        /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
ok    lib/libssl.4.dylib loads only system libraries and <dest>
== Signatures
ok    openfortivpn signature valid
ok    lib/libcrypto.4.dylib signature valid
ok    lib/libssl.4.dylib signature valid
== Manifest
ok    openfortivpn matches the manifest
ok    lib/libcrypto.4.dylib matches the manifest
ok    lib/libssl.4.dylib matches the manifest
ok    manifest lists exactly the 3 files present
== Runs from the copy
ok    openfortivpn --version: 1.24.1
```

The ownership section fails in a dry run, as it must: the scratch directory is not
root-owned. The real destination's parents are already suitable
(`/`, `/Library` and `/Library/PrivilegedHelperTools` are `root:wheel 755`).

Before the copy, Homebrew's binary loaded
`/opt/homebrew/opt/openssl@4/lib/libssl.4.dylib` and `libcrypto.4.dylib`, and
`libssl` loaded `libcrypto` through a second path
(`/opt/homebrew/Cellar/openssl@4/4.0.3/lib/libcrypto.4.dylib`). Both resolve to the
same file and become one copy.

## Manifest

```json
{
  "openfortivpn_version": "1.24.1",
  "openssl_version": "OpenSSL 4.0.3 29 Sep 2026",
  "homebrew_keg": "1.24.1_1",
  "set_sha256": "<hash of the copied files>",
  "source_set_sha256": "<hash of the files as Homebrew shipped them>",
  "files": [
    { "file": "openfortivpn", "sha256": "…", "source": "/opt/homebrew/Cellar/openfortivpn/1.24.1_1/bin/openfortivpn", "source_sha256": "…" },
    { "file": "lib/libcrypto.4.dylib", "sha256": "…", "source": "/opt/homebrew/Cellar/openssl@4/4.0.3/lib/libcrypto.4.dylib", "source_sha256": "…" },
    { "file": "lib/libssl.4.dylib", "sha256": "…", "source": "/opt/homebrew/Cellar/openssl@4/4.0.3/lib/libssl.4.dylib", "source_sha256": "…" }
  ]
}
```

Two hashes per file are needed, and this shapes phases 2 and 3:

- `sha256` is the installed file. The helper compares it before each spawn (PLAN.md 2.3).
- `source_sha256` is the file as copied, before rewriting. The update check (3.4)
  must compare **these** with `/opt/homebrew`, because the installed files differ
  from their sources by design: rewriting and re-signing changes every hash.
- The copy is deterministic: two runs to the same destination give identical
  manifests. A different destination path gives different installed hashes and the
  same source hashes.

## How versions are read

| What | Source | Trust |
|---|---|---|
| openfortivpn version | `<copy>/openfortivpn --version` → `1.24.1` | from the copied binary itself |
| OpenSSL version | version string inside the copied `libcrypto` (`strings`) → `OpenSSL 4.0.3 29 Sep 2026` | from the copied library itself |
| Homebrew revision | keg directory name → `1.24.1_1` | user-writable path, informational |
| Dependency versions | `INSTALL_RECEIPT.json` → `runtime_dependencies` lists `openssl@4 4.0.3` and `ca-certificates 2026-09-25` | user-writable file, informational |

The dylib's Mach-O "current version" is `4.0.0` for every OpenSSL 4.x and says
nothing useful. No `openssl` executable is copied, so `openssl version` is not available.

## Finding: OpenSSL reads user-writable files that are not dylibs

Homebrew's OpenSSL has these directories compiled in (`openssl version -a`, and the
same strings are inside `libcrypto`):

```
OPENSSLDIR: "/opt/homebrew/etc/openssl@4"
MODULESDIR: "/opt/homebrew/Cellar/openssl@4/4.0.3/lib/ossl-modules"
```

Both are owned by the logged-in user. Rewriting load commands does not change them.
`openssl-paths.sh` runs a small program that makes the same first OpenSSL calls as
openfortivpn (`SSL_CTX_new`, `SSL_CTX_set_default_verify_paths`; both are imported by
the openfortivpn binary) against the **copied** libraries:

```
== Environment cleared, PATH only (PLAN.md 2.3 as written)
SSL_CTX_new: ok, set_default_verify_paths: 1
TRACE fopen /opt/homebrew/etc/openssl@4/cert.pem
TRACE fopen /opt/homebrew/etc/openssl@4/openssl.cnf
no extra library loaded
== OPENSSL_CONF points at a hostile config
SSL_CTX_new: ok, set_default_verify_paths: 1
TRACE fopen /opt/homebrew/etc/openssl@4/cert.pem
ARBITRARY LIBRARY LOADED: loaded into pid 29003, uid 501, euid 501
== OPENSSL_CONF=/dev/null, OPENSSL_MODULES in the copy, SSL_CERT_FILE=/etc/ssl/cert.pem
SSL_CTX_new: ok, set_default_verify_paths: 1
TRACE fopen /etc/ssl/cert.pem
no extra library loaded
```

What this shows:

1. With the environment cleared, as PLAN.md 2.3 specifies, the copied libraries still
   open `/opt/homebrew/etc/openssl@4/openssl.cnf` and `cert.pem`.
2. An OpenSSL config file can name a provider module by path, and the library loads
   it. Whoever can write `openssl.cnf` therefore runs code in the process, which in
   the helper's child is root. This is the same class of problem as F3 and F4, through
   a file that is not a dylib.
3. A user-writable `cert.pem` lets the same user add a CA and have a forged gateway
   certificate accepted.
4. Three environment variables remove every Homebrew path from the trace:
   `OPENSSL_CONF=/dev/null`, `OPENSSL_MODULES=<root-owned directory>`,
   `SSL_CERT_FILE=/etc/ssl/cert.pem` (macOS ships it `root:wheel 644`).
   OpenSSL ignores these variables only in set-uid programs; a child of a root
   launchd daemon is not one.

Limits of this evidence: the hostile config was supplied through `OPENSSL_CONF`, not
by editing Homebrew's file, which the agent does not modify; that the default file is
*read* is shown by the first run. openfortivpn itself was not run this far, because it
exits without root before touching OpenSSL.

When the spike was written, PLAN.md 2.3 cleared the child environment and set only
`PATH`. Two ways out were put to the owner: the helper also sets the three variables
above, with fixed, helper-chosen values; or the S2 fallback, a statically linked
openfortivpn built with a root-owned `--openssldir`. The first was chosen; see
[Result](#result).

## Running it (maintainer)

```bash
sudo spikes/openfortivpn-copy/copy.sh          # expect RESULT: PASS, ownership included
spikes/openfortivpn-copy/verify.sh             # same checks again, without root

# Real SAML connect from the copy, with the environment the helper would use:
dest=/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.spike.openfortivpn.d
sudo env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  OPENSSL_CONF=/dev/null OPENSSL_MODULES="$dest/lib/ossl-modules" SSL_CERT_FILE=/etc/ssl/cert.pem \
  "$dest/openfortivpn" <host>:<port> --saml-login -c /dev/null -v

sudo spikes/openfortivpn-copy/remove.sh
```

`-c /dev/null` keeps Homebrew's own openfortivpn config out of the test; the copy
accepts it without complaint. Whether `-c` fully replaces the default config is S3's
question. Add `--trusted-cert=<digest>` or `--realm=<name>` if your gateway needs
them. Do not paste the gateway host, certificate digests or the SAML URL into the
result; `RESULT: PASS` from `copy.sh` and "tunnel came up / did not" are enough.

**Pass:** `copy.sh` as root ends with `RESULT: PASS`, and the SAML connect brings the
tunnel up from the copy.

## Result

**PASS**, run by the maintainer on 2026-10-13, macOS 15.7.9 (Apple Silicon),
openfortivpn 1.24.1 with OpenSSL 4.0.3 from Homebrew.

| Step | Outcome |
|---|---|
| `sudo copy.sh` | `RESULT: PASS`, ownership checks included |
| `verify.sh` (no root) | passed |
| Real connect from the copy | `--saml-login` with the env-pinned OpenSSL brought the tunnel up |

The connect used the environment shown under "Running it": `PATH`,
`OPENSSL_CONF=/dev/null`, `OPENSSL_MODULES` inside the copy and
`SSL_CERT_FILE=/etc/ssl/cert.pem`. Gateway host, port, certificate digests and the
SAML URL are deliberately not recorded.

### SAML and a non-default VPN port

The first SAML attempts timed out with openfortivpn waiting on `127.0.0.1:8020`.
The cause was on the gateway, not in the copy: its SAML service-provider URLs had no
port, while SSL VPN listens on a non-default port, so the browser was never sent back
to a place that leads to the local listener. It was fixed on the gateway; the SP URLs
now include the VPN port.

Requirement for the external-browser flow, worth stating in the user documentation
(3.3): the gateway's SAML SP entity ID and ACS URL must use the SSL VPN `host:port`.

### Decision

The owner accepted the environment approach (PLAN.md decision log, 2026-10-13, 1.2):
the helper pins the child's OpenSSL paths with the three variables, and there is no
static build. PLAN.md 2.3 now lists them and requires a test that the child opens no
`/opt/homebrew` path.

When this result was recorded, the root-owned copy was still present on the
maintainer's Mac; `sudo spikes/openfortivpn-copy/remove.sh` deletes it.
