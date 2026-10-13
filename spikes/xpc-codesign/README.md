# S1 — XPC caller verification with a self-signed identity

Throwaway spike for PLAN.md phase 1, task 1.1. Not part of the app.

**Question:** can a root launchd daemon accept XPC connections only from a client
signed with the local self-signed identity, without a Team ID, and keep accepting
that client after it is rebuilt?

## What is here

| File | Purpose |
|---|---|
| `Sources/daemon/main.swift` | Root daemon: `NSXPCListener(machServiceName:)`, UID check, `setCodeSigningRequirement` |
| `Sources/client/main.swift` | Client: calls the daemon once, prints `ACCEPTED` or `REJECTED` |
| `Sources/Protocol.swift` | The one-method XPC interface |
| `build.sh` | Builds and signs the daemon and clients A, B, C into `dist/` (no root) |
| `selftest.sh` | Unprivileged check over an anonymous listener (no root, nothing installed) |
| `install.sh` | **sudo.** Installs the daemon as a launchd job in mode `leaf`, `root` or `uid-only` |
| `run.sh` | Runs A, B, C against the installed daemon, rebuilds A, runs them again (no root) |
| `uninstall.sh` | **sudo.** Removes everything `install.sh` created |

The three clients are the same program, signed differently:

| Client | Signature | Identifier | Expected |
|---|---|---|---|
| A | local identity | `eu.dvad.fortivpntray.spike.client` | accepted |
| B | ad-hoc | `eu.dvad.fortivpntray.spike.client` | rejected |
| C | local identity | `eu.dvad.fortivpntray.spike.other` | rejected |

Requirement the daemon sets on every connection, with the hash read from `dist/client-a`:

- mode `leaf`: `identifier "eu.dvad.fortivpntray.spike.client" and certificate leaf = H"<sha1>"`
- mode `root`: `identifier "eu.dvad.fortivpntray.spike.client" and certificate root = H"<sha1>"`
- mode `uid-only`: no requirement; only `effectiveUserIdentifier == allowed uid` (the fallback)

## What `install.sh` puts on the system

- `/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.spike.xpc` (the daemon)
- `/Library/LaunchDaemons/eu.dvad.fortivpntray.spike.xpc.plist`
- `/var/log/eu.dvad.fortivpntray.spike.xpc.log`
- the launchd job `system/eu.dvad.fortivpntray.spike.xpc`

Nothing else, and nothing named like the app, its helper or an upstream install.
`uninstall.sh` removes all four. The daemon only answers `whoAmI`; it does nothing privileged.

## Running it (maintainer)

```bash
security unlock-keychain ~/Library/Keychains/fvt-signing.keychain-db
export FVT_SIGN_IDENTITY="FortiVPNTray Local Signing"
export FVT_SIGN_KEYCHAIN="$HOME/Library/Keychains/fvt-signing.keychain-db"

spikes/xpc-codesign/build.sh
spikes/xpc-codesign/selftest.sh                # optional, no root

sudo spikes/xpc-codesign/install.sh leaf
spikes/xpc-codesign/run.sh                     # expect RESULT: PASS (signed)

sudo spikes/xpc-codesign/install.sh root       # the other requirement form
spikes/xpc-codesign/run.sh

sudo spikes/xpc-codesign/install.sh uid-only   # the fallback
spikes/xpc-codesign/run.sh uid-only            # expect all three accepted

sudo spikes/xpc-codesign/uninstall.sh
```

`run.sh` rebuilds client A, so it needs the two `FVT_SIGN_*` variables and an
unlocked keychain in the same shell. Paste the full output of each `run.sh` below.

**Pass:** in `leaf` mode (or, failing that, `root` mode) A is accepted, B and C are
rejected, and the same holds after A is rebuilt with a different cdhash.

## Checked without root (agent)

These do not replace the run above; they only show the pieces work before anything is installed.

- `build.sh` compiles both programs in Swift 6 language mode and signs them. Client A's
  designated requirement is `identifier "eu.dvad.fortivpntray.spike.client" and certificate leaf = H"…"`;
  the ad-hoc client B's is a bare `cdhash`.
- The certificate chain of a binary signed with the identity holds one certificate, so
  leaf and root are the same hash and the two requirement forms differ only in wording.
- `codesign --verify -R '<requirement>'` on the files: A satisfies both forms; B and C fail both.
- Rebuilding A with a different build note changes its cdhash and keeps the leaf hash.
- `selftest.sh`, where the daemon binary connects to itself over an anonymous listener
  using the same delegate and `setCodeSigningRequirement` call:

  ```
  self-test uid-only: accepted (ok)
  self-test leaf, own identifier: accepted (ok)
  self-test root, own identifier: accepted (ok)
  self-test leaf, other identifier: rejected (ok)
  self-test leaf, other certificate: rejected (ok)
  ```

- With no daemon installed, each client prints `REJECTED` and exits 1.
- The plist commands in `install.sh` produce a valid plist with `MachServices` and the
  expected `ProgramArguments` when run against a temporary file.

Not checked by the agent: anything in `install.sh` or `uninstall.sh` as root, a real
launchd Mach service, a connection from a second macOS user.

## Finding for phase 2: Swift 6 isolation traps

The first version of the client crashed with `SIGTRAP` (exit 133) as soon as XPC
called its error handler. Top-level code in `main.swift` is main-actor isolated in
Swift 6, a closure written there inherits that isolation, and the runtime traps when
XPC runs it on its own queue. The compiler did not warn. The helper must create its
XPC handlers in nonisolated code and mark them `@Sendable`, as this spike now does.

## Result (maintainer run)

_Not run yet._
