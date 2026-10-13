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

## Result

**PASS**, run by the maintainer on 2026-10-13, macOS 15.7.9 (Apple Silicon).

| Mode | Run | Outcome |
|---|---|---|
| `leaf` | yes | A accepted, B and C rejected; same after rebuilding A with a different cdhash |
| `root` | no | not needed: `leaf` passed, and for this identity leaf and root are the same certificate |
| `uid-only` | no | fallback not needed |

Output of `run.sh` in `leaf` mode. The only change is the certificate hash in the
daemon's start line, replaced by `<leaf sha1>` because the leaf hash is not stored
in the repository:

```
== First build
client-a   expected=accept exit=0 ok         cdhash=11a215c215fa3b9ff1a548d0e44d48acc15ca283
           ACCEPTED: daemon says accepted pid=23105 uid=501 [first build]
client-b   expected=reject exit=1 ok         cdhash=3e1886f3ba739358c609fe15db9833d0297b003c
           REJECTED: Couldn’t communicate with a helper application. [first build]
client-c   expected=reject exit=1 ok         cdhash=95e45dc7eb426905f2386fbec6bbe658e6eea9ea
           REJECTED: Couldn’t communicate with a helper application. [first build]
== Rebuild client A with the same identity (different binary, different cdhash)
/Users/dvadeisa/Repositories/FortiVPNTray/spikes/xpc-codesign/dist/daemon: replacing existing signature
/Users/dvadeisa/Repositories/FortiVPNTray/spikes/xpc-codesign/dist/client-a: replacing existing signature
/Users/dvadeisa/Repositories/FortiVPNTray/spikes/xpc-codesign/dist/client-b: replacing existing signature
/Users/dvadeisa/Repositories/FortiVPNTray/spikes/xpc-codesign/dist/client-c: replacing existing signature
client-a   expected=accept exit=0 ok         cdhash=6f6efe09aaaa154072b8172fbd4255cca99a8bf5
           ACCEPTED: daemon says accepted pid=23196 uid=501 [rebuilt 1791892383]
client-b   expected=reject exit=1 ok         cdhash=8768d7f65960ed56384918362343a8b23bafcc85
           REJECTED: Couldn’t communicate with a helper application. [rebuilt 1791892383]
client-c   expected=reject exit=1 ok         cdhash=2df964a825511f2102840541f52e6bbfafcd5f90
           REJECTED: Couldn’t communicate with a helper application. [rebuilt 1791892383]
== Daemon log (/var/log/eu.dvad.fortivpntray.spike.xpc.log)
starting as uid=0 service=eu.dvad.fortivpntray.spike.xpc allowed-uid=501 requirement=identifier "eu.dvad.fortivpntray.spike.client" and certificate leaf = H"<leaf sha1>"
connection from pid=23021 uid=501
whoAmI: accepted pid=23021 uid=501
connection from pid=23027 uid=501
connection from pid=23036 uid=501
connection from pid=23105 uid=501
whoAmI: accepted pid=23105 uid=501
connection from pid=23110 uid=501
connection from pid=23115 uid=501
connection from pid=23196 uid=501
whoAmI: accepted pid=23196 uid=501
connection from pid=23201 uid=501
connection from pid=23206 uid=501
RESULT: PASS (signed)
```

How to read the daemon log:

- Every client reaches `shouldAcceptNewConnection` ("connection from"), because the
  requirement is enforced after that, when the first message arrives. Only client A
  gets as far as `whoAmI`; B and C have their message dropped and the connection
  invalidated, which the client sees as "Couldn’t communicate with a helper application".
- The first three connections (pids 23021, 23027, 23036) are from an earlier `run.sh`
  against the same installed daemon, which stopped at the rebuild step because
  `FVT_SIGN_IDENTITY` was not exported in that shell. Its output is not recorded here.
- The run above is pids 23105 to 23115 (first build) and 23196 to 23206 (after the rebuild).

What this settles for phase 2 (PLAN.md 2.1):

- An XPC Mach service of a root launchd daemon can pin its callers with
  `setCodeSigningRequirement("identifier … and certificate leaf = H…")` using a
  self-signed identity, with no Team ID.
- The pin is on the certificate, not the cdhash: client A was accepted with two
  different cdhashes.
- An ad-hoc signed binary with the right identifier and a correctly signed binary
  with another identifier are both rejected.

Not covered by this run: a caller from a second macOS user, and modes `root` and `uid-only`.

When this result was recorded, the spike daemon was still installed on the
maintainer's Mac; `sudo spikes/xpc-codesign/uninstall.sh` removes it.
