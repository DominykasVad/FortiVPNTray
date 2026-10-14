# FortiVPNTray fork — hardening plan (PRIMARY)

Base: upstream FortiVPNTray v0.2.3 (itstone/FortiVPNTray, MIT), Swift app + Rust helper.
Fallback base if this one turns out unworkable: openfortivpn-connect v0.1.9
(separate PLAN.md in that tree).

Goal: native macOS menu-bar client for openfortivpn (SAML / Entra) whose root
helper is safe even when a hostile process runs as the logged-in user.

## Hard constraints

- **No paid Apple Developer account. Ever.** Nothing in this plan may depend on a
  Team ID, Developer ID, provisioning profile, notarization or restricted
  entitlement. Signing = ad-hoc or a local self-signed code-signing certificate.
- **No `SMAppService`.** Ad-hoc daemons get pinned by cdhash and break on every
  rebuild; behaviour with self-signed identities is unverified. Install stays
  `install -o root` + `launchctl bootstrap` via an admin prompt (as today).
- No entitlements, no App Sandbox, no App Groups, no keychain access groups.
- Every risky assumption is proven by a throwaway **spike** first, and every
  spike has a **fallback** that keeps the project alive if it fails.

## Status

**Current phase: 3**, starting with 3.0. Phases 0–2 are done (all tasks merged).
How to work (branches, commits, definition of done, hard rules): see
`AGENTS.md`. Each phase ends with a
**task list**; one task = one sub-phase = one branch = one PR. Tick the box in
the same commit as the change. Boxes marked *(maintainer)* are ticked by the
maintainer only.

- Spikes live in `spikes/<name>/`, are self-contained, and never get wired into
  the app. Report spike results (pass/fail + evidence: command output, logs).
- Items marked **(verify)** are assumptions — confirm, report, don't build on them blind.

## Threat model

Helper runs as root. Assume any process running as the logged-in user may be
hostile. The helper API must be harmless even to such a caller; other local
users must not reach it at all. Out of scope: attacker with root; compromised FortiGate.

## Findings in v0.2.3 (why)

The Rust helper is byte-identical to openfortivpn-connect's apart from renamed paths.

| # | Where | Problem |
|---|-------|---------|
| F1 | `helper/src/server.rs` | Socket `/var/run/fortivpntray-helper.sock` mode `0666`, no peer check. |
| F2 | `helper/src/handlers.rs`, `validation.rs` | `spawn-vpn` runs caller-supplied argv as root; 4-entry blocklist. `--pppd-log=<path>`, `-c <file>` bypass it. App-side checks in `Models.swift` `Validation.extraArguments` don't count — attacker talks to the socket directly. |
| F3 | `validation.rs`, `VPNEngine.swift` | Executes user-owned `/opt/homebrew/bin/openfortivpn`, which loads user-owned Homebrew OpenSSL dylibs. |
| F4 | openfortivpn **(verify)** | Without `-c`, reads `/opt/homebrew/etc/openfortivpn/config` (user-writable); a `pppd-plugin` line runs as root. |
| F5 | `handlers.rs` | Log path prefix-checked only (`/tmp/fortivpntray-*`); root opens create+append following symlinks. |
| F6 | `handlers.rs` `kill-vpn` | Caller-supplied `gateway` becomes default route; caller-supplied pid. |
| F7 | `handlers.rs` `setup-dns` | Any caller sets system resolvers. |
| F8 | `handlers.rs` `cleanup_network` | `killall pppd` hits every pppd on the system. |
| F9 | `Models.swift` `arguments(password:)` | `-p <password>` in argv → visible in `ps`. |
| F10 | `VPNEngine.swift` `GatewayCertificate` | `ignoreCertErrors` re-fetches and trusts whatever cert is presented, every connect → MITM. |
| F11 | `Models.swift` `extraArgs` | Free-form extra args feature → more raw argv toward root. |

---

## Phase 0 — Human setup + hygiene

**Done (0.0):** signing identity `FortiVPNTray Local Signing` (self-signed
root, code signing, long validity) lives in its own keychain
`~/Library/Keychains/fvt-signing.keychain-db` (own password, locks on sleep and
after 5 min, in the user search list). The leaf SHA-1 is never stored or
typed by hand: build and installer derive it (0.2, 2.1). Test-sign worked. For `docs/signing.md` (0.2), document this
setup as it was done:
```
security create-keychain ~/Library/Keychains/fvt-signing.keychain-db
security set-keychain-settings -l -u -t 300 ~/Library/Keychains/fvt-signing.keychain-db
security list-keychains -d user -s login.keychain-db fvt-signing.keychain-db
# Keychain Access → Certificate Assistant → Create a Certificate: Self Signed Root,
# Code Signing, "Let me override defaults", long validity, location: fvt-signing
security find-certificate -c "FortiVPNTray Local Signing" -Z ~/Library/Keychains/fvt-signing.keychain-db
security unlock-keychain ~/Library/Keychains/fvt-signing.keychain-db   # per build session
# certificate trusted for code signing (user domain) — so find-identity -v lists it:
security find-certificate -c "FortiVPNTray Local Signing" -p ~/Library/Keychains/fvt-signing.keychain-db > /tmp/fvt.pem
security add-trusted-cert -r trustRoot -p codeSign -k ~/Library/Keychains/fvt-signing.keychain-db /tmp/fvt.pem
```
Rules: never "Always Allow" for codesign; back up as `.p12` outside the repo;
losing it means a new identity and a helper reinstall (re-pin).

Agent:
1. New identity, so the fork never collides with upstream installs: bundle id
   `eu.dvad.fortivpntray` (helper label `eu.dvad.fortivpntray.helper`). Update
   `AppIdentity` (`Models.swift`), `Info.plist`, helper label, socket/Mach names,
   scutil key, log names. One source of truth: a new `FortiVPNShared` target.
2. `build.sh`: signing identity from env `FVT_SIGN_IDENTITY` (+ optional
   `FVT_SIGN_KEYCHAIN`); unset → ad-hoc, and the build prints a loud warning that
   the helper will run in UID-only mode (see S1 fallback).
3. CI: cleaned up in task 0.5 (tests + build only, no releases, general PR checks, actions pinned to SHAs). CI builds are for testing, not daily use.
4. Remove `extraArgs` (F11): model field, editor UI, `Validation.extraArguments`.
   Decode-and-drop on load for old profiles.

### Tasks — phase 0
<details>
<summary>All 7 tasks done (0.0–0.6)</summary>

- [x] **0.0** *(maintainer)* Signing identity created in its own keychain, leaf SHA-1 recorded (human steps 1–3).
- [x] **0.1** New identity `eu.dvad.fortivpntray` everywhere + `FortiVPNShared` target holding `AppIdentity` (agent item 1). Mechanical rename in its own commit, separate from the new target.
- [x] **0.2** `build.sh` signing via `FVT_SIGN_IDENTITY` / `FVT_SIGN_KEYCHAIN`, ad-hoc warning; after signing, print the leaf SHA-1 read from the built app (`codesign -d --extract-certificates` + hash, or equivalent) so it can be compared with the identity; `docs/signing.md` (agent item 2).
- [x] **0.3** Remove `extraArgs`, decode-and-drop old profiles, tests (agent item 4).
- [x] **0.4** Move the package to Swift 6: `swift-tools-version: 6.0`, Swift 6 language mode for all targets. Fix strict-concurrency errors without `@unchecked Sendable` / `nonisolated(unsafe)` unless each use has a comment saying why. No behaviour change; tests stay green.
- [x] **0.5** CI: remove the release job, release-version check and artifact upload; keep tests + build + `codesign --verify`; add a general PR workflow (actionlint, file hygiene: valid YAML/JSON/plist, no merge-conflict markers, final newline, no trailing whitespace; >5 MiB guard; gitleaks on the PR commits; Markdown link check); pin all actions to commit SHAs; keep `permissions: contents: read`.
- [x] **0.6** Split CI into two workflows: `ci-general.yml` (from pr.yml; every PR + push to main, no path filter) and `ci-app.yml` (from native.yml; only on `native/**`, `helper/**`, its own file). Both: concurrency with cancel-in-progress, skip drafts, timeout-minutes, `types: [opened, synchronize, reopened, ready_for_review]`. Keep SHA pinning and `contents: read`. Update AGENTS.md CI sentence.

</details>

**Review checkpoint 0.**

---

## Phase 1 — Spikes (prove before building)

### S1 — XPC caller verification with a self-signed identity
`spikes/xpc-codesign/`: a minimal root launchd daemon exposing a Mach service
(plist `MachServices`), plus two tiny clients.
- Daemon: `NSXPCListener(machServiceName:)`; in `listener(_:shouldAcceptNewConnection:)`
  call `connection.setCodeSigningRequirement(req)` (macOS 13+) where
  `req = identifier "<client id>" and certificate leaf = H"<sha1>"`; also log
  `connection.effectiveUserIdentifier`.
- Client A signed with the self-signed identity → must succeed.
- Client B identical but ad-hoc signed → must be rejected.
- Client C signed with the identity but different identifier → must be rejected.
- Also try requirement form `anchor H"<sha1 of root>"` if leaf form misbehaves.
- Install/remove via a script using `launchctl bootstrap/bootout system`.

**Pass:** A accepted, B and C rejected, repeatable after rebuilding A (no cdhash pinning).
**Fallback if fail:** keep XPC, drop the signature requirement, enforce
`effectiveUserIdentifier == allowedUID` only. Weaker (same-user malware can
connect), which Phase 2's design already makes harmless-ish. If XPC itself
misbehaves for a launchd daemon without a team: Unix socket in a root-owned dir +
`getpeereid()` UID check.

### S2 — Root-owned copy of Homebrew's openfortivpn
Source is Homebrew (`brew install openfortivpn`); nothing is bundled or built
by us. `spikes/openfortivpn-copy/`: a script that copies
`/opt/homebrew/bin/openfortivpn` **and** every non-system dylib it loads
(recursively — OpenSSL's libssl/libcrypto) into a root-owned dir, rewrites load
paths with `install_name_tool -change` (and `-id`) to that dir, re-signs each
file ad-hoc, and writes a manifest `{file, sha256, version}` for the set.
**Pass:** `otool -L` on every copied file shows only `/usr/lib/*`, `/System/*`
or the root-owned dir; `codesign --verify` passes; `openfortivpn --version`
runs from the copy; `--saml-login` connects to the real FortiGate
(maintainer runs it). Report how versions are read: `INSTALL_RECEIPT.json`,
`--version`, OpenSSL version.
**Fallback if fail:** build pinned openfortivpn with static OpenSSL
(`no-shared`) from source and copy that single binary instead. Last resort:
copy without rewriting, verify ownership of the dylib chain at spawn time and
refuse if user-writable — document it.

### S3 — openfortivpn config handling
Read the pinned openfortivpn source (`src/main.c`, `src/config.c`):
- Does `-c <file>` fully replace the default config, or also read `SYSCONFDIR/.../config`? (F4)
- Which config keys exist (`pppd-plugin`, `pppd-log`, `pppd-ifname`, `pppd-call`, `user-cert`…)?
- Does `-v` log the SVPNCOOKIE or SAML tokens? At which verbosity?
- How does it read a password when not in argv/config (tty only?).
**Output:** short `spikes/openfortivpn-config/FINDINGS.md`. No fallback needed —
this only shapes Phase 2.

### Tasks — phase 1
<details>
<summary>All 3 tasks done (1.1–1.3)</summary>

- [x] **1.1** S1 spike: code + install/remove scripts. *(maintainer)* runs it as root and reports; agent records result.
- [x] **1.2** S2 spike: Homebrew copy + rewrite + re-sign script, manifest, `otool -L` evidence. *(maintainer)* runs it as root and does a real SAML connect.
- [x] **1.3** S3: `spikes/openfortivpn-config/FINDINGS.md`.

</details>

**Review checkpoint 1** — decide transport (S1) and binary strategy (S2) here.

---

## Phase 2 — New Swift helper (replaces `helper/` Rust crate)

Package layout (`native/Package.swift`):
- `FortiVPNShared` — constants (`AppIdentity`), Codable protocol types,
  validators (moved from `Models.swift` `Validation`), `LogParser`/`LogBuffer`
  (moved from FortiVPNCore — the helper now parses output).
- `FortiVPNHelper` — executable, runs as root under launchd.
- `FortiVPNCore` / `FortiVPNTray` — app, depend on Shared.
Delete `helper/` (Rust) once Phase 2 passes review.

Principle: **the helper owns the whole tunnel lifecycle.** No argv, paths, PIDs,
gateway IPs or DNS servers cross the boundary from the app.

### 2.1 Transport + caller check (F1)
Per S1 result: XPC Mach service with code-signing requirement **and** UID check,
or UID-only fallback. Allowed UID and (if applicable) the requirement's leaf hash
are passed as `ProgramArguments` in the plist written at install time — the
install happens behind the admin prompt, so they can't be changed silently.
The leaf hash is **derived, never configured**: the app reads it from its own
running code signature (`SecCodeCopySelf` → signing certificates → SHA-1 of the
leaf) and hands it to the install script; ad-hoc signed app (no certificate)
→ install in UID-only mode with a visible warning. Rebuilding with the same
identity keeps the hash, so no reinstall; a new identity requires Repair.
Helper refuses to start without them. Settings shows which mode is active
("Signed caller check" / "UID-only").

### 2.2 API (F2, F6, F7)
```
version() -> (helper: String, protocol: Int)
connect(ConnectRequest) -> sessionID
disconnect()
status() -> Status { state, sessionID?, iface?, vpnIP?, since?, lastError? }
readLog(sessionID, offset) -> (lines, nextOffset)
pendingSAMLURL() -> URL?            // helper parsed it; app opens the browser
```
`ConnectRequest`: `host` (hostname/IPv4, no leading `-`/`.`), `port` (1–65535),
`realm?` (`[A-Za-z0-9._-]{1,63}`; S3: openfortivpn truncates at 63 silently), `auth` = `.saml(listenPort ≥1024, default 8020)`
(SAML is the only auth method; there is no password case),
`trustedCerts` (`^[0-9a-f]{64}$`, ≤16), `useSystemDNSFallback: Bool` (no DNS
server addresses cross from the app). Reject anything else; one session at a time.

### 2.3 Spawning (F2, F3, F4)
- Config file per session in `/Library/Application Support/<label>/run/`
  (`root:wheel 0700`), file `0600`, created `O_CREAT|O_EXCL|O_NOFOLLOW`; values
  that contain `\n`, `\r`, `\0` or `=` rejected, never escaped.
- Child argv is fixed: `openfortivpn -c <that file> -v`, plus only helper-chosen
  fixed flags that have no config key. Per S3 there are none today: `set-dns`,
  `pppd-use-peerdns` and `saml-login` all have keys, so the argv is exactly those
  three arguments. No positional `host:port`. Exactly one `-v` (S3: `-vv` and
  above log HTTP bodies and worse).
- The config writer emits, in this order: `set-dns = 0`, `pppd-use-peerdns = 0`,
  `host`, `port`, `saml-login = <listen port>`, `realm` (if set), one
  `trusted-cert` line per pin. `-c` fully replaces the default config (S3), so
  nothing else is read. An unknown key silently drops the rest of the file (S3),
  so the writer only emits keys known to the pinned openfortivpn version, and a
  test parses the written file back and checks every key arrived. A config file
  the child cannot open is the helper's error; openfortivpn only warns.
- Binary per S2 at `/Library/PrivilegedHelperTools/<label>.d/openfortivpn`
  (the root-owned copy — never the Homebrew path).
  Before each spawn: file + every parent dir root-owned, not group/other
  writable, regular file, not symlink; same for every copied dylib; sha256 of the set matches the manifest, otherwise refuse.
- Child env cleared, then exactly: `PATH=/usr/bin:/bin:/usr/sbin:/sbin`,
  `OPENSSL_CONF=/dev/null`, `OPENSSL_MODULES=<root-owned dir>`,
  `SSL_CERT_FILE=/etc/ssl/cert.pem` (S2: Homebrew OpenSSL's compiled-in openssldir
  is user-writable). A test proves the child opens no `/opt/homebrew` path.
  stdout/stderr piped to the helper. Config file deleted once tunnel is up and
  on any exit.

### 2.4 Logs (F5)
Helper keeps an in-memory ring buffer per session (redacted with `LogParser.redacted`),
served via `readLog`. Redaction must cover the two secrets `-v` prints (S3): the
session cookie (`Cookie: SVPNCOOKIE=…`, the whole rest of the line) and the SAML
session id (`Using SAML authentication URL /remote/saml/auth_id?id=…`). A test
uses the exact log formats from `spikes/openfortivpn-config/FINDINGS.md`. No `/tmp` anywhere.

### 2.5 DNS, routes, cleanup (F6, F7, F8)
- Helper records original default gateway (`route -n get default`) and resolves
  server IP itself. Persists `{pid, iface, serverIP, gateway, dnsApplied}`, the
  pppd PID and each PID's identity (below) to a root-owned state file (survives
  helper restart / sleep).
- DNS through SystemConfiguration (`SCDynamicStoreCopyValue` / `SetValue` /
  `RemoveValue`), not the `scutil` binary: typed API, nothing to parse, nothing
  to inject. On "Tunnel is up": apply DNS from parsed `Found dns server/suffix`
  lines; if none parsed and `useSystemDNSFallback`, the helper uses the system
  resolvers it read itself before connecting (`State:/Network/Global/DNS`).
- Routes: `/sbin/route` via `Process` with an argument array, values only from
  validated sources (resolved server IPv4, recorded gateway, ppp iface name
  matching `^ppp[0-9]+$`).
- Disconnect: SIGINT tracked pid → SIGKILL after 2 s; record pppd's PID (child of
  the tracked openfortivpn) while openfortivpn is still alive and persist it in the
  state file; on disconnect stop that recorded pppd explicitly, because after
  SIGKILL on openfortivpn its pppd is reparented to launchd and `pgrep -P` no
  longer finds it. Never match pppd by name (F8). Remove the server host route;
  restore the default route only if it currently points at the session's ppp
  iface; remove the DNS key; flush the DNS cache with
  `/usr/bin/dscacheutil -flushcache` and `/usr/bin/killall -HUP mDNSResponder`,
  both via `Process` with argument arrays.
- Every recorded PID (openfortivpn and pppd) is stored with its start time and
  executable path. Before signalling one, verify it is still the same process:
  compare the start time (`proc_pidinfo` / `PROC_PIDTBSDINFO`,
  `pbi_start_tvsec` + `pbi_start_tvusec`) and the executable path. Mismatch →
  don't signal, just clear the state. Test with a recorded PID whose process has
  exited.
- Cleanup runs on every exit path: disconnect, child exits unexpectedly (helper
  notices, not the app), helper restart. Every step is idempotent and
  independent, so one failure doesn't skip the rest.
- State file: in a root-owned dir, written atomically (temp file
  `O_CREAT|O_EXCL|O_NOFOLLOW`, then `rename`), strict JSON decode, size limit.
  Unreadable or invalid state → log, do nothing destructive.
- Orphan sweep at helper start and before connect uses only the state file and
  the identity check above.
- Tests: every system call (signals, process info, routes, SystemConfiguration)
  is behind a protocol with a fake; unit tests never touch the real network,
  routes or DNS. Real behaviour (sleep/wake, stale routes, other pppd untouched)
  is checked in phase 4.

### 2.6 Installer
Extend `HelperInstaller` (`Helper.swift`): single admin prompt that `install`s the
helper binary root:wheel, copies openfortivpn + its dylibs from Homebrew into
`/Library/PrivilegedHelperTools/<label>.d/` per S2 (rewrite, re-sign, manifest),
refuses if Homebrew's openfortivpn is missing, creates
run/log/state dirs, writes the plist (with `MachServices`, `--allowed-uid`, and
`--client-req-leaf` or `--uid-only`), `launchctl bootout` + `bootstrap`. Uninstall removes all of
it. Version check compares **protocol** version.
- Admin step: the prompt runs one installer script. Every value interpolated into
  it is validated first (allowed UID: digits, non-zero; leaf SHA-1: 40 hex;
  everything else constants from `AppIdentity`) and shell-quoted. No caller- or
  user-supplied strings, no paths from the environment. Paths with spaces
  (`/Library/Application Support`) quoted everywhere.
- Allowed UID = the logged-in user running the app (`getuid()` of the app), never
  the sudo/root UID. Leaf hash = `CodeSignature.leafSHA1OfRunningCode()`; nil →
  `--uid-only` with a visible warning in the UI. Plist `ProgramArguments` built
  with `HelperLaunchArguments.arguments` (no hand-written flags).
- openfortivpn copy (S2, as root inside the script): same procedure as
  `spikes/openfortivpn-copy`: copy binary + every non-system dylib (found via
  `otool -L`, not hardcoded), rewrite load paths, re-sign ad-hoc, write
  `manifest.json` in exactly the format `OpenFortiVPNInstall.verify()` reads,
  create empty `certs/` (root:wheel 0755). No `ossl-modules` dir. Refuse if
  Homebrew openfortivpn is missing. After install, the app calls the helper (or
  runs verify logic) to confirm the install passes `OpenFortiVPNInstall.verify()`;
  report failure clearly.
- Replacing the Rust helper: it uses the same label and executable path. Install
  must bootout it, replace the binary, remove the old socket
  `/var/run/eu.dvad.fortivpntray.helper.sock` and old log.
- Uninstall: refuse while a session is active. Removes helper binary, plist,
  `.d` tree, run dir, state file and its dir, log. bootout first. Leaves profiles
  alone.
- Tests: script generation is unit-tested (exact output for signed and uid-only,
  quoting, refusal of bad values). The script itself is run only by the
  maintainer. The PR carries a short maintainer test procedure: install,
  `sudo launchctl print system/eu.dvad.fortivpntray.helper`, owners/modes of the
  `.d` tree, `verify()`, uninstall, nothing left.

### Tasks — phase 2
- [x] **2.0** Package layout: `FortiVPNShared` gets protocol types, validators, `LogParser`/`LogBuffer` (moves only, no behaviour change).
- [x] **2.1** Transport + caller check.
- [x] **2.2** API + `ConnectRequest` validation, with tests for every rejection rule.
- [x] **2.3** Spawning: config writer, argv builder, binary/dylib ownership checks.
- [x] **2.4** Logs: ring buffer + redaction.
- [x] **2.5** DNS, routes, cleanup, state file.
- [x] **2.6** Installer / uninstaller.
- [x] **2.7** Delete `helper/` (Rust), its CI step and build steps.

**Review checkpoint 2** — full helper diff.

---

## Phase 3 — App side

- `VPNEngine.swift`: shrink to a client of the new API; drop log file handling,
  gateway/DNS/IP resolution, `processAlive`, Homebrew existence check.
- Delete `GatewayCertificate` and `ignoreCertErrors` (F10) — model, UI, decode-and-drop.
  Keep the existing explicit cert-pin confirmation flow driven by `.certificate` events
  (events now come from the helper's parsed output).
- SAML: app polls `pendingSAMLURL()` and opens it (existing behaviour).
- Password authentication is removed from the app (3.0, F9): SAML is the only
  auth method, so nothing is read from or stored in Keychain.
- Settings: helper status shows caller-check mode; README updated
  (Homebrew openfortivpn required at install/update time only; signing doc).
- openfortivpn update check (app side, as the user, never root): compare the
  manifest of the installed copy with Homebrew's current binary + dylibs by
  **hash of the whole set** (OpenSSL can change without openfortivpn's version
  changing). On difference show installed vs. Homebrew versions (openfortivpn
  and OpenSSL) and offer **Update**, which re-runs the copy step behind one
  admin prompt. Declining keeps the working copy. Never auto-update. Disabled
  while connected.
- Interface byte counters can stay app-side (unprivileged `getifaddrs`).
- 3.1: the app opens `pendingSAMLURL()` only if it is https, its host and port
  equal the profile's, and its path is `/remote/saml/start`. The helper builds it
  from the validated request, but the app checks it anyway before
  `NSWorkspace.open`.
- 3.1: `VPNEngine`'s old `/tmp` session log and the Rust-era `AppIdentity` names
  go; after that, remove the Rust-era constants that only the installer cleanup
  still needs, or keep just those two with a comment.
- 3.2: the cert-pin flow needs the gateway's digest. The helper exposes only
  redacted log lines; check that openfortivpn's `trusted-cert = <digest>` hint
  survives redaction and is parsed app-side from `readLog`, or add a typed field
  to `HelperStatus`. Decide and record it.
- 3.4: the app reads `manifest.json` (root-owned, 0644) for installed hashes and
  source hashes; never trusts it for anything the helper relies on.

### Tasks — phase 3
- [x] **3.0** Remove password authentication from the app (F9): `AuthType` and its editor radio, username field, Keychain password storage and access, related tests. No migration: there are no existing profiles or saved passwords to carry over. Docs updated in 3.3.
- [x] **3.1** `VPNEngine` as client of the new API; SAML URL polling.
- [x] **3.2** Delete `GatewayCertificate` / `ignoreCertErrors` (decode-and-drop); cert-pin flow from helper events.
- [ ] **3.3** Settings shows caller-check mode; README + native/README updated.
- [ ] **3.4** openfortivpn update check + Update action (runs through the admin-prompt install path, like Repair — **not** a new helper API call: a same-user caller must not be able to trigger a re-copy).
- [ ] **3.5** SAML login window, chosen per profile like FortiClient: a profile setting
  "Use external browser for SAML" (default off).
  - Off (embedded): ASWebAuthenticationSession (no entitlement;
    prefersEphemeralWebBrowserSession = false, so the Safari/Entra session and "stay signed in"
    are shared). The redirect to 127.0.0.1:<listen port> is loaded by the window and reaches
    openfortivpn as before; the app closes the window when the helper reports connected, on
    disconnect or failure; user cancel → disconnect.
  - On (external): NSWorkspace.open in the default browser, as now.
  - Both only with a URL that passes SAMLLogin.isExpected. The setting is app-side only and
    never sent to the helper. Old profiles decode with the default. Decision-log line.

**Review checkpoint 3.**

---

## Phase 4 — Tests and attack checklist

Unit: validators (leading `-`, `=`, whitespace, newline, unicode, overlong),
config writer rejection cases, argv builder exact output (SAML-only, fixed argv),
`LogParser` with real log samples (move existing `CoreTests` cases accordingly).

Manual, maintainer on the Mac (report pass/fail):
1. SAML connect/disconnect; split DNS resolves internal names.
2. Sleep with tunnel up → wake → disconnect/reconnect clean, no stale routes.
3. Second macOS user cannot connect to the helper.
4. Ad-hoc-signed copy of the app (or a test client) is rejected (S1 pass mode only).
5. Hostile same-user client: `connect` with host `-c/tmp/x`, realm with newline → rejected.
6. `pppd-plugin = /tmp/x.so` in `/opt/homebrew/etc/openfortivpn/config` → not loaded.
7. `otool -L` on installed openfortivpn and its dylibs → only system libs or root-owned rewritten paths.
7a. Replace `/opt/homebrew/bin/openfortivpn` with a script → connect still uses the root copy; app offers Update showing a mismatch.
7b. Upgrade only the OpenSSL formula openfortivpn links (currently `openssl@4`, found via `otool -L`) → app detects the change.
8. Built-in L2TP/other pppd untouched by disconnect.
9. Rebuild + reinstall app with same identity → helper still accepts it.
10. Kill openfortivpn with SIGKILL while connected (`sudo kill -9 <pid>`) → after the helper's
    cleanup the Mac still has a working default route and DNS (ping, name lookup). If not,
    record what macOS did and open a fix task.

### Tasks — phase 4
- [ ] **4.1** Unit tests listed above.
- [ ] **4.2** *(maintainer)* Manual checklist 1–10, results recorded here.

**Review checkpoint 4.**

## Decision log

One line per real decision (a choice between alternatives that later work must
respect): `YYYY-MM-DD · task · decision · why`. Never edit or delete an entry;
supersede it with a new one that names the old.

- 2026-10-13 · — · FortiVPNTray is primary, openfortivpn-connect is fallback · native Swift, smaller surface than Tauri.
- 2026-10-13 · — · No paid Apple account, no SMAppService · see Hard constraints.
- 2026-10-13 · — · openfortivpn is never bundled in the app or its release zip; a separate installer (from S2's build) puts it in the root-owned dir · keeps the MIT app free of GPLv3 distribution obligations.
- 2026-10-13 · — · Supersedes the previous line: no separate installer. The helper installer copies Homebrew's openfortivpn + dylibs into the root-owned dir on admin approval; the app detects Homebrew changes by set hash and offers Update; never bundled · root must not run user-writable files (F3), copying locally is not distribution, user decides on every update.
- 2026-10-13 · 0.4 · Whole package on Swift 6 language mode before phase 2 · the new root helper is written in strict concurrency from the start instead of migrated later.
- 2026-10-13 · 0.5 · No GitHub Releases from CI; CI only tests and builds · CI builds are ad-hoc signed and would run the helper in UID-only mode, and the fork is not distributed.
- 2026-10-13 · 0.6 · Two workflows: general checks always, app build/tests only when native/ or helper/ change; no separate Rust workflow · build.sh compiles the helper into the app anyway, and the Rust helper is removed in 2.7.
- 2026-10-13 · 1.1 · S1 passed: XPC Mach service with `setCodeSigningRequirement` (identifier + certificate leaf hash) plus UID check; UID-only fallback not needed · self-signed identity accepted, ad-hoc and wrong identifier rejected, rebuild with same identity still accepted.
- 2026-10-13 · 1.2 · S2 passed: root-owned copy of Homebrew openfortivpn + OpenSSL dylibs, paths rewritten, re-signed, manifest with installed and shipped hashes · real SAML connect through the copy worked.
- 2026-10-13 · 1.2 · Child OpenSSL pinned via OPENSSL_CONF=/dev/null, OPENSSL_MODULES=<root dir>, SSL_CERT_FILE=/etc/ssl/cert.pem; no static build · Homebrew OpenSSL's compiled-in openssldir is user-writable and openssl.cnf can load code as root.
- 2026-10-13 · 1.3 · Password authentication dropped; SAML is the only auth method · the gateway uses SAML/Entra; removes Keychain handling, password transport to root and F9 entirely.
- 2026-10-13 · 1.3 · Child argv is fixed (`-c <file> -v` + helper-chosen flags without a config key); host, port, realm, trusted certs etc. only in the validated config file · nothing caller-derived reaches argv; S3 showed -c fully replaces the default config.
- 2026-10-13 · 2.1 · UID-only mode needs an explicit `--uid-only` launch argument; `--allowed-uid` without `--client-req-leaf` or `--uid-only` is an error · a damaged or hand-edited plist must not silently start the helper with the weaker caller check.
- 2026-10-14 · 2.2 · Structured XPC values (`ConnectRequest`, `HelperStatus`, `LogChunk`) travel as JSON `Data`; the helper decodes strictly (unknown or missing keys, wrong types, over 16 KiB → rejected) and validation runs inside decoding · one parser for hostile input, no NSSecureCoding classes in root, and a decoded request is always a valid one.
- 2026-10-14 · 2.2 · Trusted-cert fingerprints are lowercase only at the helper (`^[0-9a-f]{64}$`); the app lowercases before validating and sending · the helper applies the plan's rule as written and does no normalising of caller input.
- 2026-10-14 · 2.2 · `--allowed-uid 0` is rejected by both the launch-argument builder and parser · the helper serves one logged-in user; a 0 most likely means the installer took the UID of `sudo`.
- 2026-10-14 · 2.2 · No DNS server addresses cross from the app; ConnectRequest carries only `useSystemDNSFallback`, the helper reads the system resolvers itself · any caller-chosen resolver, however range-checked, would let a same-user attacker redirect all DNS while the tunnel is up (F7).
- 2026-10-14 · 2.3 · Child SSL_CERT_DIR = empty root-owned <label>.d/certs, checked before spawn · Homebrew OpenSSL's compiled-in certs dir is user-writable and is consulted during gateway verification even with SSL_CERT_FILE set; a CA dropped there would make a forged gateway cert pass.
- 2026-10-14 · 2.3 · A disconnect while the launcher's start is still running is recorded and acted on when start returns; the launcher's stop never runs alongside its start · the child may be spawned before its PID is recorded, and only after start returns can stop reach it, so it is never left running.
- 2026-10-14 · 2.4 · The session log belongs to the session id and is kept until the next connect, independent of the session state; output after the child's exit or a disconnect is still stored · the child's last lines (usually the reason it failed) can arrive after its exit is reported, and `readLog` of the last session must show them.
- 2026-10-14 · 2.4 · `pendingSAMLURL` is built by the helper from the validated request (`https://<host>:<port>/remote/saml/start?redirect=1[&realm=…]`) and offered only once the child printed exactly that URL; the URL is redacted from the log · nothing from the child's output reaches the browser, and SAML URLs are never logged.
- 2026-10-14 · 2.4 · No on-disk log copy; the session log is in memory only · every file copy is another place unredacted output could end up; the in-memory log covers error reporting.
- 2026-10-14 · 2.5 · DNS state is read and written through SystemConfiguration (`SCDynamicStore…`), not the `scutil` binary · typed API, nothing to parse, nothing to inject.
- 2026-10-14 · 2.5 · Flush DNS cache with dscacheutil and SIGHUP to mDNSResponder · dscacheutil alone leaves mDNSResponder's cache, so internal names could resolve to stale VPN answers after disconnect; HUP only flushes, it does not stop the daemon.
- 2026-10-14 · 2.5 · The default route is restored only while the recorded pppd is still the same running process, besides pointing at the session's ppp interface · once that pppd is gone its interface name can belong to another VPN's pppd, whose default route must stay untouched.
- 2026-10-14 · 2.5 · A recorded PID that fails the identity check is skipped; the other cleanup steps still run and the state is removed afterwards · a stale host route and the DNS key are exactly what a crashed session leaves, and they are removed by validated value, not by PID.
- 2026-10-14 · 2.5 · Connect is refused if the state file cannot be saved, and it is saved before openfortivpn is started · without it a helper crash would leave routes and DNS nothing can undo.
- 2026-10-14 · 2.6 · The install is confirmed inside the admin script: the newly installed helper runs as root with `--verify-install` (the same `OpenFortiVPNInstall.verify()` as before each spawn) and the job is bootstrapped only if it passes · the app has no XPC call for it, and as the user it could not run the check with root's trust rules.
- 2026-10-14 · 2.6 · The installer refuses a helper copy whose sha256 differs from what the app hashed before the prompt; the copied openfortivpn is never run during install (versions come from the keg name and `strings`) · the bundle is user-writable and could be swapped during the prompt; running the copy as root without the helper's OpenSSL environment could read user-writable OpenSSL configuration.
- 2026-10-14 · 2.6 · Uninstall is refused if the helper reports a session over XPC, and the script also refuses while the state file exists · removing the helper mid-session would leave routes and DNS nobody cleans up; the state-file check works even when the helper cannot be asked.
- 2026-10-14 · 3.1 · The app takes connected/ended from the helper's `status()`, not from log lines; the log is used for display and the certificate digest only · the helper owns the session, and its status also covers ends the log never shows (helper restart, another client's disconnect).
- 2026-10-14 · 3.1 · Of the Rust-era names only `AppIdentity.socketPath` and `helperLogPath` stay, commented, for the installer's cleanup · nothing else uses them; `helperVersion`, `sessionLogPrefix`, the socket client and `LogBuffer` are gone.
- 2026-10-14 · 3.1 (fix) · Gateway-pushed DNS suffix lists: the whole `Found dns suffix …` value is split at ';', ',' and whitespace, each part checked with `Validation.hostname`, empty or invalid parts dropped, duplicates merged, at most 16 kept · openfortivpn prints the gateway's `domain=` value as one string, and a list with spaces after the ';' kept only its first suffix.
- 2026-10-14 · 3.2 · The pin prompt's digest is parsed app-side from `readLog`, not a typed `HelperStatus` field, and only from openfortivpn's exact hint line (`ERROR:      --trusted-cert <64 lowercase hex>`) directly after its failure line · redaction leaves those lines intact and the API stays unchanged; the certificate's subject and issuer follow as gateway-controlled lines split at '/', so any looser match would let a gateway propose the digest to pin.

## Open questions

- (none)

## Later / optional
- Auto-reconnect after wake, connect on launch.
- Intel build (Homebrew prefix `/usr/local`; drop the `uname -m` gate).
- Never: SMAppService, notarization, anything needing a Team ID.
