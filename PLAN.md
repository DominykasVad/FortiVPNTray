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

**Current phase: 2**, starting with 2.0. Phases 0 and 1 are done (all tasks merged).
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
`trustedCerts` (`^[0-9a-f]{64}$`, ≤16), `dnsFallback: [IPv4]` (≤4, only used if
the tunnel provides no DNS). Reject anything else; one session at a time.

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
uses the exact log formats from `spikes/openfortivpn-config/FINDINGS.md`. Optional on-disk copy only in
the root-owned dir, file `0600`. No `/tmp` anywhere.

### 2.5 DNS, routes, cleanup (F6, F7, F8)
- Helper records original default gateway (`route -n get default`) and resolves
  server IP itself. Persists `{pid, iface, serverIP, gateway, dnsApplied}` to a
  root-owned state file (survives helper restart / sleep).
- On "Tunnel is up": apply DNS via `scutil` from parsed `Found dns server/suffix`
  lines; fallback list only if none parsed (existing `effectiveDNS` rule).
- Disconnect: SIGINT tracked pid → SIGKILL after 2 s; kill only pppd children of
  that pid (`pgrep -P`); remove the server host route; restore default route only
  if it currently points at the session's ppp iface; remove scutil key; flush cache.
- Child exits unexpectedly → same cleanup automatically (helper notices, not the app).
- Pre-connect orphan sweep uses only the persisted state file.

### 2.6 Installer
Extend `HelperInstaller` (`Helper.swift`): single admin prompt that `install`s the
helper binary root:wheel, copies openfortivpn + its dylibs from Homebrew into
`/Library/PrivilegedHelperTools/<label>.d/` per S2 (rewrite, re-sign, manifest),
refuses if Homebrew's openfortivpn is missing, creates
run/log/state dirs, writes the plist (with `MachServices`, `--allowed-uid`,
`--client-req-leaf`), `launchctl bootout` + `bootstrap`. Uninstall removes all of
it. Version check compares **protocol** version.

### Tasks — phase 2
- [x] **2.0** Package layout: `FortiVPNShared` gets protocol types, validators, `LogParser`/`LogBuffer` (moves only, no behaviour change).
- [ ] **2.1** Transport + caller check.
- [ ] **2.2** API + `ConnectRequest` validation, with tests for every rejection rule.
- [ ] **2.3** Spawning: config writer, argv builder, binary/dylib ownership checks.
- [ ] **2.4** Logs: ring buffer + redaction.
- [ ] **2.5** DNS, routes, cleanup, state file.
- [ ] **2.6** Installer / uninstaller.
- [ ] **2.7** Delete `helper/` (Rust), its CI step and build steps.

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

### Tasks — phase 3
- [ ] **3.0** Remove password authentication from the app (F9): `AuthType` and its editor radio, username field, Keychain password storage and access, related tests. No migration: there are no existing profiles or saved passwords to carry over. Docs updated in 3.3.
- [ ] **3.1** `VPNEngine` as client of the new API; SAML URL polling.
- [ ] **3.2** Delete `GatewayCertificate` / `ignoreCertErrors` (decode-and-drop); cert-pin flow from helper events.
- [ ] **3.3** Settings shows caller-check mode; README + native/README updated.
- [ ] **3.4** openfortivpn update check + Update action (runs through the admin-prompt install path, like Repair — **not** a new helper API call: a same-user caller must not be able to trigger a re-copy).

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

### Tasks — phase 4
- [ ] **4.1** Unit tests listed above.
- [ ] **4.2** *(maintainer)* Manual checklist 1–9, results recorded here.

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

## Open questions

- (none)

## Later / optional
- Auto-reconnect after wake, connect on launch.
- Intel build (Homebrew prefix `/usr/local`; drop the `uname -m` gate).
- Never: SMAppService, notarization, anything needing a Team ID.
