# AGENTS.md

Rules and facts for any coding agent working in this repository. Read this file
and `PLAN.md` before starting any task. `PLAN.md` says *what* to do next; this
file says *how* to work. If they conflict, stop and ask.

## Project

This is the **FortiVPNTray fork**: a native macOS menu-bar client for
[openfortivpn](https://github.com/adrienverge/openfortivpn) (password + SAML /
Entra ID), with a root helper. Forked from `itstone/FortiVPNTray` v0.2.3, which
derives from `walcew/openfortivpn-connect`. The fork point is the annotated tag
`fork-point` (upstream v0.2.3, commit `8f9cc41`). There is no upstream
tracking: do not add an upstream remote, do not cherry-pick, do not open PRs
against `itstone/FortiVPNTray` or `walcew/openfortivpn-connect`.

The GitHub repo is `DominykasVad/FortiVPNTray`. The fork's identity is
`eu.dvad.fortivpntray` (helper `eu.dvad.fortivpntray.helper`); since task 0.1
the code uses only the fork's identifiers; upstream's
`com.itstone.fortivpntray*` must not reappear (IdentityTests enforces it).

**This is the primary project.** A separate repository, openfortivpn-connect
(Tauri, `src-tauri/`, pnpm), is the fallback with its own `PLAN.md` and
`AGENTS.md`. Identity check before any task: this repo has
`native/Package.swift` and `helper/Cargo.toml` (until 2.7) and **no**
`src-tauri/` or `package.json`. If not, you are in the wrong repo: stop. Never
apply that repo's plan here, never touch it. If a fix here is also needed there,
say so in the report.

Licence is **MIT**. Keep `LICENSE` and the attribution to itstone and Wallacy
Santos Ferreira. Never relicense, never strip credits.

## Current phase

The current phase is the one PLAN.md marks under **Status**, sub-phases in
order. Work only on that. If it marks none, take only tasks the owner gives
explicitly. Anything not in PLAN.md is **out of scope**.

## Layout

```
native/
  Package.swift
  Sources/FortiVPNCore/   models, storage, Keychain, log parsing, helper client, VPNEngine
  Sources/FortiVPNTray/   SwiftUI + AppKit UI
  Tests/FortiVPNCoreTests/
  Resources/              Info.plist (bundle id, version), icon
  scripts/                build.sh, test.sh
helper/                   Rust root helper — replaced by a Swift target in phase 2, deleted in 2.7
spikes/<name>/            throwaway proofs (PLAN.md phase 1); never wired into the app
docs/                     releases/, screenshots/, signing.md (phase 0)
PLAN.md, AGENTS.md
```

Phase 2 adds `FortiVPNShared` (constants, protocol types, validators, log
parsing) and `FortiVPNHelper` (root executable). Dependencies point one way:
`FortiVPNTray → FortiVPNCore → FortiVPNShared ← FortiVPNHelper`. The helper never
imports Core or UI code; the UI never talks to the helper except through Core.

## Toolchain and commands

macOS 13+, Apple Silicon only (for now). Swift 6 toolchain (Xcode or Command
Line Tools); Rust stable only while `helper/` exists. Commands run from the
repo root.

| Task | Command |
|---|---|
| Swift tests | `native/scripts/test.sh` |
| Rust helper tests (until 2.7) | `cargo test --manifest-path helper/Cargo.toml --locked` |
| Dev build (doesn't replace a running app) | `FORTIVPNTRAY_OUTPUT_DIR="$PWD/native/dist/development" native/scripts/build.sh` |
| UI smoke test (logged-in session) | `native/dist/development/FortiVPNTray.app/Contents/MacOS/FortiVPNTray --smoke-test` |

If no Xcode is selected, prefix with `DEVELOPER_DIR=/Library/Developer/CommandLineTools`.
No Swift linter/formatter is configured; adding one is a decision — ask.
Python helper scripts, if ever needed: `uv` only. No Homebrew packages added as
build dependencies without asking.

## Definition of done (every task)

1. `native/scripts/test.sh` passes, `cargo test` passes while `helper/` exists,
   and the dev build succeeds.
2. New or changed behaviour has tests — every validator, parser, config writer
   and argv builder without exception. Do not delete, skip or weaken an existing
   test to make the suite pass; if a test is genuinely wrong, say so and explain.
3. The matching checkbox in `PLAN.md` is ticked **in the same commit** as the
   change (never a separate "tick" commit). Boxes marked *(maintainer)* are never
   ticked by the agent. A real decision (a choice between alternatives that later
   work must respect) gets one line in the PLAN.md **Decision log**. Everything
   else goes in the commit message body.
4. Report: what changed, what you verified and how, what you did not verify —
   in particular anything that needs root or a real gateway, which only the
   maintainer can run.

## Hard rules

### Scope and decisions
- Working notes, scratch scripts and investigation output go in `scratch/` at
  the repo root (git-ignored). Never commit them, never leave them elsewhere.
  Spikes are not scratch: they go in `spikes/<name>/` and are committed.
- Branches: **one task (`0.1`, `2.3`, …) = one branch (`phase-0.1`) = one PR**.
  Start the next task only after the previous one is merged into `main`. Never
  commit directly to `main`; the owner merges. Keep commits small.
- Commit as often as useful, push the branch once when the task is ready for
  review and open the PR then. Push again only for review fixes. CI
  (`.github/workflows/native.yml`) runs on pull requests and `main`.
- A phase's **Review checkpoint** in PLAN.md means: after its last task's PR,
  stop until the owner starts the next phase.
- One PLAN.md task per change set. No drive-by refactors, renames or
  reformatting outside the task. Mechanical changes (renames, moves) go in
  their own commits, never mixed with behaviour changes.
- If a task needs a decision PLAN.md does not cover (a new dependency, a change
  of the helper protocol not described, an entitlement, a security trade-off),
  stop and ask. Do not pick silently.

### Apple platform constraints
- **No paid Apple Developer account. Ever.** Nothing may depend on a Team ID,
  Developer ID, provisioning profile, notarization or a restricted entitlement.
- **No `SMAppService`.** Helper install stays `install -o root` +
  `launchctl bootstrap` behind one admin prompt.
- No entitlements, no App Sandbox, no App Groups, no keychain access groups.
- Signing is ad-hoc or the local self-signed identity (`docs/signing.md`).
  Never create, export or unlock signing identities; never print the keychain
  password; never click or script "Always Allow".
- Swift 6 language mode where practical. No third-party Swift dependencies.

### Privileged operations on this Mac
- Never run `sudo`, `launchctl`, the helper installer/uninstaller, or anything
  that changes routes, DNS, `/Library`, `/var` or `/etc` on the machine. Write
  the script; the owner runs it and pastes the result.
- Never connect to a real VPN gateway. Tests use mocks.
- An upstream FortiVPNTray may be installed; nothing you run may touch
  `com.itstone.fortivpntray*` files, sockets or launchd jobs.

### Helper security (threat model)
- The helper runs as root. Assume **any process running as the logged-in user
  is hostile** and talks to the helper directly. App-side validation never
  counts as protection; the helper validates everything itself.
- No argv, file paths, PIDs, gateway IPs or DNS servers cross from the app to
  the helper (PLAN.md 2.2). Inputs are allow-listed (regex/range), never
  block-listed. Values with `\n`, `\r`, `\0` or `=` going into an openfortivpn
  config are rejected, never escaped.
- Root never executes or loads anything user-writable: binary, dylibs and every
  parent directory are checked root-owned and not group/other-writable before
  each spawn.
- Root file creation: `O_CREAT|O_EXCL|O_NOFOLLOW`, `0600`, inside root-owned
  `0700` dirs. Nothing under `/tmp`.
- Subprocesses use `Process` with an argument array and a cleared environment
  (`PATH=/usr/bin:/bin:/usr/sbin:/sbin`). Never `/bin/sh -c`, never string
  interpolation into a shell.
- Only kill/clean up what the helper itself started and recorded (PIDs, pppd
  children, routes, scutil keys). Never `killall`.

### Secrets and logs
- Never log or persist passwords, `SVPNCOOKIE`, SAML URLs/tokens or Keychain
  contents. Logs go through `LogParser` redaction before leaving the helper.
- Passwords live in Keychain only, are read right before connect, sent once,
  never put in argv or a file that outlives the connect.
- Never commit real gateway hostnames, IPs, certificate fingerprints, usernames
  or logs from the real network. Test fixtures use `vpn.example.com`,
  `192.0.2.0/24` / `198.51.100.0/24`, made-up fingerprints.

### Licences
- MIT repo. openfortivpn is GPLv3 and is **never bundled**: not in the `.app`,
  not in the release zip. The user installs it with Homebrew; the helper
  installer copies it (+ dylibs) into the root-owned dir on admin approval, and
  root only ever runs that copy, never `/opt/homebrew/...`. Updates are offered,
  never automatic (PLAN.md S2, 2.6, 3.4).
- Don't copy code from FortiClient, Fortinet SDKs or any proprietary source.

### Style
- Follow the existing code style; no mass reformatting.
- No `print()` in app or helper code; use `os.Logger` (subsystem = bundle id).
- Commit messages: `<area>: <imperative summary>` where area is `app`, `core`,
  `shared`, `helper`, `spike`, `build`, `ci`, `doc`. Body explains *why*.

## Reference

- `PLAN.md` — phases, tasks, findings F1–F11, decision log, open questions.
- `README.md`, `native/README.md` — behaviour and build details (upstream text until 3.3).
- `docs/signing.md` — local signing identity (from task 0.2).
