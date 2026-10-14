# FortiVPNTray — Build and development

A macOS 13+ Apple Silicon application using SwiftUI and AppKit. Everything in this repository is Swift: the app (`FortiVPNTray`, `FortiVPNCore`), the shared protocol and validation code (`FortiVPNShared`), and the root helper (`FortiVPNHelper`). The external openfortivpn executable supplies the VPN engine.

## Build and run

Requirements: Apple Command Line Tools (Swift 6+), and `brew install openfortivpn` before installing or repairing the helper.

```bash
native/scripts/test.sh
native/scripts/build.sh
open native/dist/FortiVPNTray.app
```

If needed, prefix the build commands with `DEVELOPER_DIR=/Library/Developer/CommandLineTools` to select that installed toolchain for this command only. You can also open `native/Package.swift` in Xcode for editing and debugging. Use the build script for a complete app bundle containing the helper and icon.

Set `FORTIVPNTRAY_OUTPUT_DIR="$PWD/native/dist/development"` when building to a separate bundle without replacing a running app. Quit the existing app before launching the new bundle.

The build produces a signed `.app` with the helper in `Contents/Resources/FortiVPNHelper`, and `native/dist/FortiVPNTray-native-arm64.zip`; it is never notarized. Without `FVT_SIGN_IDENTITY` it is ad-hoc signed and the helper is installed in **UID-only** mode; set `FVT_SIGN_IDENTITY` (and optionally `FVT_SIGN_KEYCHAIN`) to sign with the local identity so the helper checks the app's certificate; see [docs/signing.md](../docs/signing.md).

## Helper

- Install/Repair in Settings runs one script behind one administrator prompt. It installs the helper, copies Homebrew's openfortivpn and every non-system library it loads into `/Library/PrivilegedHelperTools/eu.dvad.fortivpntray.helper.d` (load paths rewritten, re-signed, hashes in `manifest.json`), writes the launchd job with your user ID and, for a locally signed app, its certificate hash, and starts the helper only after the helper itself has checked the copy. It refuses if Homebrew's openfortivpn is missing.
- Uninstall is refused during a session; it removes the helper, its job, the openfortivpn copy and its state, and keeps profiles.
- The app talks to the helper over XPC (`eu.dvad.fortivpntray.helper`): version, connect, disconnect, status, log, SAML URL. Settings shows the helper's state, version and caller check (*Signed caller check* or *UID-only*); the app requires the same protocol version as the helper.
- After `brew upgrade` of openfortivpn or OpenSSL, Repair copies the new version; the helper keeps running its old copy until then.

## Application behavior

- Closing the main window switches the app to Accessory mode: no running Dock icon, but the status item and VPN remain. Open it from the menu bar to restore the window and Dock icon. Minimize retains normal macOS behavior.
- Connection errors keep a hidden main window hidden. The tray offers a message-review action; opening the window displays the pending error.
- Quit disconnects the current session before exiting. A failed disconnect keeps the application open with an actionable error.
- Profiles and settings use `eu.dvad.fortivpntray`. Profiles hold the gateway host and port, an optional realm and certificate pins; SAML is the only authentication method, and nothing is stored in Keychain.
- Run one FortiVPNTray instance at a time. Do not connect multiple VPN clients concurrently: the helper manages a PPP interface, DNS and routes.
- Settings distinguishes missing, incomplete, unresponsive, ready and incompatible helper states. Install/removal shows progress and verifies the result. During a VPN session, changing the helper is disabled with an explicit explanation; Refresh remains available. Uninstall asks for confirmation and keeps profiles.
- On connect, the helper reports the SAML login URL; the app opens it in the browser only if it is https, uses the profile's host and port, and goes to `/remote/saml/start`.
- An untrusted gateway certificate ends the attempt with a prompt that shows its SHA256 fingerprint; confirming pins it to the profile and reconnects. There is no option to trust any certificate.
- DNS supplied by the VPN takes precedence. If fallback is enabled and the VPN supplies no DNS servers, the system resolvers the helper read before connecting are kept.
- Logs in the UI are bounded and come from the helper already redacted (session cookie, SAML ids, URLs). Nothing is written to `/tmp`, and no raw log export is provided.
- New profiles can be saved during a session without changing the active or selected profile. Existing profiles can be opened read-only during a session; editing and deletion remain disabled; malformed configuration is preserved and reported rather than silently replaced.
- The 400×560 dark single-column window shows a connection card, profile list, and Logs / Settings / About footer. Creating, editing or viewing a profile uses the entire content area, with a scrollable form and fixed navigation/actions; the connection card and footer return when the profile page closes. The connection card includes a 60-sample download/upload chart.
- The tray opens a graphical popover sharing the main connection card: profile, VPN IP, live duration, green/orange traffic history, rates and totals. Connected uses a green filled checkmark shield; disconnected uses an outline shield. Opening the tray preserves Accessory mode. Counters and charts observe the same model as the main window.

## Verification

`native/scripts/test.sh` runs every test target. Among others:

- **Shared:** request validation and strict decoding, validators, log redaction with openfortivpn's exact formats, DNS suffix and certificate digest parsing.
- **Core:** profile/settings JSON and persistence, the installer script (exact text, quoting, refusals, `bash -n`), the XPC client against a fake helper, and `VPNEngine` against a scripted fake helper.
- **Helper:** the caller check, the session state machine, openfortivpn's config file and argv, the spawn-time file checks on a fake install, OpenSSL file access of the child, the state file, process identity checks, and cleanup against fake processes, routes and DNS.

They do not start a VPN, install privileged software, or change routes or DNS.

Run an in-process AppKit integration check in a logged-in graphical session:

```bash
native/dist/FortiVPNTray.app/Contents/MacOS/FortiVPNTray --smoke-test
```

This uses a temporary empty configuration, does not contact the helper, and checks actual window visibility, activation policy, shared tray telemetry, icon changes, popover sizing and close/reopen behavior. It also renders synthetic tray/settings screenshots to the temporary directory. It exits automatically. It does not substitute for visual QA or a real SAML gateway test.

Manual acceptance (PLAN.md phase 4): install the helper; add/edit/delete a test profile; connect with SAML; confirm corporate DNS resolution; close and reopen while connected; disconnect and quit; confirm network recovery after gateway loss and sleep/wake; uninstall and check that nothing is left.

Architecture follows Apple's [NSHostingView](https://developer.apple.com/documentation/swiftui/nshostingview) and [NSApplication activation policy](https://developer.apple.com/documentation/appkit/nsapplication/activationpolicy-swift.enum/accessory) APIs.
