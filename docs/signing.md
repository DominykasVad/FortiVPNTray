# Local code signing

FortiVPNTray is never signed with an Apple Developer identity and is never
notarized. A build is signed in one of two ways:

| Build | How | Helper caller check |
|---|---|---|
| Local identity | `FVT_SIGN_IDENTITY` set | Signed caller check: the helper can require this certificate |
| Ad-hoc | `FVT_SIGN_IDENTITY` unset | UID-only: any process of the logged-in user can talk to the helper |

Use the local identity for the app you run every day. Ad-hoc builds are for CI
and quick tests.

## One-time setup

The identity is a self-signed code-signing certificate named
`FortiVPNTray Local Signing`. It lives in its own keychain, with its own
password, which locks on sleep and after 5 minutes.

```bash
security create-keychain ~/Library/Keychains/fvt-signing.keychain-db
security set-keychain-settings -l -u -t 300 ~/Library/Keychains/fvt-signing.keychain-db
security list-keychains -d user -s login.keychain-db fvt-signing.keychain-db
```

Create the certificate in **Keychain Access → Certificate Assistant → Create a
Certificate**:

- Name: `FortiVPNTray Local Signing`
- Identity Type: Self Signed Root
- Certificate Type: Code Signing
- "Let me override defaults": long validity, location: `fvt-signing`

Then trust it for code signing in the user domain, so that
`security find-identity -v` lists it:

```bash
security find-certificate -c "FortiVPNTray Local Signing" -p ~/Library/Keychains/fvt-signing.keychain-db > /tmp/fvt.pem
security add-trusted-cert -r trustRoot -p codeSign -k ~/Library/Keychains/fvt-signing.keychain-db /tmp/fvt.pem
rm /tmp/fvt.pem
```

## Building

Unlock the keychain once per build session, then build with the identity:

```bash
security unlock-keychain ~/Library/Keychains/fvt-signing.keychain-db
FVT_SIGN_IDENTITY="FortiVPNTray Local Signing" \
FVT_SIGN_KEYCHAIN="$HOME/Library/Keychains/fvt-signing.keychain-db" \
native/scripts/build.sh
```

- `FVT_SIGN_IDENTITY`: name of the identity. Unset, empty or `-` means ad-hoc.
- `FVT_SIGN_KEYCHAIN`: optional; restricts the lookup to that keychain. Setting
  it without `FVT_SIGN_IDENTITY` is an error.

`build.sh` calls `native/scripts/sign.sh`, which signs the bundled helper and
then the app, runs `codesign --verify --deep --strict`, and stops the build if
any step fails. A named identity that cannot be used never falls back to
ad-hoc.

If macOS asks whether `codesign` may use the key, choose **Allow**.

## Checking the result

A signed build ends with:

```
Signed with: FortiVPNTray Local Signing
Leaf certificate SHA-1: <40 hex digits>
```

The hash is read back from the built app (`codesign --display
--extract-certificates`, then SHA-1 of the leaf certificate), not from the
keychain. Compare it with the identity:

```bash
security find-certificate -c "FortiVPNTray Local Signing" -Z ~/Library/Keychains/fvt-signing.keychain-db | grep SHA-1
```

The two must be equal. The hash is never stored in the repository or typed by
hand; the build and the helper installer derive it.

The app's designated requirement then has the form the helper will check:

```bash
codesign -d -r- native/dist/FortiVPNTray.app
# designated => identifier "eu.dvad.fortivpntray" and certificate leaf = H"<same hash>"
```

An ad-hoc build prints a warning instead and carries no certificate.

## Rules

- Never choose "Always Allow" for `codesign`.
- Back the identity up as a `.p12` outside the repository.
- Losing the identity means creating a new one and reinstalling the helper so
  it pins the new certificate. Rebuilding with the same identity keeps the
  hash and needs no reinstall.
- CI builds are ad-hoc and are for testing only.
