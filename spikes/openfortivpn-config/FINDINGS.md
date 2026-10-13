# S3 — openfortivpn config handling

Spike for PLAN.md phase 1, task 1.3. Reading notes only; nothing here is wired into the app.

**Source read:** openfortivpn `v1.24.1` (tag commit `a40a2d5`), files `src/main.c`,
`src/config.c`, `src/config.h`, `src/log.c`, `src/log.h`, `src/http.c`,
`src/http_server.c`, `src/userinput.c`, `src/tunnel.c`. This is the version Homebrew
installs (keg `1.24.1_1`). Line numbers below refer to that tag.

**Checked by running** `/opt/homebrew/bin/openfortivpn` unprivileged with made-up
values: it parses arguments and config, prints debug lines, and exits at
"not spawned with root privileges" before it opens a connection. Items marked
*(run)* were confirmed that way; the rest is from the source only.

## Answers to the four questions

### 1. Does `-c <file>` fully replace the default config? — Yes

- There is one `config_file` variable. It starts as `SYSCONFDIR "/openfortivpn/config"`
  and `-c` overwrites it (`main.c:219`, `main.c:630`). Exactly one file is loaded
  (`main.c:665`). *(run)*
- Homebrew sets `SYSCONFDIR` to `/opt/homebrew/etc/openfortivpn`, so the default is
  `/opt/homebrew/etc/openfortivpn/openfortivpn/config`. That file **exists** on this
  Mac, owned by the logged-in user, and is loaded when `-c` is absent. *(run)*
  **F4 is confirmed.**
- `-c ''` loads no file at all (`main.c:665`). *(run)*
- A config file that cannot be opened is only a warning; the run continues with
  built-in defaults (`main.c:670`). *(run)* The helper must not rely on openfortivpn
  failing when its config is missing.
- Command-line options override the file, field by field (`merge_config`,
  `config.c:525`). *(run)* Trusted certificates given on the command line replace
  the file's whole list (`config.c:633`).

### 2. Which config keys exist?

Format (`config.c:187`): one `key = value` per line; a line starting with `#` is a
comment; the line is split at the **first** `=`; leading and trailing whitespace is
trimmed from key and value; there is no quoting or escaping.

| Keys | Why it matters to a root helper |
|---|---|
| `host`, `port`, `username`, `password`, `realm`, `sni` | plain values; `host` and `port` can be given here instead of as an argument |
| `otp`, `otp-prompt`, `otp-delay`, `no-ftm-push` | not used by this project |
| `saml-login` (value = listen port 1–65535) | config form of `--saml-login[=port]` |
| `trusted-cert` (repeatable, must be 64 characters) | the pin list |
| `set-dns`, `set-routes`, `half-internet-routes`, `persistent`, `use-syslog`, `pppd-use-peerdns`, `pppd-accept-remote` | behaviour switches; the built-in defaults are `set-dns = 1`, `set-routes = 1`, `pppd-use-peerdns = 0` |
| **`pppd-plugin`** | pppd loads this file as a plugin: code as root |
| **`pppd-log`** | pppd writes its debug log to this path as root |
| **`pppd-call`**, **`pppd-ipparam`**, **`pppd-ifname`** | change what pppd runs or how its scripts are called |
| **`pinentry`** | a program openfortivpn executes to ask for the password (`userinput.c:251`): code as root |
| **`user-cert`**, **`user-key`**, `pem-passphrase`, **`ca-file`** | file paths read as root; `user-cert = pkcs11:…` loads an OpenSSL engine (`tunnel.c:1110`) |
| **`insecure-ssl`**, `cipher-list`, `min-tls`, `seclevel-1` | weaken TLS |
| `user-agent`, `hostcheck`, `check-virtual-desktop` | sent to the gateway |
| `cookie`, `cookie-on-stdin` | recognised but ignored in a file (`config.c:278`) |
| `use-resolvconf`, `ppp-system` | compiled out on macOS; ignored with a warning |

`--ifname` exists only as a command-line option.

Parser behaviour that affects the config writer:

- **An unknown key stops parsing.** Every line after it is silently dropped, and the
  file is still reported as loaded (`config.c:480`, returns 0). *(run)* A bad
  `saml-login` port does the same (`config.c:426`). Consequence: write the
  security-relevant keys first and never emit a key that this version does not know.
- **A newline inside a value becomes a second key.** *(run)* This is the injection
  PLAN.md 2.3 already rejects.
- `=` inside a value is kept: `realm = a=b c` gives `a=b c`. *(run)* Rejecting `=`
  (PLAN.md 2.3) is stricter than needed, which is fine.
- Leading and trailing whitespace cannot be expressed in a value; it is trimmed. *(run)*
- Later duplicates of a key win, except `trusted-cert`, which accumulates.
- Size limits (`config.h`): host 253, username 64, password 256, realm 63. Longer
  values are truncated silently, not rejected.

### 3. Does `-v` log the SVPNCOOKIE or SAML tokens? — Yes, at one `-v`

Verbosity (`log.h`): default is INFO; each `-v` raises it one level.

| Flag | Level | What appears |
|---|---|---|
| none | INFO | `Authenticate at 'https://host:port/remote/saml/start?redirect=1…'` (no secret), `Connected to gateway.`, `Authenticated.`, `Tunnel is up and running.` |
| `-v` | DEBUG | **`Cookie: SVPNCOOKIE=…`** (`http.c:446`, `tunnel.c:1392`), **`Using SAML authentication URL /remote/saml/auth_id?id=<session id>`** (`http.c:693`), `Found dns server …` and `Found dns suffix …` (`http.c:883`, `http.c:894`), `Configuration host/realm/port/username`, `One-time password = …` |
| `-vv` | DEBUG_DETAILS | every HTTP request and response in full, including cookie headers; the password is masked in requests only (`http.c:88`) |
| `-vvv` | DEBUG_ALL | **`Configuration password = "…"` in clear text** (`main.c:741`) *(run)*, and the password unmasked in HTTP requests |

Consequences:

- The helper needs `-v`: the DNS lines PLAN.md 2.5 parses exist only at DEBUG. So the
  session cookie and the SAML session id **will** be in the child's output, and
  redaction in the helper is not optional. Never pass more than one `-v`.
- The app's current `LogParser.redacted` does not cover this fully: it replaces
  `cookie: <one token>` and `http(s)://…` URLs. The SAML line carries the id in a
  relative URL (`/remote/saml/auth_id?id=…`), which neither pattern matches, and a
  cookie line with a second `; name=value` part would keep that part. 2.4 should
  redact these two lines by their exact prefixes and have tests with these samples.
- With the password in a config file or on stdin, it is not printed at `-v` or `-vv`
  (0 occurrences in both). *(run)*

### 4. How does it read a password that is not in argv or the config? — From stdin, not only a tty

`read_password` (`userinput.c:332`) runs when a username is set, no password was
given, and neither a cookie nor SAML is in use (`main.c:726`):

- If `pinentry` is configured it executes that program; otherwise
- it prints `VPN account password: ` and reads **stdin** up to the first newline or
  end of file. It tries to switch off terminal echo and carries on if stdin is not a
  terminal. A pipe works. *(run)*
- With stdin at end of file it gets an empty password and continues. *(run)*
- `-p <password>` is overwritten with `*` in the process arguments after parsing
  (`main.c:641`), so it is visible in `ps` only briefly, but it is visible (F9).

So the password can reach openfortivpn three ways: argv (bad), a `password =` line in
the config file, or a pipe on stdin. Only the last one never touches the disk and
keeps leading and trailing spaces.

## Other things the source shows

- **SAML listener.** `--saml-login` listens on `127.0.0.1:<port>` only
  (`http_server.c:251`), accepts `GET /?id=<id>` where the id is alphanumeric or `-`,
  and waits at most 5 × 10 seconds. Any local process, from any local user, can send
  that request; whoever is first supplies the session id. The helper cannot change
  this; it bounds the damage only because the id must still be a session the gateway accepts.
- **Environment.** `https_proxy`, `HTTPS_PROXY`, `all_proxy`, `ALL_PROXY` are honoured
  (`tunnel.c:690`). The cleared child environment (PLAN.md 2.3) covers it.
- **Shell.** Routes are changed through `system()` and `popen()` with commands built
  from addresses and interface names (`ipv4.c:660`, `ipv4.c:727`, `ipv4.c:227`).
  With a fixed `PATH` and no caller-supplied strings in them this is acceptable; it
  is one more reason the environment must be the helper's.
- **Root check.** openfortivpn refuses to run unless `geteuid() == 0` (`main.c:745`),
  after parsing and after reading the password.
- **Host argument.** `host:port` is the one positional argument. Both can be given as
  config keys instead, in which case no caller-derived text is on the command line.

Not looked at: Apple's `pppd` itself (its own option files and plugin loading), and
anything after the tunnel is up.

## What this means for phase 2

Already in PLAN.md and confirmed:

- Always pass `-c <helper's file>`; it fully replaces the default (2.3, F4).
- Reject values containing `\n`, `\r` or `\0`; never escape (2.3).
- Set `set-dns = 0` and `pppd-use-peerdns = 0` explicitly; the default for `set-dns` is 1.
- Redact logs in the helper before anything is buffered (2.4).

New, for the owner to decide (also listed under PLAN.md "Open questions"):

1. **Password on stdin instead of in the config file.** PLAN.md 2.3 does not say
   where the password goes. A pipe to the child's stdin keeps it off the disk and
   out of argv, and is supported as shown above.
2. **Everything in the config file, constant argv.** `host`, `port`, `realm`,
   `username`, `trusted-cert`, `saml-login`, `set-dns` and `pppd-use-peerdns` are all
   config keys. The child's command line can then be exactly
   `openfortivpn -c <file> -v` for every connection, instead of the flags PLAN.md 2.3
   lists. If positional `host:port` is kept, the leading-`-` rule in 2.2 is what
   stops it being parsed as an option.
3. **Config writer rules that follow from the parser:** emit only keys known to this
   version, the security-relevant ones first, and treat the file being unreadable as
   the helper's error, because openfortivpn will not.
4. **Redaction tests** for the two `-v` lines quoted in section 3.
