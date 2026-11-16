# Deployment configuration and production blockers

This repository is a defensive anti-cheat client/server. The transport is intentionally **plain TCP**. HMAC authenticates protocol messages and protects their integrity; it does not encrypt traffic or hide metadata.

A successful CI build is not a production certification. The remaining blockers below must be resolved and tested against the exact game/client release before deployment.

## Client endpoint

The client no longer silently targets loopback. Set the process environment variable `OBLIVION_SERVER` to the deployed server's DNS name, IPv4 address, or IPv6 address, and set `OBLIVION_SERVER_PORT` to its TCP port, before loading the DLL / calling `Oblivion_Entry()`.

Examples:

- DNS name: `shield.example.net`
- IPv4: `203.0.113.10`
- IPv6: `2001:db8::10`

Use an ASCII DNS name or an IDNA/Punycode hostname. The client rejects an empty, overlong, or unsupported-character value. The host name limit is 253 bytes. The port must be a canonical decimal value from 1 through 65535. Configure the server with the same value in `OBLIVION_LISTEN_PORT`.

All builds fail initialization when either endpoint variable is missing or invalid; local development must configure an explicit endpoint too.

## Required server configuration

The server has no operational defaults for its listener, storage paths, concurrency limit, request timeout, or heartbeat policy. Windows and Linux use the same required environment variable names. Startup fails when any required value is missing, malformed, or outside its supported range.

| Variable | Requirement |
|---|---|
| `OBLIVION_LISTEN_ADDRESS` | Explicit local IPv4/IPv6 address or resolvable local interface name; printable ASCII, no whitespace |
| `OBLIVION_LISTEN_PORT` | Canonical decimal TCP port, 1–65535 |
| `OBLIVION_LISTEN_BACKLOG` | Required integer, 1–65535 |
| `OBLIVION_BAN_LIST_PATH` | Absolute path to an existing, readable regular file |
| `OBLIVION_VIOLATION_LOG_PATH` | Absolute path to a writable append-only log destination; must differ from the ban-list path |
| `OBLIVION_MAX_CONCURRENT_CLIENTS` | Required integer, 1–1024 |
| `OBLIVION_REQUEST_TIMEOUT_MS` | Required integer, 100–120000 |
| `OBLIVION_HB_INTERVAL_MS` | Required integer, 100–60000 |
| `OBLIVION_HB_JITTER_MS` | Required integer, 0–10000 |
| `OBLIVION_HB_TIMEOUT_MS` | Required integer, 250–120000 |
| `OBLIVION_HB_MAX_MISS` | Required integer, 1–10 |
| `OBLIVION_HB_RTT_WARN_MS` | Required integer, 0–60000 |

The listener binds only to the address supplied in `OBLIVION_LISTEN_ADDRESS`; it does not choose a wildcard address automatically. Configure a local address that exists on the host. Clients must use the reachable server address and the same TCP port.

The ban-list file must exist before startup. An empty file represents an empty ban list. The server no longer searches for a fixed `bans.txt` beside its executable. The violation log is opened at the configured absolute path; the server no longer chooses a fixed `violations.log` path.

## Server secret provisioning

Configure exactly one of these sources:

- `OBLIVION_SECRET`: the secret text supplied by the service environment.
- `OBLIVION_SECRET_FILE`: an absolute path to a plaintext secret file.

Do not set both. Do not omit both. The secret must contain at least 32 printable ASCII bytes and must not contain placeholder markers. A secret file may end with one line ending; no other whitespace is accepted. Restrict its filesystem permissions to the server service account and authorized administrators.

The server no longer searches for `secret.dat`, no longer assumes a secret-file location beside the executable, and no longer XOR-decodes server-side secret files. The client must still be provisioned with the exact same secret text. The client supports its existing `OBLIVION_SECRET` environment source or its existing client-side secret-file format; do not copy the server plaintext file into the client deployment unless the client is explicitly configured to read plaintext.

**Critical limitation:** the protocol still uses one long-lived shared secret available to an untrusted client. Challenge-response prevents transmitting the key over TCP but does not prevent extraction from the client process or its local configuration. This remains a P0 production blocker. Per-account/per-session credentials from a trusted authentication service, with server-side revocation and rotation, are not implemented.

The server's environment and file sources are mutually exclusive to avoid ambiguity. Changing the shared key requires a coordinated server/client rollout because overlapping-key migration is not implemented.

## Protocol invariants versus deployment configuration

The following remain code-defined intentionally and must not be overridden independently on the server: frame delimiter and message grammar, HMAC algorithm/domain labels, SHA-256 digest width, HWID syntax, status encoding, and maximum protocol field/frame sizes. These are wire-format and security invariants shared with the client, not deployment placeholders.

Operating-system constants and cryptographic API flags are also not runtime configuration. They are selected by the platform and must remain tied to the implementation.

## Network exposure

- Restrict inbound TCP to the configured listener address/port and expected client networks using the host firewall and perimeter/security-group rules.
- Do not expose the secret file, ban list, logs, or administrative access publicly.
- Plain TCP is deliberate; TLS remains out of scope. Network observers can see message contents and metadata even though authenticated frames are MAC-protected.
- Validate DNS/routing and firewall access from a real client host. CI does not validate network deployment.

## Release integrity data

The file-integrity checks for `RRO.exe`, `Republic.grf`, and `DATA.ini` still require hashes from the exact approved production distribution. Do not invent or reuse hashes from another game build. The manifest also needs signature verification using a pinned public key before it can be trusted against local modification.

The unsigned-module allowlist must be replaced with exact approved module identities/hashes from that signed release manifest. Publisher trust must be pinned to approved signer identities, not display-name text. These remain production blockers until the approved distribution and signing material are available.

## Operations

Run the server under a dedicated least-privilege service account. Keep the secret, configured ban list, violation log, and backups readable only by authorized operators. Back up the ban list and configuration before changes and test restoration. Review ban decisions against server-side evidence; do not permanently ban based on a single weak heuristic.

Windows and Linux operational logs use the domain-separated HMAC `HWID_ID` pseudonym instead of raw HWID. The HMAC key is still the shared client/server secret and therefore does not protect the identifier from clients or anyone who extracts that key. Log rotation, file access control, and retention policy remain operator responsibilities.

## Required pre-production validation

Test the exact Release client and target server environment for:

1. Missing, duplicate, invalid, and valid configuration sources; every missing required server setting must prevent startup.
2. Unreadable/missing ban list, unwritable log path, same ban/log path, and secret-file permission failures.
3. Valid/invalid secret authentication, TCP fragmentation/coalescing, partial sends, delayed responses, disconnects, invalid MACs, and replayed/stale frames.
4. Heartbeat status transitions and graceful shutdown without false timeout escalation.
5. DLL host lifecycle and cancellation during initialization.
6. Process/module enumeration under access-denied, process-exit, and architecture-boundary conditions.
7. File/self-integrity pass/fail tests against approved fixtures and firewall allow/deny behavior.

CI builds Linux GCC and Windows Debug/Release x86/x64 and runs portable configuration/protocol tests. It does not execute the game, injector, Windows security APIs, or the production network environment.
