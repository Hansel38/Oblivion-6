# Deployment configuration and production blockers

This repository is a defensive anti-cheat client/server. The transport is intentionally **plain TCP**. HMAC authenticates protocol messages and protects their integrity; it does not encrypt traffic or hide metadata.

A successful CI build is not a production certification. The remaining blockers below must be resolved and tested against the exact game/client release before deployment.

## Client endpoint

The Release client no longer silently targets loopback. Set the process environment variable `OBLIVION_SERVER` to the deployed server's DNS name, IPv4 address, or IPv6 address before loading the DLL / calling `Oblivion_Entry()`.

Examples:

- DNS name: `shield.example.net`
- IPv4: `203.0.113.10`
- IPv6: `2001:db8::10`

Use an ASCII DNS name or an IDNA/Punycode hostname. The client rejects an empty, overlong, or unsupported-character value. The host name limit is 253 bytes. The default TCP port is `54321`; it is currently fixed in the client and defaults to the same value in both server implementations.

Release builds fail initialization when `OBLIVION_SERVER` is missing or invalid. Debug builds alone retain `127.0.0.1` as a local development default.

## Shared secret configuration

The Windows client reads `OBLIVION_SECRET` from its process environment or falls back to `secret.dat` beside the game executable. The Windows and Linux servers read `OBLIVION_SECRET` or `secret.dat` beside the server executable. The same key must be provisioned to client and server for the current protocol.

The server refuses to start when no production secret is configured. Release clients fail initialization when no client secret is available. Do not put the secret in source control, command-line arguments, logs, or support tickets. Restrict access to server configuration and backups. A key of at least 32 random bytes is recommended; the current code does not enforce key entropy or minimum length.

**Critical limitation:** the current design still uses one long-lived shared secret available to an untrusted client. XOR-encoding `secret.dat` is obfuscation, not encryption, and a value held by the client can be extracted from the file or process memory. Challenge-response prevents sending the key over TCP but does not solve local extraction. This remains a P0 production blocker. A real trusted authentication service issuing per-account/per-session credentials, with server-side revocation and rotation, is required; that service is not implemented here.

Changing the shared key requires a coordinated client/server rollout because the current deployment supports one active shared key. Treat rotation as a maintenance operation: prepare the new key, update the server and all client deployments together, verify check-in and heartbeat, then retire the old key. There is no overlapping-key migration mechanism at present.

## Network exposure

- Open inbound **TCP 54321** only from the game/client networks that are expected to connect. Apply equivalent restrictions in the cloud security group, perimeter firewall, and host firewall.
- The server listener uses the default port documented above. Do not expose administrative access, secret files, ban files, or logs over the public network.
- Plain TCP is deliberate and TLS is out of scope. Network observers may read traffic metadata and message contents even though authenticated frames are MAC-protected. Use a trusted network path and firewall restrictions appropriate to that exposure.
- Validate the deployed server address and routing from a real client host; a successful local build does not test DNS, routing, or firewall rules.

## DLL host lifecycle

The injector/game host must call exported `Oblivion_Entry()` after `LoadLibrary` succeeds. Before orderly unload, it must call `Oblivion_Shutdown()` and wait for it to return, then call `FreeLibrary`. Do not call either export while holding the Windows loader lock. Unloading without the shutdown export is unsupported.

## Release integrity data

The file-integrity checks for `RRO.exe`, `Republic.grf`, and `DATA.ini` still need hashes computed from the exact approved production distribution. Do not invent or reuse hashes from a different game build. The integrity manifest also needs a pinned public-key signature verification mechanism before it can be trusted against local modification. These are open release blockers until the approved files, signing key, and verification path exist.

## Operations

- Run the server under a dedicated, least-privilege service account. Keep the secret, `bans.txt`, `violations.log`, and backups readable only by authorized operators.
- Back up the ban list and server configuration before deployment and before changes. Test restore procedures.
- Review ban decisions against server-side evidence; do not permanently ban solely on one weak heuristic signal.
- Preserve logs during incident response. Restrict access because process paths and hardware identifiers can be sensitive. Log rotation, redaction, and retention controls remain incomplete in the current implementation.
- On suspected shared-key compromise, isolate the server, preserve relevant logs, coordinate key rotation, and redeploy clients before reopening access.

## Required pre-production validation

Run these tests against the exact Release client, supported Windows versions, and the production-like server:

1. Valid and invalid shared-secret check-in; missing `OBLIVION_SERVER` must fail closed in Release.
2. TCP fragmentation/coalescing, delayed responses, partial sends, disconnects, invalid MACs, altered PONG status/timestamp, and replayed or stale frames.
3. Startup status transition from unavailable to healthy and graceful shutdown back to unavailable; verify server logs and no false heartbeat-miss escalation.
4. DLL host sequence: repeated `Oblivion_Entry()`, `Oblivion_Shutdown()`, and unload cycles, including cancellation during initialization.
5. Process/module enumeration under access-denied, process-exit, and 32/64-bit boundary conditions; verify unavailable inspection is not silently treated as clean and not misreported as cheating.
6. Self-integrity and file-integrity pass/fail tests against clean, approved fixtures; verify legitimate relocation and runtime loader changes do not create false positives.
7. Firewall allow/deny tests from the intended client networks and from untrusted networks.

The current CI covers Linux GCC and Windows Debug/Release x86/x64 builds. It does not execute the game, injector, actual network protocol, Windows security APIs, or deployment environment.
