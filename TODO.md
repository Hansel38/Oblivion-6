# Oblivion-6 — Security & Stability TODO

Audit baseline: `main` at the time this branch was created.
Working branch: `hardening/anti-cheat-bugfixes`

This checklist tracks findings from a source review. A checked item means the code change was committed to this branch; it does **not** mean it has passed a Windows/game integration test.

## Status legend

- [x] Implemented in this branch; runtime verification still required.
- [ ] Not implemented yet.
- **P0** Critical security or reliability risk.
- **P1** High-priority correctness/stability issue.
- **P2** Hardening, maintainability, or operational improvement.

## Completed in this branch

- [x] **P1 — Heartbeat thread lifetime:** replace detached heartbeat worker with an owned `std::thread`, atomic stop flag, socket shutdown to unblock receive, and join during teardown.
- [x] **P1 — Heartbeat bypass configuration:** remove the production client-side environment-variable switch that disabled heartbeat.
- [x] **P1 — Client handshake validation:** require the exact `OK;SESSION_NONCE:<decimal>;` response structure and reject malformed/missing nonce instead of accepting any response containing `OK`.
- [x] **P1 — TCP client writes:** add a send-all loop so partial TCP sends do not silently truncate check-in or violation reports.
- [x] **P1 — TCP heartbeat framing on client:** retain unread bytes between frames and read bounded semicolon-terminated heartbeat messages, including fragmented TCP frames.
- [x] **P1 — File SHA-256 read loop:** distinguish successful EOF from failed `ReadFile`; do not interpret a stale `GetLastError()` after successful EOF as an I/O failure.
- [x] **P0 — Public development secret fallback:** client and server no longer silently use `DEV_SECRET_NOT_SET` in non-debug builds.
- [x] **P0 — Server startup configuration:** Windows and Linux server refuse to start when the secret is missing or is the development placeholder.
- [x] **P0 — Secret disclosure:** remove logging of expected and received authentication secrets from both server implementations.
- [x] **P1 — Windows environment secret length:** avoid including the `_dupenv_s` terminating NUL byte in the server authentication key.

- [x] **P1 — ProcessWatcher ownership:** use `std::unique_ptr` for scanner components; startup now rolls back cleanly if thread creation fails.
- [x] **P1 — AntiSuspend lifecycle:** make start/stop idempotent and join worker threads rather than leaving them detached.
- [x] **P1 — Scanner UTF-8 buffer overflow:** allocate space for the terminating NUL during `WideCharToMultiByte` in overlay and injection scanners.
- [x] **P1 — Overlay window state:** refresh the game window rectangle and handle destroyed windows or failed Win32 window queries safely.
- [x] **P1 — IAT PE bounds:** validate image headers, import descriptors, thunk tables, and import-name strings before dereferencing them.
- [x] **P1 — Module path trust checks:** resolve long module paths dynamically and compare against normalized Windows/Program Files directory roots rather than substring matches.
- [x] **P1 — Signature publisher consistency:** align trusted publishers with the publishers in the process verification map.
- [x] **P1 — System/Program Files module trust:** require a valid Authenticode signature for modules in those locations; filename-only unsigned exceptions cannot override a failed signature there.
- [x] **P1 — TCP server framing:** both server variants use bounded, timeout-aware semicolon frame reads and retain or reject pipelined data deliberately.
- [x] **P1 — TCP complete writes:** both server variants use send-all for protocol responses and heartbeat messages.
- [x] **P1 — Portable socket framing:** shared helper handles EINTR and avoids Linux `FD_SETSIZE` overflow by using `poll()`.
- [x] **P0 — CSPRNG nonces:** generate server session and heartbeat nonces using Windows CNG or OpenSSL RAND_bytes; fail closed on RNG errors.
- [x] **P0 — Constant-time authentication checks:** enforce fixed-size 64-character HMAC comparisons and constant-time shared-secret comparison.
- [x] **P1 — Negotiated heartbeat timing:** server sends active interval/timeout to the client; client validates and uses the negotiated values.
- [x] **P1 — Heartbeat threshold configuration:** use configured consecutive-miss thresholds consistently in both server variants.
- [x] **P1 — Heartbeat server configuration:** Linux server validates supported environment values and passes the resulting config into each session.
- [x] **P1 — Bounded server concurrency:** cap active client handlers at 256 and handle thread-creation failures without terminating the listener.
- [x] **P2 — Concurrent violation logging:** serialize writes to `violations.log` in Windows and Linux server variants.
- [x] **P2 — Log injection:** strip control characters from client details and stop logging raw malformed protocol bytes.
- [x] **P1 — HMAC provider failures:** check BCrypt property retrieval and OpenSSL HMAC return values before consuming digest data.
- [x] **P2 — Automated build workflow:** add GitHub Actions builds for Linux server and Windows Release x86/x64. CI results still need to be observed and fixed if failing.

## Open findings — prioritize next

### P0 — Authentication and transport security

- [ ] **P0 — Replace shared static client secret.** The client embeds or loads a long-lived shared secret. Any secret shipped to an untrusted client can be extracted; obfuscation does not make it confidential. Use per-account/per-session credentials issued by a trusted login service, short-lived challenges, and server-side revocation.
- [ ] **P0 — Protect the protocol with TLS.** Check-in and violation reports currently send credentials and metadata over plain TCP. Deploy TLS with certificate validation and a documented certificate-rotation strategy. HMAC alone does not provide confidentiality.
- [ ] **P0 — Authenticate all protocol frames consistently.** The initial check-in uses a raw shared secret while heartbeat uses a derived HMAC key. Define a versioned, canonical protocol and authenticate message type, length, sequence, nonce, client identity, and payload.
- [x] **P0 — Use constant-time MAC comparison.** Both server variants reject non-64-character MACs and compare heartbeat HMACs in constant time.
- [x] **P0 — Replace predictable `rand()` nonces.** Both servers use the OS CSPRNG (Windows CNG / OpenSSL RAND_bytes) for session and heartbeat nonces, and fail closed when RNG fails.
- [ ] **P0 — Remove raw credential transmission from violation reports.** Violation messages currently include the same static secret used for check-in. Authenticate the report with a session key instead; never put secrets in payloads or logs.

### P1 — TCP protocol and server correctness

- [x] **P1 — Implement framed reads on both server implementations.** Initial requests and heartbeat replies use bounded semicolon-delimited frame parsing with deadlines.
- [x] **P1 — Implement send-all on both server implementations.** Server protocol writes use a complete-send loop, including Linux interrupted-call handling.
- [x] **P1 — Violation report acknowledgement:** both server variants send explicit `OK;` for review-only reports or `KICK;` for banned HWIDs; the client reads a complete response frame and rejects unknown/missing responses.
- [x] **P1 — Preserve pipelined frames.** Shared frame reader retains unread bytes; initial request path rejects unexpected extra client frames.
- [x] **P1 — Fix heartbeat threshold semantics.** Both server variants use `max_consecutive_miss` for warning/flagging transitions. Exact threshold behavior still needs runtime tests.
- [x] **P1 — Apply server heartbeat configuration.** Linux server passes validated heartbeat settings into sessions; Windows server sends its configured defaults to the client.
- [x] **P1 — Validate Linux heartbeat environment configuration.** Linux rejects invalid or out-of-range interval, timeout, jitter, miss-count, and RTT settings; Windows uses bounded defaults. Add equivalent configurable Windows settings only if required.
- [x] **P1 — Fix authentication failure flow.** Invalid credentials take the rejection branch, send `KICK;`, and do not enter the CHECKIN/report handlers; the client socket is closed on handler exit.
- [ ] **P1 — Do not accept empty/unknown client status as healthy.** Heartbeat status is currently hard-coded to `1|1` on the client. Connect it to real health state and treat unavailable checks distinctly from successful checks.
- [ ] **P1 — Bound client connection and handshake duration.** DNS resolution and blocking `connect()` currently have no explicit deadline. Add bounded connect/receive deadlines and structured error handling.

### P1 — Client lifecycle and stability

- [ ] **P1 — Remove heavy cleanup from `DllMain`.** `DLL_PROCESS_DETACH` stops and joins workers, deletes objects, and logs while under the loader lock. Introduce an explicit exported shutdown API and require the host to call it before unloading; keep `DllMain` minimal.
- [ ] **P1 — Synchronize initialization and shutdown.** The initialization thread is detached while global raw pointers are read/written by worker and detach paths. Add a lifecycle state machine, owned initialization thread, cancellation, and synchronization.
- [x] **P1 — Fix partial-construction leaks in `ProcessWatcher`.** Scanner ownership now uses `std::unique_ptr` and constructor unwinding cleans up completed components.
- [ ] **P1 — Make watcher stop interruptible.** `Sleep(500..3000)` delays shutdown; use a condition variable/event and interruptible wait.
- [ ] **P1 — Avoid blocking joins during loader-lock detach.** Validate shutdown order with a host that loads/unloads the DLL repeatedly.
- [ ] **P1 — Validate module path lengths.** Several calls use `GetModuleFileNameW(..., MAX_PATH)` without detecting truncation. Support long paths or fail explicitly.
- [ ] **P1 — Handle Winsock startup failure consistently.** Ensure every successful `WSAStartup` is balanced exactly once and no socket operation proceeds after failed initialization.

### P1 — Integrity and detection correctness

- [ ] **P1 — Replace placeholder/example file hashes.** `RRO.exe`, `Republic.grf`, and `DATA.ini` hashes must be generated from an approved clean release and signed in a trusted manifest. The repository currently labels some values as examples.
- [ ] **P1 — Protect the integrity manifest.** A hash list stored only in the client binary is not a trust anchor if the binary and comparison logic can both be patched. Verify a signed manifest using a pinned public key.
- [ ] **P1 — Fix self-integrity PE bounds validation.** Validate DOS/NT header offsets, section table bounds, image size, raw file ranges, relocation blocks, and integer overflow before dereferencing disk or mapped-image data.
- [ ] **P1 — Review disk-vs-memory section comparison.** PE sections are mapped differently from raw file sections; validate alignment, zero-filled virtual tails, relocations, imports, hotpatches, and legitimate runtime modifications before comparison.
- [ ] **P1 — Correct current-thread debug-register check.** `GetThreadContext(GetCurrentThread())` is not a reliable way to inspect the current thread context. Use a supported, documented method or remove this heuristic.
- [ ] **P1 — Avoid fail-open on inaccessible process data.** Process/module/signature queries often return false/empty on access denial. Distinguish inaccessible, unsupported, and clean states; do not silently treat all errors as safe.
- [ ] **P1 — Review heuristic false positives.** Generic window classes (for example `TForm1`) and broad handle/module heuristics can flag legitimate software. Build a signed allowlist and telemetry-based tuning process.
- [x] **P1 — Bound ProcessWatcher PID cache.** Remove PIDs absent from the current process snapshot and clear the cache on watcher restart. Signature cache limits and PID-creation-time identity remain open.
- [ ] **P1 — Verify process identity against PID reuse.** Cache keys based only on PID can incorrectly reuse decisions after process exit and PID recycling.

### P2 — Data handling and privacy

- [ ] **P2 — Harden HWID generation.** Current HWID uses CPU brand, motherboard UUID, and disk serial, with `UNKNOWN` fallbacks. Handle COM initialization outcomes correctly, normalize values, and document privacy/retention policy.
- [ ] **P2 — Fix COM apartment handling.** `CoInitializeEx` can return `S_FALSE` (successful initialization) and `RPC_E_CHANGED_MODE`; only call `CoUninitialize` when this call successfully initialized COM.
- [ ] **P2 — Avoid leaking hardware identifiers in console output.** Redact or pseudonymize HWID in operational logs.
- [ ] **P2 — Add log rotation and access controls.** `violations.log` currently grows without bound and may contain sensitive process/path data.
- [ ] **P2 — Synchronize ban-list writes.** `violations.log` writes are now serialized, but ban-list reads/writes still need an explicit synchronization and atomic update strategy.
- [ ] **P2 — Fix whitespace trimming on empty ban-list lines.** Guard `find_first_not_of` / `find_last_not_of` results before arithmetic and substring operations.
- [ ] **P2 — Validate ban-list entries.** Reject malformed identifiers and prevent concurrent duplicate writes.

### P2 — Build, repository hygiene, and observability

- [ ] **P2 — Remove generated Visual Studio build artifacts from source control.** Repository currently includes `Debug`, `Release`, `.tlog`, `.iobj`, `.ipdb`, and `.pdb` artifacts. Add appropriate ignore rules and remove generated files from Git history as appropriate.
- [x] **P2 — Add automated CI workflow.** Linux server and Windows Release x86/x64 builds are configured in GitHub Actions. Check run results and add Debug builds / warnings-as-errors later.
- [ ] **P2 — Add unit tests.** Cover frame parser fragmentation/coalescing, malformed messages, maximum lengths, nonce parsing, HMAC verification, config validation, and ban-list parsing.
- [ ] **P2 — Add fuzz tests.** Fuzz all protocol parsers and PE parsing routines using bounded input corpora.
- [ ] **P2 — Add integration tests.** Exercise check-in, banned client, invalid secret, partial send, delayed response, disconnect, heartbeat timeout, and graceful shutdown.
- [ ] **P2 — Add structured security telemetry.** Use event IDs, severity, session correlation IDs, and redaction. Avoid logging credentials or full hardware identifiers.
- [ ] **P2 — Document deployment.** Define TLS termination, firewall policy, secret provisioning, rotation, backup, ban review, and incident response.

## Verification checklist

- [ ] Windows Visual Studio build: Debug x86
- [ ] Windows Visual Studio build: Release x86
- [ ] Windows Visual Studio build: Debug x64
- [ ] Windows Visual Studio build: Release x64
- [ ] Linux build: `make clean && make`
- [ ] Static analysis: MSVC Code Analysis / clang-tidy
- [ ] Runtime test: client handshake and nonce parsing
- [ ] Runtime test: heartbeat fragmentation/coalescing
- [ ] Runtime test: shutdown/unload under repeated cycles
- [ ] Runtime test: file integrity pass/fail with known test fixtures
- [ ] Security test: invalid/missing secret fails closed
- [ ] Security test: malformed/oversized protocol messages rejected

## Notes

- PR #1 was merged into `main`; commits after that merge are collected for follow-up review.
- A checked item means source changes were committed, not that a build/runtime test has passed.
- This branch is a defensive hardening pass, not a claim that the anti-cheat is bypass-proof.
- Do not automatically ban solely on a single heuristic signal. Prefer server-side evidence, confidence scoring, and human review to reduce false positives.
- Any protocol redesign must update Windows client, Windows server, Linux server, and deployment documentation together.
