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

## Open findings — prioritize next

### P0 — Authentication and transport security

- [ ] **P0 — Replace shared static client secret.** The client embeds or loads a long-lived shared secret. Any secret shipped to an untrusted client can be extracted; obfuscation does not make it confidential. Use per-account/per-session credentials issued by a trusted login service, short-lived challenges, and server-side revocation.
- [ ] **P0 — Protect the protocol with TLS.** Check-in and violation reports currently send credentials and metadata over plain TCP. Deploy TLS with certificate validation and a documented certificate-rotation strategy. HMAC alone does not provide confidentiality.
- [ ] **P0 — Authenticate all protocol frames consistently.** The initial check-in uses a raw shared secret while heartbeat uses a derived HMAC key. Define a versioned, canonical protocol and authenticate message type, length, sequence, nonce, client identity, and payload.
- [ ] **P0 — Use constant-time MAC comparison.** Server heartbeat code currently compares HMAC strings with ordinary string equality. Use a constant-time comparison after strict length/hex validation.
- [ ] **P0 — Replace predictable `rand()` nonces.** Server session and ping nonces are currently generated using `rand()`. Use the operating system CSPRNG (Windows CNG / Linux `getrandom` or OpenSSL RAND_bytes) and fail closed if randomness generation fails.
- [ ] **P0 — Remove raw credential transmission from violation reports.** Violation messages currently include the same static secret used for check-in. Authenticate the report with a session key instead; never put secrets in payloads or logs.

### P1 — TCP protocol and server correctness

- [ ] **P1 — Implement framed reads on both server implementations.** Initial server request parsing calls `recv()` once and assumes the complete request arrived. TCP may fragment or coalesce messages. Implement bounded incremental frame parsing with deadlines for check-in, reports, and heartbeat.
- [ ] **P1 — Implement send-all on both server implementations.** Server responses and heartbeat pings/pongs currently use one `send()`; handle partial sends and interrupted calls.
- [ ] **P1 — Preserve pipelined frames.** Server handshake response and first heartbeat ping may arrive together. Carry unread bytes forward rather than discarding bytes beyond the first delimiter.
- [ ] **P1 — Fix heartbeat threshold semantics.** `max_consecutive_miss` is not consistently applied: warning/flagging logic uses hard-coded values (3 and 5). Define a single policy, validate config bounds, and test exact threshold transitions.
- [ ] **P1 — Apply server heartbeat configuration.** Server reads `OBLV_HB_*` settings into `globalHbCfg`, but the session handler creates a fresh default config. Pass the validated configuration into each client session.
- [ ] **P1 — Validate all environment configuration.** Reject zero/overflow/out-of-range intervals, timeout, jitter, miss count, and RTT thresholds. Ensure timeout and interval combinations are coherent.
- [ ] **P1 — Fix authentication failure flow.** After an invalid secret, the server currently sends `KICK;` but does not immediately return from the handler. Close the session and stop processing further branches.
- [ ] **P1 — Do not accept empty/unknown client status as healthy.** Heartbeat status is currently hard-coded to `1|1` on the client. Connect it to real health state and treat unavailable checks distinctly from successful checks.
- [ ] **P1 — Bound client connection and handshake duration.** DNS resolution and blocking `connect()` currently have no explicit deadline. Add bounded connect/receive deadlines and structured error handling.

### P1 — Client lifecycle and stability

- [ ] **P1 — Remove heavy cleanup from `DllMain`.** `DLL_PROCESS_DETACH` stops and joins workers, deletes objects, and logs while under the loader lock. Introduce an explicit exported shutdown API and require the host to call it before unloading; keep `DllMain` minimal.
- [ ] **P1 — Synchronize initialization and shutdown.** The initialization thread is detached while global raw pointers are read/written by worker and detach paths. Add a lifecycle state machine, owned initialization thread, cancellation, and synchronization.
- [ ] **P1 — Fix partial-construction leaks in `ProcessWatcher`.** Its constructor allocates multiple components with raw `new`; if a later allocation throws, earlier allocations leak. Use `std::unique_ptr` members and initialize safely.
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
- [ ] **P1 — Bound global caches.** `m_scannedProcesses` and signature caches need lifecycle cleanup/limits to avoid unbounded growth and stale PID/path decisions.
- [ ] **P1 — Verify process identity against PID reuse.** Cache keys based only on PID can incorrectly reuse decisions after process exit and PID recycling.

### P2 — Data handling and privacy

- [ ] **P2 — Harden HWID generation.** Current HWID uses CPU brand, motherboard UUID, and disk serial, with `UNKNOWN` fallbacks. Handle COM initialization outcomes correctly, normalize values, and document privacy/retention policy.
- [ ] **P2 — Fix COM apartment handling.** `CoInitializeEx` can return `S_FALSE` (successful initialization) and `RPC_E_CHANGED_MODE`; only call `CoUninitialize` when this call successfully initialized COM.
- [ ] **P2 — Avoid leaking hardware identifiers in console output.** Redact or pseudonymize HWID in operational logs.
- [ ] **P2 — Add log rotation and access controls.** `violations.log` currently grows without bound and may contain sensitive process/path data.
- [ ] **P2 — Synchronize file writes.** Multiple detached server client threads can write to the same log and ban list concurrently. Use a mutex and atomic file update strategy.
- [ ] **P2 — Fix whitespace trimming on empty ban-list lines.** Guard `find_first_not_of` / `find_last_not_of` results before arithmetic and substring operations.
- [ ] **P2 — Validate ban-list entries.** Reject malformed identifiers and prevent concurrent duplicate writes.

### P2 — Build, repository hygiene, and observability

- [ ] **P2 — Remove generated Visual Studio build artifacts from source control.** Repository currently includes `Debug`, `Release`, `.tlog`, `.iobj`, `.ipdb`, and `.pdb` artifacts. Add appropriate ignore rules and remove generated files from Git history as appropriate.
- [ ] **P2 — Add automated CI.** Build Windows x86/x64 Debug/Release and Linux server with warnings-as-errors where practical.
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

- This branch is a defensive hardening pass, not a claim that the anti-cheat is bypass-proof.
- Do not automatically ban solely on a single heuristic signal. Prefer server-side evidence, confidence scoring, and human review to reduce false positives.
- Any protocol redesign must update Windows client, Windows server, Linux server, and deployment documentation together.
