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
- [x] **P1 — Linux secret file location:** resolve `secret.dat` next to `/proc/self/exe` rather than the service manager's current working directory; cap file size and reject incomplete/error reads.

- [x] **P1 — ProcessWatcher ownership:** use `std::unique_ptr` for scanner components; startup now rolls back cleanly if thread creation fails.
- [x] **P1 — AntiSuspend lifecycle:** make start/stop idempotent and join worker threads rather than leaving them detached.
- [x] **P1 — SelfIntegrityGuard lifecycle:** roll back running state if worker creation fails and always join a joinable worker during Stop.
- [x] **P1 — Scanner UTF-8 buffer overflow:** allocate space for the terminating NUL during `WideCharToMultiByte` in overlay and injection scanners.
- [x] **P1 — Overlay window state:** refresh the game window rectangle and handle destroyed windows or failed Win32 window queries safely.
- [x] **P1 — IAT PE bounds:** validate image headers, import descriptors, thunk tables, and import-name strings before dereferencing them.
- [x] **P1 — IAT ordinal imports:** use the correct 32-bit or 64-bit ordinal flag for the active build architecture.
- [x] **P1 — MemoryScanner PE parsing:** validate DOS/NT offsets, machine/optional-header type, full section-table bounds, section RVAs, and raw file ranges; reject truncated/duplicate sections.
- [x] **P1 — MemoryScanner memory ranges:** validate complete readable executable-section spans across page regions instead of silently skipping inaccessible or partially queried sections.
- [x] **P1 — Executable file reads:** reject failed/negative/oversized file lengths before allocation and use alignment-safe hash extraction.
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

### P0 — Authentication over plain TCP (TLS intentionally out of scope)

- [ ] **P0 — Replace shared static client secret.** The client embeds or loads a long-lived shared secret. Any secret shipped to an untrusted client can be extracted; obfuscation does not make it confidential. Use per-account/per-session credentials issued by a trusted login service, short-lived challenges, and server-side revocation.
- [x] **Design decision — Keep plain TCP; do not add TLS.** The deployment intentionally uses ordinary TCP sockets. The protocol must still authenticate every client-to-server and server-to-client frame, bind message type/length/session/sequence/nonce/payload into a MAC, reject replay and malformed frames, and avoid sending the long-lived shared secret in reports. Plain TCP does not encrypt traffic, so credentials and metadata remain observable to network observers; this is an accepted deployment trade-off, not a pending TLS task.
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
- [x] **P1 — Apply server heartbeat configuration.** Both Linux and Windows servers now pass the validated heartbeat configuration into each client session; Windows no longer logs environment overrides while silently using per-session defaults.
- [x] **P1 — Validate server heartbeat environment configuration.** Linux and Windows strictly parse numeric environment values and enforce supported interval, timeout, jitter, miss-count, and RTT bounds before accepting clients.
- [x] **P1 — Fix authentication failure flow.** Invalid credentials take the rejection branch, send `KICK;`, and do not enter the CHECKIN/report handlers; the client socket is closed on handler exit.
- [ ] **P1 — Do not accept empty/unknown client status as healthy.** Heartbeat status is currently hard-coded to `1|1` on the client. Connect it to real health state and treat unavailable checks distinctly from successful checks.
- [x] **P1 — Bound client TCP connection attempts.** Use nonblocking `connect()` plus `select()` / `SO_ERROR` with a single five-second deadline shared across all resolved addresses in both check-in and violation-report paths.
- [x] **P1 — Bound DNS resolution duration.** Replace both synchronous `getaddrinfo()` calls with cancellable `GetAddrInfoExW()` completion-event resolution; cancel after five seconds and wait for cancellation completion before releasing query state.

### P1 — Client lifecycle and stability

- [ ] **P1 — Remove heavy cleanup from `DllMain`.** `DLL_PROCESS_DETACH` stops and joins workers, deletes objects, and logs while under the loader lock. Introduce an explicit exported shutdown API and require the host to call it before unloading; keep `DllMain` minimal.
- [ ] **P1 — Synchronize initialization and shutdown.** The initialization thread is detached while global raw pointers are read/written by worker and detach paths. Add a lifecycle state machine, owned initialization thread, cancellation, and synchronization.
- [x] **P1 — Fix partial-construction leaks in `ProcessWatcher`.** Scanner ownership now uses `std::unique_ptr` and constructor unwinding cleans up completed components.
- [x] **P1 — Make watcher stop interruptible.** Replace the 500–3000 ms sleep with a condition-variable wait that is notified by `Stop()`, preserving the normal scan interval while allowing prompt shutdown.
- [ ] **P1 — Avoid blocking joins during loader-lock detach.** Validate shutdown order with a host that loads/unloads the DLL repeatedly.
- [x] **P1 — SelfIntegrityGuard module path length.** Resolve the module path with a dynamically sized buffer and fail explicitly if the Windows path cannot be retrieved within the supported buffer limit.
- [x] **P1 — DllMain splash-image module path length.** Resolve the module path with a dynamically sized buffer, detect API failure/truncation, and skip splash loading safely when the path cannot be resolved.
- [ ] **P1 — Handle Winsock startup failure consistently.** Ensure every successful `WSAStartup` is balanced exactly once and no socket operation proceeds after failed initialization.

### P1 — Integrity and detection correctness

- [ ] **P1 — Replace placeholder/example file hashes.** `RRO.exe`, `Republic.grf`, and `DATA.ini` hashes must be generated from an approved clean release and signed in a trusted manifest. The repository currently labels some values as examples.
- [ ] **P1 — Protect the integrity manifest.** A hash list stored only in the client binary is not a trust anchor if the binary and comparison logic can both be patched. Verify a signed manifest using a pinned public key.
- [x] **P1 — Fix self-integrity PE bounds validation.** Validate DOS/NT header offsets, section table bounds, mapped-image readable ranges, raw file ranges, relocation blocks, section metadata consistency, and integer overflow before dereferencing disk or mapped-image data.
- [ ] **P1 — Review disk-vs-memory section comparison.** PE sections are mapped differently from raw file sections; validate alignment, zero-filled virtual tails, relocations, imports, hotpatches, and legitimate runtime modifications before comparison.
- [x] **P1 — Remove invalid current-thread debug-register check.** Remove the `GetThreadContext(GetCurrentThread())` hardware-breakpoint heuristic because Windows explicitly returns an invalid context for a running current thread; the unsupported signal is no longer used for debugger decisions.
- [x] **P1 — Remove unsupported PEB `NtGlobalFlag` offset read.** The handcrafted PEB layout read `NtGlobalFlag` at an architecture/version-dependent offset not present in the documented PEB layout; retain only the documented `BeingDebugged` prefix.
- [x] **P1 — Do not silently stop SelfIntegrityGuard on unreadable PE headers.** Report a distinct `SELF_INTEGRITY_UNAVAILABLE` failure when mapped or disk PE headers cannot be inspected, rather than exiting the monitoring loop silently.
- [x] **P1 — Do not silently skip signature module enumeration failures.** Retry `ERROR_BAD_LENGTH`; report snapshot/first/next enumeration errors and module-path or reporting-conversion failures rather than treating an incomplete scan as trusted.
- [ ] **P1 — Avoid fail-open on inaccessible process data.** Process/module/signature queries often return false/empty on access denial. Distinguish inaccessible, unsupported, and clean states; do not silently treat all errors as safe.
- [x] **P1 — Narrow API-hook prologue detection.** Treat `0xFF` as a branch only when its ModRM operation encodes indirect CALL/JMP, and use `VirtualQuery` allocation-base checks instead of dereferencing module PE headers.
- [ ] **P1 — Review remaining heuristic false positives.** Generic window classes (for example `TForm1`) and broad handle/module heuristics can still flag legitimate software; review these separately.
- [x] **P1 — Bound ProcessWatcher PID cache.** Remove PIDs absent from the current process snapshot and clear the cache on watcher restart. Signature cache limits and PID-creation-time identity remain open.
- [ ] **P1 — Verify process identity against PID reuse.** Cache keys based only on PID can incorrectly reuse decisions after process exit and PID recycling.

### P2 — Data handling and privacy

- [ ] **P2 — Harden HWID generation.** Current HWID uses CPU brand, motherboard UUID, and disk serial, with `UNKNOWN` fallbacks. Handle COM initialization outcomes correctly, normalize values, and document privacy/retention policy.
- [ ] **P2 — Fix COM apartment handling.** `CoInitializeEx` can return `S_FALSE` (successful initialization) and `RPC_E_CHANGED_MODE`; only call `CoUninitialize` when this call successfully initialized COM.
- [ ] **P2 — Avoid leaking hardware identifiers in console output.** Redact or pseudonymize HWID in operational logs.
- [ ] **P2 — Add log rotation and access controls.** `violations.log` currently grows without bound and may contain sensitive process/path data.
- [ ] **P2 — Synchronize ban-list writes.** `violations.log` writes are now serialized, but ban-list reads/writes still need an explicit synchronization and atomic update strategy.
- [x] **P2 — Fix whitespace trimming on empty ban-list lines.** Skip empty/whitespace-only lines before trimming, avoiding `std::string::npos` arithmetic in both Windows and Linux ban-list parsers.
- [ ] **P2 — Validate ban-list entries.** Reject malformed identifiers and prevent concurrent duplicate writes.

### P2 — Build, repository hygiene, and observability

- [ ] **P2 — Remove generated Visual Studio build artifacts from source control.** Repository currently includes `Debug`, `Release`, `.tlog`, `.iobj`, `.ipdb`, and `.pdb` artifacts. Add appropriate ignore rules and remove generated files from Git history as appropriate.
- [x] **P2 — Add automated CI workflow.** Linux server and Windows Release x86/x64 builds are configured in GitHub Actions. Check run results and add Debug builds / warnings-as-errors later.
- [ ] **P2 — Add unit tests.** Cover frame parser fragmentation/coalescing, malformed messages, maximum lengths, nonce parsing, HMAC verification, config validation, and ban-list parsing.
- [ ] **P2 — Add fuzz tests.** Fuzz all protocol parsers and PE parsing routines using bounded input corpora.
- [ ] **P2 — Add integration tests.** Exercise check-in, banned client, invalid secret, partial send, delayed response, disconnect, heartbeat timeout, and graceful shutdown.
- [ ] **P2 — Add structured security telemetry.** Use event IDs, severity, session correlation IDs, and redaction. Avoid logging credentials or full hardware identifiers.
- [ ] **P2 — Document deployment.** Define plain-TCP network exposure, firewall/IP restrictions, secret provisioning and rotation, backup, ban review, and incident response. Do not add TLS to this deployment.

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
- The transport is intentionally plain TCP (no TLS). Any protocol redesign must update Windows client, Windows server, Linux server, and deployment documentation together. MACs provide authenticity/integrity, not confidentiality.
