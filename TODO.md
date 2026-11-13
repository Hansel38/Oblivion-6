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

- [ ] **P0 — Replace shared static client secret.** The client still embeds or loads a long-lived shared secret, which can be extracted from an untrusted client. The new challenge-response flow prevents the secret from being sent over TCP, but does not prevent local extraction. Per-account/per-session credentials from a trusted login service and server-side revocation remain unresolved.
- [x] **Design decision — Keep plain TCP; do not add TLS.** The deployment intentionally uses ordinary TCP sockets. Challenge-response authenticates client requests without transmitting the static secret; session configuration, heartbeat PING/PONG, and `OK`/`KICK` session/report control frames are MAC-authenticated. Pre-authentication rejection frames remain unsigned because no authenticated session exists yet. Plain TCP does not encrypt traffic, so request metadata remains observable to network observers; this is an accepted deployment trade-off, not a pending TLS task.
- [ ] **P0 — Authenticate all protocol frames consistently.** Challenge responses, client request MACs, session configuration, server heartbeat PINGs, client PONGs, and `OK`/`KICK` control acknowledgements are authenticated with HMAC. PONG authentication now uses the `PONG:v1` domain and binds the sequence, client timestamp, nonce, status, and HWID; the status field can no longer be altered independently of its MAC. Heartbeat keys are bound to HWID, the connection challenge, and the session nonce. Pre-authentication rejection frames remain unsigned because no authenticated session exists yet; complete protocol versioning and remaining cross-frame sequence binding are still open.
- [x] **P0 — Use constant-time MAC comparison.** Both server variants reject non-64-character MACs and compare heartbeat HMACs in constant time.
- [x] **P0 — Replace predictable `rand()` nonces.** Both servers use the OS CSPRNG (Windows CNG / OpenSSL RAND_bytes) for session and heartbeat nonces, and fail closed when RNG fails.
- [x] **P0 — Remove raw credential transmission from requests and violation reports.** Client check-in and violation frames no longer contain the static secret. Each connection uses a server-generated CSPRNG challenge; the client proves possession with HMAC-SHA256, and the server validates the MAC in constant time. Runtime interoperability testing remains required.
- [x] **P0 — Bind heartbeat keys to the authenticated handshake.** Derive the heartbeat session key from a versioned domain label, HWID, the verified connection challenge, and the server session nonce consistently in the Windows client and both server implementations. Runtime interoperability and replay tests remain required.

### P1 — TCP protocol and server correctness

- [x] **P1 — Implement framed reads on both server implementations.** Initial requests and heartbeat replies use bounded semicolon-delimited frame parsing with deadlines.
- [x] **P1 — Implement send-all on both server implementations.** Server protocol writes use a complete-send loop, including Linux interrupted-call handling.
- [x] **P1 — Violation report acknowledgement:** both server variants send explicit `OK;` for review-only reports or `KICK;` for banned HWIDs; the client reads a complete response frame and rejects unknown/missing responses.
- [x] **P1 — Preserve pipelined frames.** Shared frame reader retains unread bytes; initial request path rejects unexpected extra client frames.
- [x] **P1 — Fix heartbeat threshold semantics.** Both server variants use `max_consecutive_miss` for warning/flagging transitions. Exact threshold behavior still needs runtime tests.
- [x] **P1 — Apply server heartbeat configuration.** Both Linux and Windows servers now pass the validated heartbeat configuration into each client session; Windows no longer logs environment overrides while silently using per-session defaults.
- [x] **P1 — Validate server heartbeat environment configuration.** Linux and Windows strictly parse numeric environment values and enforce supported interval, timeout, jitter, miss-count, and RTT bounds before accepting clients.
- [x] **P1 — Fix authentication failure flow.** Invalid credentials take the rejection branch, send `KICK;`, and do not enter the CHECKIN/report handlers; the client socket is closed on handler exit.
- [x] **P1 — Do not accept empty/unknown client status as healthy.** The client now reports separate anti-suspend and self-integrity states, initially unavailable and marked healthy only after both monitors start. Both servers require the exact `0|0`, `0|1`, `1|0`, or `1|1` bit format, authenticate it in the PONG MAC, and log transitions to/from unavailable without misclassifying a valid transport heartbeat as packet loss. Runtime initialization, shutdown, and server log-transition tests remain required.
- [x] **P1 — Bound client TCP connection attempts.** Use nonblocking `connect()` plus `select()` / `SO_ERROR` with a single five-second deadline shared across all resolved addresses in both check-in and violation-report paths.
- [x] **P1 — Bound DNS resolution duration.** Replace both synchronous `getaddrinfo()` calls with cancellable `GetAddrInfoExW()` completion-event resolution; cancel after five seconds and wait for cancellation completion before releasing query state.
- [x] **P1 — Require an explicit production server endpoint.** Release builds now require a valid ASCII DNS name or IP address in `OBLIVION_SERVER`; only Debug builds default to loopback. The TCP port remains `54321`. Deployment/runtime endpoint validation remains required.
- [x] **P1 — Resolve secret files only beside the executable.** Client/server Windows loaders now use bounded dynamic `GetModuleFileNameW` buffers and skip file fallback when the executable directory cannot be resolved; they no longer search the current working directory. The client also reads `OBLIVION_SECRET` dynamically with a size limit and validates UTF-8 conversion. Runtime path/long-secret tests remain required.

### P1 — Client lifecycle and stability

- [x] **P1 — Remove heavy cleanup from `DllMain`.** `DllMain` now only records the module handle and disables thread notifications on process attach. Export `Oblivion_Shutdown()` performs worker joins and object destruction outside the loader lock; the host must call it before unloading. Host integration and repeated unload tests remain required.
- [x] **P1 — Synchronize initialization and shutdown.** Replace the detached initialization thread with an owned thread; add explicit `NotStarted/Starting/Started/Stopping/Stopped` states, shutdown cancellation checkpoints, serialized shutdown, and join initialization before cleaning shared objects. Runtime race/stress tests remain required.
- [x] **P1 — Fix partial-construction leaks in `ProcessWatcher`.** Scanner ownership now uses `std::unique_ptr` and constructor unwinding cleans up completed components.
- [x] **P1 — Make watcher stop interruptible.** Replace the 500–3000 ms sleep with a condition-variable wait that is notified by `Stop()`, preserving the normal scan interval while allowing prompt shutdown.
- [x] **P1 — Avoid blocking joins during loader-lock detach.** `DllMain` no longer joins workers. The host calls `Oblivion_Shutdown()` before `FreeLibrary`; repeated load/unload validation remains open in the verification checklist.
- [x] **P1 — SelfIntegrityGuard module path length.** Resolve the module path with a dynamically sized buffer and fail explicitly if the Windows path cannot be retrieved within the supported buffer limit.
- [x] **P1 — DllMain splash-image module path length.** Resolve the module path with a dynamically sized buffer, detect API failure/truncation, and skip splash loading safely when the path cannot be resolved.
- [x] **P1 — Handle Winsock startup failure consistently.** `NetworkReporter` performs all potentially throwing HWID/WMI initialization before `WSAStartup`, records the successful startup only after success, and balances it once in its destructor. Windows server startup checks `WSAStartup` before socket use and calls `WSACleanup` on every reachable startup-error exit. Runtime failure-path checks remain required.

### P1 — Integrity and detection correctness

- [ ] **P1 — Replace placeholder/example file hashes.** `RRO.exe`, `Republic.grf`, and `DATA.ini` hashes must be generated from an approved clean release and signed in a trusted manifest. The repository currently labels some values as examples.
- [ ] **P1 — Protect the integrity manifest.** A hash list stored only in the client binary is not a trust anchor if the binary and comparison logic can both be patched. Verify a signed manifest using a pinned public key.
- [x] **P1 — Discard incomplete SelfIntegrityGuard disk images.** Validate file-size conversions against `size_t` and `streamsize`, handle allocation failures, verify the exact read byte count, and publish the disk image only after a complete successful read so a later `Start()` cannot mistake a partial buffer for initialized data. Runtime short-read/retry fixtures remain required.
- [x] **P1 — Fix self-integrity PE bounds validation.** Validate DOS/NT header offsets, section table bounds, mapped-image readable ranges, raw file ranges, relocation blocks, section metadata consistency, and integer overflow before dereferencing disk or mapped-image data.
- [x] **P1 — Distinguish unreadable self-integrity sections from tampering.** `CompareSection` now returns `Match`, `Mismatch`, or `Incomplete`; inaccessible or invalid memory/range checks report `SELF_INTEGRITY_UNAVAILABLE`, while only a confirmed byte mismatch reports `SELF_TAMPER_DETECTED`. Execute-only and inaccessible-page runtime fixtures remain required.
- [ ] **P1 — Review disk-vs-memory section comparison.** PE sections are mapped differently from raw file sections; validate alignment, zero-filled virtual tails, relocations, imports, hotpatches, and legitimate runtime modifications before comparison.
- [x] **P1 — Remove invalid current-thread debug-register check.** Remove the `GetThreadContext(GetCurrentThread())` hardware-breakpoint heuristic because Windows explicitly returns an invalid context for a running current thread; the unsupported signal is no longer used for debugger decisions.
- [x] **P1 — Remove unsupported PEB `NtGlobalFlag` offset read.** The handcrafted PEB layout read `NtGlobalFlag` at an architecture/version-dependent offset not present in the documented PEB layout; retain only the documented `BeingDebugged` prefix.
- [x] **P1 — Fix UTF-8 conversion buffer bounds in process heuristics.** Convert explicit wide-character lengths without requesting a trailing NUL, allocate the exact encoded byte count, and verify the conversion result before returning.
- [x] **P1 — Resolve process image paths beyond `MAX_PATH`.** Use a bounded dynamically sized `QueryFullProcessImageNameW` buffer for path heuristics, owner-name lookup, and signature-whitelist path lookup.
- [x] **P1 — Scan valid prefixes from partial memory reads.** Classify page protection by its base protection bits (including readable copy-on-write pages) and inspect only the byte count reported by `ReadProcessMemory`, even when the API also reports a partial-copy failure.
- [x] **P1 — Do not silently stop SelfIntegrityGuard on unreadable PE headers.** Report a distinct `SELF_INTEGRITY_UNAVAILABLE` failure when mapped or disk PE headers cannot be inspected, rather than exiting the monitoring loop silently.
- [x] **P1 — Do not silently skip signature module enumeration failures.** Retry `ERROR_BAD_LENGTH`; report snapshot/first/next enumeration errors and module-path or reporting-conversion failures rather than treating an incomplete scan as trusted.
- [x] **P1 — Do not silently skip process enumeration failures.** Report snapshot creation and `Process32First` failures; accept only `ERROR_NO_MORE_FILES` as normal `Process32Next` completion, while allowing an intentional `Stop()` to end the scan without an error.
- [x] **P1 — Report incomplete AdvancedProcessHeuristics process enumeration.** Report process snapshot and first-entry failures, and accept only `ERROR_NO_MORE_FILES` as normal completion of `Process32NextW`; an incomplete process list is no longer silently treated as a clean scan.
- [x] **P1 — Bound MemoryScanner baseline CRC comparisons.** A stored whole-region CRC is compared only when the complete baseline range is available; a shorter region now returns `MEMORY_INTEGRITY_UNAVAILABLE` rather than re-reading live memory or hashing beyond the region. Failed disk fallback reads and invalid reference ranges also return unavailable instead of being labeled tampering. Runtime page-boundary and short-region fixtures remain required.
- [x] **P1 — Report incomplete MemoryScanner runtime module enumeration.** Phase 4 reports snapshot/first/next and `VirtualQuery` failures, validates module base and region progress, and limits scans to the intersection with `modBaseSize`. Runtime fault-injection fixtures remain required.
- [x] **P1 — Distinguish baseline module lookup from incomplete enumeration.** Baseline creation now reports `MODULE_ENUMERATION_UNAVAILABLE` for Toolhelp snapshot/first/next failures and reserves `MODULE_BASE_NOT_FOUND` for a completed enumeration with no matching executable. Runtime API-failure fixtures remain required.
- [ ] **P1 — Avoid fail-open on inaccessible process data.** Execute-only and guarded committed executable pages in selective memory scans now produce `Incomplete` rather than being skipped as clean; runtime status-mapping fixtures and review of the incomplete-scan startup policy remain open. Memory-signature, system-handle, process-path, module, and window scans distinguish clean, suspicious, and incomplete outcomes. Process and module Authenticode checks now separate definitive trust failures from provider/system/publisher-extraction failures. Incomplete module verification remains startup-blocking through the non-ban `MODULE_SIGNATURE_UNAVAILABLE` report rather than being mislabeled as `UNTRUSTED_MODULE`. Runtime status-mapping fixtures and review of the incomplete-scan startup policy remain open.
- [x] **P1 — Do not skip handle-target verification when the owner image path is unavailable.** `GetProcessName` now requests only `PROCESS_QUERY_LIMITED_INFORMATION`; when the name still cannot be resolved, the scanner continues with the authoritative `DuplicateHandle`/`GetProcessId` target check and reports a confirmed game handle as `UNKNOWN_PROCESS` rather than silently skipping it.
- [x] **P1 — Narrow API-hook prologue detection.** Treat `0xFF` as a branch only when its ModRM operation encodes indirect CALL/JMP, and use `VirtualQuery` allocation-base checks instead of dereferencing module PE headers.
- [x] **P1 — Bound process signature verification cache.** Remove the process-global path cache; retain signature decisions only within the current scan phase and cap each cache at 256 entries. Once full, verify directly instead of inserting, so cached trust cannot survive a later scan or watcher restart and memory use stays bounded. Windows runtime file-replacement and long-running-process tests remain required.
- [ ] **P1 — Review remaining heuristic false positives.** Generic window classes (for example `TForm1`) and broad handle/module heuristics can still flag legitimate software; review these separately.
- [x] **P1 — Remove generic window-class false positives.** Remove `TForm1`, `TMainForm`, and generic Qt window-class names from exact-match detections; retain the CE/debugger-specific class names. Runtime fixtures across clean Lazarus/Delphi/Qt applications remain required.
- [x] **P1 — Bound ProcessWatcher PID cache.** Remove PIDs absent from the current process snapshot and clear the cache on watcher restart. PID reuse is checked against process creation time.
- [x] **P1 — Verify process identity against PID reuse.** Key ProcessWatcher cache entries by PID plus `GetProcessTimes()` creation time; discard the prior entry when the current process identity cannot be queried, so stale scan decisions are not reused.

### P2 — Data handling and privacy

- [ ] **P2 — Harden HWID generation.** Current HWID uses CPU brand, motherboard UUID, and disk serial, with `UNKNOWN` fallbacks. Handle COM initialization outcomes correctly, normalize values, and document privacy/retention policy.
- [x] **P2 — Fix COM apartment handling.** A scoped COM initializer treats both `S_OK` and `S_FALSE` as successful initialization and balances either with exactly one `CoUninitialize`; `RPC_E_CHANGED_MODE` leaves the caller's existing COM apartment untouched. Runtime validation under both apartment models remains required.
- [ ] **P2 — Avoid leaking hardware identifiers in console output.** Redact or pseudonymize HWID in operational logs.
- [ ] **P2 — Add log rotation and access controls.** `violations.log` currently grows without bound and may contain sensitive process/path data.
- [ ] **P2 — Synchronize ban-list writes.** `violations.log` writes are now serialized, but ban-list reads/writes still need an explicit synchronization and atomic update strategy.
- [x] **P2 — Fix whitespace trimming on empty ban-list lines.** Skip empty/whitespace-only lines before trimming, avoiding `std::string::npos` arithmetic in both Windows and Linux ban-list parsers.
- [ ] **P2 — Validate ban-list entries.** Reject malformed identifiers and prevent concurrent duplicate writes.

### P2 — Build, repository hygiene, and observability

- [x] **P2 — Remove generated Visual Studio build artifacts from source control.** PR #29 added scoped ignore rules and removed 59 tracked Visual Studio intermediates, build outputs, and generated logs (about 8.3 MB). The root `Release/` runtime assets were preserved.
- [x] **P2 — Add automated CI workflow.** GitHub Actions builds the Linux server with GCC and the Windows solution in Debug and Release for both x86 and x64. Warnings-as-errors and static analysis remain separate follow-ups.
- [ ] **P2 — Add unit tests.** CI tests heartbeat status/PONG serialization, TCP frame fragmentation/coalescing and bounds, and shared challenge-nonce validation including uint64 overflow and malformed decimal input. Real HMAC verification, config validation, ban-list parsing, and Windows runtime framing remain open.
- [ ] **P2 — Add fuzz tests.** Fuzz all protocol parsers and PE parsing routines using bounded input corpora; add memory-signature fixtures spanning contiguous `VirtualQueryEx` regions with matching and differing executable protections.
- [ ] **P2 — Add integration tests.** Exercise check-in, banned client, invalid secret, partial send, delayed response, disconnect, heartbeat timeout, and graceful shutdown.
- [ ] **P2 — Add structured security telemetry.** Use event IDs, severity, session correlation IDs, and redaction. Avoid logging credentials or full hardware identifiers.
- [x] **P2 — Document deployment.** `DEPLOYMENT.md` documents the plain-TCP endpoint, firewall restrictions, secret handling/rotation limitations, backups, ban review, incident response, and remaining release blockers. TLS remains intentionally out of scope.

## Verification checklist

- [x] Windows Visual Studio build: Debug x86
- [x] Windows Visual Studio build: Release x86
- [x] Windows Visual Studio build: Debug x64
- [x] Windows Visual Studio build: Release x64
- [x] Linux build: `make clean && make`
- [ ] Static analysis: MSVC Code Analysis / clang-tidy
- [ ] Runtime test: client handshake and nonce parsing
- [ ] Runtime test: heartbeat fragmentation/coalescing
- [ ] Runtime test: call `Oblivion_Entry()`, then `Oblivion_Shutdown()`, then unload the DLL across repeated cycles
- [ ] Runtime test: file integrity pass/fail with known test fixtures
- [ ] Security test: invalid/missing secret fails closed
- [ ] Security test: malformed/oversized protocol messages rejected

## Notes

- PR #1 was merged into `main`; commits after that merge are collected for follow-up review.
- A checked item means source changes were committed, not that a build/runtime test has passed.
- The host/injector must call exported `Oblivion_Entry()` after loading the DLL and exported `Oblivion_Shutdown()` before unloading it. Calling `FreeLibrary` without the shutdown export is unsupported; process termination is left to the operating system.
- This branch is a defensive hardening pass, not a claim that the anti-cheat is bypass-proof.
- Do not automatically ban solely on a single heuristic signal. Prefer server-side evidence, confidence scoring, and human review to reduce false positives.
- The transport is intentionally plain TCP (no TLS). Any protocol redesign must update Windows client, Windows server, Linux server, and deployment documentation together. MACs provide authenticity/integrity, not confidentiality.
