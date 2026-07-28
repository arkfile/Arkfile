# Additional Verification Approaches

## Locked plan (current)

Supplement unit tests, `e2e-test.sh`, and `e2e-playwright.sh` with checks that turn Arkfile's privacy and crypto claims into regressions developers can fail on. Whole-program formal verification across Go, TypeScript, Web Crypto, CGO/libopaque, and browsers is not presently realistic. Focus on security-critical boundaries.

The prerequisite security cleanup in `docs/wip/full-cleanup-2.md` is complete as of July 27, 2026. Go and TypeScript native suites, `dev-reset.sh`, `e2e-test.sh`, and `e2e-playwright.sh` pass. Shared cryptographic fixtures, initial parser fuzz targets, random public Account and Custom Key salts, owner FEK envelope version 2, `.arkbackup` version 2, logging allowlists, and production build-profile checks are stable. Offline and online integrity orchestration are implemented and their full intended sequence was validated on July 28, 2026.

### Offline orchestration: `scripts/testing/offline-integrity-test.sh`

**Status: implemented; default groups pass as of July 28, 2026.** This script runs without a server or deployment. It does not invoke `dev-reset.sh`, `e2e-test.sh`, `e2e-playwright.sh`, or `fdre2e.sh`. It uses explicit preflight checks, ordered groups, pass/fail accounting, cleanup, group selection, and a final report. Go and fuzz workers are capped at half of online CPUs with a minimum of one.

Initial default groups:

- Shared Go and TypeScript cryptographic conformance fixtures, including explicit-salt KDF, AAD, owner-envelope, share-envelope decrypt, and AES-GCM vectors. The pinned share fixture also rejects wrong share/file binding, ciphertext corruption, and authenticated sub-floor KDF parameters.
- Deterministic malformed-input and parser regression tests for owner FEK envelopes, share envelopes, share tickets, and `.arkbackup` bundles.
- Short, explicitly time-bounded native Go fuzz runs seeded by the committed fixtures. Longer fuzz campaigns remain optional and must not run by default.
- Focused upload-completion, share-download-limit, payment-credit, and security-event state invariants that do not require a live server.
- Focused race-detector runs for upload completion, share download limits, concurrent payment delivery, and subscription callback idempotency. These run by default because they exercise the security-sensitive concurrency invariants directly.
- Arkfile-specific `go/analysis` checks after their focused analyzer tests pass.
- Existing production build-profile checks that prove debug console logging, production source maps, unsafe WASM tracing, and `NORANDOM` builds are excluded.

The script must use the same CGO and vendored-library environment as the supported Go test command in `AGENTS.md`. It must fail clearly when required local build artifacts or tools are absent, without attempting a deployment or silently skipping a group. Network-dependent vulnerability databases and optional third-party scanners must not make the deterministic default suite depend on external availability.

### Online orchestration: `scripts/testing/online-integrity-test.sh`

**Status: implemented; full live sequence passed July 28, 2026.** This script must be invoked as `sudo bash scripts/testing/online-integrity-test.sh` because it inspects root-protected deployment configuration, service logs, database snapshots, storage data, and Arkfile's private temporary directory. It requires a live development deployment produced by `dev-reset.sh`, the post-E2E auto-approval policy, and the authenticated admin and development cleanup APIs. It does not invoke reset or E2E scripts itself. It creates a unique dedicated integrity user, isolated CLI/admin HOME, files, shares, canaries, and temporary state under `/tmp/arkfile-integrity-test-data`; it captures and rechecks the shared E2E user's approval, MFA-file digest, and auto-approval policy so it cannot silently break the following Playwright run. All six online groups passed, and the following Playwright run passed all 18 tests.

The CLI RSS regression ceiling remains 262,144 KiB with permitted growth of 98,304 KiB across 1 MiB, 20 MiB, 50 MB, and 100 MB upload/download operations. A five-run local baseline collected by `scripts/testing/cli-rss-baseline.sh` observed 25,568 KiB minimum RSS, 104,232 KiB maximum RSS, and 77,692 KiB maximum growth; individual run growth ranged from 61,920 to 77,692 KiB. These results support the current regression bounds for this machine and tested payload range. They do not prove bounded memory for the representative 6 GB file on a 3 GB device, and the thresholds remain intentionally conservative.

Initial default groups:

- Privacy canaries through account-password, custom-password, upload, metadata, sharing, download, and `.arkbackup` flows.
- Baseline and post-test delta inspection of service logs, security-event rows, application database fields, temporary files, and stored objects. Scan only relevant post-baseline material and report the exact surface and canary class on failure.
- CLI streaming-memory measurements across small increasing payloads, initially 1 MiB, 20 MiB, 50 MB, and at most 100 MB. Assert a documented bounded-memory ceiling or slope appropriate to chunked processing rather than claiming zero growth.
- CLI interruption tests proving downloads cancel without publishing partial plaintext or retaining temporary output, while uploads honor their established SIGINT contract by finishing the active file cleanly and leaving no client temporary state. Do not claim control over operating-system or browser download-manager partial files.
- Selected live authorization and accounting races only where they add coverage beyond deterministic native state/concurrency tests.

Canary checks must allow Arkfile's intentional operational metadata: ownership username, pre-padding encrypted size, padded size, chunk count, plaintext chunk size, encrypted-stream and stored-object digests, routing type, public Account Key salt and KDF profile, and owner-envelope version, key type, KDF profile, and public salt. Public cryptographic metadata is not a privacy-canary failure. Passwords, plaintext file contents, plaintext filenames, plaintext content digests, plaintext password hints, FEKs, KEKs, and OPAQUE outputs remain prohibited.

Online integrity may run between shell E2E and Playwright only if it preserves `arkfile-dev-test-user`, its password and MFA state, `/tmp/arkfile-e2e-test-data/mfa-secret`, and auto-approval. The preferred full manual sequence is:

1. `sudo bash scripts/dev-reset.sh`
2. `bash scripts/testing/offline-integrity-test.sh`
3. `bash scripts/testing/e2e-test.sh`
4. `sudo bash scripts/testing/online-integrity-test.sh`
5. `sudo bash scripts/testing/e2e-playwright.sh`

### Top three approaches

#### 1. Cross-client cryptographic conformance and short fuzzing

**Status: implemented and orchestrated offline.** The shared corpus pins explicit-salt Account, Custom, and Share Key derivation, chunk and metadata AAD, owner FEK envelope headers and wrapping, share-envelope decryption and field recovery, and AES-GCM behavior for Go and TypeScript consumers. The offline script runs the paired fixture consumers, deterministic malformed-input regressions, and separately time-bounded seeded native fuzz targets. Keep expected outputs fixed during routine tests so one client is not silently used as the oracle for the other. Extend cross-client fixtures only where canonical serialization is defined. Server padding and `.arkbackup` remain Go-only unless a TypeScript implementation exists.

#### 2. Privacy-canary and streaming resource invariants

**Status: online orchestration and live validation complete.** The online script uses a unique dedicated identity and protected canary classes, captures pre-test database, journal, temporary-file, application-log, and storage baselines, and reports the exact changed surface and canary class on failure. It includes CLI upload/download RSS measurements at 1 MiB, 20 MiB, 50 MB, and 100 MB, CLI interruption cleanup, and a concurrent one-download share check. The full online run and subsequent Playwright preservation check passed on July 28, 2026. Service Worker resource measurements may follow after CLI measurements are stable. Blob fallback remains a full-plaintext assembly path and is not subjected to a bounded-memory assertion.

#### 3. Custom `go/analysis` checkers for Arkfile architectural invariants

**Status: implemented and enabled in offline integrity.** Three one-purpose analyzers reject raw request IP sources entering persistent logging/audit sinks, security-event type construction or direct SQL persistence outside the logging package, and OPAQUE client session/export outputs entering Arkfile file-crypto calls. They are packaged behind the `cmd/arkfile-analyzers` multichecker driver and have positive and negative `analysistest` fixtures. They deliberately do not claim whole-program secret taint tracking, universal SQL-injection proof, or cryptographic correctness from syntax-level analysis.

### Follow-on and deferred decisions

- **TLA+ / model checking of server state machines** -- deferred (high value later; not in default integrity groups until the top three exist).
- **Tamarin / ProVerif protocol models** -- deferred (after conformance corpus and preferably after a TLA+ state model).
- **Crypto hot-path benchmarks with baselines** -- package-native Go benchmarks now cover 16 MiB chunk encrypt/decrypt, FEK wrap/unwrap, Share Key derivation, and share-envelope create/parse/seal/open with allocation reporting. Initial benchmark capture and any evidence-backed regression thresholds remain pending. Benchmarks complement streaming memory canaries; they are not a substitute for them and are not part of the default integrity pass/fail path.
- **Gobra / Dafny / shipping verified-generated Go** -- not feasible for near-term product confidence; overstated practicality; Dafny-to-Go shipping conflicts with Arkfile's one canonical implementation path.
- **Differential testing against age, RFC 8188, or secretbox** -- not appropriate; Arkfile envelope and chunk formats are not implementations of those protocols.
- **Folding integrity into `e2e-test.sh` or replacing Playwright** -- rejected; integrity sits beside them.
- **Invoking `dev-reset.sh` from either integrity script** -- rejected. Offline integrity does not require a server; online integrity assumes reset and shell E2E already ran.

### Implementation order

1. Completed: define and implement the narrow custom analyzers, allowed exceptions, fixtures, and multichecker driver.
2. Completed: implement `offline-integrity-test.sh` around deterministic conformance, parser, fuzz, analyzer, and production-build checks.
3. Completed: implement `online-integrity-test.sh` with dedicated identity creation, canary generation, baseline/delta capture, cleanup, and precise failure reporting.
4. Completed in the initial script: add CLI memory measurements, interruption cleanup, and a one-download share race.
5. Completed initial developer workflow: the full manual sequence passed, including all six online groups and the following 18-test Playwright run. Five repeated online measurements established the local CLI RSS baseline documented above; conservative thresholds were retained.
6. Pending after CLI measurements stabilize: consider Service Worker resource measurements without changing Blob fallback's documented resource model.

---

## Exploration (background menu)

Potential additional testing approaches and tools that could supplement existing unit, integration, and end-to-end tests for Arkfile. Considering: Go server and Go/TypeScript clients, and whether formal verification could play a role and how it might be applied. The sections below retain the original menu. Status notes mark how each item relates to the locked plan above.

## Supplementing Tests for a Secure File Storage System

Given the security-critical nature of the codebase, layering techniques beyond example-based testing is well worth the effort. Below is a menu ordered roughly by cost/benefit, with formal verification discussed at the end.

### Cheap, High-Value Additions

#### Static analysis and security scanning

**Status: feasible; partially overlaps top approach 3.** Generic scanners complement custom `go/analysis` rules. Prefer Arkfile-specific analyzers (approach 3) as the primary static integrity signal; treat the tools below as optional complements once those exist.

- **`go vet` and `golangci-lint`** with a curated linter set (staticcheck, unused, ineffassign, copylocks, etc.).
- **`gosec`** -- security-focused analyzer that flags crypto misuse, hardcoded credentials, weak randomness, insecure TLS, etc.
- **`govulncheck`** -- scans your dependency graph against the Go vulnerability database and reports *actually reachable* vulnerable code, which dramatically reduces noise.
- **Semgrep** with the Go and crypto rule packs -- good for catching custom anti-patterns (e.g., using AES-CBC without authentication, reusing nonces, mixing key versions). Feasible; optional later if custom analyzers leave gaps.
- For the TS client: **`eslint-plugin-security`**, **`bun`/`osv-scanner` audit**, and a strict `tsconfig` with `strict` + `noUncheckedIndexedAccess`. Feasible; prefer `bun` over npm per project tooling.

#### Race detection and memory sanitizer

**Status: focused race coverage implemented by default; sanitizers remain deferred.** The offline integrity suite runs security-sensitive upload-completion, share-limit, payment-delivery, and subscription-idempotency tests under `go test -race`. MSan/ASan remain optional future work where the CGO toolchain supports them.

- Run tests with `-race` in CI; consider `-gcflags=all=-d=checkptr` for unsafe audits.
- If you use cgo (e.g., for libopaque / related C bindings), run under **MSan/UBSan** via `go build -msan`/`-asan` where the toolchain and environment support it.

#### Crypto microbenchmarks

**Status: benchmark functions implemented; baseline capture pending.** Package-native Go benchmarks report time and allocations for the crypto hot paths listed in the locked plan and remain outside default pass/fail integrity until stable measurements justify thresholds.

#### Fuzzing

**Status: in scope for short seeded fuzz (top approach 1); long campaigns deferred.** Go native fuzzing since 1.18 is ideal for parsers and deserializers:

```go
func FuzzDecodeEnvelope(f *testing.F) {
    f.Add([]byte("valid-envelope-bytes..."))
    f.Fuzz(func(t *testing.T, data []byte) {
        _, err := DecodeEnvelope(data)
        if err == nil && /* panics or invariant violations */ false {
            t.Fatal("expected error or got invalid state")
        }
    })
}
```

Prioritize fuzz targets around:

- Wire-format parsers (envelopes, headers, metadata blobs)
- Path/route parsing (defense against traversal in sharing URLs)
- Auth token validation
- Anything that touches untrusted bytes *before* authenticated decryption

For deeper, coverage-guided fuzzing of the binary as a whole, **libFuzzer via `go fuzz` headers**, **sydr-fuzz**, or **OSS-Fuzz** integration are good options. **Status: deferred / optional** -- useful after short fuzz is wired into offline integrity; do not block the default integrity path on OSS-Fuzz-scale campaigns.

#### Property-based testing

**Status: feasible; refine toward fixed-vector conformance (top approach 1).** Round-trip-only property tests (encrypt in A, decrypt in B) are useful but weaker than a shared byte-exact corpus, because Go and TS can share the same mistake. Prefer fixed keys/nonces/expected bytes plus deliberate corruption; use rapid/fast-check around decoders and state transitions as a supplement.

- Go side: **`pgregory.net/rapid`** or **`github.com/leanovate/gopter`**
- TS side: **fast-check**

Generate random plaintexts, keys, AAD, and have **both** clients encrypt with the same parameters; assert that each can decrypt the other's ciphertext. This catches endian, padding, encoding, and algorithm-mismatch bugs that hand-written tests miss. You can share corpus via JSON test vectors generated by one and consumed by the other.

#### Mutation testing

**Status: feasible; deferred.** **`go-mutesting`** or **`gremlins`** reveal whether tests actually catch logic errors or just execute lines. Informative for access-check helpers once the integrity suite exists; not part of the first offline integrity cut.

### Architectural / Runtime Techniques

#### Trace-based runtime verification

**Status: feasible in spirit; deferred.** For an authorization-heavy server, instrument policy decisions and replay them against a reference model. Tools like **OpenTelemetry + a custom policy checker** can assert invariants like "no object was ever read without a matching `allow` decision" across an entire E2E run. Privacy canaries (top approach 2) cover a related but more Arkfile-specific class of invariants first.

#### Differential testing against a reference implementation

**Status: not appropriate for Arkfile's custom formats.** If a crypto envelope format has a reference (e.g., RFC 8188 for HTTP encryption, age, or libsodium's `secretbox`), generate ciphertexts from the reference and confirm clients decrypt them -- and vice versa. Arkfile's envelope and chunk formats are not implementations of those protocols, so differential testing against them would be misleading. Prefer Arkfile's own fixed conformance corpus instead.

#### Model-based testing for the sharing/permission state machine

**Status: feasible; deferred (related to later TLA+ work).** Permissions on shared files form a small state machine (create share -> issue tickets -> download under limits -> revoke/expire). Encode it in **`rapid`** or in DSL-based tools like **`fsm-go`**, and let the model drive both the server API and assertions about who can read what at any point. Strong complement once default integrity groups exist; selected traces can also come from a future TLA+ model.

### Formal Verification -- Partial Boundaries Only

Formal verification is realistic for *parts* of the system, not the whole thing. Metzger's point (quoted below) applies: there is no viable path today to formally verify the full Go + TypeScript + CGO + browser stack. Pick small boundaries.

#### 1. Cryptographic protocol verification

**Status: deferred (high ROI later, after executable conformance).** If the system defines its own protocol for key exchange, sharing, or authenticated requests (even a small one), model it in:

- **ProVerif** or **Tamarin** -- symbolic, unbounded-session proofs of secrecy, authentication, and forward secrecy.
- **CryptoVerif** -- computational, closer to the actual primitives.

These tools have been used to validate WireGuard, TLS 1.3, Signal's double ratchet, etc. Even without proving the implementation, proving the *protocol design* rules out a large class of bugs. A later Arkfile model could cover OPAQUE session composition, key-context separation (auth vs file crypto), FEK wrapping, share envelopes, tickets, replay, revocation, and compromise assumptions.

#### 2. Verifying the Go implementation of the protocol (Gobra)

**Status: not planned near-term; practicality overstated for this codebase.** A 2022 paper ([ar5iv.labs.arxiv.org](https://ar5iv.labs.arxiv.org/html/2212.02626)) demonstrates verifying **Go implementations** of Needham-Schroeder-Lowe, signed Diffie-Hellman, and WireGuard using **Gobra**, a separation-logic-based verifier for Go ([viperproject/gobra](https://github.com/viperproject/gobra)). Their approach:

- A reusable ghost-code library maintains a global trace of protocol events as shared state.
- Each participant is treated as a concurrent thread; the Dolev-Yao attacker is another thread.
- Security properties (injective agreement, forward secrecy) are proven modularly per participant.
- The library is almost entirely ghost code, so it imposes no runtime overhead and existing implementations need not be restructured much.

Interesting research direction; do not treat as a near-term integrity deliverable. Prefer conformance corpus, canaries, and custom `go/analysis` for product confidence first.

#### 3. Verifying critical Go modules with Dafny

**Status: not feasible as a shipping strategy.** **Dafny** can compile to Go (e.g., **daisy-nfsd**). For leaf modules with crisp specs you could specify in Dafny, prove, and compile to Go. Shipping Dafny-generated Go alongside or instead of hand-written Go introduces another implementation path, contrary to Arkfile's "one canonical path" principle. Keep as background research only; do not plan to replace envelope/AEAD/KDF modules this way.

#### 4. Whole-program nil-safety and parameter tracking with goprove

**Status: watch / optional later.** **goprove** offers a CLI/GitHub Action for whole-program proofs and a `go/analysis` plugin for per-package checks. May inform custom analyzer work; not required for the first offline integrity cut. Prefer first-party `golang.org/x/tools/go/analysis` checkers encoding Arkfile-specific rules (top approach 3).

#### 5. TLA+ for stateful server behavior

**Status: deferred (highest-value formal addition after the top three).** A small TLA+ specification of upload initialization, chunk acceptance, completion, quota accounting, file deletion, share creation, ticket issuance, expiry, download limits, revocation, and concurrent requests. Model checking can establish invariants such as "an incomplete upload never becomes downloadable," "storage cannot be credited twice," "a share cannot issue new tickets after revocation," and "every successful download consumes limits exactly as specified." Selected model-generated traces can become API tests. Keep this out of the default integrity scripts until conformance, canaries, and custom analyzers exist.

---

### References

- https://pkg.go.dev/golang.org/x/tools/go/analysis
- https://github.com/ahmedaabouzied/goprove
- https://github.com/zzctmac/daisy-nfsd
- https://github.com/viperproject/gobra
- https://github.com/NyxFoundation/speca
- https://ar5iv.labs.arxiv.org/html/2212.02626
- `docs/security.md` (plaintext vs operational metadata classification)
- `AGENTS.md` (privacy claims, client parity, streaming constraints)

---

## Background discussion (preserved)

### Perry E. Metzger on formal verification of systems code (X, Jun 17, 2026)

Relevant framing: whole-program formal verification of systems software remains blocked by missing or incomplete language semantics and tooling. Quoted for context:

"""
If you’re not a computer scientist, skip this post.

The biggest impediment to formal verification of systems code is currently this: we have at least three extant formal semantics for C, no viable formal semantics for Rust, and no other viable systems languages. (Yes, I am ignoring C++.)

If we want to formally verify systems code at all, never mind at scale, we need either a new systems language with a formal semantics, or we need a formal semantics for Rust and a reasonable feeling that the semantics reflects the actual implementation of the language and can be maintained going forward as the language evolves.

Unfortunately, as good as Rust is, and it is very good by historical standards, it is a complicated language, and there is a strong suspicion that the type system is not actually sound. It is also probably too large a language for which to build a formally verified compiler given the current state of the art (though that might change), and it is not clear that the official compiler would not rapidly evolve away from a version of the language that a formally verified compiler implemented.

Even given a formally verified compiler and a semantics, neither of which exist, the current proof assistant landscape, tools like Rocq and Lean, are hardly ideal for this sort of work, even given AI assistance.

So, we are in a position in which we know that there is a substantial gap between what we need in order to move forward to formally verified systems software, and the tooling that we have currently.

This is a hard problem. It is also one that needs a solution, or more likely, a set of solutions.

(One irony of the current situation is that most experiments in formally verified systems software still reuse one of CompCert’s intermediate representations as a target. And thus, C is still being perpetuated, even in high assurance programming work.)
"""

- Perry E. Metzger @perrymetzger on X - Jun 17, 2026

### Initial response from ChatGPT 5.6 Sol (preserved)

Metzger’s central point applies here: whole-program formal verification of Arkfile across Go, TypeScript/Web Crypto, C/CGO, browsers, compilers, and deployment infrastructure is not presently realistic. The productive response is to formally specify small, security-critical abstractions while testing whether implementations conform to them. The original WIP menu had useful ideas, but it overstated the practicality of Gobra and Dafny, and compiling verified Dafny into Go would introduce another implementation path contrary to Arkfile’s “one canonical path” principle. Differential testing against age, RFC 8188, or secretbox is also inappropriate because Arkfile’s envelope and chunk formats are not implementations of those protocols.

The highest-value formal addition would be a small TLA+ specification of Arkfile’s stateful server behavior: upload initialization, chunk acceptance, completion, quota accounting, file deletion, share creation, ticket issuance, expiry, download limits, revocation, and concurrent requests. Model checking can establish invariants such as “an incomplete upload never becomes downloadable,” “storage cannot be credited twice,” “a share cannot issue new tickets after revocation,” and “every successful download consumes limits exactly as specified.” This directly supplements example-based tests because it explores operation orderings and concurrency combinations that E2E tests are unlikely to enumerate. Selected model-generated traces could then become API tests, connecting the specification to the implementation.

In parallel, build one cross-client cryptographic conformance corpus covering chunk encryption, FEK envelopes, metadata AAD, share envelopes, padding, backup formats, malformed inputs, truncation, reordered or duplicated chunks, wrong key-type bytes, and boundary sizes. Every vector should be consumed by both Go and TypeScript, with fixed keys, nonces, salts, and expected bytes. Add Go native fuzz targets and fast-check properties around all untrusted decoders and state transitions, including the C/CGO OPAQUE boundary. This is more valuable than merely proving round trips, because two implementations can share the same mistake; byte-level expected vectors and deliberate corruption establish an independent contract.

Finally, add explicit privacy and resource-invariant testing. Instrument test deployments with unique plaintext canaries and assert that passwords, filenames, plaintext digests, hints, and file fragments never appear in HTTP server observations, logs, database fields, temporary files, or stored objects. Separately, run large synthetic streams while measuring peak browser-worker and CLI memory, asserting memory remains bounded independently of file size and that interruption leaves no usable partial plaintext. A Tamarin or ProVerif model could later formalize Arkfile’s composition of OPAQUE sessions, key-context separation, FEK wrapping, share envelopes, tickets, replay, revocation, and compromise assumptions, but pursue that after the executable conformance corpus and TLA+ state model: those two additions offer strong guarantees without pretending to verify the entire language and compiler stack.

**How this maps to the locked plan:** conformance, parser checks, short fuzzing, custom `go/analysis`, and production build checks belong to offline integrity. Privacy canaries, resource measurements, interruption cleanup, and selected live races belong to online integrity. Crypto hot-path benchmarks with baselines are a brief deferred follow-on. TLA+ and Tamarin/ProVerif remain deferred formal work. Gobra/Dafny shipping and foreign-protocol differential testing remain rejected for the reasons above.
