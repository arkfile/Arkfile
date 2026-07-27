# Additional Verification Approaches

## Locked plan (current)

Supplement unit tests, `e2e-test.sh`, and `e2e-playwright.sh` with checks that turn Arkfile's privacy and crypto claims into regressions developers can fail on. Whole-program formal verification across Go, TypeScript, Web Crypto, CGO/libopaque, and browsers is not presently realistic. Focus on security-critical boundaries.

### Orchestration: `scripts/testing/integrity-test.sh`

**Status: planned (primary vehicle).** Name: `integrity-test.sh`. Pattern: same class as `e2e-test.sh` / `e2e-playwright.sh` (preflight, ordered `run_*` groups, pass/fail accounting, final report). Does not run `dev-reset.sh` or `e2e-test.sh`. Not an `fdre2e.sh`-style wrapper (`fdre2e.sh` remains human-only).

Prerequisites:

- `sudo bash scripts/dev-reset.sh` already completed (binaries under `/opt/arkfile/bin`, live server, admin bootstrap, `ADMIN_DEV_TEST_API_ENABLED`).
- `bash scripts/testing/e2e-test.sh` already completed (shared test user, MFA secret at `/tmp/arkfile-e2e-test-data/mfa-secret`, auto-approval enabled via e2e's final group).

Playwright compatibility: integrity may run between e2e and Playwright. It must not break Playwright prerequisites: preserve `arkfile-dev-test-user` login/password/MFA, preserve `mfa-secret`, leave auto-approval enabled, and avoid deleting the shared user. Prefer `/tmp/arkfile-integrity-test-data` and dedicated canary users/files/shares over mutating e2e artifacts. Reading e2e artifacts is fine; mutating them is not.

Suggested order: `dev-reset.sh` -> `e2e-test.sh` -> `integrity-test.sh` -> `e2e-playwright.sh`.

### Top three approaches (in scope for integrity-test)

#### 1. Cross-client cryptographic conformance and short fuzzing

**Status: in scope (default integrity groups).** One shared corpus of fixed vectors for chunk encryption, FEK envelopes, metadata AAD, share envelopes, padding, `.arkbackup`, key-type bytes, boundary sizes, and deliberately malformed or truncated inputs. Fixed keys, nonces, salts, and expected ciphertext bytes consumed by both Go (`arkfile-client` / packages) and TypeScript. Prefer byte-exact expected outputs over encrypt/decrypt round trips alone so both clients cannot share the same mistake. Add short Go native fuzz (and TS property checks) around untrusted decoders: envelopes, headers, tokens, share path parsing. Mostly offline against built code; keep long fuzz campaigns optional later.

#### 2. Privacy-canary and streaming resource invariants

**Status: in scope (default integrity groups; needs live server).** Instrument uploads, shares, and downloads with unique plaintext canaries (passwords, filenames, digests, hints, file fragments) using dedicated integrity users so Playwright's shared user is untouched. Assert canaries never appear in HTTP observations, server logs, database fields, temp files, or stored objects, while allowing only intentional operational metadata (`size_bytes`, padded size, chunk counts, username, `password_type`, FEK key-type byte). Separately run large synthetic streams and assert peak CLI (and later browser-worker) memory stays bounded independent of file size, and that interruption leaves no usable partial plaintext.

#### 3. Custom `go/analysis` checkers for Arkfile architectural invariants

**Status: in scope (default integrity groups; offline).** Encode project-specific rules that generic linters miss: no raw IP logging (EntityID only), no plaintext filename/digest/hint reaching persistence or logs, no mixing OPAQUE session material into file-crypto paths, parameterized SQL only, and similar "server must never learn X" constraints. Package as a small module of one-purpose checkers behind a single `multichecker` driver that enables every analyzer by default (so a forgotten flag cannot silently skip a rule), following the same discipline as [SpiceDB's custom analyzers](https://github.com/authzed/spicedb/tree/main/tools/analyzers): domain invariants as analyzers, not a port of their concrete checks. Treat these as adversarial `go vet`-style architectural checks (anti-slop for Arkfile-specific forbidden patterns), not generic style lint. Invoke from an integrity group via that driver / `go vet`. Cheap and continuous. Does not prove crypto or concurrency correctness; see deferred formal work below.

### Explicitly deferred or rejected for the default path

- **TLA+ / model checking of server state machines** -- deferred (high value later; not in default integrity groups until the top three exist).
- **Tamarin / ProVerif protocol models** -- deferred (after conformance corpus and preferably after a TLA+ state model).
- **Crypto hot-path benchmarks with baselines** -- deferred (brief; after the top three). Later optional integrity group: Go `Benchmark*` for chunk encrypt/decrypt, FEK wrap/unwrap, share-envelope seal/open, and related envelope work, with a baseline to catch large time/alloc regressions. Complements streaming memory canaries; not a substitute for them.
- **Gobra / Dafny / shipping verified-generated Go** -- not feasible for near-term product confidence; overstated practicality; Dafny-to-Go shipping conflicts with Arkfile's one canonical implementation path.
- **Differential testing against age, RFC 8188, or secretbox** -- not appropriate; Arkfile envelope and chunk formats are not implementations of those protocols.
- **Folding integrity into `e2e-test.sh` or replacing Playwright** -- rejected; integrity sits beside them.
- **Invoking `dev-reset.sh` from integrity** -- rejected; assume reset (and e2e) already ran.

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

**Status: feasible; deferred relative to the top three.** Valuable for CGO (libopaque) and concurrent handlers. Candidates for a later integrity group or CI job (`go test -race`, `-msan`/`-asan` where workable), not required for the first integrity-test cut.

- Run tests with `-race` in CI; consider `-gcflags=all=-d=checkptr` for unsafe audits.
- If you use cgo (e.g., for libopaque / related C bindings), run under **MSan/UBSan** via `go build -msan`/`-asan` where the toolchain and environment support it.

#### Crypto microbenchmarks

**Status: feasible; deferred (see locked plan).** Same brief scope as the deferred benchmarks bullet above; complements approach 2 memory bounds.

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

For deeper, coverage-guided fuzzing of the binary as a whole, **libFuzzer via `go fuzz` headers**, **sydr-fuzz**, or **OSS-Fuzz** integration are good options. **Status: deferred / optional** -- useful after short fuzz is wired into integrity-test; do not block the default integrity path on OSS-Fuzz-scale campaigns.

#### Property-based testing

**Status: feasible; refine toward fixed-vector conformance (top approach 1).** Round-trip-only property tests (encrypt in A, decrypt in B) are useful but weaker than a shared byte-exact corpus, because Go and TS can share the same mistake. Prefer fixed keys/nonces/expected bytes plus deliberate corruption; use rapid/fast-check around decoders and state transitions as a supplement.

- Go side: **`pgregory.net/rapid`** or **`github.com/leanovate/gopter`**
- TS side: **fast-check**

Generate random plaintexts, keys, AAD, and have **both** clients encrypt with the same parameters; assert that each can decrypt the other's ciphertext. This catches endian, padding, encoding, and algorithm-mismatch bugs that hand-written tests miss. You can share corpus via JSON test vectors generated by one and consumed by the other.

#### Mutation testing

**Status: feasible; deferred.** **`go-mutesting`** or **`gremlins`** reveal whether tests actually catch logic errors or just execute lines. Informative for access-check helpers once the integrity suite exists; not part of the first integrity-test cut.

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

Interesting research direction; do not treat as a near-term integrity-test deliverable. Prefer conformance corpus, canaries, and custom `go/analysis` for product confidence first.

#### 3. Verifying critical Go modules with Dafny

**Status: not feasible as a shipping strategy.** **Dafny** can compile to Go (e.g., **daisy-nfsd**). For leaf modules with crisp specs you could specify in Dafny, prove, and compile to Go. Shipping Dafny-generated Go alongside or instead of hand-written Go introduces another implementation path, contrary to Arkfile's "one canonical path" principle. Keep as background research only; do not plan to replace envelope/AEAD/KDF modules this way.

#### 4. Whole-program nil-safety and parameter tracking with goprove

**Status: watch / optional later.** **goprove** offers a CLI/GitHub Action for whole-program proofs and a `go/analysis` plugin for per-package checks. May inform custom analyzer work; not required for the first integrity-test cut. Prefer first-party `golang.org/x/tools/go/analysis` checkers encoding Arkfile-specific rules (top approach 3).

#### 5. TLA+ for stateful server behavior

**Status: deferred (highest-value formal addition after the top three).** A small TLA+ specification of upload initialization, chunk acceptance, completion, quota accounting, file deletion, share creation, ticket issuance, expiry, download limits, revocation, and concurrent requests. Model checking can establish invariants such as "an incomplete upload never becomes downloadable," "storage cannot be credited twice," "a share cannot issue new tickets after revocation," and "every successful download consumes limits exactly as specified." Selected model-generated traces can become API tests. Out of default integrity-test until conformance, canaries, and custom analyzers exist.

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

**How this maps to the locked plan:** conformance corpus + short fuzz, privacy/resource canaries, and custom `go/analysis` (domain invariants as analyzers) are the default integrity-test scope. Crypto hot-path benchmarks with baselines are a brief deferred follow-on. TLA+ and Tamarin/ProVerif remain deferred formal work. Gobra/Dafny shipping and foreign-protocol differential testing remain rejected for the reasons above.
