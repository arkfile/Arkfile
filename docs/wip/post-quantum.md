# Post-Quantum Cryptography Migration Plan

Date: 2026-04-06
Status: Research Complete, Phases 1-2 Complete

## Background

Filippo Valsorda's April 2026 analysis (https://words.filippo.io/crqc-timeline/) shifts the CRQC (Cryptographically Relevant Quantum Computer) timeline dramatically forward. Google and Heather Adkins set 2029 as their deadline. New papers show 256-bit elliptic curves can be broken with far fewer qubits than previously estimated. The risk framing is no longer "will CRQCs exist?" but "can you guarantee they WON'T exist by 2030?"

Key guidance from Filippo:
- Symmetric crypto (AES-256, SHA-256, Argon2id, HKDF) is safe. Grover's algorithm does not meaningfully threaten symmetric primitives at 128+ bit security levels.
- All asymmetric/ECC crypto must migrate to ML-KEM (key exchange) and ML-DSA (signatures).
- Non-PQ key exchange should be treated as potential active compromise.
- File encryption is especially vulnerable to store-now-decrypt-later (SNDL) attacks.
- Hybrid PQ+classic for key exchange is fine; for signatures, go straight to ML-DSA-44.

Reference: age v1.3.0 added PQ recipients; age will soon warn/error on non-PQ types.

## Arkfile Cryptographic Inventory

### SAFE (No PQ Action Needed)

| Component | Algorithm | Why Safe |
|---|---|---|
| File data encryption | AES-256-GCM | Symmetric; Grover impractical at 256-bit |
| Key derivation (passwords) | Argon2id (128MB, 4 iter, 32B key) | Symmetric/memory-hard; no quantum advantage |
| Hashing | SHA-256, SHA-384, SHA-512 | Symmetric; preimage resistance holds |
| HKDF key derivation | HKDF-SHA256 | Symmetric (HMAC-based) |
| FEK wrapping | AES-256-GCM | Symmetric |
| Master key system | AES-256-GCM + HKDF | All symmetric |
| TOTP codes | HMAC-SHA1 (6 digits) | Symmetric MAC; code space is the limit |
| Share envelope encryption | AES-256-GCM-AAD | Symmetric |
| Metadata encryption | AES-256-GCM | Symmetric |

Arkfile's core advantage: the entire file encryption chain (password -> Argon2id -> KEK -> AES-256-GCM(FEK) -> AES-256-GCM(data)) is 100% quantum-safe. Files stored in S3 are NOT vulnerable to SNDL attacks.

### VULNERABLE (Requires PQ Migration)

| Component | Algorithm | Threat | Priority |
|---|---|---|---|
| TLS key exchange | X25519, ECDHE P-384 | Shor breaks ECDLP; SNDL on recorded sessions | CRITICAL |
| TLS certificates | ECDSA P-384, RSA 4096 | Shor breaks ECDSA/RSA; enables active MitM | HIGH |
| OPAQUE auth | Ristretto255, X25519 (libsodium) | Shor breaks all ECC-based OPRF/key exchange | CRITICAL (but no PQ replacement exists) |
| JWT signing | Ed25519 | Shor breaks EdDSA; enables token forgery | HIGH |
| Internal TLS (rqlite, SeaweedFS) | ECDSA P-384 | Same as external TLS | HIGH |

## Migration Phases

### Phase 1: PQ TLS Key Exchange [DONE]

Effort: Minimal (config change only)
Impact: Protects all data in transit from SNDL attacks
Breaking changes: None

Actions:
- [x] Add x25519mlkem768 as first curve preference in Caddyfile (production)
- [x] Install/upgrade Caddy built with Go 1.24+ (required for x25519mlkem768 support)
- [x] Go app direct TLS: Go 1.26.1 defaults include X25519MLKEM768 automatically
- [x] arkfile-client CLI: already enforces TLS 1.3 with Go 1.26.1 default curves
- [ ] Verify PQ key exchange negotiation with a test client

How it works: X25519MLKEM768 is a hybrid key exchange combining classical X25519 with ML-KEM-768 (post-quantum lattice-based KEM). TLS session keys are derived from both, so security holds if either one is unbroken. This is transparent to application code -- only the TLS handshake changes.

Browser support: Chrome 124+, Firefox 131+, Edge 124+, Safari 18+ all support ML-KEM/X25519MLKEM768 in TLS 1.3.

### Phase 2: TLS 1.3 Only [DONE]

Effort: Config and code changes across 6 files
Impact: All connections use PQ key exchange; no TLS 1.2 fallback
Breaking: None (all clients already use TLS 1.3)

Completed actions:
- [x] Caddyfile: `protocols tls1.3` (removed TLS 1.2 fallback and TLS 1.2 cipher suites)
- [x] main.go: Added `tls.Config{MinVersion: tls.VersionTLS13}` to Go server
- [x] handlers/middleware.go: Removed TLS 1.2 version detection case
- [x] arkfile-client: Already enforced `MinVersion: tls.VersionTLS13`
- [x] docs/setup.md: Updated TLS protocol documentation
- [x] docs/wip/go-utils-project.md: Removed TLS 1.2 option references

### Phase 3: JWT Signing Migration (Future)

Effort: Medium
Impact: Prevents JWT forgery by CRQC
Breaking: JWT format change; tokens get larger

Current: Ed25519 (EdDSA) -- 32-byte public key, 64-byte signatures
Target: ML-DSA-44 (FIPS 204) -- 1312-byte public key, 2420-byte signatures

Requirements:
- golang-jwt library needs ML-DSA signing method support
- JWT tokens will be significantly larger (~2.5KB signatures vs 64 bytes)
- All JWT middleware and verification must be updated
- Token rotation during migration

Since Arkfile is greenfield with no deployments, this can be a clean switch rather than a gradual migration. No backwards compatibility needed.

### Phase 4: TLS Certificate Signatures (Future)

Effort: Medium-High (depends on ecosystem)
Impact: Prevents certificate forgery / active MitM
Breaking: Requires PQ-capable CA chain

Current: ECDSA P-384 certificates (self-signed CA for internal, ACME for external)
Target: ML-DSA-44 certificates

Blockers:
- Public CAs (Let's Encrypt/ACME) don't yet issue ML-DSA certificates widely
- Internal CA (04-setup-tls-certs.sh) could be migrated earlier since we control it
- WebPKI is working on Merkle Tree Certificates but not widely deployed
- Client certificate validation libraries need ML-DSA support

Internal services (rqlite, SeaweedFS) are easier to migrate since we control both endpoints and the CA.

### Phase 5: OPAQUE Authentication (Future -- Hardest)

Effort: Very High
Impact: Core authentication protocol
Breaking: Complete protocol replacement

Current: libopaque using Ristretto255/X25519/libsodium
Problem: No standardized PQ-PAKE protocol exists yet

The OPAQUE protocol fundamentally depends on:
- OPRF (Oblivious Pseudo-Random Function) based on Ristretto255 ECDLP hardness
- DH key exchange for server authentication
- Both broken by Shor's algorithm

Options being tracked:
1. NIST PQ-PAKE standardization efforts (not finalized)
2. KEM-based PAKE constructions (research stage)
3. SRP-like protocols adapted for PQ (would lose OPAQUE's strong properties)
4. Interim: rely on PQ TLS tunnel to protect OPAQUE exchanges (Phase 1)

The PQ TLS tunnel from Phase 1 provides meaningful interim protection: an attacker would need a CRQC operating in real-time AND the ability to perform active MitM (which requires breaking TLS certificates too). Passive recording of OPAQUE exchanges over a PQ-TLS tunnel yields nothing useful to a future CRQC.

## Risk Assessment Summary

With Phase 1 complete (PQ TLS key exchange):
- SNDL attacks on recorded traffic: MITIGATED (PQ key exchange)
- Active MitM with future CRQC: PARTIALLY MITIGATED (attacker needs to also forge ECDSA certificates, which requires real-time CRQC + certificate forgery)
- Stored encrypted files in S3: SAFE (symmetric crypto)
- Share envelopes: SAFE (symmetric crypto)
- Authentication protocol: VULNERABLE to real-time CRQC attack, but protected by PQ TLS tunnel against passive recording

## References

- Filippo Valsorda, "A Cryptography Engineer's Perspective on Quantum Computing Timelines" (April 6, 2026): https://words.filippo.io/crqc-timeline/
- age file encryption PQ support (v1.3.0): https://github.com/FiloSottile/age
- Go crypto/tls X25519MLKEM768: added in Go 1.24, default in Go 1.24+
- Caddy x25519mlkem768 support: in default curves list (requires Go 1.24+ build)
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA): finalized August 2024
- X-Wing hybrid KEM: draft-connolly-cfrg-xwing-kem
