# Automation Ideas

## Framing

Arkfile is designed for individuals who hold their own passwords and perform encryption and decryption on their own devices, against a zero-knowledge server that never learns passwords, plaintext, or visitor PII. Real-world usage increasingly includes automation scenarios the current CLI and server were not explicitly designed for -- nightly backups from headless hosts, CI pipelines archiving artifacts, scan-to-vault ingestion, scheduled mirrors to cold-storage instances, and small internal tools acting on behalf of authenticated users -- and today these are achievable but ergonomically push operators toward patterns that quietly weaken the model: long-lived passwords in environment variables, TOTP secrets on argv, a single "shared" account whose compromise exposes an entire organization, or home-grown wrappers that terminate decryption on a networked proxy and become a higher-value target than Arkfile itself. 

This document collects ideas for making automated access both more convenient and more secure without compromising the project's core tenets; every proposal is evaluated against fixed constraints (server must not learn passwords or plaintext, the Argon2id-derived Account Key must not leave the device that holds it, no PII or IP information may be logged, and there must remain one correct way to perform each critical operation per client type), and ideas that would require relaxing any of those constraints are called out explicitly rather than hidden behind convenience framing.

---

Ideas ranked by security/convenience gain vs. risk to the core tenets (zero-knowledge server, password never transmitted, client-side encryption, no PII logging, end-to-end privacy for sharing).

Things I'd propose, grouped. I've tried to flag honestly where each idea has a catch.

---

## A. Safe, high-value improvements (aligned with project tenets)

### A1. First-class non-interactive credential inputs on the CLI

**Status today:** The CLI mostly works non-interactively but input handling is a bit ad-hoc -- `readPassword` reads from stdin-or-TTY with a 10s pipe timeout, TOTP comes via `--totp-code` / `--totp-secret` flags (where `--totp-secret` on argv is leak-prone), and there's no uniform way to pass multiple secrets.

**Proposal:** Standardize on explicit, safe input channels, following the pattern Docker, gh, and age use:
- `--password-stdin` and `--totp-code-stdin` (already partial for offline_decrypt).
- `--password-fd N` / `--totp-fd N` -- read from a specific file descriptor passed by the parent process. This is the systemd/`LoadCredentialEncrypted=` idiom and avoids argv/env leakage entirely.
- `--password-file PATH` and `--totp-secret-file PATH`, read-once-and-unlink semantics optional (`--consume-secret-file`).
- Remove / deprecate `--totp-secret <arg>` on argv, or at minimum print a warning (ps/argv leaks).

**Why it's safe:** Moves secrets off argv and env and onto fds/files where the OS can enforce permissions. No protocol change. No server change.

**Catch:** Very minor -- need to not regress the existing e2e-test.sh flow.

### A2. Named, per-purpose API tokens ("PATs" for arkfile)

**Status today:** Service automation has to do the full OPAQUE dance every TTL expiry (1–4h), meaning the service account's password must live on disk for the relogin, and the agent must be kept warm. The `key-ttl` ceiling of 4h (see `cmd/arkfile-client/agent.go`) is a sensible ceiling for human-held keys but painful for service accounts.

**Proposal:** Allow an authenticated user to mint a **scoped API token** tied to their account:
- Scopes: `upload-only`, `download-only`, `share-create`, `read-metadata`, etc.
- Per-token rate/size limits.
- Per-token optional allow-list of file patterns or a dedicated subtree once folders land (see `docs/wip/folders-multi-upload-v2.md`).
- Server stores only a hash of the token.
- Expiry + rotation + server-side revocation listed in the user's account UI.

**Critical design constraint (to preserve tenets):** The token grants **server API access only**. It does NOT carry or replace the Account Key / Argon2id-derived key. Encryption/decryption still requires either (a) a cached Account Key in the agent or (b) per-file custom passwords or (c) the file being uploaded with a one-off custom password the service only knows for that upload. The server never learns anything new.

Concretely, two useful modes fall out:
- **"Ingest-only" token + custom password per file.** Service uploads files, each with a random custom password, and stores `(file_id, custom_password)` pairs in its own secret store. Server has a long-lived bearer token, zero key material. Compromise of the token lets you push garbage in; it doesn't let you decrypt anything.
- **"Read-only metadata" token** for dashboards/inventory that want file lists without ever holding keys.

**Why it's safe:** Tokens are access-control to the API; they don't weaken the crypto. Scopes shrink blast radius. No change to OPAQUE or AES-GCM.

**Catch:** Real complexity -- new DB table, revocation plumbing, new endpoints, new CLI subcommand (`arkfile-client token create --scope upload-only --ttl 90d`). But this is the single biggest quality-of-life win for automation and it aligns with Arkfile's model rather than fighting it.

### A3. Longer agent TTL *optionally*, gated by attestation/policy

**Status today:** `MaxKeyTTLHours = 4` in agent.go.

**Proposal:** Allow up to 24h (or "session lifetime") TTL but only when:
- The binary is launched under a systemd unit with `ProtectSystem=strict`, `MemoryDenyWriteExecute=`, `PrivateTmp=`, etc., or
- The host provides a TPM quote / YubiKey touch ritual at re-use, or
- The agent socket parent dir is on a tmpfs that's wiped on reboot.

Or simpler: `--key-ttl-max-hours 24` opt-in flag behind a `--i-understand-headless` style gate, logged in the agent audit counter. Humans stay capped at 4; opt-in headless mode can go longer.

**Why it's reasonably safe:** The 1–4h cap is belt-and-suspenders for attended desktops; headless systems with proper hardening don't meaningfully benefit from forcing re-login, they just get service accounts whose password is more exposed in practice.

**Catch:** Any TTL extension is a real tradeoff; if disk-swapping is defeated by mlock (already done) and core dumps are disabled, the window matters mostly against live-memory attackers. Document that.

### A4. Agent-as-a-service: systemd unit and OCI image

**Status today:** Agent is a user-space daemon auto-started by CLI; no first-party systemd unit, no container story.

**Proposal:** Ship:
- `systemd/arkfile-client-agent@.service` (user instance) and `arkfile-client-agent.service` (system instance for service accounts).
- `systemd/arkfile-login-warmer@.timer` that re-runs `login --non-interactive` from `LoadCredentialEncrypted=` before the agent's TTL expires.
- A minimal OCI image (distroless) that bundles `arkfile-client` with a `/run/secrets/arkfile/` convention.
- A one-page `docs/automation.md` with the hardening checklist (no core dumps, mlock limits, AppArmor/SELinux sample profile).

**Why it's safe:** Pure packaging. Makes the "do it correctly" path the easy path.

**Catch:** Adds maintenance burden to the project.

### A5. Machine-readable output across the board

**Status today:** `list-files --json` exists. Other commands are human-oriented.

**Proposal:** `--output json` (or `--json`) on `login`, `upload`, `share create`, `share list`, `delete-file`, `contact-info`, `export` for stable machine-parseable output (jsonlines for bulk ops). Stabilize the schema and document it. This dramatically simplifies bash/Python/Go glue and kills fragile regex parsing.

**Why it's safe:** Zero crypto impact; it's just IO.

**Catch:** Need to commit to schema stability going forward.

### A6. Bulk/batch operations as first-class primitives

**Status today:** e2e-test.sh loops `arkfile-client upload` N times; that's O(N) OPAQUE logins in the worst case, and each invocation pays agent handshake cost.

**Proposal:**
- `arkfile-client upload --from-manifest files.jsonl` -- reads lines like `{"path": "...", "password-type": "account"}` and uploads sequentially, reusing the agent key. Emits result lines on stdout.
- `arkfile-client download --from-manifest` symmetric.
- `arkfile-client share create --from-manifest` for batch share minting.

**Why it's safe:** Just orchestration. Agent key reuse is already safe.

**Catch:** Error handling semantics need to be explicit (fail-fast vs. continue-on-error, partial-progress checkpointing).

---

## B. Medium-value improvements with real design questions

### B1. Share-for-automation: "recipient-bound" shares

**Status today:** Shares are `ShareURL + SharePassword`. Both secrets. If you want to "let this CI job download this backup," you hand it both. Compromise of either alone is useless, but the two together decrypt the file until revoked.

**Proposal (exploratory):** A variant share where instead of a human-memorable password, the share is bound to a recipient's X25519 pubkey. Uploader encrypts the share envelope to that pubkey. Recipient presents a signature from the privkey to download. Useful when the recipient is a machine, not a human, and we want proof-of-holder.

**Why it preserves tenets:** Server still sees ciphertext; neither key leaves the parties.

**Catch:** Kind of reinvents a public-key layer on top of Arkfile's symmetric model, and collides with Arkfile's design of anonymous-recipient sharing (no account, no pubkey infra). It may be an *unnecessary* second way to do sharing. I would flag this as "nice idea, probably not a fit for the project's stated minimalism." Mention it only because you asked. Better answer: just use Pattern-B service accounts with a custom-password-per-file.

### B2. Per-file/per-folder "append-only" policy

**Proposal:** Let a user mark a folder (when folders ship) as append-only, and mint tokens/shares that can only append, not list or mutate. Useful for log ingestion, tamper-evident drops, "drop box" style intake.

**Why it preserves tenets:** Server-side authorization check; no crypto change.

**Catch:** Requires folders to be done first. Coordinate with `docs/wip/folders-multi-upload-v2.md`.

### B3. Offline-first CLI modes for air-gapped automation

**Status today:** Already good -- `export` / `decrypt-blob` exist.

**Proposal:** Small gaps to fill:
- `arkfile-client encrypt --out file.arkpkg` (produces an encrypted artifact that's uploadable later by any means).
- `arkfile-client upload-encrypted --in file.arkpkg` (uploads an already-encrypted artifact, skipping local encryption).
- Lets a CI runner encrypt in a sandboxed step with ephemeral keys, then a separate restricted step pushes the ciphertext.

**Why it preserves tenets:** Strengthens them -- enables splitting the trust boundary between "has plaintext" and "has network."

**Catch:** Needs careful format versioning; shouldn't diverge from the on-wire chunked envelope.

---

## C. Things I'd explicitly *not* do, even though they'd be convenient

Calling these out because they're the usual "automation-friendly" features that would quietly erode the privacy story.

### C1. "Service password-less login" via server-stored credentials
A "just let the server hand my service a session token" flow would require the server to know or hold something password-equivalent. That directly violates the OPAQUE / zero-knowledge design. **Don't do this.** A1+A2 cover the real use case without this compromise.

### C2. Password recovery via email / admin reset
Same reason. The server cannot recover what it never knew. The account password *is* the KEK for everything metadata-related. Any "reset" actually means "destroy and recreate the account." Make that explicit in admin docs; don't build a reset flow that looks like it works.

### C3. Server-side thumbnail/preview generation
Tempting for "share this nicely in Slack" workflows. Would require server-side decryption. **Don't.** Preview generation must stay client-side (browser or a recipient's CLI).

### C4. A central key-escrow / "corporate recovery" feature
Businesses will ask for this. It's incompatible with the project's tenets. The honest answer is: the *user* may opt to wrap a second copy of their FEK to a corporate public key at upload time, client-side -- but that's a per-file, user-initiated choice, not a server-mandated escrow. If we ever add it, it lives behind an explicit `--also-wrap-to <pubkey>` upload flag and is clearly surfaced to the user. I'd flag this as a future design discussion, not something to quietly slip in.

### C5. Generic request/response logging "for ops"
IP/PII-free is already a tenet (HMAC'd EntityIDs per AGENTS.md). Automation traffic tempts ops to log more. Hold the line; if logs are needed, add metrics (rates, counts, sizes) that contain no per-request identity.

---

## D. Ranked shortlist if you wanted to just do a few

If I had to pick the top three that preserve everything and unlock the automation story:

1. **A2 -- Scoped, revocable API tokens** for service accounts. Single biggest unlock. Correctly designed, it does not weaken crypto one bit; it just bounds blast radius.
2. **A1 -- Clean non-interactive credential input** (`--password-fd`, `--password-file`). Cheap, eliminates a real category of secret-leak.
3. **A4 -- Official systemd/OCI packaging + docs** for the "Pattern B service account" host. Makes the secure path the default path.

Honorable mention: **A5 (JSON output everywhere)** -- trivial in cost, massive in ecosystem impact, makes every wrapper (Python/Node/bash) dramatically more reliable.

---
