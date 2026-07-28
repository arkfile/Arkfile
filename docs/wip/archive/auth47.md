# Auth47 Integration Plan for Arkfile

This document outlines the plan for integrating Auth47 as an alternative login method into Arkfile. The goals are to offer a Bitcoin / BIP47 payment-code based login option alongside the existing OPAQUE path, leave OPAQUE fully intact for users who prefer it, keep mandatory MFA (TOTP and/or WebAuthn per the current post-auth challenge model) for every login method, and preserve Arkfile's client-side file encryption model without weakening zero-knowledge guarantees.

## Scope: What Auth47 Replaces (and What It Does Not)

Arkfile uses the Account Password for two completely independent purposes (see `AGENTS.md`):

1. **Authentication (today: OPAQUE).** The password participates in an OPAQUE password-authenticated key exchange so the server never learns it. Nothing from that handshake is used for file crypto.
2. **File encryption (Argon2id -> Account Key).** Separately, on the client only, the same password is fed through Argon2id with a username-bound salt to derive an Account Key (KEK). That KEK wraps per-file FEKs and encrypts owner file metadata. Custom file passwords and share passwords remain separate.

**Auth47 can replace only purpose (1) -- the OPAQUE login/registration handshake.** It proves that the client controls the BIP47 notification-address private key for a claimed payment code (`PM8T...`). It does not produce a client-only secret suitable for deriving an Account Key.

Auth47 login proofs are public, challenge-bound authentication artifacts. The challenge URI includes a fresh nonce; the wallet signs that challenge; the proof (`challenge`, `nym`, `signature`) is sent to the server for verification. Because the nonce changes every login, successive proofs do not converge on a stable secret. Because the proof is server-visible, anything derived from it with a public function is also derivable by the operator. Auth47 answers "does this client control this BIP47 identity right now?" It is not a key agreement and does not export the identity private key to the browser or CLI.

**The Account Password therefore remains a standing, separate requirement for Auth47 users.** Registration and ongoing file operations still collect or prompt for an Account Password that meets the same strength rules as today. Login with Auth47 establishes the session (then MFA); encrypt/decrypt/upload/download still need the Account Password (or a cached Account Key derived from it). "Passwordless Arkfile" is out of scope for this plan. Future work might explore Auth47-adjacent wallet ceremonies (for example, signing a fixed never-uploaded message, or a wallet-native app-key export from the BIP47 identity key) to retire the typed Account Password; that is explicitly not part of v1 and must not reuse Auth47 login proofs as KEK material.

BIP47 itself does include real ECDH shared secrets (notification-transaction payload encryption and payment-address derivation). Those secrets are bilateral: both channel parties can recompute them. Using ECDH against a server-held payment code would let the server derive the same secret and decrypt vault data, which is incompatible with Arkfile's threat model. That BIP47 payment crypto must not be confused with Auth47 login or with Account Key derivation.

## Identity Model

Do not use the human PayNym string (for example `+littlevoice`) as `users.username`. Auth47's `nym` field is a BIP47 payment code (`PM8T...`). PayNym names and nymIDs are a social layer on top (paynym.rs / paynym.is) and are optional for display only.

- **Arkfile username:** conventional human-readable username chosen at registration, stored in `users`, used for salts (`arkfile-account-key-salt:{username}`), billing, ownership, and admin tooling -- same as OPAQUE users.
- **Auth47 binding:** store the verified payment code (or a stable unique encoding of it) in `auth47_identities`, unique, foreign-keyed to the user. That is the login identifier.
- **PayNym display (optional):** resolving `+name` or avatars via paynym.rs must not be required for auth or registration. Depending on an external directory harms availability and increases correlatability for privacy-sensitive personas.

Storing a Bitcoin payment code beside an Arkfile username is a durable link the operator can see. Document that privacy cost in security docs when the feature ships. It is acceptable as an explicit trade for users who want Auth47; it must not be hidden.

## Registration vs Login

Do not auto-provision accounts on a bare login proof without the rest of Arkfile's registration ceremony. Mirror the existing OPAQUE shape as closely as possible:

**Registration (Auth47):** user chooses username and Account Password; completes an Auth47 challenge to bind a payment code; server creates `users` (`login_type = AUTH47`) plus `auth47_identities`; issues a temp MFA-setup token; client runs the existing MFA enrollment flow; honor `RequireApproval` / `is_approved` the same way as OPAQUE registration.

**Login (Auth47):** server-minted challenge; wallet proof verified; lookup by payment code; issue temp MFA token (`aud` / `requires_totp` consistent with the hardened two-tier JWT model); complete MFA; issue full JWT + refresh token. Then the client prompts for Account Password (or uses cached Account Key) for crypto ops -- same as needing the password after OPAQUE login for key derivation.

Open questions for implementation detail (decide before coding): whether one payment code may bind to only one username; whether linking OPAQUE and Auth47 on one account is v1 or later (prefer forbid linking in v1); whether admins may use Auth47 or remain OPAQUE-only for bootstrap and `arkfile-admin` login.

## Auth47 Challenge Lifecycle

Challenge creation and nonce state belong on the trusted server path, not in the browser alone. Follow the pattern used by working Auth47 demos (see Sources):

1. Server generates a random nonce (for example 16 bytes hex) and expiry (for example five minutes).
2. Server builds an Auth47 URI with both `c=` (callback) and `r=` (resource) for wallet compatibility, plus `e=` expiry. Example shape: `auth47://{nonce}?c={callback_url}&e={expiry}&r={callback_url}`. Do not URL-encode the callback URL; wallets expect it unencoded.
3. The string the wallet signs is always the `r=` form of the challenge. The `c=` parameter is not included in the signed challenge.
4. Server stores nonce metadata (expiry, unused) for one-time use.
5. Frontend displays QR / deep link / copyable URI; may poll a status endpoint.
6. Wallet POSTs proof JSON to the callback (and/or an explicit verify endpoint): `{ "auth47_response": "1.0", "challenge": "auth47://...?r=...&e=...", "nym": "PM8T...", "signature": "..." }`.
7. Server (via verifier) checks nonce, expiry, one-time use, callback/resource binding to this Arkfile instance, and cryptographic validity against the notification address derived from `nym`.
8. On success, continue into Arkfile MFA + session issuance as above.

Rate-limit Auth47 challenge minting and failed verifies using EntityID (HMAC of visitor network identity), not raw IP logging, consistent with other auth endpoints.

## Auth47 Verifier Bridge Service

Avoid reimplementing Auth47 verification in Go. A small Bun/TypeScript service uses `@samouraiwallet/auth47` (with `@bitcoinerlab/secp256k1` / `@samouraiwallet/bip47` as needed) and exposes an internal-only API (for example `POST /verify-auth47-proof`) that returns success + verified payment code or an error. Bind to localhost / internal network only; the Go backend is the sole caller. Go still owns nonce storage, expiry, replay protection, user provisioning, MFA, and JWT issuance. Pin library versions and track upstream maintenance (the Auth47 TS package has moved under Dojo tooling historically).

Deploy wiring (systemd unit, health check, `dev-reset` / `local-deploy` / `prod-deploy` / `prod-update`) must be specified when implementation starts; greenfield is fine, but the service is not optional once Auth47 is enabled.

## Database Schema

- Add `login_type` on `users` (for example `OPAQUE` | `AUTH47`). Existing users: `OPAQUE`.
- New table `auth47_identities`: unique payment-code `nym`, `user_id` FK, timestamps. No OPAQUE row required for Auth47-only users.
- Audit all code paths that assume `opaque_user_data` exists (login, re-registration after OPAQUE key rotation, admin status, cleanup). Auth47 users must get clear errors or N/A behavior, not panics or confused re-registration prompts.

## Go Backend

- Challenge mint endpoint (authenticated to this instance's callback URL and nonce store).
- Proof submit / finalize endpoint that verifies via the Bun bridge, looks up or rejects unknown identities on login, and drives registration finalize separately.
- After Auth47 success, reuse the same MFA challenge builder and temp-token rules as OPAQUE finalize (TOTP and/or WebAuthn), then full JWT + refresh token.
- Do not invent an OPAQUE-shaped `sessionKey` from Auth47 material for file crypto. If a random placeholder is needed for API symmetry, it must not be used as KEK input.
- Admin path: decide explicitly. Default recommendation for v1: Auth47 for normal users only; bootstrap and `arkfile-admin` remain OPAQUE.

## Frontend

- Registration: username + Account Password + Auth47 bind + MFA setup + approval gate.
- Login: "Sign in with Auth47" (user-facing copy; avoid jargon like "OPAQUE Auth" in the UI) showing QR/URI; on verified session, MFA; then Account Password prompt / Account Key cache for file ops -- reuse `completeLogin` patterns that already treat password as optional for session but required for crypto.
- Reuse JWT storage, refresh, and `authenticatedFetch` after full tokens are issued.
- Compatible wallets to target in docs/UI: Ashigaru, Sparrow, and other BIP47/Auth47 clients noted by the ecosystem (BlueWallet BIP47 support is more limited; Samourai is legacy).

## CLI and Admin (`arkfile-client`, `arkfile-admin`)

AGENTS.md treats CLI as a first-class client with one clear login path. Auth47 is interactive (QR / deeplink / paste proof). The plan must not leave CLI as an afterthought:

- **`arkfile-client`:** Auth47 register/login (print URI or QR-in-terminal, wait for callback on localhost or accept pasted proof), then Account Password on stdin/prompt for Argon2id, then existing key-agent behavior. e2e coverage needs a deterministic mock Auth47 signer; real wallet QR flows will not run unattended.
- **`arkfile-admin`:** v1 recommendation is OPAQUE-only unless there is a strong reason otherwise; document that choice.

Until CLI support exists, Auth47 is a browser-only auth surface and should be phased explicitly rather than implied complete.

## OPAQUE Coexistence and Session Consistency

OPAQUE remains fully supported. Both paths share MFA gating and the same full JWT / refresh token model, revocation, and middleware. Auth47 does not weaken or bypass MFA. Account linking / switching login types is a future consideration; v1 should keep one primary `login_type` per account unless a binding ceremony is fully designed against account-takeover confusion.

## Privacy and Threat Notes

- Server learns payment code <-> username binding for Auth47 users; OPAQUE users do not create that Bitcoin-identity link.
- Lose wallet seed: lose Auth47 login. Lose Account Password: lose ability to decrypt account-wrapped files. Dual-loss recovery story belongs in user FAQ when shipping.
- Tor-friendly callback URLs and Onion-Location-style deployment concerns matter for the cross-border persona; callback must match what the wallet displays for user verification.
- Do not log raw IPs; use EntityID rate limits on challenge and verify.

## Sources and References

### Provided / primary demos

- [paymentcode.io](https://paymentcode.io/) -- BIP47 and PayNym hub (Auth47 demo, Lab, docs, explorer).
- [paymentcode.io Auth47 login](https://paymentcode.io/auth) -- working QR challenge + wallet verify flow.
- [paymentcode.io documentation](https://paymentcode.io/docs) -- BIP47 protocol summary, Auth47 URI/proof format, PayNym API overview, code examples.
- [paymentcode.io BIP47 Lab](https://paymentcode.io/lab) -- payment-code validation, Alice/Bob ECDH payment-channel walkthrough, notification-address message verifier.
- [linkinparkrulz/bip47-website](https://github.com/linkinparkrulz/bip47-website) -- source for the paymentcode.io-style terminal (challenge mint, callback/verify, polling, PayNym proxy, guestbook).

### Protocol and libraries

- [BIP47 (reusable payment codes)](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki) -- payment codes, notification address, ECDH channel and address derivation.
- [@samouraiwallet/auth47](https://www.npmjs.com/package/@samouraiwallet/auth47) -- Auth47 verifier (URI generation, proof verification).
- [Dojo-Open-Source-Project/auth47](https://github.com/Dojo-Open-Source-Project/auth47) (archived; notes move into dojo-tools) -- Auth47 TypeScript history.
- [@samouraiwallet/bip47](https://www.npmjs.com/package/@samouraiwallet/bip47) -- payment code parse/derive, notification address.
- [@samouraiwallet/bitcoinjs-message](https://www.npmjs.com/package/@samouraiwallet/bitcoinjs-message) -- Bitcoin message signing verify (notification-address signatures).
- [@bitcoinerlab/secp256k1](https://www.npmjs.com/package/@bitcoinerlab/secp256k1) -- secp256k1 backend used with the above.

### PayNym directory / API

- [paynym.rs](https://paynym.rs/) -- PayNym directory; avatar URLs of the form `https://paynym.rs/{payment_code}/avatar`.
- PayNym API notes in-repo on the demo project: [paynym-api.md](https://github.com/linkinparkrulz/bip47-website/blob/master/paynym-api.md) (create/claim/token/follow; claim authenticates by signing a server token with the notification key).

### Ecosystem explainers

- [What Are Auth47 Paynym Accounts? (The Bitcoin Manual)](https://thebitcoinmanual.com/articles/auth47-paynym-accounts/) -- user-facing Auth47 / PayNym authentication overview.
- [PayNym.rs -- How It Works](https://paynym.rs/how-it-works) -- PayNym identity and Auth47 as challenge-response with BIP47 keys.
- [RoninDojo -- Using Auth47 Paynyms](https://blog.ronindojo.io/auth47-paynyms/) -- example third-party Auth47 account creation UX.

### Arkfile-internal

- `AGENTS.md` -- Account Password vs OPAQUE separation; privacy and streaming constraints; CLI as first-class client.
- `docs/security.md` -- server knowledge classification (update when Auth47 ships to record payment-code binding).
- `crypto/password-requirements.json` / `crypto/argon2id-params.json` -- Account Password and Argon2id params still apply to Auth47 users for file encryption.
