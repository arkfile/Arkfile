# CLI Cleanup & Cohesion Plan

This plan follows the same audit methodology as `docs/wip/server-cleanup.md`, applied to the Go CLI utilities: `cmd/arkfile-admin`, `cmd/arkfile-client`, the credential agent (`agent.go` and platform stubs), and the shared MFA package (`cli/mfa`). Every command handler and helper is reviewed against the Function Review Sanity Checks in `docs/AGENTS.md`: required, correctly implemented, well placed, reachable, privacy-preserving, and free of stubs, deprecated paths, duplicated logic, and leftover placeholder code. Arkfile is greenfield; we delete unused or unreachable CLI paths rather than maintain compatibility shims. The audit was cross-checked against `scripts/testing/e2e-test.sh` and `scripts/testing/e2e-playwright.sh` so we keep what E2E actually exercises and either delete or add coverage for what it does not. Where E2E hedges (`|| true`, pass-with-warning, or multiple acceptable outcomes), we tighten tests and fix CLI or server behavior so there is one canonical expected result.

Status: implementation complete — pending user E2E verification (`dev-reset.sh`, `e2e-test.sh`)
Created: 2026-07-17  
Scope: `cmd/arkfile-admin/` (~6,200 source LOC across decomposed files), `cmd/arkfile-client/` (~6,964 source LOC plus tests), `cli/mfa/` (~973 source LOC plus tests), new shared packages under `cli/{flags,format,jsonutil,secureinput}/`. No TypeScript frontend changes in this document unless a CLI contract fix requires a matching API assertion.

## Principles

One canonical way per operation within each binary (single upload path, single session loader, single JSON printer). Fail closed: no silent `--json` failures, no misleading help text, no stale fallback comments that do not match behavior. Delete dead code rather than deprecate it. Shared logic belongs in `cli/` packages (MFA is the existing good pattern); do not duplicate HTTP clients, formatters, or session helpers across admin and client unless the divergence is intentional and documented. E2E assertions must be exact. After each workstream: `sudo bash scripts/dev-reset.sh`, then `bash scripts/testing/e2e-test.sh`, optionally `sudo bash scripts/testing/e2e-playwright.sh`, plus targeted `go test ./cmd/arkfile-client/... ./cli/mfa/...` (and new admin tests once added).

## Progress tracker

| Workstream | Status | Notes |
|------------|--------|-------|
| Dead code removal | [x] done | Removed dead handlers/aliases; wired `list-tasks` / `cancel-all-tasks`; dropped `upload_id` init fallback |
| `--json` flag reliability | [x] done | `cli/flags.PopBool` for trailing `--json`; Usage text warns flag ordering |
| Hygiene and comment cleanup | [x] partial | WIP doc refs and stale comments addressed; user-facing stdout dividers (`---`, `===`, table rules) kept for CLI readability |
| Duplicate helper consolidation | [x] done | `cli/jsonutil`, `cli/format`, `cli/secureinput`; admin wrappers in `helpers.go` |
| Admin `main.go` decomposition | [x] done | Slim `main.go` (~470 LOC); domain files `auth/user/file/system/session/client/helpers` |
| Agent security hardening | [x] done | `requireSession` before `requireAccountKey`; session-bound `GetAccountKey`; offline RPC split |
| Usage string and help accuracy | [x] done | Admin Usage lists wired commands including storage task commands |
| Session helper consolidation (admin) | [x] done | `requireAdminSession` / `requireAdminMFASession`; 5 intentional MFA-path exceptions unchanged |
| Client billing output parity | [x] done | Human output shows billable bytes, rate, runway, transactions from `/api/credits` |
| Share auth comment alignment | [x] done | Comments match ticket-only client behavior |
| Password input helper alignment | [x] done | Admin uses `cli/secureinput` via `readPassword` wrapper |
| Automation output review | [x] done | Consolidated on `cli/mfa.PrintAutomationBackupCodes` |
| MFA correctness and output | [x] done | `PickResetMethod` single prompt; shared backup output in `cli/mfa/output.go` |
| Agent digest-cache hardening | [x] done | Digest RPCs require session binding; `agent status --show-digests` gated on active session |
| E2E false-green removal | [x] partial | Refresh-token SKIP when missing; MFA credential JSON no longer logged; re-enroll idempotency reruns login |
| Error message consistency | [x] done | Canonical admin session messages via `requireAdminSession` |
| Unit test gap fill | [x] done | Admin `session_test.go` / `helpers_test.go`; agent digest binding test; `cli/flags` tests |
| E2E coverage gaps | [ ] deferred | Untested commands listed below remain follow-up |
| E2E hedging review | [ ] partial | Refresh-token false-green fixed; broader `\|\| true` audit deferred |

---

## Audit summary

| Metric | arkfile-admin | arkfile-client | cli/mfa |
|--------|---------------|----------------|---------|
| Go files (including tests) | 14 | 23 | 7 |
| Source LOC | 6,325 | 6,964 | 973 |
| Test LOC | 0 | 2,238 | 113 |
| `_test.go` files | **0** | 5 | 2 |
| Top-level / subcommands | 52 wired | 30+ | via client + admin wrappers |
| E2E-exercised commands | ~35 invocations | ~40+ invocations | setup, recovery, backup-code, defer-MFA, and TOTP paths |
| Dead / unwired symbols | 5+ confirmed | 1 dead alias | none |
| Largest file | `main.go` (3,032 lines) | `commands.go` (2,402) + `main.go` (1,824) | `setup.go` (462) |

**Highest-impact findings**

1. **`arkfile-admin/main.go` is 48% of the admin package** — HTTP client, session I/O, auth, and 23 command handlers (22 wired plus one dead alias) still live inline while newer domains already have dedicated `*_commands.go` files.
2. **Admin session enforcement is duplicated and incomplete in five handlers** — 16 billing/payments/subscriptions handlers use `requireBillingSession`, while roughly 44 others repeat an inline `ExpiresAt` check after `loadAdminSession`. Five handlers omit expiry checks: `setup-mfa`, `mfa`, `recover-mfa`, `list-user-mfa`, and `verify-storage`. Replace the duplicated checks with one `requireAdminSession()` while preserving an explicit, documented temp-token exception where MFA setup/recovery requires it.
3. **Admin has no unit tests** — all correctness rides on e2e; client has tests for agent, crypto, offline decrypt, reregistration verifier, and upload batch helpers only.
4. **Go `flag.Parse` silently ignores `--json` after positional args** — class of bug that caused the `billing set-price` e2e failure (fixed in e2e with `--json` before price; CLI help still documents fragile order).
5. **Two admin handlers are unwired and one alias is dead** — `list-tasks` and `cancel-all-tasks` have live matching server routes and should be wired; `handleSetupTOTPCommand` is never registered and should be deleted.
6. **Agent authorization is inconsistent** — four `GetAccountKey("")` call sites bypass session binding, digest-cache RPCs have no token binding, and `agent status` prints every file ID and plaintext SHA-256 digest. Active-session list/share paths should bind to the session; offline decrypt needs an explicitly separate capability.
7. **AGENTS.md hygiene violations throughout** — decorative `===`/`---` dividers in source and stdout; `docs/wip/` references embedded in code comments.
8. **Help text drift** — client Usage lists `share delete` (not implemented) but omits `revoke-all`; admin Usage omits `payments` and `subscriptions` groups (billing is listed) and duplicates approval-policy entries.
9. **E2E can report false success** — MFA idempotency, refresh-token/JWT revocation prerequisites, replication skip counts, and billing failure checks contain PASS-without-assertion or pass-with-warning paths beyond the 42 `|| true` occurrences.
10. **Canonical validation has drifted** — admin `validateAdminUsername` claims to mirror `utils.ValidateUsername` but accepts leading/trailing `._-,` that the server rejects.

---

## Dead code removal

### Problem

Greenfield policy: unreachable handlers and compatibility aliases add confusion and maintenance cost without serving operators or e2e.

### Confirmed dead or unwired code

| Item | Location | Issue | Recommended action |
|------|----------|-------|---------------------|
| `handleListTasksCommand` | `storage_commands.go` | Full handler; no `case "list-tasks"` in `main.go` | Wire + document, or delete |
| `handleCancelAllTasksCommand` | `storage_commands.go` | Same for `cancel-all-tasks` | Wire + document, or delete |
| `handleSetupTOTPCommand` | `admin/main.go:934`, `client/main.go:786` | Never registered in either binary's dispatch switch | Delete both |
| `User` struct | `admin/main.go:168` | Defined, never referenced | Delete |
| `generateTOTPCode` | `admin/main.go:975` | Defined but never called; its `totp` import exists only for this function | Delete function and import |
| `safeInt64FromAny` | `subscriptions_commands.go:277` | Defined but never called | Delete |
| Bootstrap comment block | `admin/main.go:738-748` | Stream-of-consciousness uncertainty about `session_id` location | Replace with verified behavior or delete |

### Decision criteria

Both unwired storage commands have live matching routes: `GET /api/admin/storage/tasks` and `POST /api/admin/storage/cancel-all-tasks`. They provide operator value beyond single-task status/cancellation, so the preferred action is to wire, document, and test them rather than delete them.

---

## `--json` flag reliability

### Problem

Go's `flag` package stops parsing at the first non-flag argument. When users or scripts pass `COMMAND ARG --json`, `--json` is silently ignored and human-readable output is emitted. Tests using `jq` then fail even though the underlying API call succeeded (exact failure mode seen with `billing set-price 19.99 --json`).

### Affected commands (admin)

| Command | Fragile usage | Safe usage (e2e today) |
|---------|---------------|------------------------|
| `billing set-price PRICE [--json]` | `set-price 19.99 --json` | `set-price --json 19.99` |
| `payments show ID [--json]` | `show INV --json` | `show --json INV` |
| `payments sync-invoice ID [--json]` | `sync-invoice ID --json` | `sync-invoice --json ID` |

Commands with flags only (no positional before `--json`) are unaffected: `billing show --json`, `security-events --type X --json`, etc.

### Client `--json` naming collision

`contact-info set --json FILE` uses `--json` to mean **JSON input file path**, not stdout JSON. Every other subcommand uses `--json` for machine-readable output. This is a usability trap, not a parser bug.

### Target design

Pick one approach per binary and apply consistently:

**Option A (minimal):** Update all `--help` text and examples to require flags before positionals. Add a one-line note in top-level Usage: "Place `--json` before positional arguments."

**Option B (robust):** Pre-scan `args` for `--json` / `-json` before `flag.Parse`, or use a small custom parser for subcommands that take both positionals and `--json`. Same fix for client if any positional+`--json` combinations are added later.

**Option C (e2e guard):** Add regression tests (shell or Go) that assert `--json` after positional either works or returns a clear error — never silent human output.

Recommended: **Option B** for admin billing/payments; **Option A** immediately as documentation fix; rename client `contact-info set --input` or `--file` in a follow-up breaking change (greenfield allows it).

---

## Hygiene and comment cleanup

### Problem

`docs/AGENTS.md` forbids `===` and `---` in comments and log/print output, WIP planning doc references in code comments, and "keeping for backwards compatibility" / "for now" placeholder reasoning.

### Violations to fix

**Decorative dividers in source comments**

| File | Approx. count |
|------|---------------|
| `cmd/arkfile-client/commands.go` | 8 section blocks |
| `cmd/arkfile-client/main.go` | 4 section blocks |
| `cmd/arkfile-client/agent.go` | 1 section block |
| `cmd/arkfile-client/upload_batch_test.go` | 5 section blocks |

**Decorative dividers in stdout**

| File | Pattern |
|------|---------|
| `cmd/arkfile-admin/main.go` | `--------------------------`, `================`, `strings.Repeat("-", 80)` in user listings |
| `cmd/arkfile-admin/billing_commands.go` | Table rules via `strings.Repeat("-", …)` |
| `cmd/arkfile-admin/storage_commands.go` | `strings.Repeat("-", 100)` |
| `cmd/arkfile-admin/payments_commands.go` | `strings.Repeat("-", 100)` |
| `cmd/arkfile-client/commands.go` | `strings.Repeat("-", 80)` in list output |
| `cli/mfa/setup.go`, `recover.go`, `output.go` | `=== … ===`, `--------------------` in user-facing MFA output |

Replace with blank lines, indented labels, or fixed-width columns without rule characters. MFA backup-code display needs a readable layout that does not use forbidden patterns.

**WIP document references in code**

| File | Reference |
|------|-----------|
| `cmd/arkfile-client/main.go:1383-1423` | `docs/wip/general-enhancements.md` |
| `cmd/arkfile-client/offline_decrypt.go:3` | `docs/wip/arkbackup-export.md` |

Move normative spec pointers to `docs/scripts-guide.md` or inline a one-line format description; delete WIP paths from comments.

**Stale or greenfield-flagged comments**

| File | Text | Action |
|------|------|--------|
| `admin/main.go:748` | `For now, I'll assume it's in Data.` | Verify bootstrap response shape; write definitive comment or fix parsing |
| `admin/main.go:934` | `kept as an alias for compatibility` | Delete alias (see dead code) |
| `admin/main.go:735` | `fallback to top-level SessionID` | Rename to neutral "or top-level field" if behavior kept |
| `commands.go:1725-1727` | X-Download-Token fallback on ticket failure | **Comment is wrong** — code only sets X-Share-Ticket (see share auth section) |
| `billing_commands.go:462-466` | `emptyOrValue(v, fallback)` param name | Rename param to `defaultVal` or `ifEmpty` |
| `admin/main.go:1-2` | Claims the hybrid admin tool operates "without network access" | Replace with an accurate network/local description |
| `storage_commands.go:683-684` | Comment says split alerts by comma; code splits on period | Align parsing with the server's comma-joined alert format |
| `billing_commands.go:418-419` | Says helper is used only by billing | Include payments and subscriptions or rename/generalize helper |
| `subscriptions_commands.go:260` | Human reconcile output uses raw `%+v` map formatting | Add intentional human fields and use shared JSON output only for `--json` |

---

## Duplicate helper consolidation

### Problem

`server-cleanup.md` deferred `formatFileSize` and section-divider cleanup to this pass. Admin and client each maintain parallel copies of formatters, HTTP/session plumbing, and JSON helpers.

### Duplication inventory

| Helper / pattern | Admin | Client | Target |
|------------------|-------|--------|--------|
| `formatFileSize` | `main.go:2826` | `main.go:1630` | `cli/format/format.go` or reuse server `handlers/format.go` if importable |
| `formatBytes` / `formatClientBytes` | `subscriptions_commands.go:264` | `billing_commands.go:186` | Single binary-unit formatter |
| `safeString`, `safeInt64`, `safeBool`, `safeFloat64` | `main.go:2907+` | ad hoc in billing | `cli/jsonutil/` |
| `printJSON` | `billing_commands.go:472`; inline elsewhere | various | one `cli/jsonutil/print.go` |
| `HTTPClient`, `makeRequest`, JWT/session refresh | `main.go` | `main.go` | Consider `cli/apiclient/` shared package (larger lift) |
| `requireBillingSession` | `billing_commands.go:420` | N/A | Generalize to `requireAdminSession` for all admin commands |
| Session load / expiry | 49 direct `loadAdminSession` calls; ~44 duplicate inline expiry checks | `requireSession` pattern in client | Replace with `requireAdminSession`; define explicit MFA temp-token helper |
| `defaultString` / `emptyOrValue` | `billing_commands.go:464` | `commands.go:1610` | Same-purpose default-string helper under different names |
| `clientMFARequester` / `adminMFARequester` | thin wrappers | thin wrappers | Already share `cli/mfa` — keep |
| `looksLikeDollarsAndCents` | `billing_commands.go:437` | client billing | Share if client validates amounts locally |
| `validateAdminUsername` | `main.go:2964` | canonical helper is `utils.ValidateUsername` | Delete the partial fork and call the canonical validator |
| `safeInt64FromAny` | `subscriptions_commands.go:277` | duplicates `safeInt64` and is unused | Delete |

### Consolidation order

Extract pure functions first (format, JSON field accessors, dollar-string validation) — no behavior change, easy to unit test. Defer shared HTTP client package until admin `main.go` split reduces merge conflict surface.

---

## Admin `main.go` decomposition

### Problem

At 3,032 lines, `main.go` mixes dispatch, infrastructure, and 23 command handlers (22 wired plus one dead alias). Newer command groups (`billing_commands.go`, `storage_commands.go`, rotation files) established the intended pattern but migration stalled.

### Recommended file extractions

| New file | Contents moved from `main.go` |
|----------|-------------------------------|
| `client.go` | `HTTPClient`, `Response`, `newHTTPClient`, `makeRequest`, `fetchOpaqueServerID` |
| `session.go` | `AdminConfig`, `AdminSession`, load/save, `getAdminSessionFilePath`, **`requireAdminSession()`** |
| `helpers.go` | `formatFileSize`, `safe*`, `parseStorageLimit`, `boolYesNo`, `statusStr`, shared `printJSON` |
| `auth_commands.go` | `bootstrap`, `login`, `logout`, `setup-mfa`, `adminMFARequester` |
| `user_commands.go` | User lifecycle: list/approve/unapprove/revoke/status/contact/set-storage/update/delete/force-logout |
| `file_commands.go` | `list-files`, `list-shares`, `delete-file`, `revoke-share`, `export-file`, `security-events` |
| `system_commands.go` | `system-status`, `health-check` |
| `main.go` (slim) | `Usage`, `main()` switch, `printUsage`, `printVersion`, logging only |

`verify_storage.go` already follows the one-file-per-domain pattern; use it as the template.

### Inconsistency to fix

`verify_storage.go` is one of only five handlers that loads a session without checking expiry. Most handlers already enforce expiry, but roughly 44 do so with duplicated inline checks while 16 billing-family handlers use `requireBillingSession`. Aligning all applicable handlers on `requireAdminSession()` removes the duplication and closes the five omissions. MFA setup/recovery temp-token flows need explicit semantics rather than an accidental bypass.

---

## Agent security hardening

### Problem

The credential agent holds the account key (KEK) in memory for dedup and filename decryption. E2e covers start/stop/status lifecycle only, not binding edge cases.

### Current controls (good)

Unix domain socket at `~/.arkfile/agent-{uid}.sock`, mode 0600; peer credential validation on Linux/macOS/BSD; session binding via SHA-256 of access token; TTL 1–4 hours with background expiry; mlock best-effort; secure zeroing on wipe; access rate warning.

### Findings requiring action

| Issue | Location | Severity | Recommendation |
|-------|----------|----------|----------------|
| Empty `token_hash` skips binding check | `agent.go:445-453` | Medium | Require non-empty token hash for normal `get_account_key`; use a separately named, auditable offline capability where no session exists |
| `GetAccountKey("")` call sites | `commands.go` (list/share filename decrypt) and `offline_decrypt.go` | Medium | Bind active-session operations; give offline decrypt a separate explicit capability |
| `requireAccountKey()` skips session expiry | `main.go:566-580` | Medium | Load through `requireSession()` before retrieving the bound key |
| Digest RPCs have no token binding | `agent.go` store/get/add/remove digest handlers | Medium | Apply the account-key authorization policy or define a deliberately scoped read-only capability |
| `agent status` prints digest contents | `main.go:1311-1319` | Medium | Print only entry count by default; require an explicit diagnostic flag for file IDs/digests |
| Windows peer auth always true | `agent_windows.go` | Medium | Document as unsupported for agent; or implement equivalent pipe ACL check |
| Windows mlock unsupported | `agent_windows.go` | Low | Document limitation in `agent status` output |
| Windows daemon isolation weaker | `daemon_windows.go` | Low | `daemon_unix.go` uses `Setsid: true`; Windows uses empty `SysProcAttr`. Combined with always-true peer auth, the Windows agent path is materially weaker — document as unsupported or harden |
| Digest cache stores plaintext SHA-256 | `agent.go` digest map | Low | Accept for dedup; document in agent help that cache is content-sensitive |
| Auto-start on most client commands | `main.go:231-236` | Low | Keep; ensure failures are visible in non-verbose mode when agent is required |
| Zombie scan uses Linux `/proc` | `main.go:1242-1267` | Low | Gate message by GOOS or extend |
| Shared agent code calls `os.Getuid()` | `agent.go:118,642` | Medium | Verify Windows builds; move UID lookup behind platform-specific helpers if needed |

### E2E additions (optional)

Agent session mismatch wipes key (unit test exists in `agent_test.go`); e2e could verify list-files after manual session file tamper — lower priority than fixing empty-token and digest authorization paths.

---

## Usage string and help accuracy

### Admin `Usage` constant (`main.go`)

| Gap | Detail |
|-----|--------|
| Missing groups | `payments`, `subscriptions` not listed in top-level Usage (billing is listed at lines 80-89) |
| Duplicate entries | `set-approval-policy` / `get-approval-policy` appear under both NETWORK and SYSTEM |
| Dead command docs | No `setup-totp` in switch (alias dead) |

### Client `Usage` constant (`main.go`)

| Gap | Detail |
|-----|--------|
| `share delete` | Documented but not implemented — only `create`, `list`, `revoke`, `download` exist |
| `revoke-all` | Implemented and e2e-tested but omitted from Usage |
| `billing` / `subscription` | Present in switch; verify examples match `docs/scripts-guide.md` when that doc is updated |

### Target

Generate Usage from a single command registry table, or audit manually so every wired `case` in `main()` appears exactly once in help with correct subcommand list.

---

## Session expiry enforcement (admin)

### Problem

`loadAdminSession` (`admin/main.go:2803`) loads and unmarshals the session file but does not itself check `ExpiresAt`. Sixteen billing/payments/subscriptions handlers check through `requireBillingSession`, and roughly 44 other handlers immediately repeat the same inline check. Five handlers omit expiry validation: `handleSetupMFACommand`, `handleMFACommand`, `handleListUserMFACommand`, `handleRecoverMFACommand`, and `handleVerifyStorageCommand`. The MFA setup/recovery paths may need valid temp-token behavior, but that exception must be explicit and tested.

### Target design

```go
func requireAdminSession(config *AdminConfig) (*AdminSession, error)
```

Single implementation in `session.go` (after decomposition) that loads the session and checks expiry. All access-token network commands call it at the top. MFA temp-token flows use a separately named helper that validates the state appropriate to enrollment or recovery. Dev/test-only local commands (rotation prepare/apply reading mandate files) may intentionally skip — document those exceptions in the function comment. Remove `requireBillingSession` once all callers use the general helper.

---

## Client billing output parity

### Problem

`docs/wip/prod-prep/05-subscriptions.md` requires web and `arkfile-client` to expose the same user-facing billing capabilities and enforcement. CLI commands exist, but human output omits fields the web panel shows from the same `/api/credits` response. `billing show --json` already emits the complete raw `resp.Data`.

### Parity gaps (`billing show`)

| Field | Web (`billing.ts`) | CLI today |
|-------|-------------------|-----------|
| Balance / billing_mode | Yes | Yes |
| Billable bytes / rate / projected cost | Yes | **Missing from human output; present in raw JSON when returned** |
| Credits runway (hours) | Yes | **Missing from human output; present in raw JSON when returned** |
| Transaction history | Yes | **Missing from human output; present in raw JSON when returned** |
| Top-up / subscribe / portal | Yes | Separate subcommands (subscribe/portal not e2e-tested) |

### Target

Extend only the human `billing show` formatter to display `transactions`, `credits_runway`, and usage costing fields already returned by the API. Do not add new API calls. Add an E2E assertion that existing `--json` output contains the API fields; avoid wrapping or renaming them unless the CLI deliberately adopts a stable normalized schema.

### Out of parity scope

Rich DOM formatting, iframe checkout embedding, and `--watch` polling UX — CLI only needs scriptable equivalents (`--wait`, `--open-browser` already exist on top-up/subscribe).

---

## Share auth comment alignment

### Problem

Server-cleanup deferred full ticket-only share auth (static `X-Download-Token` fallback kept on server). Client comment at `commands.go:1725-1727` still claims `setShareAuthHeader` falls back to `X-Download-Token` on ticket failure. Implementation only sets `X-Share-Ticket` and returns an error if ticket issuance fails.

### Target

Delete the stale fallback comment. If ticket-only is the canonical path, ensure share download error messages tell the recipient to retry (ticket refresh on 403 already exists in `fetchShareChunkWithTicketRefresh`). Coordinate with server if static token path is removed later.

---

## Password input helper alignment

### Problem

The two binaries implement password reading with divergent signatures and behavior:

- Admin: `readPassword() (string, error)` — no prompt argument, no stdin-pipe timeout (`admin/main.go:2993`)
- Client: `readPassword(prompt string) ([]byte, error)` — takes a prompt, includes a timeout to prevent indefinite hangs when stdin is a pipe (`client/main.go:1660`)

The client's timeout-on-pipe behavior is a real robustness feature the admin version lacks. Different return types (string vs []byte) also force callers to handle memory differently. The admin string-returning implementation retains immutable password copies that cannot be explicitly zeroed, while the client clears byte buffers after use.

### Target

Either consolidate into a shared `cli/secureinput` package with a single signature (prompt + timeout, returning a zeroed []byte), or document the intentional divergence. If consolidated, the admin callers should gain the timeout protection. Ensure returned buffers are zeroed after use in both binaries.

---

## Automation output review

### Problem

`printAutomationBackupCodes` (`client/main.go:790`, called at `:825`) emits machine-readable backup-code lines for e2e and scripts. Similar output exists in `cli/mfa/output.go`, so behavior is duplicated and inconsistent between setup/verify and admin/client paths. It ships in the production user binary with no build gate.

### Target

Flag for developer review: is automation-readable backup-code output appropriate in the shipped user binary, or should it be gated behind a build tag, a dev flag, or a dedicated e2e helper? Per the Greenfield App and Function Review Sanity Checks, testing-only code paths in the shipped binary should be surfaced and either justified or removed.

---

## MFA correctness and output

### Findings

- `cli/mfa.PickResetMethod` prints its own replacement-factor menu and then calls `PickMethod`, which prints a second menu.
- `PrintRecoverResult` always prints the TOTP secret in human-readable enrollment instructions; `--show-secret` only adds a machine-readable `TOTP_SECRET:` line. Showing the secret is necessary to enroll an authenticator, but flag/help text must describe the distinction accurately.
- Backup-code automation formatting is duplicated between `cmd/arkfile-client/main.go` and `cli/mfa/output.go`; the shared helper emits only indices 0 and 1 and silently ignores additional codes.
- Admin and client recovery wrappers duplicate token selection, argument parsing, and result printing.
- Admin MFA manage/recover paths bypass the normal expiry helper; client `recover-mfa` similarly loads the session directly. Define explicit temp-token and access-token requirements.

### Target

Use one interactive picker, one automation formatter, and one shared recovery command path. Keep human enrollment output sufficient to configure TOTP while ensuring machine-readable secret/backup output is deliberate, documented, and not written to logs.

---

## Error message consistency

### Problem

The "not logged in" error wording differs between handlers:

- `verify_storage.go:50`: `"not logged in as admin (use 'arkfile-admin login' first): %w"`
- `billing_commands.go:423`: `"not logged in as admin (use 'arkfile-admin login'): %w"`

One says "first", the other does not. Similar drift likely exists across other handlers.

### Target

Adopt one canonical "not logged in" message emitted by `requireAdminSession()`. Once all handlers route through it, the wording is uniform by construction. Audit other user-facing error strings for similar drift during the hygiene pass.

---

## `commands.go:539` fallback liveness

### Problem

`commands.go:539` reads `// Try upload_id as fallback` when parsing an upload response field. The current server returns only `session_id`. `makeRequest` also promotes `Data["session_id"]` into `Response.SessionID`, making the tertiary fallback redundant with the primary lookup.

### Target

Remove the dead `Data["upload_id"]` fallback. Keep one canonical `session_id` extraction path; remove the redundant promoted-field fallback unless `Response.SessionID` is required by another response shape.

`payments sync-invoice` similarly probes `resp.Data["data"]` before using `resp.Data`, but the standard response envelope is already flattened into `Response.Data`. Verify the handler contract and remove the nested-data branch if no endpoint returns that shape.

---

## Fail-closed client output

### Problem

`share list` prints the raw response body and returns success when JSON decoding fails (`commands.go:1390-1394`). Scripts can therefore receive malformed/unexpected output with exit status 0. Agent auto-start failures are also hidden unless verbose mode is enabled, which delays the actionable error until a later key operation.

### Target

Return a non-zero error on share-list decode failure unless the user explicitly requested raw output. Surface agent startup failures immediately for commands that require the agent; optional dedup/enrichment paths may warn and continue only when behavior remains correct and the warning is visible.

---

## Global `--json` decision

### Problem

Neither binary defines a global `--json` flag; every subcommand defines its own. This per-subcommand design is exactly why the positional-ordering bug exists (a global flag parsed before dispatch would not have the problem).

### Target

Make an explicit decision and document it in this plan: keep per-subcommand `--json` (more explicit, current) and enforce flags-before-positionals via help text and parser hardening, or add a global `--json` consumed before subcommand dispatch. Either way, record the rationale so future subcommands follow one convention.

---

## Unit test gap fill

### Current coverage

**arkfile-client**

| Test file | Covers |
|-----------|--------|
| `agent_test.go` | Key store/retrieve, binding, expiry, digest, socket |
| `crypto_utils_test.go` | Chunk encrypt/decrypt, FEK, file ID conflict |
| `upload_batch_test.go` | `collectUploadInputs`, JWT refresh, `atomicSaveAuthSession` |
| `offline_decrypt_test.go` | `.arkbackup` / decrypt-blob |
| `reregistration_test.go` | Password verifier only |

**cli/mfa**

| Test file | Covers |
|-----------|--------|
| `setup_test.go` | `ParseMFAMethod`, `extractOptionsJSON` |
| `manage_test.go` | Credential parsing, reset method pick |

**arkfile-admin:** none.

### Priority tests to add

| Target | Rationale |
|--------|-----------|
| `parseStorageLimit` | Pure helper in admin main |
| Canonical username validation | Delete `validateAdminUsername`; test bootstrap through `utils.ValidateUsername`, including leading/trailing special characters |
| `looksLikeDollarsAndCents` | Billing input validation |
| Flag parsing: `--json` after positional | Regression for silent failure class |
| `requireAdminSession` and MFA token helpers | Expiry correctness and explicit temp-token exceptions |
| `requireAccountKey` expiry | Prevent agent-key retrieval through an expired session |
| Agent digest authorization | Ensure unauthorized or mismatched access cannot read/update content-sensitive digests |
| `cli/mfa/recover.go` | No tests for `RunRecover`; cover one-menu selection and output modes |
| Share-list malformed JSON | Must fail non-zero outside `--raw` mode |
| `billing_commands.go` / `subscription_commands.go` (client) | Response parsing, 409 top-up when subscribed |

Handler-level integration tests for full upload/share flows remain e2e's job unless flakiness demands otherwise.

---

## E2E coverage map

### arkfile-admin — exercised

Auth: `login`, `logout`, bootstrap rejection. Users: `list-users`, `user-status`, `approve-user`, `unapprove-user`, `update-user`, `user-contact-info`, `reset-user-mfa`, `flag-user-reregistration`. Files/shares: `list-files`, `list-shares`, `delete-file`, `revoke-share`. System: `system-status`, `health-check --detailed`, `security-events`. Storage: `storage-status`, `storage-sync-status`, `copy-file`, `copy-all`, `verify-all --watch`, `task-status`. Billing: full `billing` suite. Payments: `list`, `show --json`. Subscriptions: `list-plans`, `show`, gift grant/cancel, bridge webhook flows. Policy: `set-approval-policy`, `reset-registration-throttle`.

### arkfile-admin — not exercised

| Category | Commands |
|----------|----------|
| Admin self-service MFA | `setup-mfa`, `mfa`, `recover-mfa` |
| User lifecycle | `set-storage`, `revoke-user`, `force-logout`, `delete-user`, `list-user-mfa`, `export-file` |
| Policy read | `get-approval-policy` |
| Storage ops | `copy-user-files`, `cancel-task`, `set-primary/secondary/tertiary`, `swap-providers`, `set-cost`, `verify-storage` |
| Payments/subscriptions admin | `payments sync-invoice`, `payments reconcile`, `subscriptions set-plan`, `sync`, `reconcile` |
| Key rotation (all) | `rotate-user-secret-master`, `rotate-envelope-master`, `rotate-jwt-keys`, `rotate-opaque-keys` |
| Dead / unwired | `list-tasks`, `cancel-all-tasks` |
| Meta | `version`; `--json` ordering regression |

### arkfile-client — exercised

Register, login (TOTP, backup, defer-MFA, re-registration), logout, MFA setup, `generate-totp`, upload (single, custom password, multi-file batch), download, list-files (`--raw`, `--json`), delete-file, share create/list/revoke/download, export + `decrypt-blob`, contact-info get/set, `revoke-all`, agent stop/status, billing show, subscription status/plans, billing top-up rejection paths.

### arkfile-client — not exercised

| Category | Commands |
|----------|----------|
| MFA manage | `mfa list/remove/regenerate-backup-codes/set-label` |
| Upload variants | `--dir`, `--recursive` |
| Share | `share list --json` |
| Contact | `contact-info delete` |
| Billing | `billing show --json`, `billing invoice status` |
| Subscription | `subscribe`, `portal`, `--json`, `--watch` |
| Agent | explicit `agent start` (daemon auto-start covered indirectly) |
| Meta | `version` |

---

## E2E hedging review

### Problem

`e2e-test.sh` contains 42 `|| true` occurrences. Some are intentional teardown (ignore errors when service already stopped); others may hide real failures in billing/subscriptions setup. Additional false-green paths do not use `|| true`: idempotency markers can record PASS without rerunning assertions, refresh-token and JWT-revocation checks pass when prerequisites are missing, copy-all accepts an incorrect skip count with a warning, and a negative-balance upload test accepts failures unrelated to billing.

### Target

Classify each `|| true` into: **teardown** (keep), **best-effort setup** (replace with explicit precondition checks), or **assertion hedge** (remove; require PASS/FAIL). Subscriptions group uses several `|| true` on gift grant and CLI show commands — tighten to exact exit codes where the test intends to assert success. Audit the four `SKIP` paths against the final checklist instead of claiming zero undocumented skips.

Document allowed dual outcomes only where the product genuinely has two valid states, with a comment in e2e explaining why. Do not log full MFA credential payloads, TOTP secrets, or backup codes; retain only the minimum values required internally by the test.

---

## Suggested implementation order

Work in an order that fixes silent correctness bugs before cosmetic cleanup:

1. **Fail-closed correctness** — fix `--json` positional handling and share-list decode success-on-error.
2. **Agent authorization** — bind active-session key retrieval, enforce session expiry, protect digest RPCs/status output, and define an explicit offline-decrypt capability.
3. **Session helper consolidation** — replace ~44 inline checks and `requireBillingSession`; close the five omissions with explicit MFA temp-token semantics.
4. **MFA correctness** — remove the double prompt, consolidate recovery and backup-code output, and clarify secret output modes.
5. **Dead code removal and canonical validation** — dead aliases/types/helpers, dead response fallbacks, and the partial username-validator fork.
6. **Stale comments and misleading help** — bootstrap speculation, share fallback, package header, Usage drift.
7. **E2E false-green and sensitive-output pass** — prerequisite skips, PASS-without-assertion paths, and credential/secret logging.
8. **Shared pure helpers** — format + JSON util extraction; unify `defaultString`/`emptyOrValue`.
9. **Admin `main.go` decomposition** — mechanical moves after behavior fixes.
10. **Password input helper alignment** — gain timeout protection and zeroable buffers in admin.
11. **Client billing human-output parity** — transactions, runway, billable bytes/rate; JSON already carries raw fields.
12. **Hygiene stdout formatting** — replace forbidden decorative dividers.
13. **Automation output policy** — gate or justify machine-readable secrets/backup codes.
14. **Unit tests** for session/agent/MFA behavior, shared helpers, and flag parsing.
15. **E2E gap fill** — prioritize `get-approval-policy`, `revoke-user`, client `mfa list`, `--json` regression, and `version` invocation.

---

## Verification checklist (final)

- [ ] `sudo bash scripts/dev-reset.sh`
- [ ] `bash scripts/testing/e2e-test.sh` — all PASS, zero SKIP unless documented
- [ ] `sudo bash scripts/testing/e2e-playwright.sh` — all PASS
- [ ] `go test ./cmd/arkfile-client/... ./cli/mfa/... ./cmd/arkfile-admin/...` — pass (after admin tests added)
- [ ] Manual: `arkfile-admin billing set-price 19.99 --json` and `arkfile-admin billing set-price --json 19.99` both emit JSON
- [ ] Manual: `arkfile-client billing show --json` retains the raw API transactions, runway, and billable bytes/rate fields when present
- [ ] Manual: expired admin session produces a friendly "session expired, login again" message across all network commands (not just billing)
- [ ] Manual: expired client session cannot retrieve the account key through `requireAccountKey`
- [ ] Manual: `share list` malformed/unexpected JSON exits non-zero unless `--raw` was requested
- [ ] Manual: `agent status` does not print file IDs or plaintext digests by default
- [ ] Grep `cmd/arkfile-admin`, `cmd/arkfile-client`, `cli/mfa` for `docs/wip/`, `===`, `---`, `for now`, `backward compatibility` — zero inappropriate hits in source (tests may use dividers until cleaned)
- [ ] `arkfile-admin --help` and `arkfile-client --help` match wired commands

---

## E2E-confirmed hot paths (do not delete without replacement)

| Area | CLI surface |
|------|-------------|
| Auth | client register/login/logout/MFA setup; admin login/logout/bootstrap |
| Files | client upload/download/list/delete/export/decrypt-blob |
| Shares | client share create/list/revoke/download |
| Admin users | list/approve/unapprove/update/status/contact/MFA reset/reregistration flag |
| Admin files | list-files/shares, delete-file, revoke-share |
| Storage | storage-status/sync, copy-all/file, verify-all, task-status |
| Billing | admin billing full suite; client billing show, top-up gate |
| Payments | admin payments list/show |
| Subscriptions | admin gift lifecycle + bridge; client status/plans/top-up rejection |
| Agent | stop/status between test groups |
| Security | admin security-events; client revoke-all |

---

## Out of scope (this document)

TypeScript frontend billing panel changes except where e2e Playwright asserts CLI-adjacent strings. Subscription Bridge production service. Full shared `cli/apiclient` HTTP package merge (optional follow-up). Full Windows agent hardening beyond build verification and an explicit supported/unsupported decision. Production deploy script changes. Rewriting `docs/scripts-guide.md` (tracked separately in subscriptions doc TODOs).

---

## Relationship to server-cleanup

| server-cleanup item | CLI cleanup follow-up |
|---------------------|----------------------|
| Deferred `formatFileSize` cleanup | Duplicate helper consolidation workstream |
| Deferred share ticket-only auth | Share auth comment alignment; client already ticket-first |
| E2E hedging removal pattern | Apply same rigor to CLI `--json` and `\|\| true` |
| `health-check` e2e | Already wired; no CLI change needed |
| Admin contacts contract | Client `contact-info` e2e covers user path; admin reads via API |

---

## Command inventory (admin)

| Command | Handler file | E2E |
|---------|--------------|-----|
| `bootstrap` | `main.go` | Y (rejection) |
| `login` / `logout` | `main.go` | Y |
| `setup-mfa` | `main.go` | N |
| `mfa` / `recover-mfa` | `mfa_manage_commands.go` | N |
| `list-users` | `main.go` | Y |
| `approve-user` / `unapprove-user` | `main.go` | Y |
| `set-storage` / `revoke-user` | `main.go` | N |
| `user-status` / `user-contact-info` | `main.go` | Y |
| `update-user` / `delete-user` / `force-logout` | `main.go` | partial (update Y) |
| `reset-user-mfa` | `mfa_reset_commands.go` | Y |
| `list-user-mfa` | `mfa_manage_commands.go` | N |
| `flag-user-reregistration` | `reregistration_commands.go` | Y |
| `list-files` / `list-shares` | `main.go` | Y |
| `delete-file` / `revoke-share` / `export-file` | `main.go` | partial |
| `security-events` | `main.go` | Y |
| `system-status` / `health-check` | `main.go` | Y |
| `verify-storage` | `verify_storage.go` | N |
| Storage management (13 wired) | `storage_commands.go` | partial |
| `list-tasks` / `cancel-all-tasks` | `storage_commands.go` | **unwired** |
| `billing *` | `billing_commands.go` | Y |
| `payments *` | `payments_commands.go` | partial |
| `subscriptions *` | `subscriptions_commands.go` | partial |
| `set/get-approval-policy` | `approval_policy_commands.go` | partial |
| `reset-registration-throttle` | `approval_policy_commands.go` | Y |
| `rotate-*` (4 groups) | `*_rotation_commands.go` | N |
| `version` | `main.go` | N |

---

## Command inventory (client)

| Command | Handler file | E2E |
|---------|--------------|-----|
| `register` / `login` / `logout` | `main.go` | Y |
| `setup-mfa` / `recover-mfa` | `main.go`, `mfa_commands.go` | Y |
| `mfa` | `mfa_commands.go` → `cli/mfa` | N |
| `upload` / `download` / `list-files` / `delete-file` | `commands.go` | Y |
| `share *` | `commands.go` | partial |
| `export` / `decrypt-blob` | `export.go`, `offline_decrypt.go` | Y |
| `contact-info *` | `commands.go` | partial (no delete) |
| `billing *` | `billing_commands.go` | partial |
| `subscription *` | `subscription_commands.go` | partial |
| `generate-test-file` / `generate-totp` | `commands.go` | Y |
| `revoke-all` | `main.go` | Y (hidden from Usage) |
| `agent *` | `agent.go`, `main.go` | partial |
| `version` | `main.go` | N |
| `__agent-daemon` | internal | indirect |
