# Production Bitcart VPS Architecture and `arkfile-bitcart` Plan

## Purpose and Scope

This document defines the production deployment architecture for hosting a privacy-hardened, mainnet-only Bitcart payment server on a small, low-cost AlmaLinux VPS (`pay.arkfile.net`) using rootless Podman and stock Caddy, serving both the `test` and `prod` instances of `arkfile.net` from a single Bitcart stack via isolated non-superuser Bitcart merchant accounts. It also provides a complete, self-contained build prompt at the end of this document for an AI coding agent working inside the new standalone `arkfile-bitcart` repository.

Nothing in this design uses or assumes testnet, regtest, or stagenet. Bitcoin and Monero run exclusively on mainnet (`BTC_NETWORK=mainnet`, `XMR_NETWORK=mainnet`). No blockchain full nodes (`bitcoind`, `electrs`, `fulcrum`, or `monerod`) run on the Bitcart VPS; the stack points strictly at two external node URLs (`BTC_SERVER` and `XMR_SERVER`), either public nodes or operator-hosted nodes running elsewhere.

## Architectural Contrast: Upstream `bitcart-docker` vs. Local Lab vs. `arkfile-bitcart`

Upstream `bitcart-docker` (`setup.sh`) optimizes for single-tenant convenience on rootful Docker rather than privilege separation or zero-IP-logging privacy. By default, `setup.sh` requires a rootful `dockerd` daemon, mounts `/var/run/docker.sock` into its reverse-proxy generator container, installs host-execution hooks (`bitcart-agent` systemd socket or root SSH `authorized_keys` entries) so the browser admin UI can run host commands, logs visitor IP addresses in Nginx access logs, runs PostgreSQL in `trust` mode without a password, deploys unused e-commerce store and template-renderer containers, and initializes stores with unsafe checkout defaults (`transaction_speed=0`, `email_required=true`, `allow_anonymous_invoice_creation=true`).

Our local verification harness (`scripts/testing/bitcart-lab/`) proved out the core rootless Podman translation on real mainnet BTC and XMR payments, removing `dockerd`, host-agent sockets, SSH hooks, and unused store components while automating safe wallet, store, and scoped-token provisioning. However, the local lab intentionally co-locates Arkfile and Bitcart on one developer machine behind a local `.lab` CA, uses a single Bitcart store, leaves PostgreSQL on internal `trust` auth, and exposes the Bitcart admin panel on the same listener as checkout.

The new `arkfile-bitcart` repository turns those proven lab components into a dedicated production VPS deployment with strict two-host separation from Arkfile:

1. **Two-host correlation boundary:** `pay.arkfile.net` never holds Arkfile code, user accounts, or `payment_invoices.username` mappings. Arkfile sends Bitcart only a random `invoice_id` (as `order_id`), the USD price, the store ID, and `https://<arkfile-domain>/api/webhooks/bitcart`. Compromising one host cannot link an Arkfile username to on-chain payment metadata or checkout network traffic.
2. **Small VPS footprint (~850 MiB measured RSS):** Live cgroup measurements from our mainnet lab after confirmed BTC and XMR payments show the entire Bitcart container set consumes roughly 836 MiB of RAM (`worker` 287 MiB, `backend` 212 MiB, `monero` watch-only client 101 MiB, `admin` 84 MiB, `bitcoin` watch-only client 76 MiB, `postgres` 43 MiB, `caddy` 18 MiB, `redis` 8 MiB, `checkout` 7 MiB). Capping Gunicorn workers (`BITCART_API_WORKERS=2`) lets a single rootless stack run comfortably on an affordable 1 vCPU / 2 GB RAM AlmaLinux 10 Vultr VPS (with a 2 GB swap file configured during bootstrap) and minimal disk.
3. **External node URLs only:** `bitcart-btc` and `bitcart-xmr` are lightweight watch-only RPC clients (holding only watch-only `xpub` and Monero `address` + `private_view_key` + `restore_height` so stateless remote nodes never learn wallet viewing keys). They connect outbound to `BTC_SERVER` (for example `bitcoin-mainnet.blockstream.info:50002:s`) and `XMR_SERVER` (for example `https://xmr-node.cakewallet.com:18081` or a dedicated remote node). Zero blockchain history is stored on the VPS.
4. **Rootless Podman under a dedicated unprivileged OS user:** All containers run rootless under a dedicated `bitcart` Linux account (`loginctl enable-linger bitcart`) managed via native systemd user services / Podman Quadlets (or rootless Podman Compose with systemd unit integration) on AlmaLinux with `SELinux=enforcing` (`:Z` volume labels), verified `overlay` storage driver (refusing `vfs`), and `/proc/self/uid_map` startup tripwires that abort if ever invoked in the host root user namespace.
5. **Stock Caddy with automatic HTTPS (no deSEC required):** Host-level `caddy` installed from official packages terminates TLS 1.3 on ports `80`/`443` for `pay.arkfile.net` using standard Let's Encrypt HTTP-01 / TLS-ALPN-01 ACME against the Vultr public `A`/`AAAA` record. No custom `xcaddy` compilation or DNS API token is required.
6. **Zero visitor IP logging end-to-end:** Both Caddy hops (host Caddy and internal gateway Caddy) discard access logs and strip `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` headers before proxying; host Caddy sets `Strict-Transport-Security`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`; `bitcart-checkout`'s Nginx overrides `access_log off;` so browser `User-Agent` strings and `/i/<id>` request timings are never written to journald; and Bitcart's `log_retention_days` is set to `21`.
7. **Strict method-and-path public surface; SSH-only admin UI:** Public `https://pay.arkfile.net` serves only checkout static paths (`/i/*`, `/checkout/*`, `/embed/*`, `/modal/*`, `/refunds/*`) and the exact HTTP methods and API routes used by Arkfile and checkout (`POST /api/invoices`, `GET /api/invoices/count`, `GET /api/invoices/{id}`, `GET /api/stores/{id}`, `GET /api/ws/invoices/{id}`, `GET /api/manage/policies`, `GET /api/cryptos*`, and `GET /api/tor/services`). Everything else returns `404` publicly -- including `POST /api/invoices/batch` (so a leaked `invoice_management` token cannot call `mark_complete` over the internet), `GET /api/invoices/export`, unauthenticated `PATCH /api/invoices/{id}/customer` and `/details`, `/api/token*`, `/api/users*`, `/api/wallets*`, `/api/manage*` mutations, `/api/configurator*`, `/api/backups*`, `/api/plugins*`, `/api/update*`, and the `bitcart-admin` web UI. Full admin and management routes stay exclusively on `127.0.0.1:29080` via SSH port-forwarding (`ssh -L 29080:127.0.0.1:29080`), with the `admin` container runnable on demand.
8. **Network segmentation, daemon RPC auth, and SSRF hardening:** Containers split across isolated rootless Podman networks (`bitcart-edge` for `gateway`/`checkout`/`admin`/`backend`, `bitcart-data` with `Internal=true` for Postgres and Redis so data stores have zero internet egress, and `bitcart-coins` for `backend`/`worker`/`bitcoin`/`monero`) so edge containers cannot reach Postgres, Redis, or coin daemons. Coin daemons replace Bitcart's hardcoded default `electrumz` RPC password with generated 32-byte secrets (`BTC_PASS`, `XMR_PASS`), Redis requires an auto-generated password, and `firewalld` blocks outbound egress to link-local cloud metadata (`169.254.169.254/32`).
9. **Multi-environment isolation (`prod` and `test`) via non-superuser Bitcart accounts:** Inside Bitcart (`api/services/crud/invoices.py`), any user with `is_superuser=True` bypasses store ownership checks (`user.id == store.user_id or user.is_superuser`). Therefore, the idempotent provisioner creates three distinct Bitcart accounts:
   - `superadmin` (`is_superuser: true`): server owner account used only by the local provisioner and SSH-tunneled admin UI; sets `disable_registration: true` and never issues API tokens to Arkfile.
   - `prod` merchant (`is_superuser: false`): owns the `prod` watch-only BTC (`transaction_speed` inherited as `1`) and XMR (`transaction_speed: 5`) wallets, the `prod` USD store, and the `prod` `invoice_management` token placed in `arkfile.net`'s `/opt/arkfile/etc/secrets.env`.
   - `test` merchant (`is_superuser: false`): owns separate `test` watch-only BTC and XMR (`transaction_speed: 5`) wallets (ideally a separate BIP84 account `zpub` and Monero subaddress/wallet so test invoices never consume production gap limits or mix accounting), the `test` USD store, and the `test` `invoice_management` token placed in the test Arkfile server's `/opt/arkfile/etc/secrets.env`. A compromised or misconfigured test instance cannot create, inspect, or modify production invoices, stores, or wallets.

## Verified Bitcart Runtime Facts Carried Over from the Mainnet Lab

Every item below was verified directly against `bitcart/bitcart:stable` on live mainnet BTC and XMR payments and must be preserved in `arkfile-bitcart`:

- **Writable plugin directories:** `bitcart/bitcart:stable` drops privileges to `electrum` via `gosu`, while `Settings` defaults `BITCART_BACKEND_PLUGINS_DIR`, `BITCART_ADMIN_PLUGINS_DIR`, `BITCART_STORE_PLUGINS_DIR`, and `BITCART_DOCKER_PLUGINS_DIR` under `/app/modules` and `/app/data` (owned by `root`), causing Alembic migrations to crash with `PermissionError` unless all four env vars point inside `/plugins/...` (which Bitcart's entrypoint `chown`s to `electrum`).
- **Explicit internal service hostnames:** `Settings` defaults `DB_HOST`, `REDIS_HOST`, `BTC_HOST`, and `XMR_HOST` to `127.0.0.1` / `localhost`. Both `backend` and `worker` must explicitly set `DB_HOST=database`, `REDIS_HOST=redis`, `BTC_HOST=bitcoin`, and `XMR_HOST=monero`.
- **PostgreSQL password authentication:** Unlike `bitcart-docker`'s `trust` setup, `database` (`pgautoupgrade/pgautoupgrade:17-alpine`) accepts `POSTGRES_PASSWORD` (with `POSTGRES_HOST_AUTH_METHOD` unset so password auth is enforced), and `backend` + `worker` read `DB_USER=postgres`, `DB_PASSWORD=<generated>`, and `DB_DATABASE=bitcart`.
- **Healthcheck command quoting in Podman:** Podman splits `CMD` array elements containing spaces under Docker-compat healthchecks; healthchecks invoking `python3 -c ...` must use `CMD-SHELL` (or native systemd/Quadlet `HealthCmd` single-command syntax).
- **Per-coin confirmation requirements:** Arkfile (`payments/bitcart.go`) enforces `required_confirmations >= 1` for Bitcoin and `required_confirmations >= 5` for Monero (`currency == "xmr"`) at invoice creation time. Each Bitcart USD store sets `checkout_settings.transaction_speed = 1`, `underpaid_percentage = 0`, `email_required = false`, `allow_anonymous_invoice_creation = false`, and `expiration = 60`, while each Monero wallet sets `transaction_speed = 5` (via `POST /api/wallets` and `PATCH /api/wallets/<id>`).
- **Monero watch-only wallet schema:** Bitcart creates watch-only Monero wallets via `POST /api/wallets` with `{ "name": "...", "currency": "xmr", "xpub": "<XMR_PRIVATE_VIEW_KEY>", "transaction_speed": 5, "additional_xpub_data": { "address": "<XMR_ADDRESS>", "restore_height": <int> } }` (falling back cleanly without `restore_height` if an image revision rejects that optional key).
- **Second-user provisioning rule:** Creating the first Bitcart user via unauthenticated `POST /api/users` makes that user `is_superuser = true` and automatically flips `Policy.disable_registration = true`. Subsequent non-superuser merchant users (`prod` and `test`) must be created via `POST /api/users` authenticated with the superuser's bearer token and `"is_superuser": false` (which also bypasses Bitcart's live DNS MX check on placeholder internal emails such as `prod@pay.internal` and `test@pay.internal`).
- **Electrum `auto_connect` vs `BTC_ONESERVER` quirk:** In Bitcart's `daemons/btc.py`, `BTC_ONESERVER` defaults to `false` and `auto_connect` is never explicitly passed, so Electrum defaults to `auto_connect = True` and will silently fail over wallet subscriptions to random public Electrum peers if `BTC_SERVER` drops. Worse, setting `BTC_ONESERVER=true` alone causes Electrum (`electrum/network.py`) to detect the conflicting `auto_connect=True` + `oneserver=True` combination and wipe `BTC_SERVER` to `localhost:1:s`, breaking Bitcoin syncing. Seeding `{"auto_connect": false}` into Electrum's `/data/config` cleanly disables fallback to random peers in both modes: with `BTC_ONESERVER=false`, Electrum still cross-checks block headers against multiple peers without sending any wallet scripthashes to them; with `BTC_ONESERVER=true` (recommended when pointing at an operator-controlled Electrum server), Electrum connects exclusively to `BTC_SERVER`. On Monero, `XMR_SERVER` accepts a comma-separated list of explicit daemon URLs and never falls back to unknown peers when explicitly configured.
- **Expected `RendererUnavailableError` log line:** Because the optional Rust chat/email template renderer sidecar (`bitcart-renderer` on `data/renderer.sock`) is intentionally omitted and Arkfile disables buyer emails and store chat notifications, `worker` logs a caught `RendererUnavailableError` *after* `Sending IPN ... success` when an invoice completes. Invoice completion and Arkfile webhook delivery are unaffected.

## Connecting `arkfile.net` (`prod`) and Test Arkfile to `pay.arkfile.net`

Once `arkfile-bitcart` is deployed on the AlmaLinux VPS and outputs the two scoped credentials, connecting each Arkfile VPS requires only updating `/opt/arkfile/etc/secrets.env` on each Arkfile server and running its non-destructive update script:

1. On the **test** Arkfile VPS, add to `/opt/arkfile/etc/secrets.env`:
   - `ARKFILE_PAYMENTS_ENABLED=true`
   - `ARKFILE_MIN_TOP_UP_USD=0.50`
   - `ARKFILE_MAX_TOP_UP_USD=1000.00`
   - `ARKFILE_BITCART_API_URL=https://pay.arkfile.net/api`
   - `ARKFILE_BITCART_CHECKOUT_URL=https://pay.arkfile.net`
   - `ARKFILE_BITCART_STORE_ID=<test_store_id>`
   - `ARKFILE_BITCART_API_TOKEN=<test_invoice_token>`
   Then run `sudo bash scripts/test-update.sh` and verify with `arkfile-admin payments check`.
2. On the **production** `arkfile.net` VPS, set the same keys using `<prod_store_id>` and `<prod_invoice_token>`, run `sudo bash scripts/prod-update.sh`, verify with `arkfile-admin payments check`, and perform one real `$0.50` BTC and `$0.50` XMR mainnet top-up.

---

## Comprehensive Bootstrap Prompt for the New `arkfile-bitcart` Repository Agent

Copy and paste everything inside the fenced block below as the initial prompt to an AI coding agent inside the newly created empty `arkfile-bitcart` repository:

```markdown
You are designing and implementing `arkfile-bitcart`, a standalone, security- and privacy-hardened deployment repository that stands up a mainnet-only Bitcart payment server (`pay.example.com` or any operator-supplied domain) on a small AlmaLinux 10 VPS (targeting 1 vCPU / 2 GB RAM on any standard VPS provider) to process Bitcoin (BTC) and Monero (XMR) invoice top-ups for self-hosted or production Arkfile deployments (`prod`, plus an optional isolated `test` tenant on the same Bitcart server).

Read every requirement below carefully before creating any files, and build the complete repository cleanly from end to end.

### 1. Project Rules and Style Constraints

1. **Never use Docker.** Use **Podman** exclusively, and run all application containers strictly in **rootless** mode under a dedicated unprivileged Linux user (`bitcart`). Never mount `/var/run/docker.sock` or any Podman socket into any container.
2. **Mainnet only.** Never assume, configure, or document testnet, regtest, or stagenet anywhere in code, config examples, or documentation. Always set `BTC_NETWORK=mainnet` and `XMR_NETWORK=mainnet`.
3. **No full nodes or chain indexers on the VPS.** Never run `bitcoind`, `electrs`, `fulcrum`, or `monerod` on this server. Point Bitcart's lightweight watch-only wallet RPC daemons (`bitcart/bitcart-btc` and `bitcart/bitcart-xmr`) strictly at external URLs configured by the operator (`BTC_SERVER` and `XMR_SERVER`, where `XMR_SERVER` supports a comma-separated list of explicit nodes), defaulting in `bitcart.conf.example` to `BTC_SERVER=bitcoin-mainnet.blockstream.info:50002:s` and `XMR_SERVER=https://xmr-node.cakewallet.com:18081`. Always prevent silent failover of Bitcoin wallet subscriptions to random third-party Electrum peers by seeding `{"auto_connect": false}` into Electrum's `/data/config` before starting `bitcoin`, and support `BTC_ONESERVER=false` (default for public Electrum servers, keeping multi-peer SPV header cross-checking without leaking wallet scripthashes) or `BTC_ONESERVER=true` (recommended when `BTC_SERVER` is an operator-hosted Electrum server). Document the third-party node privacy/integrity trade-offs honestly in `README.md` (a public Electrum server sees derived BTC address clusters, and a remote Monero node cannot see your view key or outputs but is trusted for block height/inclusion without local RandomX PoW verification).
4. **Watch-only wallets only.** The server must never accept, generate, or store private spending keys or seed phrases. Reject any `BTC_XPUB` value starting with `xprv`, `yprv`, `zprv`, `tprv`, `uprv`, or `vprv` before calling any API. Monero wallets use only the primary address (`4...` mainnet address), private view key (64 hex chars), and integer `restore_height`.
5. **Zero visitor IP logging and minimal browser metadata.** Arkfile is a strict zero-IP-logging system, and its payment checkout host must uphold the same standard. Discard Caddy access logs on **both** Caddy hops (`log { output discard }` / no access logging), strip `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` headers on **both** Caddy hops (`header_up -X-Forwarded-For`, `header_up -X-Real-IP`, `header_up -Forwarded`) so neither `bitcart-checkout` (Nginx) nor `backend` (Gunicorn/Uvicorn) ever receives or logs a visitor's IP address, mount a minimal read-only Nginx override (`access_log off;`) into `checkout` so browser `User-Agent` strings and `/i/<id>` request timings are never written to stdout/journald, and configure Bitcart's `log_retention_days` policy to `21`.
6. **Formatting and language rules:**
   - No emojis anywhere in code, scripts, comments, logs, or markdown docs. Use `[OK]`, `[X]`, `[!]`, or `SUCCESS!` instead.
   - Never use em-dashes; use double-dashes (`--`) only.
   - Do not add hard line wraps inside markdown paragraphs; write each paragraph on a single line and let editors wrap lines.
   - Do not use terms like `allowlist` or `denylist`; use plain descriptive terms such as `permitted_routes`, `blocked_paths`, or `public_api_paths`.
   - Do not add files to git or create git commits yourself.

### 2. Target Host Architecture (AlmaLinux 10 on a Small 2 GB RAM VPS)

Design for a fresh AlmaLinux 10 x86_64 VPS with 1 vCPU and 2 GB RAM:

1. **System bootstrap (`scripts/host-setup.sh`, run as `root` once or idempotently):**
   - Verifies AlmaLinux / RHEL-family 10 (`SELinux=enforcing` preserved -- never disable SELinux).
   - Creates and enables a 2 GiB `/swapfile` (`chmod 0600`, persisted in `/etc/fstab`, `vm.swappiness=20`) if swap is not already present, giving safe headroom alongside the ~850 MiB Bitcart container footprint.
   - Installs `podman`, `podman-compose` (or configures native Podman systemd Quadlets -- prefer Podman Quadlets under `/home/bitcart/.config/containers/systemd/` because Quadlets are native to RHEL/AlmaLinux `systemd --user`, require no Python compose wrapper or `podman.socket`, and provide native `systemd` dependency ordering, healthchecks, and automatic restart on boot!), `slirp4netns` / `pasta`, `fuse-overlayfs`, `jq`, `curl`, `firewalld`, and official `caddy` (via `dnf install 'dnf-command(copr)' && dnf copr enable -y @caddy/caddy && dnf install -y caddy`, or EPEL if available).
   - Creates dedicated unprivileged system/login user `bitcart` (`/home/bitcart`, `/sbin/nologin` or `/bin/bash` with no SSH authorized_keys), ensures `/etc/subuid` and `/etc/subgid` contain a subordinate UID/GID range (`100000:65536` or non-overlapping allocated range) for `bitcart`, runs `podman system migrate` as `bitcart`, verifies `podman info --format '{{.Host.Security.Rootless}} {{.Store.GraphDriverName}}'` equals `true overlay` (aborting immediately if `vfs` is active so disk space is never exhausted), and enables `loginctl enable-linger bitcart`.
   - Configures `firewalld` to permit only `ssh`, `http` (`80/tcp`), and `https` (`443/tcp`) publicly, and adds an outbound `firewalld` / `nftables` drop rule blocking host and container egress to cloud link-local metadata (`169.254.169.254/32`) to neutralize SSRF against VPS metadata services.

2. **Two-tier Caddy + Rootless Loopback Routing (Stock Caddy Automatic TLS, No DNS Plugin):**
   - Host-level `caddy.service` owns ports `80` and `443` and automatically obtains and renews Let's Encrypt TLS certificates (TLS 1.3 enforced) for `${PAY_DOMAIN}` (for example `pay.example.com`) using standard HTTP-01 / TLS-ALPN-01 challenges against the host's public `A`/`AAAA` DNS records. No `xcaddy` build and no DNS provider API token are used.
   - Host Caddy sets strict response headers (`Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"`, `Referrer-Policy "no-referrer"`, `X-Content-Type-Options "nosniff"`, `X-Frame-Options "DENY"`), discards access logs, and strips `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` before proxying to `127.0.0.1:28080`.
   - Inside `bitcart`'s rootless Podman edge network (`bitcart-edge`), run an internal lightweight Caddy gateway container (`gateway`, `caddy:2.11.4-alpine`) that also discards access logs, strips `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` on its own `reverse_proxy` hops, and publishes two distinct host loopback ports:
     - **`127.0.0.1:28080` (Public Checkout + Strictly Method/Path-Scoped API upstream, proxied from host `caddy.service` on `https://${PAY_DOMAIN}`):**
       - CRITICAL SECURITY GATE: In Bitcart, an `invoice_management` token also permits `POST /api/invoices/batch` (`command: "mark_complete"`, which forges a confirmed completion webhook!) and `GET /api/invoices/export`, while `PATCH /api/invoices/{id}/customer` and `PATCH /api/invoices/{id}/details` are completely unauthenticated! Therefore, `:28080` MUST enforce a strict positive match on exact HTTP methods and paths and return `404` for everything else:
         - Permitted checkout static paths (`GET`/`HEAD` -> `checkout:80`): `/i/*`, `/checkout/*`, `/embed/*`, `/modal/*`, `/refunds/*`.
         - Permitted API endpoints (`handle_path /api/*` -> `backend:8000`):
           - `POST /api/invoices` (exact path only -- creates an invoice; blocks `/api/invoices/batch`, `/api/invoices/order_id/*`, `/api/invoices/*/refunds*`)
           - `GET /api/invoices/count` (for `arkfile-admin payments check`)
           - `GET /api/invoices/{id}` (single-segment invoice ID only -- blocks `/api/invoices/export`, `/api/invoices/*/customer`, `/api/invoices/*/details`, and all `PATCH`/`PUT`/`DELETE` methods)
           - `GET /api/stores/{id}` and `GET /api/stores/{id}/rates` (single-segment store ID, `GET` only -- blocks store mutations)
           - `GET /api/ws/invoices/{id}` (WebSocket invoice status updates for checkout)
           - `GET /api/manage/policies` (`GET` only, read by checkout SPA)
           - `GET /api/cryptos*` and `GET /api/tor/services` (`GET` only)
         - Every other path and method -- including `/`, `/admin*`, `/api/invoices/batch`, `/api/invoices/export`, `PATCH /api/invoices/*/customer`, `/api/token*`, `/api/users*`, `/api/wallets*`, `/api/backups*`, `/api/configurator*`, `/api/plugins*`, `/api/update*`, `/api/payouts*`, `/api/notifications*`, `/api/templates*`, and mutating `/api/manage*` -- MUST return `404`.
     - **`127.0.0.1:29080` (SSH-Tunnel-Only Admin + Provisioner listener, NEVER proxied by host Caddy):**
       - Serves full `/api/*` (`handle_path /api/*` -> `backend:8000`) and `/` (`admin:4000`) exclusively on `127.0.0.1:29080`.
       - Configure the `admin` container as an **optional on-demand** systemd user unit (`bitcart-admin.service`, stopped by default to save ~84 MiB RAM and keep Node/Nuxt idle surface closed; started on demand with `systemctl --user -M bitcart@ start bitcart-admin` when needed) with `ONE_DOMAIN_MODE=true`, `BITCART_ADMIN_ROOTPATH=/`, `BITCART_ADMIN_API_URL=http://127.0.0.1:29080/api`, and `BITCART_ADMIN_SERVER_API_URL=http://backend:8000` so an operator running `ssh -L 29080:127.0.0.1:29080 root@<vps-ip>` can open `http://127.0.0.1:29080` in a local browser cleanly without ever exposing the admin panel or `/api/token` to the internet.

### 3. Container Stack, Network Segmentation, and Hard-Won Bitcart Configuration Requirements

Segment the stack across **three** rootless Podman Quadlet networks so edge containers (`gateway`, `checkout`, `admin`) have zero network reachability to Postgres, Redis, or the coin RPC daemons, and so Postgres + Redis have zero internet egress (`Internal=true`):
- **`bitcart-edge.network`:** `gateway`, `checkout`, `admin`, `backend`.
- **`bitcart-data.network` (`Internal=true`):** `database`, `redis`, `backend`, `worker`.
- **`bitcart-coins.network`:** `bitcoin`, `monero`, `backend`, `worker` (needs outbound internet to reach `BTC_SERVER`, `XMR_SERVER`, price feeds, and Arkfile webhook URLs).

Pin all container images in a single configuration file (`images.env`, supporting `@sha256` immutable digests) and set explicit systemd `MemoryMax=` limits and capability restrictions (`DropCapability=ALL` and `NoNewPrivileges=true` on non-`gosu` containers; minimal `CHOWN`/`DAC_OVERRIDE`/`SETUID`/`SETGID` only where required by `gosu` entrypoints) in every Quadlet unit:

1. **`database` (`docker.io/pgautoupgrade/pgautoupgrade:17-alpine`, networks: `bitcart-data`, `MemoryMax=320M`):**
   - Enforce real password authentication (`POSTGRES_USER=postgres`, `POSTGRES_DB=bitcart`, `POSTGRES_PASSWORD=<auto-generated 32-byte hex secret stored mode 0600 under /home/bitcart/secrets/>`; do NOT set `POSTGRES_HOST_AUTH_METHOD=trust`).
   - Tune for a 2 GB RAM VPS (`-c shared_buffers=128MB -c random_page_cost=1.1 -c max_connections=50`).
   - Healthcheck: `pg_isready -U postgres -d bitcart`.
2. **`redis` (`docker.io/library/redis:7-alpine`, networks: `bitcart-data`, `MemoryMax=96M`):**
   - Start with `--requirepass <auto-generated 32-byte hex secret>` (or password passed via protected mounted `redis.conf` `:ro,Z`) and verify `backend`/`worker` Redis auth compatibility (note: Bitcart's `Settings` reads `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB` -- inspect whether `REDIS_PASSWORD` / `REDIS_URL` is supported by the pinned Bitcart image; if not, keep `redis` isolated exclusively on the `Internal=true` `bitcart-data` network with `--protected-mode yes` and document this clearly).
   - Healthcheck: `redis-cli ping`.
3. **`bitcoin` (`docker.io/bitcart/bitcart-btc:stable`, networks: `bitcart-coins`, `MemoryMax=256M`):**
   - `BTC_NETWORK=mainnet`, `BTC_LIGHTNING=false`, `BTC_SERVER=${BTC_SERVER}`, `BTC_ONESERVER=${BTC_ONESERVER:-false}`.
   - Override Bitcart's hardcoded `electrum` / `electrumz` daemon RPC password using generated 32-byte secret `BTC_USER=btc_rpc`, `BTC_PASS=<generated>` (matching `BTC_USER`/`BTC_PASS` in `backend` and `worker`).
   - Persistent volume `bitcart-btc-data:/data`. Before first start (and idempotently on deploy), seed `/data/config` in `bitcart-btc-data` with `{"auto_connect": false}` (preserving any existing keys) so Electrum never silently fails over wallet subscriptions to random public Electrum peers and so `BTC_ONESERVER=true` does not trigger Electrum's `auto_connect` conflict that wipes `BTC_SERVER`.
4. **`monero` (`docker.io/bitcart/bitcart-xmr:stable`, networks: `bitcart-coins`, `MemoryMax=320M`, enabled whenever `BITCART_CRYPTOS` includes `xmr` -- default `btc,xmr`):**
   - `XMR_NETWORK=mainnet`, `XMR_SERVER=${XMR_SERVER}`.
   - Override Bitcart's hardcoded `electrum` / `electrumz` daemon RPC password using generated 32-byte secret `XMR_USER=xmr_rpc`, `XMR_PASS=<generated>` (matching `XMR_USER`/`XMR_PASS` in `backend` and `worker`).
   - Persistent volume `bitcart-xmr-data:/data`.
5. **`backend` (`docker.io/bitcart/bitcart:stable`, command `just prod-api-up`, networks: `bitcart-edge`, `bitcart-data`, `bitcart-coins`, `MemoryMax=512M`):**
   - `BITCART_API_WORKERS=2` (prevents excessive worker spawning on a 2 GB VPS).
   - `IN_DOCKER=true`, `LOG_LEVEL=INFO`, `BITCART_CRYPTOS=${BITCART_CRYPTOS:-btc,xmr}`.
   - `BITCART_HOST=${PAY_DOMAIN}`, `BITCART_HTTPS_ENABLED=true`, `BITCART_REVERSEPROXY=none`, `BITCART_BACKEND_ROOTPATH=/api`.
   - `BITCART_AGENT_TRANSPORT=none`, `BITCART_ENABLE_SSH=false` (never allow host agent or SSH).
   - Explicit internal service discovery and generated credentials: `DB_HOST=database`, `DB_USER=postgres`, `DB_PASSWORD=<secret>`, `DB_DATABASE=bitcart`, `REDIS_HOST=redis`, `BTC_HOST=bitcoin`, `BTC_USER=btc_rpc`, `BTC_PASS=<secret>`, `XMR_HOST=monero`, `XMR_USER=xmr_rpc`, `XMR_PASS=<secret>`.
   - CRITICAL writable plugin paths (prevents `PermissionError` under `gosu electrum` during Alembic startup):
     - `BITCART_DATADIR=/datadir`
     - `BITCART_BACKUPS_DIR=/backups`
     - `BITCART_BACKEND_PLUGINS_DIR=/plugins/backend`
     - `BITCART_ADMIN_PLUGINS_DIR=/plugins/admin`
     - `BITCART_STORE_PLUGINS_DIR=/plugins/store`
     - `BITCART_DOCKER_PLUGINS_DIR=/plugins/docker`
   - Do NOT set `FORWARDED_ALLOW_IPS` to external networks so Uvicorn never trusts or logs client IP headers.
   - Single-command shell healthcheck polling `http://127.0.0.1:8000/cryptos` (never pass space-containing Python args inside a Docker-style `CMD` JSON array in Podman).
6. **`worker` (`docker.io/bitcart/bitcart:stable`, command `just worker`, networks: `bitcart-data`, `bitcart-coins`, `MemoryMax=512M`):**
   - Shares the exact same `backend` environment variables and volumes (`/datadir`, `/backups`, `/plugins`).
   - Needs outbound HTTPS (`443/tcp`) to deliver webhook IPNs to `https://files.example.com/api/webhooks/bitcart` (and `https://test.example.com/api/webhooks/bitcart` when a `test` tenant is enabled).
7. **`checkout` (`docker.io/bitcart/bitcart-checkout:stable`, networks: `bitcart-edge`, `MemoryMax=96M`):**
   - `ONE_DOMAIN_MODE=true`, `BITCART_API_URL=https://${PAY_DOMAIN}/api`, `BITCART_CHECKOUT_URL=https://${PAY_DOMAIN}`.
   - Mount a read-only `nginx/checkout-privacy.conf` (`access_log off;`) with `:ro,Z` so Nginx never logs checkout URLs or `User-Agent` strings to stdout/journald.
8. **`admin` (`docker.io/bitcart/bitcart-admin:stable`, command `yarn start`, networks: `bitcart-edge`, `MemoryMax=256M`, optional on-demand unit):**
   - `ONE_DOMAIN_MODE=true`, `BITCART_ADMIN_ROOTPATH=/`, `BITCART_ADMIN_API_URL=http://127.0.0.1:29080/api`, `BITCART_ADMIN_SERVER_API_URL=http://backend:8000`.
9. **Rootless user-namespace tripwire:**
   - Every host management script (`deploy.sh`, `update.sh`, `provision.sh`, `backup.sh`) must verify that container execution runs exclusively as UID `bitcart` (never rootful Podman), and any custom init/wrapper script inside containers must check `/proc/self/uid_map` and abort if `0 0 4294967295` (host root user namespace) is detected.
   - Apply `:Z` SELinux labels on all bind-mounted config files so `SELinux=enforcing` on AlmaLinux never blocks container reads.

### 4. Idempotent Multi-Tenant Provisioning (`prod` and `test` Isolation)

Write an idempotent provisioning script (`scripts/provision.sh`) that talks to `http://127.0.0.1:29080/api` on the host (as root or `bitcart` reading `/etc/arkfile-bitcart/bitcart.conf`, mode `0600`) and configures three strictly separated Bitcart accounts inside the single Bitcart instance:

1. **Operator configuration (`/etc/arkfile-bitcart/bitcart.conf`, templated from `bitcart.conf.example`):**
   - `PAY_DOMAIN=pay.example.com`
   - `BITCART_CRYPTOS=btc,xmr`
   - `BTC_SERVER=bitcoin-mainnet.blockstream.info:50002:s`
   - `BTC_ONESERVER=false` (set `true` when `BTC_SERVER` is your own remote Electrum server; `/data/config` always sets `auto_connect: false` so Electrum never falls back to random public peers)
   - `XMR_SERVER=https://xmr-node.cakewallet.com:18081` (accepts a comma-separated list of explicit Monero daemon URLs)
   - `BTC_TX_SPEED=1` (enforced `>= 1`)
   - `XMR_TX_SPEED=5` (enforced `>= 5` -- required by Arkfile's `payments/bitcart.go` confirmation floor!)
   - `BITCART_LOG_RETENTION_DAYS=21`
   - `PROD_BTC_XPUB=`, `PROD_XMR_ADDRESS=`, `PROD_XMR_PRIVATE_VIEW_KEY=`, `PROD_XMR_RESTORE_HEIGHT=`
   - Optional isolated `test` tenant (`ENABLE_TEST_TENANT=true` or automatically enabled when `TEST_BTC_XPUB` is non-empty, so single-instance self-hosters can deploy `prod` alone while operators running both `test.example.com` and `files.example.com` get full two-tenant provisioning): `TEST_BTC_XPUB=`, `TEST_XMR_ADDRESS=`, `TEST_XMR_PRIVATE_VIEW_KEY=`, `TEST_XMR_RESTORE_HEIGHT=`
   - Auto-generated random high-entropy passwords stored in `/home/bitcart/secrets/accounts.env` (`0600`) for `SUPERADMIN_PASSWORD`, `PROD_ADMIN_PASSWORD`, and `TEST_ADMIN_PASSWORD` if not already generated, so the operator does not even have to invent passwords by hand (and can read them back on the VPS if logging into the SSH-tunneled admin UI).

2. **Exact Bitcart API Provisioning Flow (must be 100% idempotent on re-runs):**
   - **Step A -- Superuser bootstrap & policy lockdown:**
     - Fast-path check first: if existing tenant credential files are already present and `GET /api/invoices/count` + `GET /api/stores/<id>` pass with all expected checkout settings (and `--force-reprovision` is not set), exit cleanly without needing to log in as `superadmin` (this also ensures automated `update.sh` runs still succeed even if an operator later enables TOTP 2FA on `superadmin@pay.internal`).
     - Register `superadmin@pay.internal` via `POST /api/users` (`{"email":"superadmin@pay.internal","password":"...","captcha_code":""}`) if no users exist yet (Bitcart automatically sets the first user to `is_superuser: true` and sets `disable_registration: true`), then obtain an in-memory `full_control` token via `POST /api/token`.
     - Lock down global instance policy via `POST /api/manage/policies` using the superuser token: `{"disable_registration": true, "discourage_index": true, "check_updates": false, "allow_anonymous_configurator": false, "allow_file_uploads": false, "log_retention_days": 21}` (reading `${BITCART_LOG_RETENTION_DAYS:-21}`).
   - **Step B -- Provision isolated non-superuser `prod` (and optional `test`) merchant accounts:**
     - CRITICAL: In Bitcart (`api/services/crud/invoices.py`), `is_superuser: true` bypasses store ownership checks (`user.id == store.user_id or user.is_superuser`). Therefore, neither `prod` nor `test` may be a superuser!
     - Using the `superadmin` bearer token, list `GET /api/users` and create `prod@pay.internal` (and `test@pay.internal` when the `test` tenant is enabled) via `POST /api/users` with `{"email":"...","password":"...","is_superuser":false}` when missing (creating users as `superadmin` bypasses both `disable_registration` and live DNS MX checks on `.internal` addresses).
   - **Step C -- Per-tenant wallets, USD store, checkout settings, and scoped `invoice_management` token (run identically for `prod` and for `test`, authenticated as that tenant's own `full_control` token in memory):**
     - Validate that `*_BTC_XPUB` is present and does not begin with `xprv`/`yprv`/`zprv`/`tprv`/`uprv`/`vprv`. Create or find the tenant's `btc` wallet (`POST /api/wallets` -- never use a trailing slash, which Bitcart 307-redirects -- with `{"name":"<env>-btc","xpub":"...","currency":"btc","lightning_enabled":false}`).
     - When `BITCART_CRYPTOS` includes `xmr`, validate `*_XMR_ADDRESS` and `*_XMR_PRIVATE_VIEW_KEY`, and create or `PATCH` the tenant's `xmr` wallet (`POST /api/wallets` or `PATCH /api/wallets/<id>`) with `transaction_speed: ${XMR_TX_SPEED}` (default `5`) and `additional_xpub_data: {"address": "...", "restore_height": <int>}` (retrying without `restore_height` if rejected). Always `PATCH` `{"transaction_speed": <XMR_TX_SPEED>}` on existing XMR wallets so confirmation updates apply in place.
     - Create or `PATCH` the tenant's store (`name: "arkfile-prod"` or `"arkfile-test"`, `default_currency: "USD"`, `wallets: [<btc_id>, <xmr_id>]`) with exact `checkout_settings`:
       - `expiration: 60`
       - `transaction_speed: ${BTC_TX_SPEED}` (`1`)
       - `underpaid_percentage: 0`
       - `email_required: false`
       - `allow_anonymous_invoice_creation: false`
     - Verify `currency_data` on `GET /api/stores/<store_id>` confirms connected wallets, and if an existing scoped token in `/home/bitcart/secrets/<env>-arkfile.env` already passes `GET /api/invoices/count` and `GET /api/stores/<store_id>` (and returns `403` when attempting to access the *other* tenant's store!), keep the existing token so re-running `update.sh` / `provision.sh` does **not** invalidate tokens already deployed in Arkfile's `secrets.env`! Only mint a new `{"permissions":["invoice_management"]}` token when none exists or `--rotate-tokens` is explicitly passed.
   - **Step D -- Security and cross-tenant isolation self-test (`scripts/verify.sh`):**
     - Automatically verify and assert (without burning `prod` Bitcoin address gap-limit indexes on routine `update.sh` runs!):
       1. `GET https://${PAY_DOMAIN}/api/invoices/count` with `prod` token returns `200`, and with no token returns `401`.
       2. `GET https://${PAY_DOMAIN}/api/stores/<store_id>` confirms `transaction_speed >= 1`, `underpaid_percentage == 0`, `email_required == false`, `allow_anonymous_invoice_creation == false`, and connected `currency_data` for every enabled coin.
       3. Unauthenticated `POST https://${PAY_DOMAIN}/api/invoices` against `prod` (and `test`, when enabled) store IDs returns `403` (proving `allow_anonymous_invoice_creation=false`).
       4. When the `test` tenant is enabled, `POST https://${PAY_DOMAIN}/api/invoices` using the `test` token with `store_id=<prod_store_id>` (and vice versa) returns `403` (proving strict tenant isolation between `test` and `prod`!).
       5. Blocked public routes return `404`: `GET /`, `POST /api/token`, `POST /api/invoices/batch` (even WITH a valid `prod` bearer token!), `GET /api/invoices/export`, `PATCH /api/invoices/00000000000000000000000000/customer`, and `GET /api/wallets`.
       6. Live invoice-creation verification (run only against the `test` store by default, or against `prod` only when `--check-prod-invoice` is explicitly passed on initial deploy so repeated `update.sh` runs never exhaust the 20-address BIP84 gap limit on `prod`): confirms `btc` has `required_confirmations >= 1`, `xmr` has `required_confirmations >= 5`, and `GET https://${PAY_DOMAIN}/i/<invoice_id>` returns `200` with `Referrer-Policy: no-referrer` and `Strict-Transport-Security`.
     - Write clean, ready-to-copy `secrets.env` snippets to `/root/arkfile-bitcart-credentials/prod-secrets.env` (and `/root/arkfile-bitcart-credentials/test-secrets.env` when enabled) with `chmod 0600`, never printed to stdout unless `--print-credentials` is passed.

### 5. Lifecycle Scripts and Deliverables to Create in `arkfile-bitcart`

Create a clean, minimal repository layout with no unnecessary abstractions:

- `README.md` -- Clear operator runbook using generic example domains (`pay.example.com` for Bitcart, `files.example.com` for production Arkfile, and `test.example.com` for an optional test Arkfile instance) covering: public `A`/`AAAA` DNS setup, provisioning a 2 GB RAM AlmaLinux 10 VPS on any provider, populating `/etc/arkfile-bitcart/bitcart.conf` with mainnet watch-only BTC and XMR keys (recommending separate BIP84 account `zpub`s and separate Monero wallets/accounts when running both `prod` and `test`), running `sudo bash scripts/deploy.sh`, copying the generated snippets into `/opt/arkfile/etc/secrets.env` on each Arkfile server (`prod-update.sh` / `test-update.sh` / `local-deploy.sh` + `arkfile-admin payments check`), accessing the Bitcart admin UI safely via `ssh -L 29080:127.0.0.1:29080`, updating pinned images via `sudo bash scripts/update.sh`, and restoring backups.
- `AGENTS.md` -- Workspace rules for future agents maintaining `arkfile-bitcart` (generic domain-neutral configuration, rootless Podman only, mainnet only, watch-only keys only, zero IP logging, non-destructive updates that preserve tokens and Postgres volumes, formatting rules).
- `bitcart.conf.example` -- Documented operator config template with generic `PAY_DOMAIN=pay.example.com` and mainnet defaults (`BTC_SERVER=bitcoin-mainnet.blockstream.info:50002:s`, `XMR_SERVER=https://xmr-node.cakewallet.com:18081`, `BTC_TX_SPEED=1`, `XMR_TX_SPEED=5`).
- `images.env` -- Central image references (supporting `@sha256` digest pinning alongside helper script `scripts/pin-digests.sh` that resolves current `:stable` tags to exact immutable `@sha256` digests on the host).
- `caddy/Caddyfile.host.template` -- Host Caddy config for `${PAY_DOMAIN}` (TLS 1.3, automatic Let's Encrypt, `log { output discard }`, stripped IP headers, HSTS, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, proxying only to `127.0.0.1:28080`).
- `caddy/Caddyfile.gateway` -- Internal rootless gateway config (`log { output discard }`, stripped IP headers) enforcing strict positive method-and-path matching on `:28080` (`404` on `/`, `batch`, `export`, `PATCH */customer`, and all admin/auth/management routes) and serving full admin + API on `:29080` (`127.0.0.1` only).
- `nginx/checkout-privacy.conf` -- Minimal read-only Nginx override (`access_log off;`) mounted into `checkout` with `:ro,Z` so checkout URLs and `User-Agent` strings are never written to journald.
- `quadlets/` -- Complete set of rootless Podman Quadlet `.network` (`bitcart-edge`, `bitcart-data` with `Internal=true`, `bitcart-coins`), `.volume`, and `.container` templates installed under `/home/bitcart/.config/containers/systemd/` with `Restart=on-failure`, healthchecks, `MemoryMax=`, capability drops, `:Z` SELinux volume labels, and optional on-demand `bitcart-admin.container`.
- `scripts/host-setup.sh` -- Idempotent AlmaLinux 10 host preparation (swap, packages, `bitcart` user, subuid/subgid, `overlay` storage check, linger, `firewalld`, host Caddy).
- `scripts/deploy.sh` -- First-time deployment orchestrator (`host-setup.sh` -> generate DB/account secrets -> install Quadlets + Caddy -> `systemctl --user -M bitcart@ daemon-reload` & start stack -> `provision.sh` -> `verify.sh`).
- `scripts/update.sh` -- Non-destructive production update script (pulls updated images from `images.env`, restarts rootless services cleanly, re-runs `provision.sh` without rotating existing valid Arkfile API tokens, and runs `verify.sh`).
- `scripts/provision.sh` -- Idempotent 3-account (`superadmin`, `prod`, `test`) Bitcart API provisioner described in Section 4.
- `scripts/verify.sh` -- Automated post-deploy security, privacy, confirmation-count, and cross-tenant isolation verifier (`[OK]` / `[X]` checks, non-zero exit on any failure).
- `scripts/backup.sh` -- Non-disruptive `pg_dump` + `/home/bitcart/secrets` encrypted or mode-`0600` archive helper suitable for cron/systemd timer and off-VPS `rsync`/`scp`.

Validate every shell script with `bash -n` / `sh -n` (and `shellcheck` if installed), double-check every Caddyfile and Quadlet unit for syntax accuracy, and review every file against the security and privacy requirements above before concluding.
```
