# Bitcart Payment Lab (Podman Compose)

## Status

The lab files are in `scripts/testing/bitcart-lab/`. Podman has not been run. The host Bitcart mock listens on `127.0.0.1:8989`. This lab must not take that port.

## Pinned Bitcart reference

`bitcart/bitcart-docker` has no release tags. The component files were read at commit `ff6ddbf612a9236e447107bd9a1d9c619e2db558` on `master`. Image tags in the compose file stay on the upstream `stable` tags until a successful payment, when they should be replaced with digests.

Images and listen ports from those components: `bitcart/bitcart:stable` runs the API (`just prod-api-up`, port 8000) and the worker (`just worker`, port 9020). `bitcart/bitcart-btc:stable` is the Bitcoin daemon on port 5000. `bitcart/bitcart-xmr:stable` is Monero on port 5011 and defaults `XMR_SERVER` to `https://seed-server.bitcart.ai`. `bitcart/bitcart-admin:stable` listens on port 4000. `bitcart/bitcart-checkout:stable` listens on port 80. Postgres is `pgautoupgrade/pgautoupgrade:17-alpine` with user `postgres`, database `bitcart`, and trust authentication. Redis is `redis:7-alpine`.

Compose service names are `database`, `redis`, `bitcoin`, `monero`, `backend`, and `worker` because those are the hostnames the Bitcart processes use. The lab does not run the Ready Store service. With the store omitted, one-domain mode serves the API at `/api/`, checkout at `/i/`, and the admin UI at `/`. Nginx strips the `/api/` prefix before the API process. The lab Caddyfile does the same. `BITCART_BACKEND_ROOTPATH=/api` is set so Bitcart still generates public URLs under `/api`.

Current Bitcart wallet creation uses `xpub` for the extended public key or the Monero view key, and `additional_xpub_data.address` for the Monero primary address. A restore height is not part of that schema. The provisioner sends it when `XMR_RESTORE_HEIGHT` is set and retries without it if Bitcart rejects the field. The provisioner does not set a wallet transaction speed. Store checkout settings are sent on create and on a later update: transaction speed at least 1, underpaid percentage 0, email off, anonymous invoice creation off.

The goal is one rootless Podman Compose project that runs a complete Arkfile instance and a real Bitcart stack beside each other. Normal browser features -- registration, OPAQUE + TOTP sign-in, file encryption and upload, streaming download and decryption (including the service worker), anonymous file shares, `.arkbackup` export, and billing -- all work at one origin (`https://arkfile.lab:18443`). Creating a top-up opens a real Bitcart checkout page (`https://bitcart.lab:19080`), displays a real Bitcoin (and, optionally, Monero) address derived from watch-only wallet material, delivers a real webhook over the Compose network, and credits the Arkfile user once confirmed on-chain. Nothing in the stack reads or writes `/opt/arkfile`, systemd units, `~/.arkfile-session.json`, or the database of a `dev-reset.sh` or `local-deploy.sh` deployment already running on the host.

## What this lab is for

`e2e-test.sh` already proves Arkfile's side of the payment protocol against `scripts/testing/bitcart-mock.go` on `127.0.0.1:8989`. The mock checks the invoice creation payload, the `pending` / `confirming` / `paid` state transitions, idempotent single-credit settlement, tampering rejection, and the rule that an unsigned webhook is treated strictly as a prompt to re-fetch and verify the invoice from the provider API. It never derives wallet addresses or watches a blockchain.

This lab is a full local Arkfile vault paired with a live Bitcart deployment to prove real watch-only wallet derivation, real Bitcart checkout rendering, real webhook delivery, and real on-chain confirmation handling end-to-end. It complements `bitcart-mock.go` and is never wired into `dev-reset.sh` or `e2e-test.sh`.

## What this lab does not do

The stack does not create coins and never holds spending keys. The operator pays the invoice address from an external wallet outside the containers. Only watch-only material -- a Bitcoin extended public key, and optionally a Monero primary address plus private view key and restore height -- is supplied via `scripts/testing/bitcart-lab/lab.env`.

The stack does not run a Bitcoin full node or a Monero full node. Bitcart's Bitcoin daemon connects to Electrum servers, and the optional Monero daemon connects to an external Monero node URL supplied by the operator.

The stack does not modify the host OS. No script edits `/etc/hosts`, the host system trust store, SSH `authorized_keys`, or `/opt/arkfile`. Before using the lab in a browser, the operator adds two lines to `/etc/hosts` by hand and imports the lab CA certificate into a dedicated browser profile by hand. All temporary host-side test files (exported `ca.crt` and isolated `arkfile-client` `HOME`) live under `/tmp/arkfile-bitcart-lab`, matching the repository's testing convention.

Subscriptions stay disabled (`ARKFILE_SUBSCRIPTIONS_ENABLED=false`) because this stack does not run a Subscription Bridge. Storage billing and PAYG metering are enabled (`ARKFILE_BILLING_ENABLED=true` and `ARKFILE_BILLING_PAYG_ENABLED=true`) so storage usage, projections, and Bitcart top-up credits work together. User sign-in in the lab uses OPAQUE password authentication plus TOTP; testing hardware security keys for MFA is not a goal of this lab.

Arkfile has no browser admin UI; per `docs/wip/admin-sec.md`, all Arkfile admin operations are CLI-only (`arkfile-admin`) over a direct loopback connection. In this lab, `arkfile-admin` is invoked inside the `arkfile` container via `podman compose exec`. Bitcart's own merchant admin UI is served in the browser at `https://bitcart.lab:19080/admin`.

Running the lab is strictly a developer action. Per `AGENTS.md`, an AI agent must never invoke Podman commands without the developer's express consent for each invocation. This document specifies the design, files, and operator workflow.

## Isolation

All lab definitions live under `scripts/testing/bitcart-lab/` as a single Compose project named `arkfile-paylab`, with one internal bridge network and named Podman volumes. It never bind-mounts `/opt/arkfile`, `/var/tmp/arkfile-build`, or the developer's home directory. The repository root is used only as the build context for `Containerfile.arkfile` (filtered through `Containerfile.arkfile.containerignore`), and `scripts/testing/bitcart-lab/lab.env` is passed via `--env-file` rather than mounted into Arkfile. Published ports bind `127.0.0.1` exclusively.

Running `podman compose down -v` from `scripts/testing/bitcart-lab/` destroys every container, network, and named volume in the lab -- including its rqlite database, SeaweedFS objects, Arkfile keys, Bitcart Postgres database, Bitcart wallet data, and generated certificates. A host `dev-reset.sh` or `local-deploy.sh` instance can run before, during, and after the lab without data or port collisions.

The Compose network permits outbound internet traffic because Bitcart requires live USD exchange-rate feeds and Electrum servers (and a remote Monero node when `--profile xmr` is enabled). Host isolation comes from binding published ports only to `127.0.0.1`, refusing host filesystem mounts, and isolating host CLI state under `/tmp/arkfile-bitcart-lab`.

Do not run Bitcart's upstream `setup.sh`. That script invokes Docker, modifies `/etc/hosts` for `.local` domains, and sets up host management (`bitcart-agent` systemd sockets or root SSH key injection). Our Compose translation explicitly sets `BITCART_AGENT_TRANSPORT=none` and `BITCART_ENABLE_SSH=false`, omits all SSH, `/run/bitcart`, `/var/lib/dbus/machine-id`, and container-socket mounts, omits `host.docker.internal`, and keeps inter-service traffic strictly on Compose DNS aliases.

Invoke the stack with rootless `podman compose`. Never invoke `docker`. If the host lacks a compose plugin, install `podman-compose` and still drive it via `podman compose`.

## Reserved and published ports

The host deployment and existing e2e harnesses own the following ports, which the lab must never publish on the host:

| Port | Owner |
|---|---|
| 8443 | Host Arkfile TLS (`dev-reset.sh` and `local-deploy.sh`) |
| 8080 | Host Arkfile HTTP |
| 8787 | Subscription Bridge mock (`scripts/testing/subscription-bridge-mock.go`, `dev-reset.sh`, `e2e-test.sh`) |
| 8989 | Bitcart mock (`scripts/testing/bitcart-mock.go`, `dev-reset.sh`, `e2e-test.sh`) |
| 4001 | Host rqlite |
| 9332 | Host SeaweedFS S3 gateway |

The lab publishes exactly two ports on `127.0.0.1`, and the servers inside the containers listen on those exact same port numbers so every URL is identical inside and outside the Compose network:

| Host bind | Container listener | Hostname / Compose DNS alias |
|---|---|---|
| `127.0.0.1:18443` | Arkfile TLS `0.0.0.0:18443` | `arkfile.lab` |
| `127.0.0.1:19080` | Bitcart Caddy TLS `0.0.0.0:19080` | `bitcart.lab` |

No other ports are published. `rqlite`, `seaweedfs`, `bitcart-db`, `bitcart-redis`, `bitcart-api`, `bitcart-btc`, and `bitcart-xmr` are reachable only on the internal Compose network.

Before opening the lab in a browser, the operator adds two entries to `/etc/hosts` by hand:

```text
127.0.0.1 arkfile.lab
127.0.0.1 bitcart.lab
```

`.lab` is not resolved by mDNS or public DNS. On the host, `arkfile.lab` and `bitcart.lab` resolve to `127.0.0.1` and hit the published ports. Inside the Compose network, `arkfile.lab` is a network alias on the `arkfile` service and `bitcart.lab` is a network alias on the `bitcart-proxy` service, so container-to-container requests connect directly over the Compose bridge without hairpinning through host loopback.

## URLs, certificates, and trust stores

When `ARKFILE_PAYMENTS_ENABLED=true`, `validatePaymentsURL` in `config/config.go` requires `BASE_URL`, `ARKFILE_BITCART_API_URL`, and `ARKFILE_BITCART_CHECKOUT_URL` to be absolute `https://` URLs unless the hostname is `127.0.0.1`, `localhost`, or `::1`. Non-loopback hostnames (`arkfile.lab` and `bitcart.lab`) therefore use HTTPS everywhere:

- `BASE_URL=https://arkfile.lab:18443` -- opened by the browser, used by `publicShareBaseURL` in `handlers/file_shares.go` when minting anonymous share links, and used by `payments.NewProvider` to construct the per-invoice webhook `https://arkfile.lab:18443/api/webhooks/bitcart`.
- `ARKFILE_DOMAIN=arkfile.lab` and `CORS_ALLOWED_ORIGINS=https://arkfile.lab:18443` -- binds the OPAQUE server identity (`idS`) and browser CORS policy to the exact same origin.
- `ARKFILE_BITCART_API_URL=https://bitcart.lab:19080/api` -- called server-to-server by `BitcartProvider` inside `arkfile`.
- `ARKFILE_BITCART_CHECKOUT_URL=https://bitcart.lab:19080` -- returned to the browser and CLI so payers open `https://bitcart.lab:19080/i/<invoice id>`.

All certificates are generated at runtime (`podman compose up`) by a one-shot `ca` init service, never baked into container images at build time. Baking a CA into a wrapper image would create a build-vs-runtime ordering failure and break whenever `podman compose down -v` wipes volumes. To maintain strict key separation across containers, `compose.yaml` uses three small certificate volumes:

1. `lab-ca-public` holds only `ca.crt` and `ca-bundle.crt` (the container's Mozilla root bundle `/etc/ssl/certs/ca-certificates.crt` concatenated with `ca.crt`). It is mounted read-only at `/ca` into `arkfile`, `bitcart-api`, `bitcart-worker`, and `provision`.
2. `lab-tls-arkfile` holds `arkfile.crt` and `arkfile.key` (DNS SANs `arkfile.lab` and `localhost`, IP SAN `127.0.0.1`). It is mounted read-only only into `arkfile`, so Bitcart containers never have Arkfile's TLS private key in their mount namespace.
3. `lab-tls-bitcart` holds `bitcart.crt` and `bitcart.key` (DNS SANs `bitcart.lab` and `localhost`, IP SAN `127.0.0.1`). It is mounted read-only only into `bitcart-proxy`.

When `ca` runs on an empty volume set, it generates the root CA private key in an in-memory directory (`/tmp`), includes X.509 Name Constraints on `ca.crt` restricting it exclusively to `DNS:arkfile.lab`, `DNS:bitcart.lab`, `DNS:localhost`, and `IP:127.0.0.1/255.255.255.255`, signs the two leaf certificates, writes `ca-bundle.crt`, and deletes the CA private key before exiting. Because the CA key is destroyed immediately after minting the two leaf certs and the CA itself is name-constrained, importing `ca.crt` into a dedicated lab browser profile cannot trust certificates for any outside domain even if a lab container were compromised.

Both Go (`crypto/x509`) in `arkfile` and Python (`ssl`, `aiohttp`, `httpx`, `requests`, `certifi`) in `bitcart-api`, `bitcart-worker`, and `provision` need to trust `ca.crt` *without* losing trust in public CAs (Bitcart fetches live USD exchange rates over HTTPS from public APIs). Setting both `SSL_CERT_FILE=/ca/ca-bundle.crt` and `REQUESTS_CA_BUNDLE=/ca/ca-bundle.crt` on `arkfile`, `bitcart-api`, `bitcart-worker`, and `provision` satisfies Go and Python `certifi` simultaneously, with no `Containerfile.bitcart` wrapper image needed.

Once the stack is up, the operator copies `ca.crt` to `/tmp/arkfile-bitcart-lab/ca.crt` and imports it into a dedicated browser profile so `https://arkfile.lab:18443`, `https://bitcart.lab:19080`, share links, and the `/sw-download.js` streaming-download service worker all run with valid TLS trust (`docs/wip/internal-lan-deploy.md` details why service workers refuse self-signed click-through warnings).

## Arkfile container configuration and runtime layout

Several startup and networking rules in the Arkfile codebase dictate exact container settings:

- **Bind address (`HOST=0.0.0.0`):** `config/config.go` defaults `cfg.Server.Host` to `"localhost"`. Inside a container namespace, binding `localhost` listens only on `lo`, making the server unreachable from both Podman's `127.0.0.1:18443:18443` port forward and Bitcart's webhook container. Setting `HOST=0.0.0.0` inside `arkfile` exposes the listener on the container's Compose interface while host exposure stays restricted by Podman's `127.0.0.1:18443:18443` binding.
- **Non-production classification (`PORT=8088`):** `utils.IsProductionEnvironment()` classifies the server as production if `PORT` is `80`, `443`, or `8443`, if the container hostname contains `prod`, `production`, or `live`, or if `ARKFILE_ENV`, `ENVIRONMENT`, `NODE_ENV`, `GO_ENV`, or `ENV` is `production` or `prod`. Setting `PORT=8088` (unpublished plain HTTP), `TLS_ENABLED=true`, `TLS_PORT=18443`, and container hostname `arkfile` keeps the lab out of production-only deployment blocks while keeping `DEBUG_MODE=false` and `ADMIN_DEV_TEST_API_ENABLED` unset. Because `main.go` installs `e.Pre(middleware.HTTPSRedirect())`, the container `HEALTHCHECK` must query `https://127.0.0.1:18443/readyz` with `--cacert /ca/ca-bundle.crt` rather than HTTP `:8088` (which returns a redirect).
- **rqlite connection (`RQLITE_NODES=rqlite:4001`):** `database.InitDB()` in `database/database.go` reads `RQLITE_NODES` (bare `host:port`, with no `http://` prefix) and ignores `RQLITE_ADDRESS`, whereas `database.OpenMaintenanceDB()` checks both. The container sets both `RQLITE_NODES=rqlite:4001` and `RQLITE_ADDRESS=http://rqlite:4001`, along with `RQLITE_USERNAME=lab-user` and the generated `RQLITE_PASSWORD`.
- **SeaweedFS storage:** `STORAGE_PROVIDER_1=generic-s3`, `STORAGE_PROVIDER_1_ID=generic-s3:arkfile-paylab`, `STORAGE_1_ENDPOINT=http://seaweedfs:9332`, `STORAGE_1_ACCESS_KEY=arkfile-paylab`, generated `STORAGE_1_SECRET_KEY`, `STORAGE_1_BUCKET=arkfile-paylab`, `STORAGE_1_REGION=us-east-1`, `STORAGE_1_FORCE_PATH_STYLE=true`, and `STORAGE_1_USE_SSL=false`. `storage.InitS3()` creates the bucket automatically on first boot.
- **Hardcoded `/opt/arkfile` paths and working directory:** `crypto.UserSecretMasterPath` in `crypto/user_secret_master.go` is hardcoded to `"/opt/arkfile/etc/keys/user-secret-master.bin"` with no env override, `auth.BootstrapTokenPath` in `auth/bootstrap.go` is hardcoded to `"/opt/arkfile/etc/keys/bootstrap-token.bin"` (requiring `/opt/arkfile/etc/keys` to exist beforehand), `handlers/route_config.go` serves `client/static/...` relative to `WORKDIR`, and `database/database.go` loads `database/unified_schema.sql` relative to `WORKDIR`. `Containerfile.arkfile` therefore stages built `bin/`, `client/`, `database/`, and `version.json` under `/opt/arkfile`, sets `WORKDIR /opt/arkfile`, mounts named volumes at `/opt/arkfile/etc/keys` (mode `0700`) and `/opt/arkfile/var` (with `HOME=/opt/arkfile/var/home`), and has `entrypoint-arkfile.sh` generate the 32-byte raw `/opt/arkfile/etc/keys/user-secret-master.bin` (mode `0400`) and 64-hex-char `ARKFILE_MASTER_KEY` on first start.
- **Billing and PAYG:** `ARKFILE_BILLING_ENABLED=true` and `ARKFILE_BILLING_PAYG_ENABLED=true` are both set (leaving `ARKFILE_BILLING_PAYG_ENABLED` unset causes `config/config.go` to default `PaygEnabled` to `false`, disabling metering and negative-balance caps). `ARKFILE_FREE_STORAGE_BYTES`, `ARKFILE_BILLING_TICK_INTERVAL`, `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH`, and `ARKFILE_MIN_TOP_UP_USD` accept optional overrides from `lab.env` so the operator can also test rapid PAYG metering and debt recovery if desired.
- **Registration and admin accounts:** `ENABLE_REGISTRATION=true`, `REQUIRE_APPROVAL=false`, and `ADMIN_USERNAMES=lab-admin`. Startup writes `/opt/arkfile/etc/keys/bootstrap-token.bin` and does not auto-create `lab-admin`. Regular user registration and top-up testing work immediately without bootstrapping an admin. When the operator wants to run `arkfile-admin` commands (`payments check`, `payments list`, `payments sync-invoice`, `payments reconcile`, `billing gift`), they run `arkfile-admin` inside the container via `podman compose exec arkfile` against `https://127.0.0.1:18443`, which satisfies `DirectLocalMiddleware` (`peerAddrIsLoopback` with no proxy headers) and `MarkedSessionMiddleware`.

## Services

All services live in `scripts/testing/bitcart-lab/compose.yaml`:

- `ca` -- one-shot init service (`restart: "no"`). Generates the name-constrained lab CA, `ca-bundle.crt`, `arkfile` leaf cert/key, and `bitcart` leaf cert/key into `lab-ca-public`, `lab-tls-arkfile`, and `lab-tls-bitcart` when absent, deletes the CA private key from `/tmp`, and exits `0`.
- `secrets-init` -- one-shot init service (`restart: "no"`). Generates the rqlite password and auth file, the SeaweedFS S3 secret and config, and `ARKFILE_MASTER_KEY` into `lab-config`. The pinned Bitcart Postgres component uses trust authentication, so this lab does not invent a database password the API would not read.
- `rqlite` -- official `rqlite/rqlite` image with auth enabled from `lab-config/rqlite-auth.json` and persistent volume `arkfile-rqlite`.
- `seaweedfs` -- official `chrislusf/seaweedfs` image running `server -s3 -s3.port=9332 -s3.config=/config/seaweedfs-s3.json` with persistent volume `arkfile-seaweedfs`.
- `database` and `redis` -- Postgres and Redis from the pinned components, backed by `bitcart-db-data`. Redis has no separate data volume because invoice state lives in Postgres.
- `bitcoin` -- `bitcart/bitcart-btc` with `BTC_NETWORK=${BTC_NETWORK:-mainnet}`, `BTC_LIGHTNING=false`, optional `BTC_SERVER`, and volume `bitcart-btc-data`.
- `monero` -- `bitcart/bitcart-xmr`, profile `xmr`, with `XMR_SERVER` and `XMR_NETWORK`, and volume `bitcart-xmr-data`.
- `backend` and `worker` -- upstream `bitcart/bitcart` with no wrapper image. Both mount `lab-ca-public` at `/ca` and set `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`. `BITCART_CRYPTOS` comes from `lab.env` and defaults to `btc`.
- `admin` and `checkout` -- the admin panel and the standalone checkout. The Ready Store service is not included, so invoices are at `/i/<id>` rather than `/admin/i/<id>`.
- `bitcart-proxy` -- Caddy `2.11.4` listening on `0.0.0.0:19080`, aliased as `bitcart.lab`, and published at `127.0.0.1:19080:19080`. It presents `bitcart.crt` and routes `/api/*` to `backend:8000` with the prefix removed, checkout paths to `checkout:80`, and everything else to `admin:4000`.
- `provision` -- one-shot idempotent provisioner (`restart: "no"`) that configures the Bitcart admin user, watch-only wallet(s), USD store, checkout security settings, and `invoice_management` token, writing `store_id` and `invoice_token` into `lab-config`.
- `arkfile` -- multi-stage Debian image built from this repo via `Containerfile.arkfile`, aliased as `arkfile.lab` on the Compose network and published at `127.0.0.1:18443:18443`. Its entrypoint waits for `lab-config` (`store_id` and `invoice_token`), `rqlite`, and `seaweedfs`, initializes `/opt/arkfile/etc/keys/user-secret-master.bin` if absent, exports `ARKFILE_PAYMENTS_ENABLED=true` and `ARKFILE_BITCART_*`, and starts `/opt/arkfile/bin/arkfile`.

## Building `Containerfile.arkfile` cleanly

`scripts/testing/bitcart-lab/Containerfile.arkfile` uses the repository root (`../../..`) as its build context and pairs with `scripts/testing/bitcart-lab/Containerfile.arkfile.containerignore` (Podman's native per-Containerfile ignore file, avoiding any `.dockerignore` clutter at the repo root). That ignore file excludes `.git/`, `vendor/`, `node_modules/`, `client/static/js/node_modules/`, `client/static/js/dist/`, `client/static/js/.buildcache`, `.vendor_cache`, host-compiled archives under `vendor_c/`, and `scripts/testing/bitcart-lab/lab.env`, so gigabytes of host build state or root-owned `dev-reset.sh` artifacts never enter or poison the container build.

The builder stage is Debian-based and runs `./scripts/setup/build.sh --build-only` as `root` (with `SUDO_USER` unset so `build.sh` never invokes `sudo` or `systemctl`). It installs the Go version required by `go.mod`, Zig-built Bun `1.3.14` (`BUN_ZIG_VERSION` in `scripts/setup/build-config.sh`; never Bun 1.4+), C/C++ build tools, `cmake`, `autoconf`, `automake`, `libtool`, `pkg-config`, `libudev-dev` (required by `build-libfido2.sh` for CLI binaries), `python3`, `git`, `jq`, and `openssl`. The final runtime stage is a slim Debian image containing only `ca-certificates`, `curl`, `libudev1`, an unprivileged `arkfile` user, and `/var/tmp/arkfile-build/{bin,client,database,version.json}` copied into `/opt/arkfile`.

## Bitcart one-domain translation

The component files were read from the commit in the pinned reference above. One-domain mode in that tree is active when `BITCART_HOST` is set and `BITCART_ADMIN_HOST`, `BITCART_STORE_HOST`, `BITCART_CHECKOUT_HOST`, and `BITCART_API_URL` are unset. The compose file follows that. `BITCART_HOST` is `bitcart.lab:19080` and `BITCART_HTTPS_ENABLED=true`, so the admin and checkout pages call `https://bitcart.lab:19080/api` instead of port 80. With the store service left out, `https://bitcart.lab:19080/i/<id>` is the checkout page.

## Idempotent provisioner

`provision` runs on the Compose network against `https://bitcart.lab:19080/api` with `SSL_CERT_FILE=/ca/ca-bundle.crt` and `REQUESTS_CA_BUNDLE=/ca/ca-bundle.crt`. Every step must be idempotent so stopping and restarting the stack (`podman compose stop` / `up` without `-v`) or re-running `provision` after a manual wallet fix works cleanly without duplicate stores or failed user creation:

1. **Fast path:** If `lab-config/bitcart.env` already contains `ARKFILE_BITCART_STORE_ID` and `ARKFILE_BITCART_API_TOKEN`, verify them against `GET /api/invoices/count` and `GET /api/stores/<id>`. If both succeed and the checkout settings match, exit `0` immediately.
2. **Wait for API:** Poll Bitcart's health/version endpoint until Postgres migrations and the API worker are ready.
3. **Ensure initial admin user:** Attempt first-user registration with a lab placeholder email (for example `admin@bitcart.lab`) and `BITCART_ADMIN_PASSWORD` from `lab.env`. If registration returns an error indicating the user already exists, treat that as already initialized and proceed.
4. **Authenticate in memory:** Request a temporary `full_control` bearer token via `POST /api/token` using `admin@bitcart.lab` and `BITCART_ADMIN_PASSWORD`. Hold this admin token in memory only; never write it to `lab-config` or disk.
5. **Ensure watch-only wallets:** Query `GET /api/wallets`. If no `btc` wallet exists, create one via `POST /api/wallets` (no trailing slash, which Bitcart 307-redirects) using `currency: "btc"` and `key: BTC_XPUB` (rejecting any string starting with `xprv`, `yprv`, `zprv`, `tprv`, `uprv`, or `vprv` before sending). Leave wallet-level `transaction_speed` unset so it cannot override the store setting. When `BITCART_CRYPTOS` includes `xmr` and no `xmr` wallet exists, create the watch-only Monero wallet with `XMR_ADDRESS`, `XMR_VIEW_KEY`, and `XMR_RESTORE_HEIGHT` using the exact schema of the pinned Bitcart tag.
6. **Ensure USD store and checkout settings:** Query `GET /api/stores`. Create a store (`default_currency: "USD"`) or select the existing lab store, attach the wallet IDs, and `PATCH /api/stores/<id>` so `checkout_settings` sets `transaction_speed` to `1` (or `BITCART_TX_SPEED` >= 1), `underpaid_percentage` to `0`, `email_required` to `false`, and `allow_anonymous_invoice_creation` to `false`.
7. **Mint invoice-only token:** Create a restricted token via `POST /api/token` with `permissions: ["invoice_management"]` only (no `full_control`, `wallet_management`, `store_management`, or `server_management`), verify `GET /api/invoices/count` with it, and atomically write `ARKFILE_BITCART_STORE_ID` and `ARKFILE_BITCART_API_TOKEN` to `lab-config/bitcart.env`.

If wallet creation fails (for example due to an xpub script-type mismatch or an Electrum/Monero daemon still initializing), `provision` exits non-zero and prints the Bitcart error body plus instructions to inspect `https://bitcart.lab:19080/admin` and re-run `podman compose --env-file lab.env up provision arkfile`. Because steps 1-7 are idempotent, re-running `provision` resumes cleanly.

## Operator configuration (`lab.env`)

`scripts/testing/bitcart-lab/lab.env` is gitignored, `chmod 600`, and never committed. `scripts/testing/bitcart-lab/lab.env.example` documents all variables with empty secrets:

- Required: `BTC_XPUB` (a mainnet watch-only `xpub`, `ypub`, or `zpub`; never a private key) and `BITCART_ADMIN_PASSWORD`.
- Optional Bitcoin settings: `BTC_NETWORK` (default `mainnet`) and `BTC_SERVER` (a specific Electrum server as `host:port:ssl`).
- Optional Monero settings (used with `BITCART_CRYPTOS=btc,xmr` and `--profile xmr`): `BITCART_CRYPTOS`, `XMR_NETWORK` (default `mainnet`), `XMR_SERVER` (remote Monero daemon URL), `XMR_ADDRESS`, `XMR_VIEW_KEY`, `XMR_RESTORE_HEIGHT`.
- Optional Arkfile billing overrides for rapid PAYG testing: `ARKFILE_FREE_STORAGE_BYTES`, `ARKFILE_BILLING_TICK_INTERVAL`, `ARKFILE_CUSTOMER_PRICE_USD_PER_TB_PER_MONTH`, `ARKFILE_MIN_TOP_UP_USD`.

All internal secrets (CA key, rqlite password, SeaweedFS S3 key, Bitcart Postgres password, `ARKFILE_MASTER_KEY`, `user-secret-master.bin`, and the Bitcart `invoice_management` token) are generated automatically inside volumes and destroyed by `podman compose down -v`.

## Operator workflow

From `scripts/testing/bitcart-lab/`, start the lab with rootless Podman. Bitcoin and Monero both default to mainnet:

```bash
cp lab.env.example lab.env
chmod 600 lab.env
# Edit lab.env to set BTC_XPUB and BITCART_ADMIN_PASSWORD
podman compose --env-file lab.env up -d --build
```

When testing Monero as well, set `BITCART_CRYPTOS=btc,xmr` and the `XMR_*` variables in `lab.env`, and pass `--profile xmr`:

```bash
podman compose --env-file lab.env --profile xmr up -d --build
```

Export the name-constrained lab CA certificate to `/tmp/arkfile-bitcart-lab` and import it into a dedicated browser profile:

```bash
mkdir -p /tmp/arkfile-bitcart-lab/home
podman compose cp arkfile:/ca/ca.crt /tmp/arkfile-bitcart-lab/ca.crt
```

Open `https://arkfile.lab:18443` in that browser profile, register a normal user, enroll TOTP, upload and download a file, create and open an anonymous share link (`https://arkfile.lab:18443/...`), and initiate a top-up from the billing panel. The checkout opens at `https://bitcart.lab:19080/i/<id>`. Pay the displayed address from an external wallet for at least the crypto amount shown. The invoice moves from `pending` to `confirming` when seen in mempool, then to `paid` after at least one block confirmation, crediting the user's USD balance once.

To test `arkfile-client` from the host without touching `~/.arkfile-session.json` or failing `cli/tlspolicy`'s loopback-only check on `--tls-insecure` (`cli/tlspolicy/tlspolicy.go` rejects `--tls-insecure` for non-loopback hostnames such as `arkfile.lab`), pass both an isolated `HOME` and `SSL_CERT_FILE`:

```bash
HOME=/tmp/arkfile-bitcart-lab/home \
SSL_CERT_FILE=/tmp/arkfile-bitcart-lab/ca.crt \
/opt/arkfile/bin/arkfile-client --server-url https://arkfile.lab:18443 billing top-up --amount 0.50 --wait
```

(If `/opt/arkfile/bin/arkfile-client` is not installed on the host, copy or invoke `/opt/arkfile/bin/arkfile-client` from the `arkfile` container.)

To run `arkfile-admin` commands (`payments check`, `payments list`, `billing gift`), execute `arkfile-admin` inside the `arkfile` container against `https://127.0.0.1:18443` so `DirectLocalMiddleware` sees a direct loopback connection:

```bash
# One-time admin bootstrap inside the lab container (interactive password + TOTP setup):
podman compose exec arkfile sh -c \
  'cat /opt/arkfile/etc/keys/bootstrap-token.bin | /opt/arkfile/bin/arkfile-admin --server-url https://127.0.0.1:18443 bootstrap --token-stdin --username lab-admin'
podman compose exec -it arkfile /opt/arkfile/bin/arkfile-admin --server-url https://127.0.0.1:18443 setup-mfa
podman compose exec -it arkfile /opt/arkfile/bin/arkfile-admin --server-url https://127.0.0.1:18443 login --username lab-admin

# Verify Bitcart configuration and inspect invoices:
podman compose exec arkfile /opt/arkfile/bin/arkfile-admin --server-url https://127.0.0.1:18443 payments check
podman compose exec arkfile /opt/arkfile/bin/arkfile-admin --server-url https://127.0.0.1:18443 payments list
```

## Success criteria

The lab is complete when all of the following hold on a machine that also has a host `dev-reset.sh` or `local-deploy.sh` instance installed:

1. Host services on `:8443`, `:4001`, and `:9332` remain untouched and healthy while the lab answers on `https://arkfile.lab:18443` (`127.0.0.1:18443`) and `https://bitcart.lab:19080` (`127.0.0.1:19080`).
2. With `/tmp/arkfile-bitcart-lab/ca.crt` imported into a dedicated browser profile, `/sw-download.js` registers cleanly, file upload and streaming download succeed, and anonymous share URLs use `https://arkfile.lab:18443/...` and decrypt in the browser.
3. `arkfile-admin payments check` inside the `arkfile` container reports `[OK]` for the API token, store, `transaction_speed >= 1`, `underpaid_percentage == 0`, `email_required == false`, and `allow_anonymous_invoice_creation == false`.
4. Creating a top-up returns a `https://bitcart.lab:19080/i/<id>` checkout URL that renders a valid payment address and QR code in the browser without mixed-content or WebSocket errors, and the invoice stored on Bitcart contains only the USD price, currency, store ID, `notification_url` (`https://arkfile.lab:18443/api/webhooks/bitcart`), and opaque `order_id` (`inv_...`), with no Arkfile username.
5. Paying an invoice from an external wallet moves Arkfile's invoice status `pending` -> `confirming` -> `paid`, Bitcart's worker log records `POST https://arkfile.lab:18443/api/webhooks/bitcart` returning `200`, and the user's balance increases by the exact USD invoice amount once (surviving later reconciler passes without double-crediting).
6. Leaving a second invoice unpaid until expiration transitions it to `expired` with zero credit applied.
7. Stopping and restarting the lab without `-v` (`podman compose stop` followed by `podman compose --env-file lab.env up -d`) preserves data and passes `provision` idempotently; running `podman compose down -v` wipes all lab state cleanly; and host `e2e-test.sh` continues using its mock on `127.0.0.1:8989` unaffected.

## Files to add

- `scripts/testing/bitcart-lab/compose.yaml` -- complete rootless Podman Compose stack (`arkfile-paylab`).
- `scripts/testing/bitcart-lab/Containerfile.arkfile` -- multi-stage Debian builder (`build.sh --build-only` with Bun `1.3.14`) and slim runtime image staged at `/opt/arkfile`.
- `scripts/testing/bitcart-lab/Containerfile.arkfile.containerignore` -- excludes `.git/`, `vendor/`, `node_modules/`, host build caches, host C archives, and `lab.env` from the build context.
- `scripts/testing/bitcart-lab/entrypoint-arkfile.sh` -- initializes `/opt/arkfile/etc/keys/user-secret-master.bin`, loads generated secrets and `bitcart.env` from `lab-config`, and execs `/opt/arkfile/bin/arkfile`.
- `scripts/testing/bitcart-lab/Caddyfile` -- one-domain HTTPS and WebSocket reverse proxy on `:19080` for `bitcart-api`, `bitcart-admin`, and `bitcart-checkout`.
- `scripts/testing/bitcart-lab/provision/` -- idempotent one-shot Bitcart provisioner script/container.
- `scripts/testing/bitcart-lab/lab.env.example` -- template for operator watch-only wallet keys and optional overrides.
- `.gitignore` -- add `scripts/testing/bitcart-lab/lab.env` (plus `scripts/testing/bitcart-lab/*.crt` and `scripts/testing/bitcart-lab/*.pem` as defense in depth).

No changes are made to `dev-reset.sh`, `local-deploy.sh`, or `e2e-test.sh` beyond the `8989` mock port already updated.

## Implementation order

1. The Bitcart component files were read at the commit in the pinned reference above, for `btc` and `xmr` on mainnet with the checkout component. Image digests are still to be recorded after the first successful payment.
2. Implement `ca`, `secrets-init`, `Caddyfile`, and the Bitcart subset of `scripts/testing/bitcart-lab/compose.yaml`. Verify (with developer consent for each Podman invocation) that `https://bitcart.lab:19080/admin` loads cleanly in the browser and that `ca-bundle.crt` validates `https://bitcart.lab:19080/api` from inside the Compose network.
3. Implement `scripts/testing/bitcart-lab/provision/` against the live Bitcart API, verifying first-run provisioning, private-key prefix rejection, idempotent re-runs on existing volumes, and the manual-UI recovery message on bad wallet input.
4. Implement `Containerfile.arkfile`, `Containerfile.arkfile.containerignore`, `entrypoint-arkfile.sh`, `rqlite`, and `seaweedfs`. Verify `/readyz` on `https://127.0.0.1:18443/readyz`, normal user registration, file upload/download, share links, and `arkfile-admin payments check` via `podman compose exec`.
5. Create a top-up invoice from the browser and from `arkfile-client` (with isolated `HOME` and `SSL_CERT_FILE`), confirm Bitcart received zero PII, pay the invoice address with mainnet bitcoin from an external wallet, verify the `200` webhook delivery and single credit settlement, and verify an unpaid invoice expiring with no credit.
6. Test the optional `--profile xmr` flow (`BITCART_CRYPTOS=btc,xmr` plus remote Monero node and watch-only view key) once the Bitcoin path is proven.
7. Pin every image reference in `compose.yaml` and `Containerfile.arkfile` by digest, test `podman compose stop` / `up -d` persistence and `podman compose down -v` clean teardown, and verify host `e2e-test.sh` on `127.0.0.1:8989` remains green.

## Open risks

- **Bitcart API schema nuances across releases:** While Arkfile's read-side schema in `payments/bitcart.go` is already fixed, the write-side fields accepted by `POST /api/wallets` (especially Monero `additional_data` fields for view key and restore height) and `PATCH /api/stores/<id>` must be verified directly against the pinned Bitcart release tag in step 1 rather than guessed.
- **Electrum connectivity:** The Bitcoin daemon uses public mainnet Electrum servers unless `BTC_SERVER` is set. A stalled server makes a broadcast transaction look invisible even when the stack is healthy. Set `BTC_SERVER` to a known-good Electrum server if the default pool stalls.
- **Monero scan catch-up time:** Even with a remote `monerod`, `monero-wallet-rpc` inside `bitcart-xmr` must scan blocks from `XMR_RESTORE_HEIGHT` to the chain tip before detecting incoming outputs. Setting `XMR_RESTORE_HEIGHT` just below the current block height before starting `--profile xmr` avoids long initial sync delays.
- **Sensitive watch-only metadata in volumes:** Although `BTC_XPUB` and `XMR_VIEW_KEY` cannot spend funds, they expose address history and incoming transfers for that wallet. Keep a dedicated test/lab wallet or subaccount for lab runs, never copy Bitcart volumes out to persistent host backups, and run `podman compose down -v` when finished.
