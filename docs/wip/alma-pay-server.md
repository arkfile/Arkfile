# BTCPay Server on AlmaLinux 10+ (rootless Podman)

This document describes the operator protocol for self-hosted BTCPay Server 2.4+ on AlmaLinux 10+. The stack uses Bitcoin Core 30+, rootless Podman only, and a dedicated `almapay` system account that cannot log in over SSH. It listens on a loopback high port behind host-installed Caddy and can include a pruned Bitcoin node, a pruned Monero node, and optional Boltz (Lightning) and Stripe (card) plugins. One BTCPay instance can host multiple stores with independent API keys and webhooks per store.

The protocol deliberately avoids upstream one-click installers that assume Debian package managers, a privileged container runtime, or binding public ports 80 and 443 inside the payment stack. Instead it uses the upstream [btcpayserver-docker](https://github.com/btcpayserver/btcpayserver-docker) repository as a compose generator and operator tooling source, while keeping runtime ownership on the `almapay` user.

The implementation contract for the separate AlmaPay repository is in [`alma-pay-spec.md`](alma-pay-spec.md). This document is a deployment runbook, not permission to mutate a production host. All upstream commits, images, plugin releases, and the external Compose provider must be pinned and tested before production use.

## Threat model and design goals

The payment VPS is a single-purpose host. Day-to-day container operations run as the unprivileged `almapay` user through rootless Podman. Containers do not receive privileged capabilities, host root bind mounts, or access to the host SSH trust store. Administrative login uses a separate operator account over SSH; `almapay` exists only to own data directories, pull images, and run compose under user systemd with linger enabled.

TLS termination and public HTTP ports live on Caddy (or an equivalent reverse proxy) outside the BTCPay compose stack. BTCPay itself binds a high port on loopback (for example `127.0.0.1:8080`), which rootless Podman can expose without capability adjustments.

Rootless Podman means container processes run as `almapay`, not as root. Never run `sudo podman` or `podman` from a root shell for this stack. Operator maintenance uses `sudo -u almapay -H` to drop into the runtime user (`almapay` has `/sbin/nologin`, so you cannot SSH in directly). That is user switching, not a privileged container runtime. Host bootstrap (packages, firewall, user creation) and Caddy installation legitimately use root; the compose stack does not.

## What upstream assumes (and what we skip)

The official `btcpay-setup.sh` script installs a container engine through Debian-oriented package paths, registers a system-wide systemd unit tied to a privileged engine service, and often deploys an integrated nginx container on ports 80 and 443. That path is incompatible with this protocol. Operators should not run `btcpay-setup.sh` on Alma as root.

What we keep from upstream: the fragment-based compose generator (`build.sh` logic), `Generated/docker-compose.generated.yml`, selected helper behavior adapted for rootless Podman, and the OCI images referenced in the generated compose file. Production must use a reviewed `upstream.lock`; it must not pull a floating branch, tag, generator image, or plugin release.

## Architecture

Public clients reach `https://pay.example.com` on Caddy. Caddy reverse-proxies to BTCPay listening on `127.0.0.1:8080`. The reference compose stack includes BTCPay Server 2.4+, PostgreSQL, NBXplorer, Bitcoin Core 30+, pruned `bitcoind`, pruned `monerod`, and supporting services. No reverse-proxy container ships inside the stack (`BTCPAYGEN_REVERSEPROXY=none`). Omit Monero or plugins by changing generator fragments and skipping the corresponding setup phases.

Lightning payments can be enabled through the Boltz plugin in nodeless mode, which accepts Lightning without running Core Lightning or LND in the compose file. On-chain Bitcoin and Monero use the local pruned nodes when those cryptos are included. Card payments can use the Stripe Payments plugin; checkout UI remains on BTCPay pages.

Integrating applications talk to BTCPay through the Greenfield API and receive settlement events on HTTPS webhooks they expose. They do not need direct access to Stripe, Boltz, or chain daemons.

AlmaPay is application-agnostic. Arkfile is the first reference integration used to prove deployment, checkout, Greenfield API, and webhook behavior, but it is not embedded in or required by the AlmaPay runtime. One deployment may serve multiple independent applications through isolated BTCPay stores and credentials.

## Configuration invariants

Replace `pay.example.com` with your real hostname and use that same value everywhere: DNS, runtime `.env` (`BTCPAY_HOST`), and the Caddy site block. Keep `BTCPAY_PROTOCOL=https` when TLS terminates at Caddy. Set `NOREVERSEPROXY_HTTP_PORT=127.0.0.1:8080`; a bare `8080` can publish on every host interface. Keep `NBITCOIN_NETWORK` consistent with wallet policy. Generator `BTCPAYGEN_*` variables define which services appear in compose; runtime `.env` defines how BTCPay presents itself on the network.

The upstream `btc` crypto definition currently selects `bitcoin.yml`, which is pinned below Bitcoin Core 30. A compliant deployment must exclude that fragment and add `bitcoincore.yml`, then inspect the rendered compose and the running daemon version. An image tag alone is not proof of the running version.

## Prerequisites

Provision a currently supported AlmaLinux 10 VPS on KVM; AlmaLinux 10.2 is the initial tested reference. OpenVZ-based VPS plans are a poor fit for chain nodes. Attach DNS for your BTCPay hostname to the host. Size the machine generously: plan for roughly 4 vCPU, 8 GB RAM, and 400 GB SSD. Pruned Bitcoin with `opt-save-storage-s` uses on the order of 50 GB. The upstream Monero fragment is pruned, but still requires substantial growing storage; leave margin for PostgreSQL, plugin wallets, temporary update capacity, backups, and logs.

AlmaLinux 10 uses cgroup v2 and SELinux by default. Keep SELinux enforcing. On x86 hosts, verify that the selected AlmaLinux architecture is compatible with the VPS CPU; normal AlmaLinux 10 x86-64 packages target x86-64-v3, while the alternate x86-64-v2 distribution has third-party package limitations.

Install Caddy on the host (package or static binary) so it can bind 443 and proxy to loopback. Caddy may run as its own unprivileged user or via a small system unit; it is outside the scope of the `almapay` compose project.

## Phase 1 — One-time host bootstrap (operator root)

Create the service identity and data root:

```bash
sudo groupadd -r almapay 2>/dev/null || true
sudo useradd -r -g almapay -d /var/lib/almapay -s /sbin/nologin -c "BTCPay Podman runtime" almapay
sudo install -d -o almapay -g almapay -m 0750 /var/lib/almapay
```

Ensure rootless Podman subordinate ID ranges exist for `almapay`; verify non-overlapping entries in `/etc/subuid` and `/etc/subgid`. Install Podman and an explicitly selected Compose provider. `podman compose` is a wrapper around an external provider, not a native Compose implementation. The AlmaPay implementation must pin and install a tested `podman-compose` version and set `PODMAN_COMPOSE_PROVIDER=/usr/bin/podman-compose`; it must fail if Docker Compose is selected.

```bash
sudo dnf -y install podman git curl jq shadow-utils
# Install the exact podman-compose package/version recorded in upstream.lock.
```

After changing subordinate IDs on an existing runtime, stop all affected containers and run `podman system migrate` as `almapay`. Never run that migration automatically against a live deployment.

Enable lingering so user services start at boot without an interactive session:

```bash
sudo loginctl enable-linger almapay
```

Configure host firewall to allow HTTPS to Caddy while keeping the BTCPay high port local-only (default firewalld: allow `https` service; do not publish `8080` publicly).

Record the runtime user id for later systemd and operator commands:

```bash
id -u almapay   # use this value wherever ALMAPAY_UID appears below
```

All Phase 2 onward container work runs as `almapay` from an operator session via `sudo -u almapay -H` (and `XDG_RUNTIME_DIR=/run/user/ALMAPAY_UID` when invoking user systemd). Do not use `sudo podman`.

## Phase 2 — Fetch compose tooling and generate the stack

From an operator session, as the runtime user (substitute your `ALMAPAY_UID` from Phase 1):

```bash
ALMAPAY_UID=$(id -u almapay)

sudo -u almapay -H git clone https://github.com/btcpayserver/btcpayserver-docker.git /var/lib/almapay/btcpayserver-docker
```

Export generation variables. This example uses mainnet Bitcoin Core 30+ (pruned), Monero (pruned), no in-stack Lightning daemon, and no integrated reverse proxy. Substitute the reviewed BTCPay and generator pins from `upstream.lock`; never use `latest`.

```bash
export BTCPAY_HOST="pay.example.com"
export BTCPAY_PROTOCOL="https"
export BTCPAYGEN_CRYPTO1="btc"
export BTCPAYGEN_CRYPTO2="xmr"
export BTCPAYGEN_REVERSEPROXY="none"
export BTCPAYGEN_LIGHTNING="none"
export BTCPAYGEN_EXCLUDE_FRAGMENTS="bitcoin"
export BTCPAYGEN_ADDITIONAL_FRAGMENTS="bitcoincore;opt-save-storage-s"
export BTCPAY_IMAGE="btcpayserver/btcpayserver:2.4.0"
export NOREVERSEPROXY_HTTP_PORT="127.0.0.1:8080"
export PODMAN_COMPOSE_PROVIDER="/usr/bin/podman-compose"
```

Run the pinned upstream generator container with rootless Podman as `almapay`. The commit and digest placeholders below must come from the reviewed lockfile:

```bash
sudo -u almapay -H bash -lc '
  cd /var/lib/almapay/btcpayserver-docker
  test "$(git rev-parse HEAD)" = "<PINNED_UPSTREAM_COMMIT>"
  podman pull btcpayserver/docker-compose-generator@sha256:<PINNED_GENERATOR_DIGEST>
  podman run --rm \
    -v "$(pwd)/Generated:/app/Generated" \
    -v "$(pwd)/docker-compose-generator/docker-fragments:/app/docker-fragments" \
    -v "$(pwd)/docker-compose-generator/crypto-definitions.json:/app/crypto-definitions.json" \
    -e BTCPAYGEN_CRYPTO1=btc \
    -e BTCPAYGEN_CRYPTO2=xmr \
    -e BTCPAYGEN_REVERSEPROXY=none \
    -e BTCPAYGEN_LIGHTNING=none \
    -e BTCPAYGEN_EXCLUDE_FRAGMENTS=bitcoin \
    -e "BTCPAYGEN_ADDITIONAL_FRAGMENTS=bitcoincore;opt-save-storage-s" \
    -e BTCPAY_IMAGE=btcpayserver/btcpayserver:2.4.0 \
    btcpayserver/docker-compose-generator@sha256:<PINNED_GENERATOR_DIGEST>
'
```

Before first start, render and inspect the complete Compose model. Installation must fail if it contains Bitcoin Core below 30, BTCPay below 2.4, `0.0.0.0:8080`, a public database or daemon RPC port, a privileged container, dangerous host mounts, or missing Bitcoin RPC/pruning arguments. Fragment composition can modify `BITCOIN_EXTRA_ARGS`, so verify that the rendered configuration retains the base RPC settings and the intended prune setting.

Create the runtime environment file beside the compose project (`/var/lib/almapay/.env`). Use the same hostname as above:

```ini
BTCPAY_HOST=pay.example.com
BTCPAY_PROTOCOL=https
NBITCOIN_NETWORK=mainnet
NOREVERSEPROXY_HTTP_PORT=127.0.0.1:8080
BTCPAY_CRYPTOS=btc;xmr
BTCPAY_IMAGE=btcpayserver/btcpayserver:2.4.0
PODMAN_COMPOSE_PROVIDER=/usr/bin/podman-compose
```

Adjust `BTCPAY_CRYPTOS` if you change `BTCPAYGEN_CRYPTO*`. Pull stack images before first boot (`Generated/pull-images.sh` if present, otherwise `podman compose pull`).

Start the stack from the directory containing `.env`:

```bash
sudo -u almapay -H bash -lc '
  cd /var/lib/almapay
  podman compose -f btcpayserver-docker/Generated/docker-compose.generated.yml --env-file .env pull
  podman compose -f btcpayserver-docker/Generated/docker-compose.generated.yml --env-file .env up -d
'
```

Initial synchronization for Bitcoin (pruned) and Monero can take hours or days. Expect elevated CPU, disk I/O, and memory until nodes catch up. Wait for reasonable chain sync before enabling production payment methods or accepting mainnet funds.

## Phase 3 — User systemd persistence

Register a user service for `almapay` so the stack survives reboot. Create `/var/lib/almapay/.config/systemd/user/btcpay.service` (replace `ALMAPAY_UID` with the numeric uid from `id -u almapay`):

```ini
[Unit]
Description=BTCPay Server (Podman Compose)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/var/lib/almapay
Environment=XDG_RUNTIME_DIR=/run/user/ALMAPAY_UID
Environment=PODMAN_COMPOSE_PROVIDER=/usr/bin/podman-compose
ExecStart=/usr/bin/podman compose -f btcpayserver-docker/Generated/docker-compose.generated.yml --env-file .env up -d --remove-orphans
ExecStop=/usr/bin/podman compose -f btcpayserver-docker/Generated/docker-compose.generated.yml --env-file .env down
TimeoutStartSec=600

[Install]
WantedBy=default.target
```

RHEL 10 recommends Quadlet for native Podman services, but Quadlet does not directly consume the authoritative upstream Compose file. This compose-level user service is therefore a deliberate design choice. Do not use deprecated `podman generate systemd`, and do not mechanically translate the project to Quadlet without equivalence tests for volumes, dependencies, networking, health checks, restart behavior, and updates.

Enable it from an operator session:

```bash
ALMAPAY_UID=$(id -u almapay)
sudo -u almapay -H XDG_RUNTIME_DIR=/run/user/${ALMAPAY_UID} systemctl --user enable --now btcpay.service
```

Confirm with `sudo -u almapay -H podman ps` and a loopback HTTP probe once sync allows (`curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/`).

For later restarts use the same pattern:

```bash
sudo -u almapay -H XDG_RUNTIME_DIR=/run/user/$(id -u almapay) systemctl --user restart btcpay.service
```

## Phase 4 — Caddy reverse proxy

Configure Caddy on the host to terminate TLS and forward to BTCPay. Minimal example (`/etc/caddy/Caddyfile` or a snippet under `/etc/caddy/conf.d/`):

```
pay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Reload Caddy after DNS points at the host. BTCPay should see HTTPS externally (`BTCPAY_PROTOCOL=https`) while the hop from Caddy to BTCPay stays HTTP on loopback. Caddy sets `X-Forwarded-Proto` and related headers by default.

For iframe embedding in third-party applications, those applications must allow this origin in `frame-src` Content Security Policy. That is an integrator concern, not part of this host protocol.

## Phase 5 — Wallets and cryptocurrencies

Complete first-time BTCPay registration through the public URL (`https://pay.example.com`). Configure a descriptor-based Bitcoin wallet per store (hot wallet or watch-only/xpub, per your policy). The reference container sets `CREATE_WALLET=false`; BTCPay and NBXplorer track descriptors/xpubs rather than depending on a Bitcoin Core hot wallet. Bitcoin Core 30 removed legacy BDB wallet loading and legacy RPCs including `importprivkey`, `importaddress`, `importmulti`, `importwallet`, `dumpprivkey`, and `dumpwallet`; no AlmaPay script or runbook may use them. Migrating a pre-existing BDB wallet with `migratewallet` is a separate, manual migration outside the fresh-install path.

Monero is configured once at server level: upload view-only wallet and `.keys` files in the Monero settings area. Never upload Monero spend keys.

Monero on BTCPay is server-wide: all stores on one instance share the same Monero wallet configuration. Bitcoin payment methods are per store. Plan multi-store layouts accordingly.

Enable BTC and XMR payment methods on each store after wallets are ready and nodes are sufficiently synced.

## Phase 6 — Plugins (optional: Boltz and Stripe)

Open **Plugins → Manage Plugins** in the BTCPay UI. Skip this phase if on-chain BTC (and XMR, if enabled) is enough.

Install **Boltz** (BoltzExchange). Restart the stack when prompted:

```bash
sudo -u almapay -H XDG_RUNTIME_DIR=/run/user/$(id -u almapay) systemctl --user restart btcpay.service
```

Choose **Nodeless** mode during setup unless you later add a local Lightning implementation to the compose file. Follow the plugin wizard to create or import a Liquid wallet, review fees, and optionally configure chain swaps from Liquid BTC to on-chain BTC with a maximum Liquid balance you accept. Enable Lightning as a payment method on each store. Boltz does not support zero-amount invoices.

Install **Stripe Payments** only after confirming its exact release declares compatibility with the pinned BTCPay 2.4.x version. Restart again using the same command. Configure Stripe API keys and enabled payment methods separately for each store. Card and wallet UI stays on BTCPay checkout pages.

BTCPay 2.4 no longer supports LNBank, LNDHub, Lightning Charge, or the deprecated Shopify Scripts integration. Do not configure them. BTCPay moved to .NET 10 beginning with 2.3.7, so query the live plugin manifest, pin each compatible Boltz, Stripe, and Monero plugin release, and test restart behavior. After plugin changes, always restart through user systemd and verify plugin status in the UI before taking production traffic.

## Phase 7 — Multiple stores and integrators

A single BTCPay instance supports many stores and consumer applications. Create a distinct store for each application and environment. For each store, note the Store ID, issue a least-privilege Greenfield API key with the required invoice permissions, and register a webhook pointing at that integrator's public HTTPS endpoint. Save the webhook signing secret the UI displays; the integrator should verify the provider signature header on delivery (for example `BTCPay-Sig`). Use separate API keys, store IDs, and webhook secrets per store so one application or test environment cannot read, mutate, or settle against another application's records. Confirm webhook delivery from the BTCPay UI before relying on automated settlement.

AlmaPay does not define an application's invoice metadata, fulfillment, ledger, or webhook route. Each integrator owns those policies and its application-level idempotency. Multiple applications on one deployment must be under one trusted server operator; store credentials do not isolate mutually distrustful administrators, and server-wide plugins and logging policy remain shared. Monero remains a custody exception: stores on the same BTCPay deployment share server-level wallet view material even when application credentials and invoice records are isolated. Use separate deployments where administration, custody, or host-level privacy policy must be independent.

## Phase 8 — Operations

Updates must be lockfile-driven, never an unreviewed `git pull`. Create and verify a pre-update backup, fetch the requested commit, regenerate Compose, inspect the configuration and image diff, pull pinned images, restart through user systemd, and run verification. Retain the previous generated configuration and image references. A BTCPay database migration may make binary rollback unsafe; the documented rollback is restoration of the pre-update database and deployment backup.

```bash
sudo -u almapay -H bash -lc 'cd /var/lib/almapay/btcpayserver-docker && git fetch origin <PINNED_COMMIT> && git checkout --detach <PINNED_COMMIT>'
# Re-run the pinned generator, review its diff, then:
sudo -u almapay -H bash -lc 'cd /var/lib/almapay && podman compose -f btcpayserver-docker/Generated/docker-compose.generated.yml --env-file .env pull'
sudo -u almapay -H XDG_RUNTIME_DIR=/run/user/$(id -u almapay) systemctl --user restart btcpay.service
```

Backups: follow BTCPay backup guidance for PostgreSQL and wallet material, and also retain deployment state that BTCPay's UI does not cover: `/var/lib/almapay/.env`, the generated compose file, the `btcpayserver-docker` git checkout (or pinned commit), and the user systemd unit. Backup jobs should run as a privileged operator reading `almapay`-owned volumes under `/var/lib/almapay` and rootless Podman volume paths (`podman volume inspect` helps locate mount sources). Test restore on a non-production host.

Disk monitoring is critical on pruned-BTC plus Monero layouts. If space tightens, adjust prune tier (`opt-save-storage-s` vs `opt-save-storage`) only with planning: changing prune fragments requires regenerating compose and resync policy review.

SELinux: Alma enforces SELinux by default. Rootless Podman usually labels volume content correctly; if bind-mounting host paths into containers, use the `:Z` relabel flag on compose volumes or set appropriate `container_file_t` contexts on host directories.

Security hygiene: do not enable BTCPay's optional host SSH integration on this layout. Restrict operator SSH keys. Separate Stripe live and test credentials across stores. Treat Monero view-only keys as confidential.

## Version and runtime verification

The deployment is not ready merely because containers are running. Verification must confirm AlmaLinux major version 10 or later, cgroup v2, SELinux state, rootless user namespaces, user systemd, the selected Compose provider, loopback-only publication, valid public TLS, chain synchronization, disk and inode capacity, and plugin compatibility.

Query the running processes rather than trusting image tags. Bitcoin Core's numeric version must be at least `300000`, BTCPay's semantic version must be at least `2.4.0`, and NBXplorer must be connected and synchronized with the selected node. If an operator needs all Bitcoin secondary indexes rebuilt, use and plan for a full `-reindex`; `-reindex-chainstate` does not rebuild indexes such as `txindex`.

AlmaLinux 10.2 is the initial supported and tested reference. Later AlmaLinux 10 minor releases and future major releases require capability checks and integration testing rather than blind acceptance based only on the version number.

## Honest limitations

This is not an officially supported BTCPay deployment shape. Upstream tests focus on Docker Compose with integrated nginx. Rootless Podman, an external Compose provider, high-port binding, external Caddy, and skipping `btcpay-setup.sh` place integration burden on the operator.

Monero remains one wallet per server*. Boltz nodeless mode routes Lightning through Liquid before optional on-chain settlement. Stripe plugin availability and version pins depend on the BTCPay release channel you deploy.

When in doubt, validate on a test store and test webhook delivery before accepting mainnet funds.

### `*` Monero Multi-Store Issues

Unlike Bitcoin, where each BTCPay store can have its own wallet and address pool, Monero is configured once for the entire server. All stores on the same instance share a single view-only wallet connected to one `monero-wallet-rpc` service. Invoices and settlement records remain per store in BTCPay, but on-chain XMR receipts accumulate in the same underlying wallet regardless of which store enabled the payment method.

If test and production stores must not share Monero funds, disable XMR on the test store, use separate Monero accounts inside one wallet only when the parties are fully trusted, or run a second BTCPay deployment with its own Monero node and wallet. Multi-wallet Monero per store is not supported by the current plugin architecture.

You cannot assign a separate Monero wallet file per store, but you can assign a different Monero account index per store in that store's Monero payment settings (for example account `0` for production and account `1` for test). BTCPay does not let you pin a fixed subaddress to each store; instead it generates a fresh subaddress for every invoice within the store's account. That gives per-store labeling and keeps payer-facing addresses in separate subaddress chains, but all accounts still belong to one wallet and share the same view material on the server.

For administrators, the practical options are: use one account index for all stores when test and prod are the same operator; split test and prod across account indices on one server when you want bookkeeping separation but accept shared wallet custody; disable Monero on non-production stores to avoid mixing test receipts into live XMR balances; or deploy a second BTCPay instance when stores must not share Monero treasury or view-key access at all. Run a current BTCPay and Monero plugin release if you rely on non-default account indices, since older builds had edge cases detecting payments outside account `0`.
