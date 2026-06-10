# BTCPay Server on Alma Linux (rootless Podman)

This document describes a deployment protocol for self-hosted BTCPay Server on Alma Linux and other RHEL-family distributions. The stack uses rootless Podman only, runs under a dedicated `almapay` system account that cannot log in over SSH, listens on high ports behind an external reverse proxy (Caddy is assumed here), and includes a pruned Bitcoin node, a Monero node, the Boltz plugin for Lightning checkout, and the Stripe Payments plugin for card payments. One BTCPay instance can host multiple stores (for example separate test and production storefronts) with independent API keys and webhooks per store.

The protocol deliberately avoids upstream one-click installers that assume Debian package managers, a privileged container runtime, or binding public ports 80 and 443 inside the payment stack. Instead it uses the upstream [btcpayserver-docker](https://github.com/btcpayserver/btcpayserver-docker) repository as a compose generator and operator tooling source, while keeping runtime ownership on the `almapay` user.

## Threat model and design goals

The payment VPS is a single-purpose host. Day-to-day container operations run as the unprivileged `almapay` user through rootless Podman. Containers do not receive privileged capabilities, host root bind mounts, or access to the host SSH trust store. Administrative login uses a separate operator account over SSH; `almapay` exists only to own data directories, pull images, and run compose under user systemd with linger enabled.

TLS termination and public HTTP ports live on Caddy (or an equivalent reverse proxy) outside the BTCPay compose stack. BTCPay itself binds a high port on loopback (for example `127.0.0.1:8080`), which rootless Podman can expose without capability adjustments.

## What upstream assumes (and what we skip)

The official `btcpay-setup.sh` script installs a container engine through Debian-oriented package paths, registers a system-wide systemd unit tied to a privileged engine service, and often deploys an integrated nginx container on ports 80 and 443. That path is incompatible with this protocol. Operators should not run `btcpay-setup.sh` on Alma as root.

What we keep from upstream: the fragment-based compose generator (`build.sh` logic), `Generated/docker-compose.generated.yml`, helper scripts such as `btcpay-up.sh` / `btcpay-down.sh` / `btcpay-update.sh` (adapted to call `podman compose` instead of any legacy compose binary), and the OCI images referenced in the generated compose file.

## Architecture

Public clients reach `https://btcpayserver.example.com` on Caddy. Caddy reverse-proxies to BTCPay listening on `127.0.0.1:8080`. The compose stack includes BTCPay Server, PostgreSQL, NBXplorer, pruned `bitcoind`, `monerod`, and supporting services. No reverse-proxy container ships inside the stack (`BTCPAYGEN_REVERSEPROXY=none`).

Lightning payments for merchants are enabled through the Boltz plugin in nodeless mode, which accepts Lightning without running Core Lightning or LND in the compose file. On-chain Bitcoin and Monero use the local pruned BTC and full Monero nodes. Card payments use the Stripe Payments plugin; checkout UI remains on BTCPay pages.

Integrating applications talk to BTCPay through the Greenfield API and receive settlement events on HTTPS webhooks they expose. They do not need direct access to Stripe, Boltz, or chain daemons.

## Prerequisites

Provision an Alma Linux 9 VPS on KVM (OpenVZ-based VPS plans are a poor fit for chain nodes). Attach DNS for `btcpayserver.example.com` to the host. Size the machine generously: plan for roughly 4 vCPU, 8 GB RAM, and 400 GB SSD. Pruned Bitcoin with `opt-save-storage-s` uses on the order of 50 GB; a Monero full node commonly exceeds 150 GB and grows over time; leave margin for PostgreSQL, plugin wallets, and logs.

Install Caddy on the host (package or static binary) so it can bind 443 and proxy to loopback. Caddy may run as its own unprivileged user or via a small system unit; it is outside the scope of the `almapay` compose project.

## Phase 1 — One-time host bootstrap (operator root)

Create the service identity and data root:

```bash
sudo groupadd -r almapay 2>/dev/null || true
sudo useradd -r -g almapay -d /var/lib/almapay -s /sbin/nologin -c "BTCPay Podman runtime" almapay
sudo install -d -o almapay -g almapay -m 0750 /var/lib/almapay
```

Ensure rootless Podman subordinate ID ranges exist for `almapay` (Alma often configures this automatically for system users; verify `/etc/subuid` and `/etc/subgid` contain `almapay` entries). Install Podman and compose support:

```bash
sudo dnf -y install podman podman-compose git curl jq
```

Enable lingering so user services start at boot without an interactive session:

```bash
sudo loginctl enable-linger almapay
```

Configure host firewall to allow HTTPS to Caddy while keeping the BTCPay high port local-only (default firewalld: allow `https` service; do not publish `8080` publicly).

All remaining setup runs as `almapay` via `sudo -u almapay -H ...` or an operator rootless session (`sudo machinectl shell almapay@` is not available with nologin; use `sudo -u almapay`).

## Phase 2 — Fetch compose tooling and generate the stack

As `almapay`:

```bash
sudo -u almapay -H git clone https://github.com/btcpayserver/btcpayserver-docker.git /var/lib/almapay/btcpayserver-docker
cd /var/lib/almapay/btcpayserver-docker
```

Export generation variables. This example uses mainnet Bitcoin (pruned), Monero, no in-stack Lightning daemon, and no integrated nginx:

```bash
export BTCPAY_HOST="btcpayserver.example.com"
export BTCPAY_PROTOCOL="https"
export BTCPAYGEN_CRYPTO1="btc"
export BTCPAYGEN_CRYPTO2="xmr"
export BTCPAYGEN_REVERSEPROXY="none"
export BTCPAYGEN_LIGHTNING="none"
export BTCPAYGEN_ADDITIONAL_FRAGMENTS="opt-save-storage-s"
export NOREVERSEPROXY_HTTP_PORT="8080"
```

Run the upstream generator container with Podman (equivalent to `./build.sh` without invoking its embedded CLI names):

```bash
podman pull btcpayserver/docker-compose-generator:latest
podman run --rm \
  -v "$(pwd)/Generated:/app/Generated" \
  -v "$(pwd)/docker-compose-generator/docker-fragments:/app/docker-fragments" \
  -v "$(pwd)/docker-compose-generator/crypto-definitions.json:/app/crypto-definitions.json" \
  -e BTCPAYGEN_CRYPTO1="$BTCPAYGEN_CRYPTO1" \
  -e BTCPAYGEN_CRYPTO2="$BTCPAYGEN_CRYPTO2" \
  -e BTCPAYGEN_REVERSEPROXY="$BTCPAYGEN_REVERSEPROXY" \
  -e BTCPAYGEN_LIGHTNING="$BTCPAYGEN_LIGHTNING" \
  -e BTCPAYGEN_ADDITIONAL_FRAGMENTS="$BTCPAYGEN_ADDITIONAL_FRAGMENTS" \
  btcpayserver/docker-compose-generator:latest
```

Create the runtime environment file beside the compose project (`/var/lib/almapay/.env`):

```ini
BTCPAY_HOST=pay.example.com
BTCPAY_PROTOCOL=https
NBITCOIN_NETWORK=mainnet
NOREVERSEPROXY_HTTP_PORT=8080
BTCPAY_CRYPTOS=btc;xmr
```

Adjust `BTCPAY_CRYPTOS` if you change `BTCPAYGEN_CRYPTO*`. Pull stack images before first boot (`Generated/pull-images.sh` if present, otherwise `podman compose pull`).

Start the stack from the directory containing `.env`:

```bash
cd /var/lib/almapay
podman compose -f btcpayserver-docker/Generated/docker-compose.generated.yml --env-file .env up -d
```

Initial synchronization for Bitcoin (pruned) and Monero can take hours or days. Expect elevated CPU, disk I/O, and memory until nodes catch up.

## Phase 3 — User systemd persistence

Register a user service for `almapay` so the stack survives reboot. As operator:

```bash
sudo -u almapay -H mkdir -p /var/lib/almapay/.config/systemd/user
```

Create `/var/lib/almapay/.config/systemd/user/btcpay.service`:

```ini
[Unit]
Description=BTCPay Server (Podman Compose)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/var/lib/almapay
Environment=XDG_RUNTIME_DIR=/run/user/%U
ExecStart=/usr/bin/podman compose -f btcpayserver-docker/Generated/docker-compose.generated.yml --env-file .env up -d --remove-orphans
ExecStop=/usr/bin/podman compose -f btcpayserver-docker/Generated/docker-compose.generated.yml --env-file .env down
TimeoutStartSec=600

[Install]
WantedBy=default.target
```

Enable it:

```bash
sudo -u almapay -H XDG_RUNTIME_DIR=/run/user/$(id -u almapay) systemctl --user enable --now btcpay.service
```

Confirm with `sudo -u almapay -H podman ps` and a loopback HTTP probe once sync allows (`curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/`).

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

Complete first-time BTCPay registration through the public URL. Configure a Bitcoin wallet per store (hot wallet or watch-only/xpub, per your policy). Monero is configured once at server level: upload view-only wallet and `.keys` files in the Monero settings area. Never upload Monero spend keys.

Monero on BTCPay is server-wide: all stores on one instance share the same Monero wallet configuration. Bitcoin payment methods are per store. Plan multi-store layouts accordingly.

Enable BTC and XMR payment methods on each store after wallets are ready.

## Phase 6 — Plugins (Boltz and Stripe)

Open **Plugins → Manage Plugins** in the BTCPay UI.

Install **Boltz** (BoltzExchange). Restart the stack when prompted (`systemctl --user restart btcpay.service` as `almapay`). Choose **Nodeless** mode during setup unless you later add a local Lightning implementation to the compose file. Follow the plugin wizard to create or import a Liquid wallet, review fees, and optionally configure chain swaps from Liquid BTC to on-chain BTC with a maximum Liquid balance you accept. Enable Lightning as a payment method on each store. Boltz does not support zero-amount invoices.

Install **Stripe Payments** (requires a recent BTCPay Server 2.3.x release). Restart again. Configure Stripe API keys and enabled payment methods separately for each store. Card and wallet UI stays on BTCPay checkout pages.

After plugin changes, always restart through user systemd and verify plugin status in the UI before taking production traffic.

## Phase 7 — Multiple stores

A single BTCPay instance supports many stores. Create distinct stores for production and test workloads. For each store, issue a Greenfield API key with invoice creation and read permissions. Register a webhook URL pointing at the integrating application's public HTTPS endpoint (for example `https://app.example.com/api/webhooks/btcpay` — substitute your application's real path). Save the webhook signing secret the UI displays; verifiers should check the provider signature header on delivery.

Use separate API keys, store IDs, and webhook secrets per store so test invoices cannot settle against production ledgers.

## Phase 8 — Operations

Updates: as `almapay`, pull newer `btcpayserver-docker` git commits, re-run the generator container if fragments changed, `podman compose pull`, then `systemctl --user restart btcpay.service`. Review upstream release notes before major version jumps.

Backups: follow BTCPay backup guidance for PostgreSQL and wallet material. Backup jobs should run as a privileged operator reading `almapay`-owned volumes under `/var/lib/almapay` and rootless Podman volume paths (`podman volume inspect` helps locate mount sources). Test restore on a non-production host.

Disk monitoring is critical on pruned-BTC plus Monero layouts. If space tightens, adjust prune tier (`opt-save-storage-s` vs `opt-save-storage`) only with planning: changing prune fragments requires regenerating compose and resync policy review.

SELinux: Alma enforces SELinux by default. Rootless Podman usually labels volume content correctly; if bind-mounting host paths into containers, use the `:Z` relabel flag on compose volumes or set appropriate `container_file_t` contexts on host directories.

Security hygiene: do not enable BTCPay's optional host SSH integration on this layout. Restrict operator SSH keys. Separate Stripe live and test credentials across stores. Treat Monero view-only keys as confidential.

## RHEL-family notes

Rocky Linux, AlmaLinux, RHEL, and CentOS Stream follow the same pattern: `dnf install podman`, `almapay` system user, rootless compose, user systemd with linger, Caddy on the host. Differences are mainly firewall backend naming and corporate mirror policies. This document uses Alma Linux 9 as the reference platform.

## Honest limitations

This is not an officially supported BTCPay deployment shape. Upstream tests focus on privileged compose with integrated nginx. Rootless Podman, high-port binding, external Caddy, and skipping `btcpay-setup.sh` place integration burden on the operator.

Monero remains one wallet per server*. Boltz nodeless mode routes Lightning through Liquid before optional on-chain settlement. Stripe plugin availability and version pins depend on the BTCPay release channel you deploy.

When in doubt, validate on a test store and test webhook delivery before accepting mainnet funds.

### `*` Monero Multi-Store Issues

Unlike Bitcoin, where each BTCPay store can have its own wallet and address pool, Monero is configured once for the entire server. All stores on the same instance share a single view-only wallet connected to one `monero-wallet-rpc` service. Invoices and settlement records remain per store in BTCPay, but on-chain XMR receipts accumulate in the same underlying wallet regardless of which store enabled the payment method.

If test and production stores must not share Monero funds, disable XMR on the test store, use separate Monero accounts inside one wallet only when the parties are fully trusted, or run a second BTCPay deployment with its own Monero node and wallet. Multi-wallet Monero per store is not supported by the current plugin architecture.

You cannot assign a separate Monero wallet file per store, but you can assign a different Monero account index per store in that store's Monero payment settings (for example account `0` for production and account `1` for test). BTCPay does not let you pin a fixed subaddress to each store; instead it generates a fresh subaddress for every invoice within the store's account. That gives per-store labeling and keeps payer-facing addresses in separate subaddress chains, but all accounts still belong to one wallet and share the same view material on the server.

For administrators, the practical options are: use one account index for all stores when test and prod are the same operator; split test and prod across account indices on one server when you want bookkeeping separation but accept shared wallet custody; disable Monero on non-production stores to avoid mixing test receipts into live XMR balances; or deploy a second BTCPay instance when stores must not share Monero treasury or view-key access at all. Run a current BTCPay and Monero plugin release if you rely on non-default account indices, since older builds had edge cases detecting payments outside account `0`.
