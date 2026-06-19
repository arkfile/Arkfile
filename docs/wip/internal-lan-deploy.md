# Internal LAN Production Deployment (Trusted TLS on a Private Network)

## Status

Draft planning document. No code has been written for this profile yet. This captures the problem, the proposed path forward, and the set of decisions we need to make before an "internal LAN prod deploy" script could be considered truly reliable.

## Background: The Problem

While testing the browser frontend after a `dev-reset.sh`, registration of a new user failed and the console reported a service worker registration failure. Two distinct issues surfaced. The first was a Trusted Types error blocking service worker registration up front, which we fixed by adding a `createScriptURL` callback to the default Trusted Types policy in `client/static/js/src/app.ts` (it previously only defined `createHTML`). The second was a 403 on the anonymous registration endpoint caused by a stale full-tier session cookie left in the browser from before the reset; we fixed that by exempting the anonymous OPAQUE register/login, admin login, and bootstrap endpoints from the CSRF middleware in `handlers/middleware.go`, since those endpoints establish a brand-new session and must never be gated by a pre-existing cookie.

With both of those resolved, registration works, but a third message remains in the browser console on dev and local deployments:

```
[arkfile-sw] SW registration failed: SecurityError: Failed to register a ServiceWorker for scope ('https://localhost:8443/') with script ('https://localhost:8443/sw-download.js'): An SSL certificate error occurred when fetching the script.
```

This is not a code bug. It is a direct consequence of serving the app over a self-signed certificate. Browsers will register a service worker only when the script is served over a certificate that chains to a Certificate Authority the device already trusts. Clicking through the browser's certificate warning lets a top-level page load proceed, but that one-time bypass does not extend to service worker script fetches, which are held to strict certificate validation. The streaming-download service worker therefore cannot register over a self-signed cert.

The functional impact is narrow but real. The service worker exists to stream very large downloads (greater than roughly 2 GB on Chromium) straight to the browser's download manager rather than buffering them in memory. When it is unavailable, large downloads fall back to the in-memory path, which is exactly the scenario that hurts memory-constrained devices. Per the project's guiding use case (a mobile device with limited RAM downloading a multi-gigabyte file), this fallback matters for any deployment that real users rely on.

## Where This Bites: Deployment Matrix

The browser only ever talks to the front door of a deployment, so what matters is the certificate presented there.

`dev-reset.sh` serves Arkfile's own self-signed TLS directly at `https://localhost:8443`. The browser sees a self-signed cert, so the service worker fails to register. This is acceptable for a development iteration loop.

`local-deploy.sh` is explicitly "no Caddy" and also has Arkfile serve its own self-signed TLS directly to the browser, on `localhost` and on the LAN IP. The browser hits the self-signed cert directly, so the service worker fails to register in the same way. This is the case we want to improve for real local and LAN usage.

`test-deploy.sh` and `prod-deploy.sh` put Caddy in front and terminate public TLS with a genuine Let's Encrypt certificate obtained over the DNS-01 challenge via deSEC. The browser sees a publicly-trusted certificate, so the service worker registers cleanly. Caddy then reverse-proxies to Arkfile's internal self-signed TLS on `localhost:8443`, a server-to-server hop where Caddy explicitly trusts the internal CA via `tls_trusted_ca_certs`. The browser never sees the internal cert. These deployments are unaffected.

So the gap is precisely the local and LAN case: a privately-reachable server where we still want a browser-trusted certificate.

## Approaches Considered and Rejected

Modifying client trust stores is rejected as a default behavior. We could have the deploy script install the generated CA into the operating system and browser trust databases on the deploying machine, and document a manual import for other LAN devices. We are explicitly choosing not to have our scripts manipulate other systems' OS or browser trust stores. It is invasive, fragile across browser packaging (Snap, Flatpak, per-profile Firefox databases), and the multi-device case cannot be automated anyway. It may be insecure as well unless there is a strict whitelist of allowed domains tied to said CA.

Serving plain HTTP is rejected. While `http://localhost` is a secure context where service workers function, LAN access by IP over HTTP is not a secure context, which would break the Web Crypto API, OPAQUE, and the service worker for exactly the LAN devices we care about.

Self-signed certificates with broader SANs do not help. The certificate generated by `scripts/setup/04-setup-tls-certs.sh` already carries correct SANs for `localhost`, `127.0.0.1`, `::1`, and any LAN IPs supplied to `local-deploy.sh`. The certificate is valid for those names and addresses; it is simply not trusted, and adding more SANs does not change that.

## Proposed Path Forward: Caddy with DNS-01 for an Internal Domain

The cleanest way to obtain a browser-trusted certificate on a private network, without touching any device's trust store, is to reuse the mechanism the production path already relies on: Caddy obtaining a Let's Encrypt certificate over the DNS-01 challenge via deSEC.

The enabling property is that DNS-01 decouples certificate issuance from inbound reachability. Caddy proves control of the domain by having the deSEC API publish a TXT record; the public CA never connects to the server. The server therefore needs only outbound internet access to the ACME and deSEC APIs. It does not need to be publicly reachable, and the domain's address records do not need to point at a public address.

The deployment shape would be: own a real registered domain or subdomain (for example `vault.example.net`), arrange for LAN devices to resolve that name to the server's private LAN IP, and let Caddy obtain and auto-renew a genuine Let's Encrypt certificate for that name over DNS-01. LAN devices connect to the domain over the local network, Caddy presents a publicly-trusted certificate, the service worker registers, and nothing is installed on any client. This is effectively the existing `prod-deploy.sh` with its public-VPS assumptions removed and its firewall posture scoped to the LAN.

## What Differs From the Existing Production Path

The existing `prod-deploy.sh` carries assumptions that are correct for a public VPS but wrong for a private network. The most significant is the hard check that compares the domain's public A record against the server's detected public IP and aborts on mismatch. For a LAN deployment the A record points at a private IP, so that check would always fail and must be removed or replaced with a check that the domain resolves to the server's LAN IP. The firewall step currently opens ports 80 and 443 to the world; on a LAN it should be scoped to the local subnet, and port 80 is not required at all because DNS-01 does not use HTTP-01 (port 80 only matters if we want an HTTP to HTTPS redirect). The various reachability checks and the HTTP redirect that assume inbound internet are unnecessary. Everything else carries over: building Caddy with the deSEC module, rendering the Caddyfile, and reverse-proxying to Arkfile's internal TLS on `localhost:8443` with the internal CA trusted.

## Decisions Required for a Reliable Internal LAN Deploy

### Name resolution strategy on the LAN

This is the single most important decision because it determines whether the deployment "just works" for clients. There are two viable models.

The first is a public address record pointing to a private IP: publish an A or AAAA record at the registrar/deSEC zone that resolves the chosen name to the server's LAN IP. The drawback is DNS rebinding protection, which many home routers and some resolvers apply by refusing to return RFC1918 private addresses for public names. Where rebind protection is active, clients cannot resolve the name even though the certificate is valid. Mitigation is to disable rebind protection or to whitelist the single domain on the router or resolver.

The second is split-horizon DNS: run a local resolver (the router, Pi-hole, or dnsmasq) that answers the chosen name with the LAN IP for devices on the network, while the public deSEC zone exists solely so Caddy can write the ACME TXT records during issuance and renewal. This avoids rebind filtering entirely and keeps the private IP out of public DNS. The cost is that the operator must run and configure a local resolver.

We need to decide which model the script targets by default, whether it supports both, and how much of the resolver configuration (if any) the script should attempt versus document as a prerequisite.

### Domain ownership and DNS provider

The approach requires a real domain whose DNS can be driven programmatically for DNS-01. Today that is deSEC, which the production scripts already integrate. We need to decide whether the internal LAN profile is deSEC-only (simplest, matches existing code) or whether it should support other DNS providers, which would mean building Caddy with additional caddy-dns modules and parameterizing the Caddyfile and token handling accordingly.

### How the server learns its LAN IP and bind posture

We need to decide how the LAN IP is determined: auto-detected (as `local-deploy.sh` already does), required as an explicit flag, or both with the flag overriding detection. Related is whether Caddy binds on all interfaces or only the LAN interface, and which ports it listens on (443 only, or also 80 for redirects), and how Arkfile itself binds behind Caddy.

### Firewall scoping

We need to decide whether the script configures the local firewall to allow the relevant ports only from the LAN subnet, leaves the firewall untouched and documents the expectation, or offers an explicit confirmation flag analogous to the existing `--external-firewall-confirmed`. The production default of opening 443 to the world is not appropriate here.

### Certificate renewal and outbound connectivity

DNS-01 renewal requires ongoing outbound access from the server to the ACME and deSEC APIs. We need to confirm this is an explicit, documented requirement, decide how renewal failures are surfaced (Caddy handles renewal automatically, but operators on isolated networks need to understand that a fully air-gapped LAN cannot use this approach), and decide whether the script validates outbound connectivity to those endpoints at deploy time.

### Application configuration for an internal domain

We need to confirm what `ARKFILE_DOMAIN`, `BASE_URL`, and `CORS_ALLOWED_ORIGINS` should be set to for the internal domain, and verify there are no lingering assumptions of `localhost`. We also need to confirm the OPAQUE server identity (`idS`) behavior: all OPAQUE participants must bind the same server identity into the protocol transcript, so the value the browser and any CLI clients fetch from the server identity config endpoint must be consistent and correct for the chosen internal domain. A mismatch here would break authentication rather than merely TLS.

### Access by name versus by IP

With this model, clients must reach the service by the domain name; hitting the raw LAN IP would still produce a certificate error because the certificate is issued for the name, not the address. We need to decide whether to document this clearly, whether to redirect or reject IP-based access, and how the deploy summary communicates the correct URL to users.

### Relationship to existing scripts

We need to decide whether this becomes a separate script (for example `lan-deploy.sh`) or a mode/flag on the existing production script (for example `--internal` with an explicit private IP). A separate script duplicates logic but keeps the public production path clean and unambiguous; a flag avoids duplication but risks conflating two deployment postures with different security assumptions. We should also decide the corresponding update path (analogous to `prod-update.sh`) so code changes can be applied to a running internal LAN instance without re-bootstrapping.

### Multi-instance and certificate naming

If more than one internal instance is expected (for example several machines on the same LAN), we need to decide on a naming scheme (distinct subdomains per host) and whether wildcards via DNS-01 are desirable, since DNS-01 supports wildcard issuance.

## Scope Note

None of this changes the privacy or security model of the application. It only changes how a private deployment presents a browser-trusted certificate so that the streaming-download service worker can function for LAN clients. The two frontend and middleware fixes that motivated this investigation (the Trusted Types `createScriptURL` policy and the CSRF exemption for anonymous auth endpoints) are already in place and are independent of whichever path we choose here.
