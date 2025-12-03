# deSEC + Caddy Integration Guide

## Overview

This guide details how to integrate **deSEC** (a secure, free DNS provider) with **Caddy** for the Arkfile project. This setup enables **DNS-01 challenges**, allowing for:
1.  **Wildcard Certificates** (e.g., `*.arkfile.net`).
2.  **Private Networking**: Obtaining valid certificates for servers that are not exposed to the public internet on port 80.
3.  **Enhanced Security**: Decoupling certificate validation from HTTP reachability.

## Prerequisites

1.  A **deSEC** account (free at [desec.io](https://desec.io)).
2.  A domain configured to use deSEC's nameservers.
3.  An API Token from deSEC.

## 1. The Challenge: Custom Caddy Build

The standard `caddy:alpine` image does **not** include the `caddy-dns/desec` module required for this integration. We must build a custom image.

We will use a **multi-stage Dockerfile** to build a custom Caddy binary and then place it into a minimal Alpine container, adhering to the project's "minimal footprint" philosophy.

### Dockerfile.caddy

Create a new file named `Dockerfile.caddy` in the project root:

```dockerfile
# --- Stage 1: Builder ---
FROM caddy:builder-alpine AS builder

# Build Caddy with the deSEC DNS module
RUN xcaddy build \
    --with github.com/caddy-dns/desec

# --- Stage 2: Final ---
FROM caddy:alpine

# Copy the custom binary from the builder stage
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

## 2. Configuration

### Caddyfile

Update your `Caddyfile` to use the `acme_dns` directive. This tells Caddy to use the deSEC API for solving challenges.

```caddy
{
    # Global ACME DNS configuration
    acme_dns desec {
        token {$DESEC_TOKEN}
    }
}

arkfile.net {
    # Explicitly use the DNS challenge (optional if global is set, but good for clarity)
    tls {
        dns desec {
            token {$DESEC_TOKEN}
        }
    }

    reverse_proxy arkfile:8080
}
```

### Environment Variables

You must provide the `DESEC_TOKEN` to the Caddy container.

## 3. Integration with Podman/Compose

Update your `compose.yaml` to build the custom Caddy image instead of pulling the upstream one.

```yaml
services:
  caddy:
    build:
      context: .
      dockerfile: Dockerfile.caddy
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp" # HTTP/3
    environment:
      - DESEC_TOKEN=${DESEC_TOKEN} # Pass the token from host env or .env file
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - arkfile_net
    restart: always
```

## 4. Security Considerations

*   **Token Protection**: The `DESEC_TOKEN` has full control over your DNS records. Treat it as a high-value secret. Do not commit it to version control.
*   **Least Privilege**: Currently, deSEC tokens have global access to your account. Ensure you are using a dedicated account or are aware of the scope.
*   **Container Security**: The custom build process uses `caddy:builder-alpine` which is a temporary build stage. The final image is based on `caddy:alpine`, maintaining the small attack surface.

## 5. Migration Steps

1.  **Create Token**: Generate a new token in the deSEC dashboard.
2.  **Create Dockerfile**: Add `Dockerfile.caddy`.
3.  **Update Compose**: Modify `compose.yaml` to build the custom image.
4.  **Update Caddyfile**: Add the `acme_dns` configuration.
5.  **Deploy**:
    ```bash
    export DESEC_TOKEN="your-token-here"
    podman-compose up -d --build
