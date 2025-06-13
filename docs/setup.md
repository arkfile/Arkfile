# Arkfile Setup Guide

This guide provides comprehensive instructions for system administrators to install, configure, and manage the Arkfile application. It covers everything from initial setup to ongoing maintenance, ensuring a secure and reliable deployment.

## High-Level Architecture

Arkfile’s architecture is composed of a client-side interface, a server-side application, and external services for storage and security. The client-side component is a web interface that uses a WebAssembly (WASM) module for in-browser encryption and decryption. The server-side is a Go application built on the Echo framework, responsible for handling user authentication, managing metadata, and interfacing with storage backends. External services include an S3-compatible object storage provider, a distributed rqlite database cluster for metadata, and a Caddy web server for TLS and reverse proxying.

## Directory Structure and Service Users

For security and organization, Arkfile uses a standardized directory structure and dedicated service users. The main application directory is located at `/opt/arkfile/`, which contains subdirectories for binaries, configuration files, application data, logs, and versioned releases. The system operates with the `arkadmin` user for management, `arkprod` and `arktest` for running the application in different environments, and the `arkfile` group. This separation helps to enforce the principle of least privilege and isolates the application's resources.

## Initial Setup

Before deploying the application, several setup scripts must be run to prepare the environment. The `scripts/setup-users.sh` and `scripts/setup-directories.sh` scripts create the necessary user accounts and directory structure. The `scripts/setup-rqlite.sh` script sets up the distributed database cluster, and `scripts/setup-minio.sh` configures the local or cluster storage if you are not using an external provider. These scripts are designed to be run once to initialize the system.

## Configuration

Environment-specific configuration is stored in `/opt/arkfile/etc/<env>/secrets.env`. This file contains sensitive information such as API keys, database credentials, and JWT secrets.

### Storage Provider Configuration

You must configure a storage provider for Arkfile to use. The supported providers are `backblaze`, `wasabi`, `vultr`, `local`, and `cluster`. For external S3-compatible providers, you will need to provide the endpoint, region, access key, secret key, and bucket name. For a local MinIO instance (`local`), you must specify the `LOCAL_STORAGE_PATH`. For a distributed MinIO setup (`cluster`), you need to define the `MINIO_CLUSTER_NODES`, access key, and secret key.

### Database Configuration

The `RQLITE_NODES` variable should contain a comma-separated list of the rqlite nodes in your cluster. You also need to provide the `RQLITE_USERNAME` and `RQLITE_PASSWORD` for authentication.

### Other Configuration

Other important settings include the `JWT_SECRET` for signing authentication tokens, `VULTR_API_KEY` if you are using Vultr for DNS challenges with Caddy, the `PROD_PORT` and `TEST_PORT` for the application to run on, and a `CADDY_EMAIL` for TLS certificate registration.

## Build and Deployment

The application is built using the `./scripts/build.sh` script, which compiles the Go code and prepares it for deployment. Deployments are handled by the `./scripts/deploy.sh` script, which takes an environment (`prod` or `test`) as an argument. This script creates a timestamped release, links it as the current version, and restarts the service, allowing for zero-downtime deployments. The system retains the last five releases, making it easy to roll back to a previous version using the `./scripts/rollback.sh` script if needed.

## Monitoring and Maintenance

The application and its dependencies are managed as systemd services. You can check the status of the `arkfile`, `rqlite`, and `minio` services using `systemctl status`. Logs can be viewed in real-time using `journalctl -u <service-name> -f`. The release management system automatically cleans up old releases, and the distributed nature of rqlite provides for automatic database failover and recovery.
