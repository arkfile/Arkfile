`NOTE: Agents, Agentic Coding Tools & LLMs must read this document to understand how to interact with and assist with this Arkfile project.`

# Arkfile: Overview for Agents

Arkfile is designed as a Privacy-First File Vault over S3. It enables file backup for file owners, with client-side encryption happening via the Web Crypto API in browsers or using the `cryptocli` tool on the command-line (prior to uploading with `arkfile-client` to the server). It uses Minio as a gateway to interface with any number of backend storage systems that are S3 compatible in order to store client-side encrypted files.

It is vital to maintain the Privacy-First design of the app and to preserve and protect user privacy end-to-end in all the work that we do.

We use OPAQUE for authentication, so that passwords are never sent to the server for logging in. libopaque C-library via CGO is used on the server side and libopaque WASM is used on the client side.

We use client-side encryption to ensure that file data is never sent to the server until and unless it is encrypted with a strong password.

We use client-side encryption to encrypt file metadata as well, including the original filename and the original sha256 digest of the original file.

We never log IP addresses or any PII of users or visitors to the app/site. (e.g. visitor IP addresses are not logged and are obfuscated with HMAC to form an EntityID for select areas that need rate-limiting, such as to protect against shared file URL enumeration type attacks.)

The server must know nothing about the nature of the data belonging to clients, nor about their passwords, nor visitor IPs.

## Greenfield App

There are no current deployments of this app anywhere at present. No need to build in "backwards compatibility" at this stage when refactoring. The focus at this stage is on fixing and proving the correct implementation of the system as it is designed and intended. Be wary and flag it to the dev anytime you come across deprecated/disabled/stub/bad/backwards-compatibility functions or comments, or any technical debt that could make it hard to work with this codebase in the future.

## Function Review Sanity Checks

- Is this function required?
- Is it implemented in a standard and secure way?
- Is it merely a stub function or otherwise incomplete?
- Is it well placed, in the right file or area of the app?
- Does it require additional review, updates, moving or potentially deletion?
- Does it align with the vision and intended design of the app as being privacy preserving for users end-to-end?

## Key Tools for Development

In order to slowly build up the core functionality of the system and prove its correct and secure implementation, the following tools are critical to use, improve upon and maintain:

- `sudo bash /scripts/dev-reset.sh` - This tool peforms a full recompilation of the app, including static-linking of OPAQUE Auth libraries, and redeploys the app and starts app services, including the local Minio server used for testing and rqlite for the database. We should use `dev-reset.sh` every time we make a change to the app itself, in order to redeploy it consistently. Do not attempt to rebuild the app using any other build scripts or manual compilation commands, including for the CLI utils written in Go. `dev-reset.sh` does all of this for you. Use it every time.

- `sudo bash /scripts/testing/e2e-test.sh` - This is the main testing script used for proving out the correct implementation and functionality of the system via in-depth, end-to-end testing of all critical app functions using a combination of `curl` and `arkfile-client` and `cryptocli`. This script is the main way that we demonstrate that the app does what it is designed to do right now. `e2e-test.sh` must not be used immediately after changes have been made to the app itself; instead use `dev-reset.sh` first, then run the test script.

## No Emojis

No emojis in any code, documentation, or responses please. If needed, instead of '❌' you can use use '[X]'. Instead of '✅' use '[OK]'. Instead of '⚠️' use '[!]'. Instead of '🎉'/'🚀'/other celebratory emojis, use 'SUCCESS!' or something to that effect. Also, no "===" characters for formatting in log/print statements please.