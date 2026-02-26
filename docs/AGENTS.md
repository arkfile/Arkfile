`NOTE: Agents, Agentic Coding Tools & LLMs must read this document to understand how to interact with and assist with this Arkfile project.`

# Arkfile: Overview for Agents

Arkfile is designed as a Privacy-First File Vault over S3. It enables file backup for file owners, with client-side encryption happening via the Web Crypto API in browsers or using the `arkfile-client` CLI tool (which handles both encryption and upload/download in a single streaming operation). It can interface with any number of backend storage systems that are S3 compatible in order to store client-side encrypted files.

It is vital to maintain the Privacy-First design of the app and to preserve and protect user privacy end-to-end in all the work that we do.

We use OPAQUE for authentication, so that passwords are never sent to the server for logging in. (The libopaque C-library via CGO is used on the server side and libopaque WASM is used on the client side in the browser. The Go CLI utils like `arkfile-client` use libopaque C-library via CGO as well.)

We use client-side encryption to ensure that file data is never sent to the server until and unless it is encrypted with a strong password.

We use client-side encryption to encrypt file metadata as well, including the original filename, size and the original sha256 digest of the original file.

We never log IP addresses or any PII of users or visitors to the app/site. (e.g. Visitor IP addresses are not logged and are obfuscated with HMAC to form an EntityID for select areas that need rate-limiting, such as to protect against shared file URL enumeration type attacks.)

The server must know nothing about the nature of the data belonging to clients, nor about their passwords, nor visitor IPs.

When users (file owners) choose to share files with others (anonymous recipients), they encrypt information about the file along with a file download token and a file encryption key all wrapped up into a share envelope that is uploaded to the server in encrypted form, so that again the server learns nothing of the files or their contents. Anonymous recipients of shared files need only the Share URL and Share Password in order access the share envelope, decrypt metadata about the file, and download and decrypt it client-side. The file sharing aspect of Arkfile does not require or collect any identifying information about the recipients (no account required to access shared files).

## Greenfield App

There are no current deployments of this app anywhere at present. No need to build in "backwards compatibility" at this stage when refactoring. The focus at this stage is on fixing and proving the correct implementation of the system as it is designed and intended. Be wary and flag it to the developers anytime you come across deprecated/disabled/stub/bad/backwards-compatibility functions or comments, or any technical debt that could make it harder to work with this codebase in the future.

## Function Review Sanity Checks

As you are implementing, updating or reviewing existing functions, go through the following mental checklist:

- Is this function required?
- Is it implemented in a standard and secure way?
- Is it merely a stub function or otherwise incomplete?
- Is it well placed, in the right file or area of the app?
- Does it require additional review, updates, moving or potentially deletion?
- Does it align with the vision and intended design of the app as being privacy-preserving for users end-to-end?

## Key Tools for Development

In order to slowly build up the core functionality of the system and prove its correct and secure implementation, the following tools are critical to use, improve upon and maintain:

- `sudo bash /scripts/dev-reset.sh` - This tool peforms a full recompilation of the app, including static-linking of OPAQUE Auth libraries, and redeploys the app and starts app services, including the local S3 storage server (current: MinIO; future: SeaweedFS) used for testing and rqlite for the database. We should use `dev-reset.sh` every time we make a change to the app itself, in order to redeploy it consistently. Do not attempt to rebuild the app using any other build scripts or manual compilation commands, including for the CLI utils written in Go. `dev-reset.sh` does all of this for you. Use it every time. If attempting to recompile typescript assets, use `bun` or `bunx` instead of `npm`/`pnpm`/`npx`/etc.

- `sudo bash /scripts/testing/e2e-test.sh` - This is the main testing script used for proving out the correct implementation and functionality of the system via in-depth, end-to-end testing of all critical app functions using a combination of `curl` and `arkfile-client`. This script is the main way that we demonstrate that the app does what it is designed to do right now. `e2e-test.sh` must not be used immediately after changes have been made to the app itself; instead use `dev-reset.sh` first, then run the test script.

## Key Configurations & Constants

Certain parameters, constants and variables are used throughout the codebase in frontend, Go CLI utils and server backend. As much as possible, these should be unified and read from common sources (such as dedicated API endpoints). Examples of existing params, constants and config files in this category are:

- crypto/argon2id-params.json: defines argon2id parameters to use for key derivation across all clients
- crypto/chunking-params.json: defines chunk size and key types used in chunking/streaming/encryption
- crypto/password-requirements.json: defines password complexity, strength and character requirements to use for various password types (account login password, account file encryption key, custom file encryption key, and share passwords).

## Using Git

Do not add files to commit, nor create any commits yourself at any time. This is up to the developers. Encourage saving progress during large projects, but DO NOT COMMIT or PUSH code to git at any time by yourself.

## No Emojis

No emojis in any code, documentation, or responses please. If needed, instead of '❌' you can use use '[X]'. Instead of '✅' use '[OK]'. Instead of '⚠️' use '[!]'. Instead of '🎉'/'🚀'/other celebratory emojis, use 'SUCCESS!' or something to that effect. 

## Comment/Log/Print Formatting

No "===" or "---" characters for formatting in log/print statements or comments please. Keep comments short and concise and focused on the intended or established functionality of the app in its ideal form. (NOTE: If you find yourself beginning to write something to the effect of "keeping this for backwards compatibility" or "keep this as a fallback" stop and immediately flag this to the developers. Refer to 'Greenfield App' and 'Function Review Sanity Checks' sections for more information.)

## Honesty and Transparency

Aim for honesty and transparency in all your work, share your full thinking including criticisms with the developers. Do not attempt to hide or sweep anything under the rug, especially if it concerns potential privacy and security gaps that exist or may be introduced by current work or during refactors. 

## REPEAT: Greenfield App

There are no current deployments of this app anywhere at present. No need to build in "backwards compatibility" at this stage when refactoring. The focus at this stage is on fixing and proving the correct implementation of the system as it is designed and intended. Be wary and flag it to the developers anytime you come across deprecated/disabled/stub/bad/backwards-compatibility functions or comments, or any technical debt that could make it harder to work with this codebase in the future.
