# Arkfile

*Private File Vault over S3*

## What Is Arkfile?

Arkfile is an open-source service that lets you store and share files while keeping them private.

Before any file leaves your computer it is **encrypted**, so the Arkfile server never sees your data.

Because of this privacy-first design, only you – and anyone with whom you choose to share – can access and open your files.

## Why People Use It

1. **Privacy-first** – files are encrypted on your device.  
2. **Share safely** – you can create sharing links with share passwords for friends or co-workers without giving them your main password.
3. **Multi-factor security** – Time-based One-Time Passwords (TOTP authentication) or Hardware Security Keys (Yubikey, Nitrokey) are used to provide two-factor protection for all accounts.
4. **Pick your storage** – use the built-in SeaweedFS server for single-node or self-hosted cluster deployments, or point Arkfile at Amazon S3, Backblaze B2, Wasabi, Vultr Object Storage, and other S3-compatible storage back-ends.
5. **Runs anywhere** – one binary, no external database. (Arkfile uses the lightweight rqlite engine under the hood.)  
6. **Offline backup & recovery** – export encrypted `.arkbackup` bundles and decrypt them offline with `arkfile-client`, no server needed.
7. **Open source** – anyone can inspect or improve the code.

## Who Uses Arkfile

Arkfile is for people who want cloud backup and secure sharing without giving the server readable files or their login password. Six common situations:

**Personal vault.** Keep personal copies of work or life documents (reviews, taxes, medical records) encrypted off your laptop, separate from employer Google Drive or iCloud.

**Professional archive.** Lawyers, journalists, and caseworkers store client or source material under client-side encryption, then share a single file via link and share password without handing over vault access.

**Cross-border life records.** Migrants, expats, and travelers keep IDs and vital documents in a pseudonymous account (no email required) and retrieve them on a new device after loss or confiscation.

**Insider preservation.** Whistleblowers and investigators keep encrypted copies outside employer systems and disclose selectively using share links, optionally with a separate password on the most sensitive files.

**Self-hosted custody.** NGOs, newsrooms, and teams run their own instance over their choice of S3-compatible storage backends so users trust their operator, region, and storage policy -- not a distant SaaS vendor.

**Password-only handoff.** Recipients download and decrypt with a share URL and share password only; no account signup, no recipient email on file.

## Local Dev Test Quick Start

```bash
sudo ./scripts/dev-reset.sh
```

The script will:

* Install all dependencies
* Set up arkfile system user
* Start a local SeaweedFS bucket  
* Start a single-node rqlite database  
* Start arkfile app
* Create arkfile-dev-admin user

## Key Concepts (Glossary)

- **Privacy-First:** The server never learns your files or passwords because everything is encrypted before upload.
- **Encryption (AES-256-GCM):** A modern algorithm that scrambles data and checks its integrity at the same time.
- **OPAQUE:** A password authentication protocol where the server never sees your password in any form, with built-in validation to ensure strong password security.
- **TOTP:** Time-based One-Time Password - generates temporary codes on your phone for extra security.
- **rqlite:** A small database that keeps data in sync across nodes without extra setup.
- **SeaweedFS:** An open-source S3-compatible storage server that works as a single node or in a cluster.
- **S3-type Storage Backends:** Any number of redundant data backup solutions that use erasure coding to ensure extremely high availability of your data.

## Need More Details?

* **User FAQ** - see `docs/user-faw.md`
* **Deployment & Ops Guide** – see `docs/setup.md`  
* **API Reference** – see `docs/api.md`  
* **Security Architecture** – see `docs/security.md`
* **Privacy** - see `docs/privacy.md`

---

## Support

Questions, comments or bug reports? Email **arkfile [at] pm [dot] me** / **arkfile [at] tutanota [dot] com** or open an issue on GitHub.  

Please avoid posting sensitive information in public issues.

---

## Donate

If you wish to contribute to development efforts, please consider making a donation:

- Bitcoin (On-chain): < contact via email for a one-time donation address >
- Bitcoin (Lightning): arkfile@coinos.io
- Monero (XMR): 8AhcDfG55P5N1pacyB9QoNTYrVGEUsgYnSrvXyHoxc2iWi6M7s4cdWHHXNu6rSjf5jYQ5hGAoR5eo75pRqPAK6hjL4jNMX6

---

*make yourself an ark of cypress wood*
