# Arkfile

*Private File Vault over S3*

## 1. What Is Arkfile?

Arkfile is an open-source service that lets you store and share files while keeping them private.

Before any file leaves your computer it is **encrypted**, so the Arkfile server never sees your data.

Because of this privacy-first design, only you – and anyone with whom you choose to share – can access and open your files.

## 2. Why People Use It

1. **Privacy first** – files are encrypted on your device.  
2. **Share safely** – you can create sharing links with share passwords for friends or co-workers without giving them your main password.
3. **Multi-factor security** – Time-based One-Time Passwords (TOTP authentication) is used to provide two-factor protection for all accounts.
4. **Pick your storage** – use the built-in MinIO server for single-node or self-hosted cluster deployments, or point Arkfile at Amazon S3, Backblaze B2, Wasabi, Vultr Object Storage, and other S3-compatible storage back-ends.
5. **Runs anywhere** – one binary, no external database. (Arkfile uses the lightweight rqlite engine under the hood.)  
6. **Open source** – anyone can inspect or improve the code.

## 3. One-Minute Quick Start

```bash
./scripts/quick-start.sh
```

The script will:

* Start a local MinIO bucket  
* Start a single-node rqlite database  
* Launch the web UI at http://localhost:8080

Once it finishes, open the URL and create your first account.

## 4. Key Concepts (Glossary)

- **Privacy-First:** The server never learns your files or passwords because everything is encrypted before upload.
- **Encryption (AES-256-GCM):** A modern algorithm that scrambles data and checks its integrity at the same time.
- **OPAQUE:** A password authentication protocol where the server never sees your password in any form, with built-in validation to ensure strong password security.
- **TOTP:** Time-based One-Time Password - generates temporary codes on your phone for extra security.
- **rqlite:** A small database that keeps data in sync across nodes without extra setup.
- **MinIO:** An open-source S3-compatible storage server that works as a single node or in a cluster.
- **S3-type Storage Backends:** Any number of redundant data backup solutions that use erasure coding to ensure extremely high availability of your data.

## 5. Need More Details?

* **Deployment & Ops Guide** – see `docs/setup.md`  
* **API Reference** – see `docs/api.md`  
* **Security Architecture** – see `docs/security.md`
* **Privacy** - see `docs/privacy.md`

---

## Support

Questions, comments or bug reports? Email **arkfile [at] pm [dot] me** or open an issue on GitHub.  

Please avoid posting sensitive information in public issues.

---

*make yourself an ark of cypress wood*
