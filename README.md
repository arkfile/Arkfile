# Arkfile

*s3-style encrypted file sharing and backup*

## 1. What Is Arkfile?

Arkfile is an open-source service that lets you store and share files while keeping them private.  
Before any file leaves your computer it is **encrypted**, so the Arkfile server never sees the readable version or your secret keys.  
Because of this “zero-knowledge” design, only you – and anyone you choose to share a special key with – can open your files.

## 2. Why People Use It

1. **Privacy first** – files are encrypted on your device.  
2. **Share safely** – you can create extra “one-time” keys for friends or co-workers without giving them your main password.  
3. **Pick your storage** – use the built-in MinIO server for quick tests or point Arkfile at Backblaze B2, Wasabi, Vultr Object Storage, and other S3-compatible back-ends.  
4. **Runs anywhere** – one binary, no external database. (Arkfile uses the lightweight rqlite engine under the hood.)  
5. **Open source** – anyone can inspect or improve the code.

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

| Term | Plain-English Meaning |
|------|-----------------------|
| **Zero-knowledge** | The server never learns your files or passwords because everything is encrypted before upload. |
| **Encryption (AES-256-GCM)** | A modern algorithm that scrambles data and checks its integrity at the same time. |
| **Argon2id** | A “memory-hard” function that turns your password into a strong key and slows down attackers. |
| **OPAQUE** | A login method where the server never sees your password, even in scrambled form. |
| **rqlite** | A small database that keeps data in sync across nodes without extra setup. |
| **MinIO** | An open-source S3-compatible storage server that works as a single node or in a cluster. |

## 5. Need More Details?

* **Deployment & Ops Guide** – see `docs/setup.md`  
* **API Reference** – see `docs/api.md`  
* **Security Architecture** – see `docs/security.md`

---

## Support

Questions or bug reports?  
Email **arkfile [at] pm [dot] me** or open an issue on GitHub.  
Please avoid posting sensitive information in public issues.

---

*make yourself an ark of cypress wood*
