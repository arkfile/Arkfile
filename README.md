# Arkfile

*s3-style encrypted file sharing and backup*

## What is Arkfile?

Arkfile is an open-source file storage and sharing platform that uses zero-knowledge encryption. Zero-knowledge means that files are encrypted on your device before being uploaded, so the server never has access to your unencrypted data or encryption keys. This ensures that your files remain private even from the service provider.

Encrypted files are then stored on any one of the multiple S3-type storage backends supported, such as Backblaze B2, Wasabi, Vultr Object Storage, or a self-hosted MinIO instance. All of the storage backends provide redundancy across multiple drives and geographic locations for high data availability.

Arkfile includes a multi-key system that allows you to create additional decryption keys for specific files. This enables secure file sharing without revealing your primary password. You can generate sharing links with independent passwords, set expiration dates, and add password hints while avoiding file duplication.

The platform is open-source to allow security audits and customization. It supports distributed deployments for organizations requiring scalable file storage and sharing capabilities.

## Quick Start

**Want to try Arkfile immediately?** Run this single command:

```bash
./scripts/quick-start.sh
```

This will set up a complete working Arkfile system with:
- Local MinIO storage
- Single-node rqlite database  
- Web interface at http://localhost:8080

**For production deployment**, see the detailed guides below:

- **[Setup Guide](docs/setup.md)**: Complete administrator installation guide
- **[Security Details](docs/security.md)**: Cryptographic design and security architecture
- **[API Reference](docs/api.md)**: Developer integration documentation

## For System Administrators

### 🆕 New to Arkfile?
**[📖 Newcomer Guide](docs/newcomer-guide.md)** - Which script should I run?

### Essential Scripts (Start Here)
- `./scripts/quick-start.sh` - **One-command setup** for testing/development
- `./scripts/setup-foundation.sh` - Set up users, directories, and keys only
- `./scripts/integration-test.sh` - Full system testing (choose COMPLETE mode)
- `./scripts/health-check.sh` - Verify system health

### All Available Scripts
For a complete list of available setup and maintenance scripts, see [scripts/README.md](scripts/README.md).

## Support & Security

For questions, comments or support, either file an issue on GitHub, or during the alpha testing stage, you can email `arkfile [at] pm [dot] me`.

For security-related issues, please email first and allow time for a review of the findings before creating a public GitHub issue.

(Do not include sensitive or personal information in any public GitHub issue.)

---

*make yourself an ark of cypress wood*
