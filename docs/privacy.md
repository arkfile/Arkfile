# Arkfile Privacy Overview

This document explains, in plain language, how Arkfile keeps user data private.

## 1. Privacy-First Philosophy

Arkfile is designed so the server never sees unencrypted file contents or user passwords.

Filenames, plaintext content hashes, custom-password hints, and owner tags are encrypted on the client before upload. The server does see operational fields it needs to run the service, including username, encrypted file length, chunk layout, and public key-derivation salts. Those fields are listed in `docs/security.md`.

## 2. Password Protection

Arkfile uses different password protection approaches depending on the type of access:

**Account Password for Authentication** uses the **OPAQUE** protocol so that, in an authentic client, the password is not placed in protocol messages. A password-authenticated key exchange is performed in a multi-step process for registration and login. The Account Password is also used separately to derive an **Account Key** which is the default means of encrypting user files. This Account Key is never sent to the server either. A replaced browser client can capture the password before OPAQUE runs. See the closing note and `docs/security.md`.

**Custom File Encryption Passwords** are separate passwords that can be used to encrypt files client-side if you choose not to use the default Account Key generated after registration. Both Account Passwords and Custom File Encryption Passwords use Argon2id for key derivation and require 15+ characters with at least 2 character classes for security.

**Share Passwords** are used when sharing previously uploaded files with others. These also use Argon2id for key derivation, but require 20+ characters with at least 2 character classes for the encryption of the Share Envelope and File Encryption Key, which grant access to users with the proper sharing link and password.

Again, none of the user passwords or private keys are ever sent to the server in raw form. It is still important for you as a user to use strong passwords, however. (Something like `H@ck3rPassw0rd!` will not cut it; use a true random password generator or a long passphrase.)

## 3. File Encryption

Every file is encrypted **client-side** before it leaves the user's device.

For each file, a fresh 256-bit File Encryption Key (FEK) is generated at random. The file data is then split into 16 MB chunks, and each chunk is sealed with **AES-256-GCM**, providing both confidentiality and integrity. The FEK is wrapped (encrypted) by a Key Encryption Key (KEK) derived from the user's Account Password via Argon2id. This key derivation happens entirely on the client and is cryptographically separate from the OPAQUE authentication process. Only the encrypted FEK and the encrypted file data are transmitted and stored on the server or S3-compatible backends.

Because every file has its own randomly generated FEK, a breach of one key cannot unlock any other files. The server never possesses the Account Password, the derived KEK, or any plaintext FEK.

## 4. Secure Sharing

When you create a share link Arkfile generates an **additional** key, unique to that share.

Recipients decrypt the file with this secondary key; your primary password remains secret.

Links can have expiry dates and can be revoked at any time. You can also set a max download count so a file could only be downloaded, say 3 times, by recipients. Custom-password hints are not included in the share. Anyone who has the share ID can fetch the envelope record before entering the share password. That public response includes `share_id`, `file_id`, the Argon2id salt, the encrypted envelope, and `size_bytes`. Filename and content hash stay inside the envelope until the share password decrypts it.

## 5. Username-Based Accounts

Arkfile uses **usernames** as the primary account identifier, not email addresses.

There is no `users.email` column. Saving contact information is optional. If you choose to provide it (email, Signal, or another method), it is stored as an encrypted blob that the instance administrator can decrypt for account-related contact, such as verifying a two-factor reset request. The system works fully without any contact information.

This username-based approach reduces the personally identifiable information required to create an account, avoids email-based cross-service tracking as a default, and supports pseudonymous usernames. It does not make an account anonymous to the instance operator, who still sees the username, storage accounting, and (if you saved it) decryptable contact info.

## 6. Minimal Metadata

The server stores what it needs to function. That includes the username, public Account Key salt and KDF profile, encrypted owner metadata (filename, content hash, custom-password hint, tags) as opaque ciphertext plus nonces, wrapped File Encryption Keys, share envelopes, timestamps, and storage-accounting fields. Size is not an encrypted display field. `size_bytes` is the pre-padding encrypted stream length, stored in plaintext so quotas, padding removal, and chunked downloads can work. Padding hides exact object size from the storage backend, not from Arkfile.

No plaintext file contents, passwords, or unwrapped encryption keys are stored. Wrapped FEK envelopes and encrypted share envelopes are stored. They are not usable without client-side secrets.

## 7. Privacy-Preserving Logging

Arkfile deliberately excludes client IP addresses from logs. Instead, each request is tagged with an **entity ID** generated by a daily-rotating HMAC key derived from a master secret via HKDF. This identifier lets the system spot suspicious behaviour patterns without exposing personal data.

For authenticated requests, the entity ID is derived from the username, providing precise per-user identification for rate limiting and security event correlation without involving the IP address at all. For unauthenticated requests such as share access attempts, the entity ID is derived from a composite of the client IP address, User-Agent header, and Accept-Language header. This composite approach distinguishes different browsers behind shared IP addresses (NAT, VPN, corporate networks) without resorting to invasive fingerprinting techniques. The HMAC output is irreversible and rotates daily, so entity IDs cannot be used to track users across days or to recover the original inputs.

Event records are written to the `security_events` rqlite table. Application logs go to the service logger (normally journald). Raw IP addresses are not persisted. Authenticated EntityIDs are derived from the username, and `security_events` can store a username alongside an EntityID. Unauthenticated EntityIDs cannot be reversed to the original IP or browser strings.

## 8. File Size Padding

To prevent attackers from identifying files by their exact size, Arkfile pads encrypted file data with cryptographically random bytes before storing it in the backend.

**Padding Methodology:** The padding uses percentage-based block alignment with randomized jitter. The block size is calculated as 2% of the encrypted file size, with a minimum floor of 64 KB for small files. The encrypted data is rounded up to the nearest block boundary, and then a cryptographically random jitter of 0 to 10% of the block size is added on top. This produces a consistent worst-case padding overhead of approximately 2.2% for files above 3.2 MB, while the 64 KB minimum floor provides meaningful size obfuscation for smaller files at negligible absolute cost.

**Storage Layer Implementation:** Padding is applied when the encrypted stream is written to SeaweedFS or another S3-compatible store. User quotas and utilization use the pre-padding encrypted length (`size_bytes`), not the original plaintext file size and not the padded object size. Users are not billed for the extra padding bytes. The Arkfile server still knows `size_bytes` because it received that length at upload init.

**Privacy Benefits:** Padding is aimed at storage backends and anyone who can see S3 objects. It does not hide `size_bytes` from the Arkfile server. For those outside observers it raises the cost of fingerprinting files by exact byte count, correlating identical uploads by identical stored size, and inferring type from size patterns. The random jitter means identical files uploaded twice need not produce identical object sizes.

## 9. File Representations and Information Exposure

A single user file exists in three distinct forms throughout the Arkfile system. Each form exposes different information to different parties, and understanding these boundaries is central to the privacy guarantees Arkfile provides.

**The Original Plaintext File** exists only on the file owner's device. Because all encryption happens client-side before any data leaves the device, the server never receives or processes the original file contents, the original filename, or the original SHA-256 digest. Only the file owner, who possesses both the file and the password used to encrypt it, can access this information.

**The Encrypted S3 Blob** is what the storage backend actually stores. It is a sequence of AES-256-GCM chunks, each `[nonce (12)][ciphertext][tag (16)]`, with no per-chunk envelope header and no two-byte prefix on the object. Cryptographically random padding is appended so the stored object size is not the exact encrypted-stream length. To an observer with access only to the storage backend, the blob is opaque bytes plus a padded size. The original filename, file hash, file contents, and exact unpadded size are unrecoverable without the owner's password. The FEK envelope header (version, key type, KDF profile, public salt) lives in the Arkfile database, not on the S3 object.

**The Export Bundle (.arkbackup)** is a self-contained package that the file owner can download for offline backup and decryption. It prepends a small binary header and a JSON metadata block to the same encrypted blob stored on S3. The metadata includes the encrypted File Encryption Key (which is itself wrapped by the owner's password-derived key), the password type used for encryption, encrypted filename and hash fields, chunk layout information, the upload timestamp, and the file identifier. From this metadata an observer can infer the approximate original file size (by subtracting the known per-chunk encryption overhead from the recorded encrypted size), the password type (account or custom), and the upload date. However, the file contents, original filename, and original SHA-256 digest remain encrypted and inaccessible without the owner's password and the corresponding Argon2id key derivation process. The export bundle is designed to contain everything needed for the `arkfile-client` tool to decrypt the file offline, but nothing that would allow decryption without the correct password.

## 10. Storage Backends

Arkfile supports multiple storage backends including Amazon S3, SeaweedFS, Backblaze B2, Wasabi, Vultr Object Storage, Hetzner Object Storage, IONOS Cloud Object Storage, and Cloudflare R2.

Encrypted file data is opaque to the storage provider; none of them receive decryption keys.

## 11. Glossary

- **Privacy-First:** The server never possesses the information needed to decrypt user files or learn passwords. It does see operational metadata described above.
- **OPAQUE:** A protocol that lets users prove they know their password without placing it in authentic protocol messages. Password strength rules are separate (`crypto/password-requirements.json`).
- **AES-256-GCM:** An encryption mode that hides data and detects tampering in one step.
- **Argon2id:** A memory-hard key derivation function used to derive encryption keys from passwords.
- **FEK (File Encryption Key):** A random 256-bit key generated for each file, used to encrypt the file data.
- **KEK (Key Encryption Key):** A key derived from the user's password via Argon2id, used to wrap the FEK.
- **HMAC:** A keyed hash that turns input (for example an IP address) into an irreversible digest.
- **Entity ID:** A short, daily-rotating HMAC code derived from the username (authenticated) or from IP plus browser signals (anonymous). Used in rate limiting instead of raw IPs. Authenticated security events may still record the username.
- **Ciphertext:** The scrambled output of an encryption algorithm.
- **FEK Envelope Header:** The authenticated prefix on the owner FEK envelope stored in the database (version, key type, KDF profile, public salt). It is not a prefix on the S3 blob.

---

A passive copy of the database and storage backend cannot read user files or passwords without client-side secrets. A live attacker who replaces the JavaScript or WASM served by the Arkfile origin can capture passwords, keys, and plaintext on the next browser use. An independently installed `arkfile-client` has a separate software-distribution trust boundary. See `docs/security.md`.

---

## Support

Questions, comments or bug reports? Email **arkfile [at] pm [dot] me** / **arkfile [at] tutanota [dot] com** or open an issue on GitHub.  

Please avoid posting sensitive information in public issues.
