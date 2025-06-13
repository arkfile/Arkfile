# Arkfile Security

This document provides a detailed overview of the security architecture of the Arkfile application. It covers the cryptographic design, authentication and authorization mechanisms, and the security measures implemented at each layer of the system.

## Cryptographic Design

Arkfile's security model is built on the principle of zero-trust, ensuring that user data is protected at all times, even from the service administrators. This is achieved through client-side encryption, where all cryptographic operations are performed within the user's browser before any data is transmitted to the server.

The cryptographic foundation uses quantum-resistant SHAKE-256 for key derivation with 10,000 iterations, providing strong protection against brute-force attacks and future computational threats. A version byte is included in the encryption format to allow for future upgrades to the cryptographic algorithms without compromising existing data. File integrity is ensured through the use of SHA-256 checksums, which are verified upon download to detect any corruption or tampering.

For large files, the system employs a chunked upload process. Files are split into 16MB chunks, and each chunk is individually encrypted and authenticated before being sent to the storage backend. This not only makes the transfer of large files more reliable but also enhances security by isolating the data into smaller, individually protected segments.

## Multi-Key Encryption and Secure Sharing

A key innovation in Arkfile is its multi-key encryption system, which allows a single file to be decrypted with multiple, independent passwords. This enables secure file sharing without requiring users to share their primary account password. When a user creates a share link, they can assign a new password to it. This new key is added to the file's encryption metadata, allowing the recipient to decrypt the file with the shared password while the original user's key remains secure. This process is storage-efficient as it does not require duplicating the file data. Users have granular control over these shared links, with the ability to set expiration dates and add password hints.

## Authentication and Authorization

User authentication is managed through JSON Web Tokens (JWT). When a user logs in, they receive a JWT that must be presented with each subsequent request to the API. This token-based system is stateless and scalable, and it allows for secure communication between the client and the server.

Authorization is enforced at the application level, ensuring that users can only access their own files and perform actions that they are permitted to. The system uses the principle of least privilege, granting users only the permissions they need to perform their tasks.

## Service and Infrastructure Security

The Arkfile application is designed to be deployed in a secure environment. It runs as a set of systemd services under dedicated, unprivileged user accounts (`arkprod` and `arktest`) to limit its access to the underlying system. The use of separate environments for production and testing further isolates the application and reduces the risk of accidental data exposure.

All communication between the client, server, and external services is encrypted using TLS, which is managed by a Caddy web server. The distributed rqlite database cluster also uses TLS for communication between nodes and requires authentication for all operations, protecting the metadata from unauthorized access. The system is designed with high availability in mind, with automatic failover and recovery mechanisms for both the database and storage backends.
