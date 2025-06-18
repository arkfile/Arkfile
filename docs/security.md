# Arkfile Security

This document provides a detailed overview of the security architecture of the Arkfile application. It covers the cryptographic design, authentication and authorization mechanisms, and the security measures implemented at each layer of the system.

## Cryptographic Design

Arkfile's security model uses client-side encryption to ensure that user data remains protected from unauthorized access, including by service administrators. All cryptographic operations are performed within the user's browser before any data is transmitted to the server.

The cryptographic implementation uses a two-layer approach combining Argon2ID for key derivation with AES-256-GCM for file encryption. Argon2ID is a memory-hard key derivation function that provides protection against brute-force attacks and GPU or ASIC-based attacks. It was selected for its memory-hard properties that increase the computational cost of attacks and its adoption as the winner of the Password Hashing Competition. Argon2ID's memory requirements provide resistance to both classical and potential quantum attacks compared to computationally-focused alternatives, though no cryptographic algorithm can be considered definitively quantum-proof. The system by default uses Argon2ID parameters of 4 iterations, 128MB memory usage, and 4 threads of parallelism, balancing security requirements with practical performance on consumer hardware.

Once Argon2ID derives the encryption key from the user's password and a unique salt, AES-256-GCM performs the actual file encryption. AES-GCM provides both confidentiality through AES encryption and authenticity through built-in authentication, ensuring that encrypted files cannot be modified without detection. Each file receives its own unique encryption key derived using Argon2ID with a unique 256-bit salt, ensuring cryptographic isolation between files even when using the same password.

Version bytes are embedded in the encryption format to enable future cryptographic upgrades without compromising existing data compatibility. File integrity is guaranteed through SHA-256 checksums computed before encryption and verified after decryption to detect any corruption or tampering, providing an additional layer of integrity checking beyond AES-GCM's built-in authentication.

For large files, the system employs a chunked upload process where files are split into 16MB segments for reliable transfer. Each file's unique encryption key is used to encrypt all chunks belonging to that file, maintaining both security and transfer efficiency.

## Multi-Key Encryption and Secure Sharing

Arkfile implements a multi-key encryption system that allows a single file to be decrypted with multiple, independent passwords. This enables file sharing without requiring users to share their primary account password. When a user creates a share link, they can assign a new password to it. This new key is added to the file's encryption metadata, allowing the recipient to decrypt the file with the shared password while the original user's key remains secure. This process avoids file duplication by storing the encrypted file once and managing multiple decryption keys through metadata. Users can control these shared links by setting expiration dates and adding password hints.

## Authentication and Authorization

User authentication is managed through JSON Web Tokens (JWT) with secure refresh token rotation to prevent token theft and replay attacks. User passwords are hashed using the same Argon2ID parameters employed for file encryption, ensuring consistent security across all password-based operations in the system. When a user logs in, they receive a JWT that must be presented with each subsequent request to the API. This token-based system is stateless and scalable, allowing for secure communication between the client and server while supporting distributed deployments.

During the login process, the system derives session keys from user passwords using Argon2ID with domain separation to prevent key reuse between authentication and file encryption contexts. These session keys are used for account-based file encryption, allowing users to encrypt files with their account credentials while maintaining cryptographic separation from the authentication layer.

Authorization is enforced at the application level, ensuring that users can only access their own files and perform actions that they are permitted to. The system uses the principle of least privilege, granting users only the permissions they need to perform their tasks, with comprehensive rate limiting implemented across all endpoints to prevent brute force attacks against both authentication and file access.

## Client-Side Password Hashing

Plain-text passwords are never sent to the server. Arkfile performs password hashing on the client side before transmitting any credentials to the server. When a user enters their password, it is processed through Argon2ID hashing directly in the browser using WebAssembly.

This approach means that network-level attackers cannot capture plain-text passwords even if they intercept HTTPS traffic through compromised certificates or other TLS vulnerabilities.

The implementation uses the same Argon2ID parameters for client-side authentication hashing as for file encryption key derivation, ensuring consistent security levels across the system. However, different salt values and domain separation prevent key reuse between authentication and encryption contexts, maintaining cryptographic isolation between these two functions.

Only password hashes and password salts are stored in the database.

## Service and Infrastructure Security

Arkfile is designed to run as a set of systemd services under dedicated, unprivileged user accounts (`arkprod` and `arktest`) to limit its access to the underlying system. The use of separate environments for production and testing further isolates the application and reduces the risk of accidental data exposure.

All communication between the client, server, and external services is encrypted using TLS, which is managed by a Caddy web server. The distributed rqlite database cluster also uses TLS for communication between nodes and requires authentication for all operations, protecting the metadata from unauthorized access. The system is designed with high availability in mind, with automatic failover and recovery mechanisms for both the database and storage backends.
