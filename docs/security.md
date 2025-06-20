# Arkfile Security

This document provides a detailed overview of the security architecture of the Arkfile application. It covers the cryptographic design, authentication and authorization mechanisms, and the security measures implemented at each layer of the system.

## Architecture Overview

Arkfile's security model uses client-side encryption to ensure that user data remains protected from unauthorized access, including by service administrators. The system maintains strict cryptographic separation between two primary security domains: user authentication and file encryption. This separation ensures that compromise of one system does not affect the security of the other, providing defense in depth through independent cryptographic operations.

## File Encryption System

### Cryptographic Implementation

The file encryption system uses a two-layer approach combining Argon2ID for key derivation with AES-256-GCM for file encryption. Argon2ID is a memory-hard key derivation function that provides protection against brute-force attacks and GPU or ASIC-based attacks. It was selected for its memory-hard properties that increase the computational cost of attacks and its adoption as the winner of the Password Hashing Competition. The system uses Argon2ID parameters of 4 iterations, 128MB memory usage, and 4 threads of parallelism, balancing security requirements with practical performance on consumer hardware.

Once Argon2ID derives the encryption key from the user's password and a unique salt, AES-256-GCM performs the actual file encryption. AES-GCM provides both confidentiality through AES encryption and authenticity through built-in authentication, ensuring that encrypted files cannot be modified without detection. Each file receives its own unique encryption key derived using Argon2ID with a unique 256-bit salt, ensuring cryptographic isolation between files even when using the same password.

### File Processing and Integrity

Version bytes are embedded in the encryption format to enable future cryptographic upgrades without compromising existing data compatibility. File integrity is guaranteed through SHA-256 checksums computed before encryption and verified after decryption to detect any corruption or tampering, providing an additional layer of integrity checking beyond AES-GCM's built-in authentication.

For large files, the system employs a chunked upload process where files are split into 16MB segments for reliable transfer. Each file's unique encryption key is used to encrypt all chunks belonging to that file, maintaining both security and transfer efficiency.

### Multi-Key Encryption and Secure Sharing

Arkfile implements a multi-key encryption system that allows a single file to be decrypted with multiple, independent passwords. This enables file sharing without requiring users to share their primary account password. When a user creates a share link, they can assign a new password to it. This new key is added to the file's encryption metadata, allowing the recipient to decrypt the file with the shared password while the original user's key remains secure. This process avoids file duplication by storing the encrypted file once and managing multiple decryption keys through metadata. Users can control these shared links by setting expiration dates and adding password hints.

## Authentication System

### OPAQUE Protocol Implementation

Arkfile implements OPAQUE (Oblivious Pseudorandom Functions for Key Exchange), a Password-Authenticated Key Exchange (PAKE) protocol that provides enhanced security properties compared to traditional password authentication systems. OPAQUE ensures that user passwords are never transmitted to the server in any form, not even as hashes, while providing mutual authentication between client and server.

The OPAQUE protocol operates through a three-phase process that eliminates common vulnerabilities associated with password-based authentication. During registration, the client generates cryptographic material that allows the server to participate in future authentication without learning the user's password. The client creates an "envelope" containing authentication data that is encrypted with keys derived from the user's password, but the server only stores this envelope without being able to decrypt it or learn anything about the underlying password.

When a user attempts to log in, the OPAQUE protocol performs a cryptographic handshake where both the client and server prove their authenticity to each other. The client demonstrates knowledge of the password without revealing it, while the server proves it possesses the legitimate authentication data for that user. This mutual authentication prevents both impersonation attacks and server compromise scenarios where an attacker gains access to authentication databases.

### Hybrid Argon2ID-OPAQUE Architecture

The implementation employs a hybrid approach that combines OPAQUE with additional Argon2ID hardening for enhanced protection against both online and offline attacks. Before the OPAQUE protocol begins, the client applies Argon2ID key derivation to the user's password using adaptive parameters based on device capabilities. This client-side hardening occurs before OPAQUE processing, providing defense against ASIC and GPU-based attacks while maintaining usability across different device types.

On the server side, OPAQUE envelopes receive additional Argon2ID hardening before database storage, using maximum parameters (128MB memory, 4 iterations, 4 threads) regardless of the client's capabilities. This dual-layer protection ensures that even if the authentication database is compromised, attackers face significant computational barriers when attempting to recover user passwords. The server-side hardening also establishes minimum computational costs that prevent credential stuffing attacks where attackers attempt to use lists of compromised passwords from other services.

### Device-Adaptive Security Parameters

The authentication system implements device capability detection to optimize security parameters for different hardware configurations while maintaining minimum security thresholds. The system defines three parameter profiles for client-side Argon2ID processing: Interactive (32MB memory, 1 iteration, 2 threads) for mobile devices and low-power systems, Balanced (64MB memory, 2 iterations, 2 threads) for mid-range hardware, and Maximum (128MB memory, 4 iterations, 4 threads) for high-end desktop systems.

Device detection occurs during the authentication process through performance benchmarking that measures available memory and processing capabilities. This adaptive approach ensures that users experience reasonable authentication times regardless of their device capabilities while maintaining strong security properties. The system enforces minimum computational costs to prevent attacks that attempt to use artificially low parameters to accelerate credential stuffing or brute force attempts.

## Session Management and Authorization

### JWT Token System

User authentication is managed through JSON Web Tokens (JWT) with secure refresh token rotation to prevent token theft and replay attacks. The OPAQUE protocol provides the foundation for secure authentication without password transmission, while JWT tokens handle session management for subsequent API requests. When a user successfully completes OPAQUE authentication, they receive a JWT that must be presented with each subsequent request to the API. This token-based system is stateless and scalable, allowing for secure communication between the client and server while supporting distributed deployments.

The OPAQUE authentication process generates session keys that are cryptographically independent from file encryption keys. These session keys are used exclusively for JWT token generation and validation, maintaining strict separation between authentication and file encryption domains.

### Access Control and Rate Limiting

Authorization is enforced at the application level, ensuring that users can only access their own files and perform actions that they are permitted to. The system uses the principle of least privilege, granting users only the permissions they need to perform their tasks. Comprehensive rate limiting is implemented across all endpoints to prevent brute force attacks against both authentication and file access, with adaptive thresholds that account for the computational cost differences between device parameter profiles used in the hybrid Argon2ID-OPAQUE system.

## Security Monitoring and Operations

### Event Logging and Monitoring

The system implements comprehensive security event logging that tracks authentication attempts, rate limiting triggers, and potential abuse patterns without exposing sensitive cryptographic material. Authentication failures, unusual access patterns, and rate limiting activations are logged with sufficient detail for security analysis while protecting user privacy and cryptographic secrets.

The system provides alerting mechanisms for security-relevant events such as repeated authentication failures, potential credential stuffing attempts, and system configuration anomalies. Emergency procedures are documented for scenarios including key compromise, authentication system failures, and suspected attacks. These procedures maintain service availability while protecting user data and authentication security, with clear escalation paths for different types of security incidents.

### Operational Security Procedures

Operational security procedures include automated key rotation for JWT signing keys, health monitoring for cryptographic subsystems, and validation procedures for deployment security configurations. The OPAQUE implementation maintains complete cryptographic separation between authentication and file encryption systems, ensuring that authentication keys derived through OPAQUE are used exclusively for login verification and JWT token generation.

## Infrastructure Security

### Service Isolation and Privileges

Arkfile is designed to run as a set of systemd services under dedicated, unprivileged user accounts to limit its access to the underlying system. The use of separate environments for production and testing further isolates the application and reduces the risk of accidental data exposure. Cryptographic keys are managed through secure storage mechanisms including systemd credentials and encrypted filesystem storage with appropriate permissions and access controls.

### Network Security and Communication

All communication between the client, server, and external services is encrypted using TLS, which is managed by a Caddy web server configured with strong cipher suites and security headers. The distributed rqlite database cluster uses TLS for communication between nodes and requires authentication for all operations, protecting both user metadata and authentication envelopes from unauthorized access. The system is designed with high availability in mind, with automatic failover and recovery mechanisms for both the database and storage backends.

### Key Management Infrastructure

Key management infrastructure provides secure generation, storage, and rotation of cryptographic material including OPAQUE server keys, JWT signing keys, and TLS certificates. Backup and recovery procedures ensure that critical cryptographic material can be restored in disaster scenarios while maintaining security properties and preventing unauthorized access to sensitive keys. The system enforces strict cryptographic domain separation to prevent security vulnerabilities that could arise from key reuse or cross-contamination between authentication and file encryption systems.
