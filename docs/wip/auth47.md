# Auth47 Integration Plan for Arkfile Project

This document outlines the comprehensive plan for integrating Auth47 as an alternative login method into the Arkfile project. The primary goals are to provide users with an additional login option, maintain the integrity and non-disruption of the existing OPAQUE authentication system, and ensure mandatory TOTP 2FA for all login methods.

The integration will involve modifications to the database schema, the introduction of a new Bun/Node.js microservice for Auth47 proof verification, updates to the Go backend to handle Auth47 login flows, and adaptations in the TypeScript/Bun/WASM frontend.

### Database Schema Modifications

To accommodate Auth47 as an alternative login method while centralizing user data, the existing `users` table will be modified to include a `login_type` column. This column will track the primary authentication method for each user, allowing for clear differentiation between OPAQUE and Auth47 users. Existing users will be assigned 'OPAQUE' as their `login_type`, while newly registered Auth47 users will be designated accordingly.

In addition, a new table named `auth47_identities` will be created. This table will serve as a dedicated repository for Auth47-specific unique identifiers, specifically the `nym` (Auth47 pseudonym), and will link back to the `users` table via a foreign key `user_id`. This approach ensures that core user information remains centralized within the `users` table, while authentication-method-specific data is kept separate, promoting a clean and extensible database design. Auth47 users will also choose a conventional human-readable username during registration, which will be stored in the `users` table, similar to OPAQUE users.

### Auth47 Verifier Bridge Service

Given the decision to avoid reimplementing the Auth47 TypeScript library in Go due to potential risks, a pragmatic solution involves developing a dedicated microservice. This service, built using Bun and TypeScript, will act as a secure bridge solely for verifying Auth47 proofs using the official `@samouraiwallet/auth47` library. This service will expose a single, internal API endpoint (e.g., `POST /verify-auth47-proof`) that accepts an Auth47 proof and returns a success status along with the verified `nym` or an error. Crucially, this service will be deployed in a secure, internal network environment, accessible only by the Go backend, to minimize its exposure.

### Go Backend Integration

The Go backend (`handlers/auth.go`) will be updated to manage the Auth47 login flow. A new handler, such as `POST /auth/login/auth47`, will be implemented to receive the Auth47 proof from the frontend. Upon receiving a proof, the Go backend will first forward it to the internal Bun/Node.js `auth47-verifier-service` for cryptographic validation.

After successful proof verification and extraction of the `nym`, the backend will perform a user lookup. If a user associated with the `nym` is found in the `auth47_identities` table, the existing user record will be retrieved. If no existing user is found, indicating a new Auth47 user, a new user entry will be provisioned in the `users` table with `login_type` set to 'AUTH47', and a corresponding entry will be added to the `auth47_identities` table. The temporary `sessionKey` used in this process will be securely generated from `crypto/rand`.

Following user identification or provisioning, the mandatory TOTP 2FA process will be initiated. The Go backend will generate a temporary JWT token (`tempToken`) with a `requiresTOTP: true` claim, and a temporary `sessionKey`. This information will be returned to the frontend, prompting the user for their TOTP code. The existing `TOTPAuth` handler will then be utilized to verify the TOTP code. Upon successful TOTP validation, the system will proceed to issue a full access JWT and a refresh token, completing the authentication process and adhering to the consistent session management logic across all login methods.

### Frontend Modifications

The TypeScript/Bun/WASM frontend will require adaptations to support the new Auth47 login flow. This includes adding user interface elements for a "Login with Auth47" option on the login screen. The frontend will integrate the `@samouraiwallet/auth47` library to generate and display the Auth47 URI (e.g., as a QR code or deep link) for the user's Auth47 client application. To enhance user clarity, user-facing frontend elements will avoid specific technical terms like "OPAQUE Auth," focusing instead on clear, intuitive language for login options.

Once the Auth47 proof is received from the user's Auth47 client, the frontend will securely submit this proof to the new `POST /auth/login/auth47` endpoint on the Go backend. Subsequently, if the backend response indicates that TOTP is required, the frontend will prompt the user for their TOTP code and submit it to the existing `POST /auth/totp/auth` endpoint, reusing the established TOTP orchestration logic. The existing client-side JWT and refresh token management, including storage in local storage, auto-refresh mechanisms, and the `authenticatedFetch` utility, can be fully reused without modification once the final access tokens are issued.

### OPAQUE Coexistence and Consistent Session Management

A critical aspect of this integration is ensuring that the existing OPAQUE authentication system remains fully functional and undisturbed. Auth47 will operate as an independent alternative login method. By channelling both OPAQUE and Auth47 authentication flows through the same mandatory TOTP verification step, and ultimately issuing the same type of JWTs and refresh tokens, consistency in session management, token validation, and revocation strategies will be maintained across all login methods. This approach guarantees that authentication integrity and user experience remain seamless, regardless of the chosen login path. Future considerations may include allowing existing users to link or switch between OPAQUE and Auth47 login types for a single account, and enabling the primary login type to be changed.
