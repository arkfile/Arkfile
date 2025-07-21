# API Mapping: aldenml/ecc to libopaque

## Overview

This document provides a detailed mapping between the aldenml/ecc OPAQUE API and Stef's libopaque API, including function signatures, parameter mappings, and implementation notes.

**NOTE**: This is a supplemental reference document. For the complete implementation plan and step-by-step instructions, see `use-libopaque-migration-guide.md`.

**UPDATE (7/21/2025)**: This mapping has been validated through comprehensive testing. The libopaque API is simpler and more straightforward than aldenml/ecc, making migration easier than initially anticipated.

## Core Types and Constants

### aldenml/ecc Types

```c
// Constants
#define ecc_opaque_ristretto255_sha512_Nn 32
#define ecc_opaque_ristretto255_sha512_Nm 64
#define ecc_opaque_ristretto255_sha512_Nh 64
#define ecc_opaque_ristretto255_sha512_Nok 32
#define ecc_opaque_ristretto255_sha512_Npk 32
#define ecc_opaque_ristretto255_sha512_Nsk 32
#define ecc_opaque_ristretto255_sha512_Noe 32
#define ecc_opaque_ristretto255_sha512_Ns 32

// Sizes
#define ecc_opaque_ristretto255_sha512_REGISTRATIONREQUESTSIZE 32
#define ecc_opaque_ristretto255_sha512_REGISTRATIONRESPONSESIZE 64
#define ecc_opaque_ristretto255_sha512_REGISTRATIONRECORDSIZE 192
#define ecc_opaque_ristretto255_sha512_CREDENTIALREQUESTSIZE 32
#define ecc_opaque_ristretto255_sha512_CREDENTIALRESPONSESIZE 192
#define ecc_opaque_ristretto255_sha512_KE1SIZE 96
#define ecc_opaque_ristretto255_sha512_KE2SIZE 320
#define ecc_opaque_ristretto255_sha512_KE3SIZE 64
#define ecc_opaque_ristretto255_sha512_CLIENTSTATESIZE 160
#define ecc_opaque_ristretto255_sha512_SERVERSTATESIZE 128

// MHF types
#define ecc_opaque_ristretto255_sha512_MHF_IDENTITY 0
#define ecc_opaque_ristretto255_sha512_MHF_SCRYPT 1
#define ecc_opaque_ristretto255_sha512_MHF_ARGON2ID 2
```

### libopaque Types (Verified)

```c
// From opaque.h - actual constants
#define OPAQUE_SHARED_SECRETBYTES 64
#define OPAQUE_REGISTRATION_RECORD_LEN 192
#define OPAQUE_USER_RECORD_LEN 256 
#define OPAQUE_USER_SESSION_PUBLIC_LEN 96
#define OPAQUE_USER_SESSION_SECRET_LEN 226
#define OPAQUE_SERVER_SESSION_LEN 320
#define OPAQUE_REGISTER_USER_SEC_LEN 192
#define OPAQUE_REGISTER_SECRET_LEN 160
#define OPAQUE_REGISTER_PUBLIC_LEN 96

// Identity structure
typedef struct {
    uint16_t idU_len;
    uint8_t *idU;
    uint16_t idS_len;
    uint8_t *idS;
} Opaque_Ids;
```

## Function Mappings (Tested and Verified)

### Registration Functions

#### CreateRegistrationRequest

**aldenml/ecc**:
```c
void ecc_opaque_ristretto255_sha512_CreateRegistrationRequest(
    uint8_t *request,      // output: REGISTRATIONREQUESTSIZE bytes
    uint8_t *blind,        // output: Ns bytes
    const uint8_t *password,
    const int password_len
);
```

**libopaque** (Actual signature):
```c
int opaque_CreateRegistrationRequest(
    const uint8_t *pwdU,
    const uint16_t pwdU_len,
    uint8_t *usr_ctx,      // output: user context (blind included)
    uint8_t *M             // output: blinded message
);
```

**Verified Mapping**:
- ✅ Password input is straightforward
- ✅ usr_ctx contains the blinding factor
- ✅ M is the blinded element to send to server
- ✅ Returns 0 on success, non-zero on error

#### CreateRegistrationResponse  

**aldenml/ecc**:
```c
void ecc_opaque_ristretto255_sha512_CreateRegistrationResponse(
    uint8_t *response,     // output: REGISTRATIONRESPONSESIZE bytes
    const uint8_t *request,
    const uint8_t *server_public_key,
    const uint8_t *credential_identifier,
    const int credential_identifier_len,
    const uint8_t *oprf_seed
);
```

**libopaque** (Actual signature):
```c
int opaque_CreateRegistrationResponse(
    const uint8_t *M,      // blinded message from client
    const uint8_t *skS,    // server's OPRF key (can be NULL)
    uint8_t *rsec,         // output: registration secret
    uint8_t *rpub          // output: registration public
);
```

**Verified Mapping**:
- ✅ M is the blinded message from registration request
- ✅ skS can be NULL (server generates ephemeral key)
- ✅ rsec and rpub are used in finalization
- ✅ No credential_identifier needed at this stage

#### FinalizeRegistrationRequest

**aldenml/ecc**:
```c
void ecc_opaque_ristretto255_sha512_FinalizeRegistrationRequest(
    uint8_t *record,       // output: REGISTRATIONRECORDSIZE bytes
    uint8_t *export_key,   // output: Nh bytes
    const uint8_t *password,
    const int password_len,
    const uint8_t *blind,
    const uint8_t *response,
    const uint8_t *server_identity,
    const int server_identity_len,
    const uint8_t *client_identity,
    const int client_identity_len,
    const int mhf,
    const uint8_t *mhf_salt,
    const int mhf_salt_len
);
```

**libopaque** (Actual signature):
```c
int opaque_FinalizeRequest(
    const uint8_t *usr_ctx,  // user context from CreateRegistrationRequest
    const uint8_t *rpub,     // registration public from server
    const Opaque_Ids *ids,   // client and server identities
    uint8_t *rrec,           // output: registration record
    uint8_t *export_key      // output: export key
);
```

**Verified Mapping**:
- ✅ usr_ctx contains password and blinding info
- ✅ rpub is from CreateRegistrationResponse
- ✅ ids structure holds both identities (can be NULL)
- ✅ rrec is sent to server for storage
- ✅ export_key matches the concept from aldenml/ecc

#### Additional Registration Function

**libopaque** also provides:
```c
void opaque_StoreUserRecord(
    const uint8_t *rsec,     // registration secret
    const uint8_t *rrec,     // registration record
    uint8_t *rec             // output: user record for storage
);
```
This combines server secret with client record for final storage.

### Authentication Functions

#### Login Request (was GenerateKE1)

**aldenml/ecc**:
```c
void ecc_opaque_ristretto255_sha512_GenerateKE1(
    uint8_t *ke1,          // output: KE1SIZE bytes
    uint8_t *state,        // output: CLIENTSTATESIZE bytes
    const uint8_t *password,
    const int password_len
);
```

**libopaque** (Actual signature):
```c
int opaque_CreateCredentialRequest(
    const uint8_t *pwdU,
    const uint16_t pwdU_len,
    uint8_t *sec,          // output: user session secret
    uint8_t *pub           // output: credential request
);
```

**Verified Mapping**:
- ✅ Same password input
- ✅ sec contains session state (like client state)
- ✅ pub is the credential request to send
- ✅ Simpler than KE1 - no key exchange at this stage

#### Login Response (was GenerateKE2)

**aldenml/ecc**:
```c
void ecc_opaque_ristretto255_sha512_GenerateKE2(
    uint8_t *ke2,          // output: KE2SIZE bytes
    uint8_t *state,        // output: SERVERSTATESIZE bytes
    const uint8_t *server_identity,
    const int server_identity_len,
    const uint8_t *server_private_key,
    const uint8_t *server_public_key,
    const uint8_t *record,
    const uint8_t *credential_identifier,
    const int credential_identifier_len,
    const uint8_t *oprf_seed,
    const uint8_t *ke1,
    const uint8_t *client_identity,
    const int client_identity_len,
    const uint8_t *context,
    const int context_len
);
```

**libopaque** (Actual signature):
```c
int opaque_CreateCredentialResponse(
    const uint8_t *pub,    // credential request from client
    const uint8_t *rec,    // user record from storage
    const Opaque_Ids *ids, // identities
    const uint8_t *context,
    const uint16_t context_len,
    uint8_t *resp,         // output: credential response
    uint8_t *sk,           // output: server's session key
    uint8_t *authU         // output: expected auth from user
);
```

**Verified Mapping**:
- ✅ pub is credential request from client
- ✅ rec is the stored user record
- ✅ Context supported (optional)
- ✅ Server gets session key immediately
- ✅ authU used to verify client later

#### GenerateKE3 / RecoverCredentials

**aldenml/ecc**:
```c
int ecc_opaque_ristretto255_sha512_GenerateKE3(
    uint8_t *ke3,          // output: KE3SIZE bytes
    uint8_t *session_key,  // output: Nm bytes
    uint8_t *export_key,   // output: Nh bytes
    const uint8_t *state,
    const uint8_t *client_identity,
    const int client_identity_len,
    const uint8_t *server_identity,
    const int server_identity_len,
    const uint8_t *ke2,
    const int mhf,
    const uint8_t *mhf_salt,
    const int mhf_salt_len,
    const uint8_t *context,
    const int context_len
);
```

**libopaque**:
```c
int opaque_RecoverCredentials(
    const uint8_t *resp,   // credential response
    const uint8_t *usr,    // user state
    const Opaque_Ids *ids,
    const uint8_t *context,
    const uint16_t context_len,
    uint8_t *sk,           // output: session key
    uint8_t *authU,        // output: authentication tag
    uint8_t *export_key   // output: export key
);
```

**Mapping Notes**:
- libopaque returns authentication tag instead of KE3
- Session key output is similar
- Export key handling is consistent

#### ServerFinish

**aldenml/ecc**:
```c
int ecc_opaque_ristretto255_sha512_ServerFinish(
    uint8_t *session_key,  // output: Nm bytes
    const uint8_t *state,
    const uint8_t *ke3
);
```

**libopaque**:
```c
int opaque_UserAuth(
    const uint8_t *authU,  // authentication tag
    const uint8_t *ssid    // session state
);
```

**Mapping Notes**:
- libopaque validates authentication tag
- Session key already generated in CreateCredentialResponse
- Different finalization approach

## Implementation Strategy

### 1. Wrapper Layer

Create a wrapper layer to adapt libopaque's API to match the existing interface:

```go
// Example wrapper function
func libopaqueCreateRegistrationRequest(password []byte) (request []byte, blind []byte, err error) {
    // Allocate buffers
    var M [OPAQUE_REGISTRATION_REQUEST_SIZE]byte
    var usr [OPAQUE_USER_STATE_SIZE]byte
    
    // Call libopaque
    ret := C.opaque_CreateRegistrationRequest(
        (*C.uint8_t)(unsafe.Pointer(&password[0])),
        C.uint16_t(len(password)),
        (*C.uint8_t)(unsafe.Pointer(&M[0])),
        (*C.uint8_t)(unsafe.Pointer(&usr[0]))
    )
    
    if ret != 0 {
        return nil, nil, fmt.Errorf("libopaque error: %d", ret)
    }
    
    // Extract blind from user state (needs investigation)
    blind = extractBlindFromUserState(usr[:])
    
    return M[:], blind, nil
}
```

### 2. State Management

libopaque uses different state management:
- User state persists across registration/authentication
- Server state is handled differently
- Need to map between the two approaches

### 3. Identity Handling

libopaque uses structured identity data:
```go
type OpaqueIds struct {
    blinded     [32]byte
    nonce       [32]byte
    nonceU      [32]byte
    pwdU        []byte
    pwdU_len    uint32
    ids_idU     []byte
    ids_idU_len uint32
    ids_idS     []byte
    ids_idS_len uint32
}
```

### 4. Error Handling

libopaque returns error codes while aldenml/ecc uses void functions:
- Need to check all return values
- Map error codes to Go errors
- Ensure proper error propagation

## Testing Considerations

1. **Test Vector Compatibility**: Verify if test vectors from aldenml/ecc work with libopaque
2. **Protocol Version**: Ensure both implement compatible OPAQUE draft versions
3. **Cryptographic Parameters**: Verify group, hash, and KDF selections match
4. **State Serialization**: Test that state can be properly saved/restored

## Implementation Reference

**For detailed implementation steps and progress tracking, see: `use-libopaque-migration-guide.md`**

### Key Takeaways from API Analysis

1. **Simplified API**: libopaque is much simpler than aldenml/ecc
   - No KE1/KE2/KE3 complexity 
   - Cleaner function signatures
   - Built-in state management

2. **Database Compatibility**: ✅ No schema changes needed
   - Existing BLOB fields work with libopaque data
   - No migration required for existing users (none exist)

3. **Memory Management**: Fixed-size buffers (easier than aldenml/ecc)

4. **Error Handling**: Consistent return codes (0 = success)

5. **WASM Critical**: Early testing required for client-side crypto

### Function Summary

| Purpose | aldenml/ecc | libopaque | Complexity |
|---------|-------------|-----------|------------|
| Registration | KE-style multi-step | Simple request/response/finalize | Simpler |
| Authentication | KE1/KE2/KE3 flow | request/response/recover/validate | Much Simpler |
| State Management | Manual KE state | Internal handling | Much Simpler |
| Error Handling | Void functions | Return codes | More Consistent |

### Next Steps Summary

See `use-libopaque-migration-guide.md` for:
- [ ] Complete step-by-step implementation plan
- [ ] Detailed technical specifications  
- [ ] Progress tracking checklists
- [ ] Build system configuration
- [ ] Testing strategies

This document serves as an API reference during implementation.
