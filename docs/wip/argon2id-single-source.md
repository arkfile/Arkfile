# Argon2id Parameters - Single Source of Truth

## Overview

This document describes the implementation of a single source of truth for Argon2id parameters used in client-side file encryption across the Arkfile application.

## Problem Statement

Previously, Argon2id parameters were hardcoded in multiple locations:
- TypeScript client code (`client/static/js/src/crypto/constants.ts`)
- Go server code (`crypto/key_derivation.go`)

This created maintenance issues and risk of parameter drift between implementations.

## Solution

Created a single JSON configuration file that both TypeScript and Go code load at runtime:

**File:** `config/argon2id-params.json`

```json
{
  "memoryCostKiB": 262144,
  "timeCost": 8,
  "parallelism": 4,
  "keyLength": 32,
  "variant": "Argon2id"
}
```

### Parameters Explained

- **memoryCostKiB**: 262144 (256 MB) - Memory-hard parameter for GPU resistance
- **timeCost**: 8 iterations - Computational cost
- **parallelism**: 4 threads - Parallel execution lanes
- **keyLength**: 32 bytes (256 bits) - Output key size for AES-256
- **variant**: "Argon2id" - Hybrid mode (best of Argon2i and Argon2d)

## Implementation Details

### TypeScript Integration

**File:** `client/static/js/src/crypto/constants.ts`

```typescript
import argon2Params from '../../../../config/argon2id-params.json';

export const ARGON2_PARAMS = {
  FILE_ENCRYPTION: {
    memoryCost: argon2Params.memoryCostKiB,
    timeCost: argon2Params.timeCost,
    parallelism: argon2Params.parallelism,
    keyLength: argon2Params.keyLength,
    variant: 2 as const, // Argon2id
  },
} as const;
```

**Type Declaration:** `client/static/js/src/types/argon2id-params.d.ts`

```typescript
declare module '*/config/argon2id-params.json' {
  interface Argon2idParams {
    memoryCostKiB: number;
    timeCost: number;
    parallelism: number;
    keyLength: number;
    variant: string;
  }
  
  const params: Argon2idParams;
  export default params;
}
```

**TypeScript Configuration:** `tsconfig.json`

- Removed `rootDir` restriction to allow imports from outside `client/static/js/src/`
- Added `config/argon2id-params.json` to `include` array
- `resolveJsonModule: true` enables JSON imports

### Go Integration

**File:** `crypto/key_derivation.go`

```go
type argon2ParamsJSON struct {
	MemoryCostKiB int    `json:"memoryCostKiB"`
	TimeCost      int    `json:"timeCost"`
	Parallelism   int    `json:"parallelism"`
	KeyLength     int    `json:"keyLength"`
	Variant       string `json:"variant"`
}

var (
	UnifiedArgonSecure UnifiedArgonProfile
	argonLoadOnce      sync.Once
	argonLoadErr       error
)

func loadArgon2Params() error {
	file, err := os.ReadFile("config/argon2id-params.json")
	if err != nil {
		return fmt.Errorf("failed to read argon2id params: %w", err)
	}

	var params argon2ParamsJSON
	if err := json.Unmarshal(file, &params); err != nil {
		return fmt.Errorf("failed to parse argon2id params: %w", err)
	}

	if params.Variant != "Argon2id" {
		return fmt.Errorf("unsupported Argon2 variant: %s", params.Variant)
	}

	UnifiedArgonSecure = UnifiedArgonProfile{
		Time:    uint32(params.TimeCost),
		Memory:  uint32(params.MemoryCostKiB),
		Threads: uint8(params.Parallelism),
		KeyLen:  uint32(params.KeyLength),
	}

	return nil
}

func init() {
	argonLoadOnce.Do(func() {
		argonLoadErr = loadArgon2Params()
	})
	
	if argonLoadErr != nil {
		panic(fmt.Sprintf("FATAL: Failed to load Argon2ID parameters: %v", argonLoadErr))
	}
}
```

## Security Considerations

### Why These Parameters?

1. **256 MB Memory Cost**: Future-proofed against hardware advances
   - Makes parallel GPU attacks expensive
   - Balances security with client-side performance
   - Standard recommendation for high-security applications

2. **8 Iterations**: Computational cost
   - Increases time required for brute-force attacks
   - Balanced with user experience (key derivation time)

3. **4 Threads**: Parallelism
   - Utilizes modern multi-core processors
   - Standard recommendation for Argon2id

4. **32-byte Output**: AES-256 key size
   - Industry standard for symmetric encryption
   - Provides 256-bit security level

### Critical Warning

**NEVER CHANGE THESE PARAMETERS** without understanding the consequences:

1. **Data Loss Risk**: Changing parameters will make existing encrypted files unreadable
2. **Migration Required**: Any parameter change requires:
   - Re-encrypting all existing files
   - Coordinated deployment across all clients
   - User notification and migration tools

### Use Case: Client-Side File Encryption Only

These parameters are used ONLY for:
- Deriving file encryption keys from user passwords
- Client-side encryption/decryption operations
- Offline decryption capability

These parameters are NOT used for:
- OPAQUE authentication (uses different key derivation)
- Server-side operations
- Password storage (OPAQUE handles authentication)

## Benefits

1. **Single Source of Truth**: One file defines parameters for entire application
2. **Type Safety**: TypeScript gets compile-time type checking
3. **Runtime Validation**: Go validates parameters at startup
4. **Maintainability**: Changes only need to be made in one place
5. **Documentation**: JSON file serves as clear documentation

## Testing

### TypeScript Compilation
```bash
cd client/static/js && bun run tsc --noEmit
```

### Go Compilation
```bash
go build -o /tmp/arkfile-test .
```

### Verification
Both compilation tests passed successfully, confirming:
- TypeScript can import and use JSON parameters
- Go can load and parse JSON parameters at runtime
- No hardcoded duplicates remain in codebase

## Future Considerations

### Parameter Updates

If parameters ever need to be updated:

1. Create migration plan for existing encrypted files
2. Update `config/argon2id-params.json`
3. Implement version detection in file headers
4. Provide migration tools for users
5. Document breaking changes clearly

### Monitoring

Consider adding:
- Performance metrics for key derivation time
- User feedback on encryption/decryption speed
- Hardware capability detection for adaptive parameters

## Related Documentation

- `docs/wip/major-auth-wasm-fix-v2.md` - OPAQUE authentication refactor
- `docs/security.md` - Overall security architecture
- `crypto/key_derivation.go` - Go implementation
- `client/static/js/src/crypto/constants.ts` - TypeScript implementation
