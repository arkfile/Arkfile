/**
 * Compile-time Cryptographic Floor Settings and clamping helpers
 *
 * All security-critical KDF, chunking, and password parameters are validated on the client side
 * against these immutable, statically embedded values. If the server is compromised or returns
 * downgraded values, we protect keys and payloads by clamping/refusing those options.
 */

import { DecryptionError } from './errors.js';

export interface Argon2Params {
  memoryCostKiB: number;
  timeCost: number;
  parallelism: number;
  keyLength: number;
}

export interface ChunkingConfig {
  plaintextChunkSizeBytes: number;
  envelope: {
    keyTypes: {
      account: number;
      custom: number;
    };
  };
  aesGcm: {
    nonceSizeBytes: number;
    tagSizeBytes: number;
    keySizeBytes: number;
  };
}

export interface PasswordConfig {
  minAccountPasswordLength: number;
  minCustomPasswordLength: number;
  minSharePasswordLength: number;
  maxPasswordLength: number;
  minCharacterClassesRequired: number;
  specialCharacters: string;
}

export interface ShareKDFParamsEmbedded {
  algorithm: string; // "argon2id"
  m_kib: number;
  t: number;
  p: number;
  dk: number;
}

// Compile-time Floors (Statically embedded from crypto/*.json)

export const FLOOR_ARGON2: Argon2Params = {
  memoryCostKiB: 65536,
  timeCost: 3,
  parallelism: 1,
  keyLength: 32,
};

export const FLOOR_CHUNKING: ChunkingConfig = {
  plaintextChunkSizeBytes: 16777216,
  envelope: {
    keyTypes: {
      account: 1,
      custom: 2,
    },
  },
  aesGcm: {
    nonceSizeBytes: 12,
    tagSizeBytes: 16,
    keySizeBytes: 32,
  },
};

export const FLOOR_PASSWORD: PasswordConfig = {
  minAccountPasswordLength: 15,
  minCustomPasswordLength: 15,
  minSharePasswordLength: 20,
  maxPasswordLength: 256,
  minCharacterClassesRequired: 2,
  specialCharacters: "`~!@#$%^&*()-_=+[]{}|;:,.<>? ",
};

// Clamping and Verification Helpers (Option B)

/**
 * Resolve KDF params: if server values are missing, invalid, or weaker than our compilation flooring,
 * we clamp field-by-field or fall back to floors. This prevents any server-side downgrade attack.
 */
export function resolveArgon2Params(server: Partial<Argon2Params> | null | undefined): Argon2Params {
  if (!server) {
    return { ...FLOOR_ARGON2 };
  }
  return {
    memoryCostKiB: Math.max(server.memoryCostKiB ?? 0, FLOOR_ARGON2.memoryCostKiB),
    timeCost: Math.max(server.timeCost ?? 0, FLOOR_ARGON2.timeCost),
    parallelism: Math.max(server.parallelism ?? 0, FLOOR_ARGON2.parallelism),
    keyLength: Math.max(server.keyLength ?? 0, FLOOR_ARGON2.keyLength),
  };
}

/**
 * Resolve Chunking params. Since chunk sizes govern stream buffer sizes, we must clamp them
 * to system settings.
 */
export function resolveChunkingParams(server: Partial<ChunkingConfig> | null | undefined): ChunkingConfig {
  if (!server) {
    return { ...FLOOR_CHUNKING };
  }
  return {
    plaintextChunkSizeBytes: Math.max(server.plaintextChunkSizeBytes ?? 0, FLOOR_CHUNKING.plaintextChunkSizeBytes),
    envelope: {
      keyTypes: {
        account: server.envelope?.keyTypes?.account ?? FLOOR_CHUNKING.envelope.keyTypes.account,
        custom: server.envelope?.keyTypes?.custom ?? FLOOR_CHUNKING.envelope.keyTypes.custom,
      },
    },
    aesGcm: {
      nonceSizeBytes: Math.max(server.aesGcm?.nonceSizeBytes ?? 0, FLOOR_CHUNKING.aesGcm.nonceSizeBytes),
      tagSizeBytes: Math.max(server.aesGcm?.tagSizeBytes ?? 0, FLOOR_CHUNKING.aesGcm.tagSizeBytes),
      keySizeBytes: Math.max(server.aesGcm?.keySizeBytes ?? 0, FLOOR_CHUNKING.aesGcm.keySizeBytes),
    },
  };
}

/**
 * Resolve Password Requirements params. Any attempt by the server to relax password security
 * is ignored; we clamp to compile-time floors.
 */
export function resolvePasswordConfig(server: Partial<PasswordConfig> | null | undefined): PasswordConfig {
  if (!server) {
    return { ...FLOOR_PASSWORD };
  }
  return {
    minAccountPasswordLength: Math.max(server.minAccountPasswordLength ?? 0, FLOOR_PASSWORD.minAccountPasswordLength),
    minCustomPasswordLength: Math.max(server.minCustomPasswordLength ?? 0, FLOOR_PASSWORD.minCustomPasswordLength),
    minSharePasswordLength: Math.max(server.minSharePasswordLength ?? 0, FLOOR_PASSWORD.minSharePasswordLength),
    maxPasswordLength: server.maxPasswordLength ?? FLOOR_PASSWORD.maxPasswordLength,
    minCharacterClassesRequired: Math.max(server.minCharacterClassesRequired ?? 0, FLOOR_PASSWORD.minCharacterClassesRequired),
    specialCharacters: server.specialCharacters ?? FLOOR_PASSWORD.specialCharacters,
  };
}

/**
 * Verifies that the KDF parameters of a decrypted share envelope are not weaker
 * than the client-side system flooring.
 */
export function validateAgainstFloor(p: ShareKDFParamsEmbedded): void {
  if (!p) {
    throw new DecryptionError('Missing KDF parameters block in share envelope');
  }
  if (p.algorithm !== 'argon2id') {
    throw new DecryptionError(`Unsupported KDF algorithm: ${p.algorithm} (expected argon2id)`);
  }
  if (p.m_kib < FLOOR_ARGON2.memoryCostKiB) {
    throw new DecryptionError(`KDF memory parameter below system floor: ${p.m_kib} < ${FLOOR_ARGON2.memoryCostKiB}`);
  }
  if (p.t < FLOOR_ARGON2.timeCost) {
    throw new DecryptionError(`KDF iterations parameter below system floor: ${p.t} < ${FLOOR_ARGON2.timeCost}`);
  }
  if (p.p < FLOOR_ARGON2.parallelism) {
    throw new DecryptionError(`KDF parallelism parameter below system floor: ${p.p} < ${FLOOR_ARGON2.parallelism}`);
  }
  if (p.dk < FLOOR_ARGON2.keyLength) {
    throw new DecryptionError(`KDF derived key length below system floor: ${p.dk} < ${FLOOR_ARGON2.keyLength}`);
  }
}
