import { FLOOR_CHUNKING } from './floors.js';

export type OwnerKeyType = 'account' | 'custom';

export interface OwnerEnvelopeHeader {
  version: number;
  keyType: OwnerKeyType;
  keyTypeByte: number;
  kdfProfile: number;
  salt: Uint8Array;
  bytes: Uint8Array;
}

export function createOwnerEnvelopeHeader(
  keyType: OwnerKeyType,
  salt: Uint8Array,
): Uint8Array {
  const config = FLOOR_CHUNKING.envelope;
  if (salt.length !== config.saltSizeBytes) {
    throw new Error(`Owner envelope salt must be ${config.saltSizeBytes} bytes`);
  }

  const header = new Uint8Array(config.headerSizeBytes);
  header[0] = config.version;
  header[1] = config.keyTypes[keyType];
  header[2] = config.kdfProfile;
  header.set(salt, 3);
  return header;
}

export function parseOwnerEnvelopeHeader(envelope: Uint8Array): OwnerEnvelopeHeader {
  const config = FLOOR_CHUNKING.envelope;
  if (envelope.length < config.headerSizeBytes) {
    throw new Error(`Owner envelope requires ${config.headerSizeBytes} header bytes`);
  }

  const bytes = envelope.slice(0, config.headerSizeBytes);
  if (bytes[0] !== config.version) {
    throw new Error(`Unsupported owner envelope version: ${String(bytes[0])}`);
  }
  if (bytes[2] !== config.kdfProfile) {
    throw new Error(`Unsupported owner envelope KDF profile: ${String(bytes[2])}`);
  }

  let keyType: OwnerKeyType;
  if (bytes[1] === config.keyTypes.account) {
    keyType = 'account';
  } else if (bytes[1] === config.keyTypes.custom) {
    keyType = 'custom';
  } else {
    throw new Error(`Unsupported owner envelope key type: ${String(bytes[1])}`);
  }

  return {
    version: bytes[0]!,
    keyType,
    keyTypeByte: bytes[1]!,
    kdfProfile: bytes[2]!,
    salt: bytes.slice(3),
    bytes,
  };
}
