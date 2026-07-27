import { fromBase64 } from './primitives.js';
import { FLOOR_CHUNKING } from './floors.js';

export interface AccountCryptoMetadata {
  username: string;
  salt: Uint8Array;
  kdfProfile: number;
}

let cachedMetadata: AccountCryptoMetadata | null = null;

export async function getAccountCryptoMetadata(username: string): Promise<AccountCryptoMetadata> {
  const normalizedUsername = username.trim();
  if (cachedMetadata?.username === normalizedUsername) {
    return {
      username: cachedMetadata.username,
      salt: cachedMetadata.salt.slice(),
      kdfProfile: cachedMetadata.kdfProfile,
    };
  }

  const response = await fetch('/api/auth/crypto-metadata', {
    method: 'GET',
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Failed to load account cryptographic metadata (${response.status})`);
  }

  const body = await response.json();
  const data = body.data ?? body;
  if (data.username !== normalizedUsername) {
    throw new Error('Authenticated account does not match requested username');
  }
  if (data.account_kdf_profile !== FLOOR_CHUNKING.envelope.kdfProfile) {
    throw new Error(`Unsupported Account Key KDF profile: ${String(data.account_kdf_profile)}`);
  }

  const salt = fromBase64(String(data.account_kdf_salt ?? ''));
  if (salt.length !== FLOOR_CHUNKING.envelope.saltSizeBytes) {
    throw new Error(`Invalid Account Key salt length: ${salt.length}`);
  }
  cachedMetadata = {
    username: normalizedUsername,
    salt: salt.slice(),
    kdfProfile: data.account_kdf_profile,
  };
  return {
    username: normalizedUsername,
    salt,
    kdfProfile: data.account_kdf_profile,
  };
}

export function clearAccountCryptoMetadata(): void {
  if (cachedMetadata) {
    cachedMetadata.salt.fill(0);
    cachedMetadata = null;
  }
}
