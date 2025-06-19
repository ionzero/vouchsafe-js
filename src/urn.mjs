import { generateKeyPair, sha256, sha512 } from './crypto/index.mjs';
import { VOUCHSAFE_SPEC_VERSION } from './version.mjs';
import { base32Encode } from './utils.mjs';
import { toBase64, fromBase64 } from './utils.mjs';
const SUPPORTED_HASHES = {
  sha256,
  sha512,
};

/**
 * Create a new Vouchsafe identity
 * @param {string} label - Required, lowercase a-z0-9 and hyphen
 * @param {string} hashAlg - Optional: 'sha256' (default) or 'sha512'
 * @returns {Promise<{ urn, publicKey, privateKey, publicKeyHash }>}
 */
export async function createVouchsafeIdentity(label, hashAlg = 'sha256') {
  if (!label || typeof label !== 'string' || !/^[a-zA-Z0-9\-_%\+]{1,32}$/.test(label)) {
    throw new Error("Invalid label. Must be lowercase, 1–32 chars, letters/numbers/hyphens only.");
  }

  const hashFn = SUPPORTED_HASHES[hashAlg];
  if (!hashFn) throw new Error(`Unsupported hash algorithm: ${hashAlg}`);

  const { publicKey, privateKey } = await generateKeyPair();

  const pubBytes = new Uint8Array(publicKey);
  const hash = new Uint8Array(await hashFn(pubBytes));
  const hashB32 = base32Encode(hash).toLowerCase();

  const urn = `urn:vouchsafe:${label}.${hashB32}` + (hashAlg !== 'sha256' ? `.${hashAlg}` : '');

  return {
    urn,
    keypair: { 
        publicKey: toBase64(pubBytes),
        privateKey: toBase64(new Uint8Array(privateKey)),
    },
    publicKeyHash: hashB32,
    version: VOUCHSAFE_SPEC_VERSION
  };
}

/**
 * Verify a Vouchsafe URN matches a given public key
 * @param {string} urn
 * @param {string} publicKeyBase64
 * @returns {Promise<boolean>}
 */
export async function verifyUrnMatchesKey(urn, publicKeyBase64) {
  const match = urn.match(/^urn:vouchsafe:([a-zA-Z0-9\-_%\+]+)\.([a-z2-7]{52})(?:\.(sha256|sha512))?$/);
  if (!match) return false;

  const [, , expectedHash, hashAlg = 'sha256'] = match;
  const hashFn = SUPPORTED_HASHES[hashAlg];
  if (!hashFn) return false;

  const pubKey = fromBase64(publicKeyBase64);
  const actualHash = new Uint8Array(await hashFn(pubKey));
  const actualB32 = base32Encode(actualHash).toLowerCase();

  return actualB32 === expectedHash;
}
