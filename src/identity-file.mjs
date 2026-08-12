import { base32Encode } from './utils.mjs';
import { sha256 } from './crypto/index.mjs';

export const VOUCHSAFE_IDENTITY_FILE_VERSION = '2.1.0';

const PBKDF2_ITERATIONS = 600000;
const MAX_PBKDF2_ITERATIONS = 5000000;
const MAX_FIELD_LENGTH = 1024 * 1024;
const MAX_ENCRYPTED_BLOB_LENGTH = 16 * 1024 * 1024;
const MAX_ENCRYPTED_BLOB_BASE64_LENGTH = Math.ceil(MAX_ENCRYPTED_BLOB_LENGTH / 3) * 4;

function decodeBase64(value, field) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Invalid Base64 ${field}`);
  }
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(value, 'base64'));
  const binary = atob(value);
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function encodeBase64(value) {
  if (typeof Buffer !== 'undefined') return Buffer.from(value).toString('base64');
  return btoa(String.fromCharCode(...value));
}

function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index += 1) different |= left[index] ^ right[index];
  return different === 0;
}

function concatBytes(...parts) {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function uint32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error('Invalid uint32');
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

function encodeString(value) {
  if (!(value instanceof Uint8Array)) throw new Error('Binary string must be bytes');
  return concatBytes(uint32(value.length), value);
}

function ascii(value) {
  return new TextEncoder().encode(value);
}

function readString(bytes, state) {
  if (state.offset + 4 > bytes.length) throw new Error('Invalid encrypted private-key blob');
  const length = new DataView(bytes.buffer, bytes.byteOffset + state.offset, 4).getUint32(0);
  const start = state.offset;
  state.offset += 4;
  if (length > MAX_FIELD_LENGTH || state.offset + length > bytes.length) throw new Error('Invalid encrypted private-key blob');
  const value = bytes.slice(state.offset, state.offset + length);
  state.offset += length;
  return { value, encoded: bytes.slice(start, state.offset) };
}

function readUint32(bytes, state) {
  if (state.offset + 4 > bytes.length) throw new Error('Invalid encrypted private-key blob');
  const value = new DataView(bytes.buffer, bytes.byteOffset + state.offset, 4).getUint32(0);
  state.offset += 4;
  return value;
}

function text(bytes) {
  return new TextDecoder('ascii', { fatal: true }).decode(bytes);
}

function cryptoApi() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
    throw new Error('Web Crypto is required for identity-file encryption');
  }
  return globalThis.crypto;
}

async function publicKeyFromPrivate(privateKey) {
  const subtle = cryptoApi().subtle;
  const privateCryptoKey = await subtle.importKey('pkcs8', privateKey, { name: 'Ed25519' }, true, ['sign']);
  const privateJwk = await subtle.exportKey('jwk', privateCryptoKey);
  const publicCryptoKey = await subtle.importKey('jwk', {
    kty: privateJwk.kty,
    crv: privateJwk.crv,
    x: privateJwk.x,
  }, { name: 'Ed25519' }, true, ['verify']);
  return new Uint8Array(await subtle.exportKey('spki', publicCryptoKey));
}

async function keyBinding(urn, publicKeyBase64, privateKeyBase64, expectedHash) {
  if (typeof urn !== 'string' || !/^urn:vouchsafe:[A-Za-z0-9_\-%+]{3,32}\.[a-z2-7]{52}$/.test(urn)) {
    throw new Error('Invalid identity URN');
  }
  const publicKey = decodeBase64(publicKeyBase64, 'publicKey');
  const subtle = cryptoApi().subtle;
  const publicCryptoKey = await subtle.importKey('spki', publicKey, { name: 'Ed25519' }, true, ['verify']);
  const rawPublicKey = new Uint8Array(await subtle.exportKey('raw', publicCryptoKey));
  if (rawPublicKey.length !== 32) throw new Error('Invalid Ed25519 public key');
  const publicKeyHash = base32Encode(new Uint8Array(await sha256(rawPublicKey))).toLowerCase();
  if (expectedHash !== undefined && expectedHash !== publicKeyHash) throw new Error('Identity publicKeyHash does not match publicKey');
  if (urn.split('.').at(-1) !== publicKeyHash) throw new Error('Identity URN does not match publicKey');

  if (privateKeyBase64 !== undefined) {
    const privateKey = decodeBase64(privateKeyBase64, 'privateKey');
    const derivedPublicKey = await publicKeyFromPrivate(privateKey);
    if (!bytesEqual(publicKey, derivedPublicKey)) throw new Error('Identity privateKey does not match publicKey');
  }
  return publicKeyHash;
}

function parseEncryptedBlob(base64) {
  // Reject oversized text before Base64 decoding allocates the binary blob.
  if (typeof base64 !== 'string' || base64.length > MAX_ENCRYPTED_BLOB_BASE64_LENGTH) {
    throw new Error('Invalid encrypted private-key blob');
  }
  const blob = decodeBase64(base64, 'encryptedPrivateKey');
  if (blob.length > MAX_ENCRYPTED_BLOB_LENGTH) throw new Error('Invalid encrypted private-key blob');
  const state = { offset: 0 };
  const ciphername = readString(blob, state);
  const kdfname = readString(blob, state);
  const kdfoptions = readString(blob, state);
  const encrypted = readString(blob, state);
  if (state.offset !== blob.length) throw new Error('Invalid encrypted private-key blob');
  if (text(ciphername.value) !== 'aes256-gcm' || text(kdfname.value) !== 'pbkdf2-sha256') {
    throw new Error('Unsupported encrypted identity-file algorithm');
  }

  const kdfState = { offset: 0 };
  const salt = readString(kdfoptions.value, kdfState).value;
  const iterations = readUint32(kdfoptions.value, kdfState);
  if (kdfState.offset !== kdfoptions.value.length || salt.length < 16 || iterations === 0 || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error('Invalid encrypted identity-file KDF options');
  }

  const encryptedState = { offset: 0 };
  const nonce = readString(encrypted.value, encryptedState).value;
  const ciphertext = readString(encrypted.value, encryptedState).value;
  const tag = readString(encrypted.value, encryptedState).value;
  if (encryptedState.offset !== encrypted.value.length || nonce.length !== 12 || ciphertext.length === 0 || tag.length !== 16) {
    throw new Error('Invalid encrypted private-key blob');
  }
  return { salt, iterations, nonce, ciphertext, tag, aad: concatBytes(ciphername.encoded, kdfname.encoded, kdfoptions.encoded) };
}

async function deriveAesKey(passphrase, salt, iterations) {
  const subtle = cryptoApi().subtle;
  const password = await subtle.importKey('raw', ascii(passphrase), 'PBKDF2', false, ['deriveBits']);
  const keyBytes = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, password, 256);
  return subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptPrivateKey(privateKeyBase64, passphrase) {
  const privateKey = decodeBase64(privateKeyBase64, 'privateKey');
  const crypto = cryptoApi();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphername = encodeString(ascii('aes256-gcm'));
  const kdfname = encodeString(ascii('pbkdf2-sha256'));
  const kdfoptions = encodeString(concatBytes(encodeString(salt), uint32(PBKDF2_ITERATIONS)));
  const aad = concatBytes(ciphername, kdfname, kdfoptions);
  const key = await deriveAesKey(passphrase, salt, PBKDF2_ITERATIONS);
  const encryptedWithTag = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, privateKey));
  const ciphertext = encryptedWithTag.slice(0, -16);
  const tag = encryptedWithTag.slice(-16);
  return encodeBase64(concatBytes(ciphername, kdfname, kdfoptions, encodeString(concatBytes(encodeString(nonce), encodeString(ciphertext), encodeString(tag)))));
}

async function decryptPrivateKey(encryptedPrivateKey, passphrase) {
  try {
    const { salt, iterations, nonce, ciphertext, tag, aad } = parseEncryptedBlob(encryptedPrivateKey);
    const key = await deriveAesKey(passphrase, salt, iterations);
    const plaintext = await cryptoApi().subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, concatBytes(ciphertext, tag));
    return encodeBase64(new Uint8Array(plaintext));
  } catch (error) {
    if (error.message?.startsWith('Unsupported') || error.message?.startsWith('Invalid encrypted identity-file')) throw error;
    throw new Error('Unable to decrypt identity private key');
  }
}

function parseIdentityFile(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data) || !data.keypair || typeof data.keypair !== 'object' || Array.isArray(data.keypair)) {
    throw new Error('Identity file must be a JSON object with a keypair');
  }
  const { urn, keypair } = data;
  if (typeof urn !== 'string' || typeof keypair.publicKey !== 'string') throw new Error('Identity file is missing urn or keypair.publicKey');
  const hasPrivateKey = typeof keypair.privateKey === 'string';
  const hasEncryptedPrivateKey = typeof keypair.encryptedPrivateKey === 'string';
  if (hasPrivateKey === hasEncryptedPrivateKey) throw new Error('Identity file must contain exactly one private-key field');

  if (data.publicKeyHash !== undefined && typeof data.publicKeyHash !== 'string') {
    throw new Error('Identity publicKeyHash must be a string when specified');
  }
  return { urn, publicKey: keypair.publicKey, privateKey: keypair.privateKey, encryptedPrivateKey: keypair.encryptedPrivateKey, publicKeyHash: data.publicKeyHash, version: data.version };
}

export async function loadIdentity(data, { passphrase } = {}) {
  const parsed = parseIdentityFile(data);
  const publicKeyHash = await keyBinding(parsed.urn, parsed.publicKey, undefined, parsed.publicKeyHash);
  let privateKey = parsed.privateKey;
  if (parsed.encryptedPrivateKey) {
    if (typeof passphrase !== 'string') throw new Error('A passphrase is required to load this encrypted identity file');
    privateKey = await decryptPrivateKey(parsed.encryptedPrivateKey, passphrase);
  }
  try {
    await keyBinding(parsed.urn, parsed.publicKey, privateKey, publicKeyHash);
  } catch (error) {
    if (parsed.encryptedPrivateKey) throw new Error('Unable to decrypt identity private key');
    throw error;
  }
  return { urn: parsed.urn, keypair: { publicKey: parsed.publicKey, privateKey }, publicKeyHash, version: VOUCHSAFE_IDENTITY_FILE_VERSION };
}

export async function serializeIdentity(identity, { passphrase, unprotected_private_key } = {}) {
  const hasPassphrase = typeof passphrase === 'string' && passphrase.length > 0;
  const allowUnprotectedPrivateKey = unprotected_private_key === true;
  if (passphrase !== undefined && !hasPassphrase) {
    throw new Error('A non-empty passphrase is required to encrypt an identity file');
  }
  if (unprotected_private_key !== undefined && !allowUnprotectedPrivateKey) {
    throw new Error('unprotected_private_key must be true when specified');
  }
  if (hasPassphrase === allowUnprotectedPrivateKey) {
    throw new Error('Set exactly one of passphrase or unprotected_private_key: true');
  }
  const loaded = await loadIdentity({
    urn: identity?.urn,
    keypair: identity?.keypair,
    publicKeyHash: identity?.publicKeyHash,
    version: identity?.version,
  });
  const keypair = { publicKey: loaded.keypair.publicKey };
  if (hasPassphrase) {
    keypair.encryptedPrivateKey = await encryptPrivateKey(loaded.keypair.privateKey, passphrase);
  } else {
    keypair.privateKey = loaded.keypair.privateKey;
  }
  return { urn: loaded.urn, keypair, publicKeyHash: loaded.publicKeyHash, version: VOUCHSAFE_IDENTITY_FILE_VERSION };
}
