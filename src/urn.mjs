import { getKeyBytes, generateKeyPair, sha256, sha512 } from './crypto/index.mjs';
import { VOUCHSAFE_SPEC_VERSION } from './version.mjs';
import { base32Decode, base32Encode, toBase64, fromBase64 } from './utils.mjs';

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

    const {
        publicKey,
        privateKey
    } = await generateKeyPair();

    const pemPubBytes = new Uint8Array(publicKey);
    const rawPubKey = await getKeyBytes('public', publicKey);

    const pubBytes = new Uint8Array(rawPubKey);
    const hash = new Uint8Array(await hashFn(pubBytes));
    const hashB32 = base32Encode(hash).toLowerCase();

    const urn = `urn:vouchsafe:${label}.${hashB32}` + (hashAlg !== 'sha256' ? `.${hashAlg}` : '');

    return {
        urn,
        keypair: {
            publicKey: toBase64(pemPubBytes),
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

    const rawPubKey = await getKeyBytes('public', publicKeyBase64);

    const pubBytes = new Uint8Array(rawPubKey);
    const hash = new Uint8Array(await hashFn(pubBytes));
    const actualB32 = base32Encode(hash).toLowerCase();

    return actualB32 === expectedHash;
}


/**
 * Create a Vouchsafe identity from an existing DER-based Ed25519 keypair
 * @param {string} label - human-readable label (3–32 chars, a-zA-Z0-9-_+%)
 * @param {{ publicKey: string, privateKey: string }} keypair - base64-encoded DER keys
 * @param {string} hashAlg - 'sha256' (default) or 'sha512'
 * @returns {Promise<{ urn, keypair, publicKeyHash, version }>}
 */
export async function createVouchsafeIdentityFromKeypair(label, keypair, hashAlg = 'sha256') {
    if (!label || typeof label !== 'string' || !/^[a-zA-Z0-9\-_%\+]{3,32}$/.test(label)) {
        throw new Error("Invalid label. Must be 1–32 characters (a–z, 0–9, -, _, %, +).");
    }

    const hashFn = SUPPORTED_HASHES[hashAlg];
    if (!hashFn) throw new Error(`Unsupported hash algorithm: ${hashAlg}`);

    if (!keypair || typeof keypair !== 'object' || !keypair.publicKey || !keypair.privateKey) {
        throw new Error("Keypair must include base64-encoded publicKey and privateKey.");
    }

    // ✅ Verify public key and extract raw bytes (throws if invalid)
    const rawPubKey = await getKeyBytes('public', keypair.publicKey);

    // ✅ Optionally verify private key format and Ed25519 algorithm
    await getKeyBytes('private', keypair.privateKey); // throws if invalid

    // ✅ Hash the raw public key for URN
    const pubBytes = new Uint8Array(rawPubKey);
    const hash = new Uint8Array(await hashFn(pubBytes));
    const hashB32 = base32Encode(hash).toLowerCase();

    /*  const hash = new Uint8Array(await hashFn(rawPubKey));
      const hashB32 = base32Encode(hash).toLowerCase();
    */

    const urn = `urn:vouchsafe:${label}.${hashB32}` + (hashAlg !== 'sha256' ? `.${hashAlg}` : '');

    return {
        urn,
        keypair: {
            publicKey: keypair.publicKey, // original DER b64
            privateKey: keypair.privateKey
        },
        publicKeyHash: hashB32,
        version: VOUCHSAFE_SPEC_VERSION
    };
}


export function validateIssuerString(iss) {
    if (typeof iss !== "string") return false;

    const prefix = "urn:vouchsafe:";
    if (!iss.startsWith(prefix)) return false;

    const rest = iss.slice(prefix.length);

    // split on first '.'
    const dot = rest.indexOf(".");
    if (dot === -1) return false;

    const label = rest.slice(0, dot);
    const afterLabel = rest.slice(dot + 1);

    // --- Optional .sha256 suffix ---
    let hashPart = afterLabel;
    let suffix = null;

    const secondDot = afterLabel.indexOf(".");
    if (secondDot !== -1) {
        hashPart = afterLabel.slice(0, secondDot);
        suffix = afterLabel.slice(secondDot + 1);

        if (suffix !== "sha256") return false;
    }

    // --- Label validation (spec) ---
    if (label.length < 3 || label.length > 32) return false;
    if (!/^[A-Za-z0-9_\-%+]+$/.test(label)) return false;

    // --- Hash validation (spec) ---
    if (!/^[a-z2-7]+$/.test(hashPart)) return false;

    // Base32 decode must succeed
    let decoded;
    try {
        decoded = base32Decode(hashPart);
    } catch {
        return false;
    }
    if (!decoded || decoded.length === 0) return false;

    return true;
}


function toHexString(uint8arr) {
    return Array.from(uint8arr)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}
