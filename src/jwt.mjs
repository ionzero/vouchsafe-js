import { SignJWT, jwtVerify, decodeJwt as joseDecodeJwt, importPKCS8, importSPKI } from 'jose';
import { toBase64, fromBase64 } from './utils.mjs';
import { verifyUrnMatchesKey } from './urn.mjs';

/**
 * Create a Vouchsafe identity-bound JWT
 * @param {string} iss - URN of the issuer (e.g. "urn:vouchsafe:alice.xxxxxx")
 * @param {string} iss_key - base64-encoded public key matching the URN
 * @param {Uint8Array|string} privateKey - Private key for signing (raw or PEM)
 * @param {object} claims - Custom JWT claims
 * @param {object} [options] - Optional fields (e.g., exp, jti)
 * @returns {Promise<string>} - Signed JWT string
 */
export async function createJwt(iss, iss_key, privateKey, claims = {}, options = {}) {
  const valid = await verifyUrnMatchesKey(iss, iss_key);
  if (!valid) {
    throw new Error('Provided iss_key does not match issuer URN');
  }

  //console.warn("privateKey", privateKey);
  const key = await toPrivateKey(privateKey);
  //console.warn("XXXXXXXXXXXXXXXXXXXXXXXXXkey", key);

  const iat = options.iat || Math.floor(Date.now() / 1000);
  const payload = {
    ...claims,
    iss,
    iss_key,
    iat
  };

  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'EdDSA' })
    .sign(key);

  return jwt;
}

/**
 * Verify a Vouchsafe JWT
 * @param {string} token - JWT string to verify
 * @param {object} [opts]
 *   - pubKeyOverride: Uint8Array or PEM string
 *   - verifyIssuerKey: boolean (default: true)
 * @returns {Promise<object>} - Decoded payload if valid
 * @throws on verification failure
 */
export async function verifyJwt(token, opts = {}) {
  const payload = joseDecodeJwt(token);
  //console.warn('payload is', payload);
  if (!payload || !payload.iss) throw new Error("Invalid JWT payload");

  const pubKey = opts.pubKeyOverride
    ? await toPublicKey(opts.pubKeyOverride)
    : await extractKeyFromPayload(payload);

  const { payload: verified } = await jwtVerify(token, pubKey, {
    algorithms: ['EdDSA']
  });

  if (opts.verifyIssuerKey !== false && verified.iss_key) {
    const matches = await verifyUrnMatchesKey(verified.iss, verified.iss_key);
    if (!matches) throw new Error("iss_key does not match iss URN");
  }

  return verified;
}

export function decodeJwt(token, { full = false } = {}) {
  const payload = joseDecodeJwt(token);
  if (!full) return payload;

  const [headerB64] = token.split('.');
  const header = JSON.parse(
    new TextDecoder().decode(
      Uint8Array.from(atob(headerB64), c => c.charCodeAt(0))
    )
  );
  return { payload, header };
}


// -- Internals --

async function toPrivateKey(input) {
  if (typeof input === 'string' && input.includes('BEGIN')) {
    return await importPKCS8(input, 'EdDSA');
  }
  const pem = toPem(input, 'PRIVATE');
  //console.warn("pemkey", pem);
  return await importPKCS8(pem, 'EdDSA');
}

async function toPublicKey(input) {
  if (typeof input === 'string' && input.includes('BEGIN')) {
    return await importSPKI(input, 'EdDSA');
  }
  const pem = toPem(input, 'PUBLIC');
  return await importSPKI(pem, 'EdDSA');
}

async function extractKeyFromPayload(payload) {
  if (!payload.iss_key) throw new Error("Missing iss_key for verification");
  return await toPublicKey(payload.iss_key);
}

function toPem(input, type = 'PRIVATE') {
  if (typeof input === 'string') {
    if (input.includes('BEGIN')) {
      return input; // already PEM
    }
    // assume it's base64 already (no re-encoding)
    return `-----BEGIN ${type} KEY-----\n${chunk(input)}\n-----END ${type} KEY-----`;
  }

  if (input instanceof Uint8Array) {
    const b64 = toBase64(input);
    return `-----BEGIN ${type} KEY-----\n${chunk(b64)}\n-----END ${type} KEY-----`;
  }

  throw new Error(`Unsupported key input type: ${typeof input}`);
}

function chunk(str, len = 64) {
  return str.match(new RegExp(`.{1,${len}}`, 'g')).join('\n');
}


