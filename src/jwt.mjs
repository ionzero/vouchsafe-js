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

    const now = Math.floor(Date.now() / 1000);
    let iat;
    let nbf;

    // if claims.iat is not defined, set it to now
    if (typeof claims.iat == 'undefined') {
	iat = now;
    } else if (typeof claims.iat == 'number') {
	// if options.iat is a number, set it, otherwise we assume it should not be included
	iat = claims.iat;
    }
    // same as above. only set nbf automatically if it wasn't provided at all
    if (typeof claims.nbf == 'undefined') {
	nbf = now;
    } else if (typeof claims.nbf == 'number') {
	nbf = claims.nbf;
    }
    const payload = {
        ...claims,
        iss,
        iss_key,
        iat,
	nbf,
    };

    if (options.exclude_iss_key) {
        delete payload.iss_key;
    }


    const jwt = await new SignJWT(payload)
        .setProtectedHeader({
            alg: 'EdDSA'
        })
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
    if (!payload || !payload.iss) throw new Error("Invalid JWT payload");

    const pubKey = opts.pubKeyOverride ?
        await toPublicKey(opts.pubKeyOverride) :
        await extractKeyFromPayload(payload);

    const verifyResult = await jwtVerify(token, pubKey, {
        algorithms: ['EdDSA']
    });

    if (opts.verifyIssuerKey !== false && verifyResult.payload.iss_key) {
        const matches = await verifyUrnMatchesKey(verifyResult.payload.iss, verifyResult.payload.iss_key);
        if (!matches) throw new Error("iss_key does not match iss URN");
    }

    return verifyResult.payload;
}

export function decodeJwt(token, {
    full = false
} = {}) {
    const payload = joseDecodeJwt(token);
    if (!full) return payload;

    const [headerB64] = token.split('.');
    const header = JSON.parse(
        new TextDecoder().decode(
            Uint8Array.from(atob(headerB64), c => c.charCodeAt(0))
        )
    );
    return {
        payload,
        header
    };
}

/**
 * Return only the application-level claims from a decoded token.
 * Strips out all core and Vouchsafe-specific claims (identity, trust, and control).
 *
 * @param {object} decodedToken - The decoded JWT payload
 * @returns {object} - Object containing only non-Vouchsafe claims
 */
export function getAppClaims(decodedToken) {
  if (!decodedToken || typeof decodedToken !== 'object') {
    return {};
  }

  const coreAndVouchsafeClaims = new Set([
    'iss',
    'iss_key',
    'jti',
    'sub',
    'kind',
    'iat',
    'exp',
    'nbf',
    'vch_iss',
    'vch_sum',
    'revokes',
    'purpose',
    'sub_key'
  ]);

  const appClaims = {};
  for (const [key, value] of Object.entries(decodedToken)) {
    if (!coreAndVouchsafeClaims.has(key)) {
      appClaims[key] = value;
    }
  }

  return appClaims;
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
