// vouch.mjs
import { decodeJwt } from 'jose';
import { createJwt, verifyJwt } from './jwt.mjs';
import { isValidUUID, toBase64 } from './utils.mjs';
import { sha256, sha512 } from './crypto/index.mjs';
import { verifyUrnMatchesKey, validateIssuerString } from './urn.mjs';

export async function hashJwt(jwt, alg = 'sha256') {
    const data = new TextEncoder().encode(jwt);
    const digestFn = alg === 'sha512' ? sha512 : sha256;

    return digestFn(data).then(bytes => {
        const hex = Array.from(new Uint8Array(bytes))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

        if (alg == 'sha256') {
            return hex;
        } else {
            return `${hex}.${alg}`;
        }
    });
}

const VOUCH_KINDS=['vch:attest', 'vch:vouch', 'vch:revoke', 'vch:burn' ];

function isValidKind(kind) {
    return VOUCH_KINDS.includes(kind);
}

export async function createVouchToken(subjectJwt, issuer, issuerKeyPair, args = {}) {

    const {
        publicKey,
        privateKey
    } = issuerKeyPair;
    const subject = decodeJwt(subjectJwt);
    //  console.log("XXXX", subject);

    if (!subject.iss || !subject.jti) throw new Error("Subject JWT must include iss and jti");

    const vch_sum = await hashJwt(subjectJwt);

    const claims = {
        ...args,
        kind: 'vch:vouch',
        sub: subject.jti,
        vch_iss: subject.iss,
        vch_sum,
        jti: args.jti || crypto.randomUUID(),
    };

    const iss_key = toBase64(publicKey);

    return createJwt(issuer, iss_key, privateKey, claims);
}

export async function createAttestation(issuer, issuerKeyPair, args = {}) {

    let jti = args.jti || crypto.randomUUID();
    const iss_key = toBase64(issuerKeyPair.publicKey);
    const claims = {
        ...args,
        kind: 'vch:attest',
        jti: jti,
        sub: jti
    };

    return createJwt(issuer, iss_key, issuerKeyPair.privateKey, claims);
}


export async function revokeVouchToken(vouchToken, issuerKeyPair, args = {}) {
    let decodedVouchToken = vouchToken;
    if (typeof vouchToken == 'string') {
        decodedVouchToken = decodeJwt(vouchToken);
    }
    const claims = {
        ...args,
        jti: args.jti || crypto.randomUUID(),
        sub: decodedVouchToken.sub,
        vch_sum: decodedVouchToken.vch_sum,
        vch_iss: decodedVouchToken.vch_iss,
        revokes: decodedVouchToken.jti,
    };

    //console.log('vouchToken', decodedVouchToken);
    //console.log('claims', claims);
    return await createRevokeToken(claims, decodedVouchToken.iss, issuerKeyPair)
}

export async function createRevokeToken(args, issuer, issuerKeyPair) {

    const requiredArgs = [
        'sub',
        'vch_sum',
        'vch_iss',
        'revokes'
    ];

    requiredArgs.forEach(fieldname => {
        if (typeof args[fieldname] != 'string') {
            throw new Error('No ' + fieldname + ' provided for revoke token');
        }
    });

    const claims = {
        ...args,
        iss: issuer,
        kind: 'vch:revoke',
        jti: args.jti || crypto.randomUUID(),
        iat: args.iat || Math.floor(Date.now() / 1000),
    };


    if (claims.purpose) {
        throw new Error('Revocation tokens must not include purpose');
    }
    if (claims.exp) {
        throw new Error('Revocation tokens must not include exp');
    }

    if (!args.revokes || (args.revokes !== 'all' && !/^[0-9a-f\-]{36}$/.test(args.revokes))) {
        throw new Error('revokes must be "all" or a valid UUID');
    }

    return createJwt(issuer, issuerKeyPair.publicKey, issuerKeyPair.privateKey, claims);
}

export async function createBurnToken(issuer, issuerKeyPair, args = {}) {

    let jti = args.jti || crypto.randomUUID();
    const iss_key = toBase64(issuerKeyPair.publicKey);
    const claims = {
        ...args,
        kind: 'vch:burn',
        jti: jti,
        sub: jti,
        burns: issuer
    };

    return createJwt(issuer, iss_key, issuerKeyPair.privateKey, claims);
}

export async function validateVouchToken(token) {
    const decoded = await verifyJwt(token); 

    if (!isValidKind(decoded.kind)) throw new Error('Invalid or missing `kind` claim');
    if (!decoded.iss_key) throw new Error('Missing required iss_key in Vouchsafe token');
    if (!decoded.jti || !isValidUUID(decoded.jti)) throw new Error('Missing or invalid jti');
    if (!decoded.sub || typeof decoded.sub !== 'string') throw new Error('Missing or invalid sub');
    if (!validateIssuerString(decoded.iss)) {
        throw new Error('Invalid token: Iss does not contain a valid Vouchsafe ID');
    }
    const urnOk = await verifyUrnMatchesKey(decoded.iss, decoded.iss_key);
    if (!urnOk) throw new Error('iss_key does not match URN in iss');

    if (decoded.kind == 'vch:attest') {
        // must be an attestation
        if (decoded.sub != decoded.jti) {
            throw new Error('Vouch tokens may not vouch for a token from the same issuer unless they are attestations');
        }
        if (typeof decoded.vch_iss != 'undefined') {
            throw new Error('Attestations may not have a vch_iss');
        }
        if (typeof decoded.vch_sum != 'undefined') {
            throw new Error('Attestations may not have a vch_sum');
        }
        if (typeof decoded.revokes != 'undefined') {
            throw new Error('Attestations may not have revokes');
        }
        if (typeof decoded.burns != 'undefined') {
            throw new Error('Attestations may not have burns');
        }
    } else if (decoded.kind == 'vch:vouch') {
        // burn token. Let's check the rules.
        if (typeof decoded.vch_iss == 'undefined') {
            throw new Error('Vouch tokens must include vch_iss');
        }
        if (typeof decoded.vch_sum == 'undefined') {
            throw new Error('Vouch tokens must have a vch_sum');
        }
        if (typeof decoded.revokes != 'undefined') {
            throw new Error('Vouch tokens may not have revokes');
        }
        // vouch tokens must not reference the signing issuer.
        if (decoded.vch_iss == decoded.iss) {
            throw new Error('Vouch tokens may not reference a themselves as issuer');
        }
        if (typeof decoded.purpose != 'undefined' && typeof decoded.purpose != 'string') {
            throw new Error('Vouch token purpose must be a valid string ');
        }
        if (typeof decoded.purpose == 'string' && !/[a-z0-9\-_:\s]/.test(decoded.purpose)) {
            throw new Error("Vouch token purpose may only contain the characters a-z, 0-9, '-', '_' and ':'");
        }
    } else if (decoded.kind == 'vch:burn') {
        // burn token. Let's check the rules.
        if (decoded.sub != decoded.jti) {
            throw new Error('Burn tokens must reference themselves (sub must equal jti)');
        }
        if (typeof decoded.vch_sum != 'undefined') {
            throw new Error('Burn tokens may not have a vch_sum');
        }
        if (typeof decoded.revokes != 'undefined') {
            throw new Error('Burn tokens may not have revokes');
        }
        // burns can only reference the signing issuer.
        if (decoded.burns != decoded.iss) {
            throw new Error('Burn tokens may not reference a different issuer');
        }
    } else if (decoded.kind == 'vch:revoke') {
        // revoke token.
        if (!decoded.vch_iss || validateIssuerString(decoded.vch_iss)) {
            throw new Error('Missing or invalid vch_iss');
        }
        // all other token types must have a vch_sum
        if (!decoded.vch_sum || !/^[A-Za-z0-9+/=]+(\.sha256|\.sha512)?$/.test(decoded.vch_sum)) {
            throw new Error('Invalid or missing vch_sum');
        }
        // if revokes is present, it's a revoke token. 
        // revoke tokens can't have a purpose claim
        if (typeof decoded.purpose != 'undefined') throw new Error('Vouch token may not have both revokes and purpose');
        if (decoded.revokes !== 'all' && !isValidUUID(decoded.revokes)) {
            throw new Error('revokes field must be "all" or a UUID');
        }
    } else {
        throw new Error('Invalid token: Unable to determine token type');
    }

    return decoded;
}

export async function verifyVouchToken(vouchJwt, subjectJwt) {
    const vouchPayload = await validateVouchToken(vouchJwt);

    const subjectPayload =await validateVouchToken(subjectJwt);

    if (vouchPayload.sub !== subjectPayload.jti) {
        throw new Error(`Vouch token 'sub' (${vouchPayload.sub}) does not match subject token 'jti' (${subjectPayload.jti})`);
    }

    if (vouchPayload.vch_iss !== subjectPayload.iss) {
        throw new Error(`Vouch token 'vch_iss' (${vouchPayload.vch_iss}) does not match subject token 'iss' (${subjectPayload.iss})`);
    }

    // need to see if we are getting a different hash algorithm
    let [expectedHash, providedAlgorithm] = vouchPayload.vch_sum.split('.');
    let alg = 'sha256';

    let digest = await hashJwt(subjectJwt, alg);

    // Compare the hash: it may or may not have a suffix, so handle that
    if (alg === 'sha256' && digest != expectedHash.replace(/\.sha256$/)) {
        throw new Error('vch_sum does not match actual hash of subject token');
        // otherwise the hashes must match exactly.
    } else if (digest != expectedHash) {
        throw new Error('vch_sum does not match actual hash of subject token');
    }

    return {
        valid: true,
        vouchPayload,
        subjectPayload
    };
}
