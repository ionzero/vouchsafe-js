// vouch.mjs
import { decodeJwt } from 'jose';
import {
    createJwt,
    verifyJwt
} from './jwt.mjs';
import { toBase64 } from './utils.mjs';
import { sha256, sha512 } from './crypto/index.mjs';
import { verifyUrnMatchesKey } from './urn.mjs';

async function hashJwt(jwt, alg = 'sha256') {
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

export async function createVouchToken(subjectJwt, issuer, issuerKeyPair, args = {}) {

  const { publicKey, privateKey } = issuerKeyPair;
  const subject =  decodeJwt(subjectJwt);

  if (!subject.iss || !subject.jti) throw new Error("Subject JWT must include iss and jti");

  const vch_sum = await hashJwt(subjectJwt);

  const claims = {
    ...args,
    kind: 'vch',
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
    kind: 'vch',
    jti: jti,
    sub: jti,
    vch_iss: args.vch_iss || issuer,
  };

  return createJwt(issuer, iss_key, issuerKeyPair.privateKey, claims);
}


// TODO: JAYK pick up here 
export async function revokeVouchToken(vouchToken, issuerKeyPair, args = {}) {
  const claims = {
    ...args,
    jti: args.jti || crypto.randomUUID(),
    sub: vouchToken.sub,
    vch_sum: vouchToken.vch_sum,
    vch_iss: vouchToken.vch_iss,
    revokes: vouchToken.jti,
  };

  return await createRevokeToken(claims, vouchToken.iss, issuerKeyPair)
}

export async function createRevokeToken(args, issuer, issuerKeyPair) {

  const requiredArgs = [
    'sub',
    'vch_sum',
    'vch_iss',
    'revokes'
  ];

  requiredArgs.forEach( fieldname => {
    if (typeof args[fieldname] != 'string') {
        throw new Error('No ' + fieldname + ' provided for revoke token');
    }
  });

  const claims = {
    ...args,
    iss: issuer,
    kind: 'vch',
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

  const { publicKey, privateKey } = issuerKeyPair;

  const iss_key = toBase64(publicKey);

  return createJwt(issuer, iss_key, privateKey, claims);
}

export async function validateVouchToken(token, {
  requireSubKey = false,
  requireVouchsafeIssuers = false
} = {}) {
  const decoded = await verifyJwt(token, {
    verifyIssuerKey: false
  });

  const {
    jti,
    iss,
    iss_key,
    kind,
    sub,
    sub_key,
    vch_iss,
    vch_sum,
    revokes,
    purpose
  } = decoded;

  if (kind !== 'vch') throw new Error('Not a Vouchsafe token (missing kind=vch)');
  if (!iss_key) throw new Error('Missing required iss_key in Vouchsafe token');
  if (!sub || typeof sub !== 'string') throw new Error('Missing or invalid sub');
  if (!vch_iss || typeof vch_iss !== 'string') throw new Error('Missing or invalid vch_iss');
  if (requireVouchsafeIssuers && !iss.startsWith('urn:vouchsafe:')) {
    throw new Error('Non-vouchsafe issuer not allowed under current settings');
  }
  const urnOk = await verifyUrnMatchesKey(iss, iss_key);
  if (!urnOk) throw new Error('iss_key does not match URN in iss');

  if (vch_iss === iss) {
    // only attestations allow vch_iss to be the same as iss, so this 
    // must be an attestation

    if (sub != jti) { 
        throw new Error('Vouch tokens may not vouch for a token from the same issuer unless they are attestations');
    }
    if (vch_sum) {
        throw new Error('Attestations may not have a vch_sum');
    }
    if (revokes) {
        throw new Error('Attestations may not have revokes');
    }
  } else {
    // all other token types must have a vch_sum
    if (!vch_sum || !/^[A-Za-z0-9+/=]+(\.sha256|\.sha512)?$/.test(vch_sum)) {
      throw new Error('Invalid or missing vch_sum');
    }
    // if revokes is present, it's a revoke token. 
    // revoke tokens can't have a purpose claim
    if (revokes) {
        if (purpose) throw new Error('Vouch token may not have both revokes and purpose');
        if (revokes !== 'all' && !/^[0-9a-f\-]{36}$/.test(revokes)) {
          throw new Error('revokes field must be "all" or a UUID');
        }
    }
    if (requireSubKey && !sub_key) {
      throw new Error('Missing sub_key');
    }
  }

  return decoded;
}

export async function verifyVouchToken(vouchJwt, subjectJwt, {
  requireSubKey = true,
  requireVouchsafeIssuers = false
} = {}) {
  const vouchPayload = await validateVouchToken(vouchJwt, {
    requireSubKey,
    requireVouchsafeIssuers
  });

  let decoded;

  // if we have a sub_key, we need to validate the subject using that key.
  if(vouchPayload.sub_key) {
    try { 
      decoded = verifyJwt(subjectJwt, { pubKeyOverride: vouchPayload.sub_key });
    } catch (err) {
      throw new Error('Subject token failed to validate with vouch sub_key:', err);
    }
  } else {
    // otherwise we just decode it and we have to assume the caller will
    // validate the subject via some other means.
    decoded = decodeJwt(subjectJwt);
  }

  const subjectPayload = decoded.payload;

  if (vouchPayload.sub !== subjectPayload.jti) {
    throw new Error(`Vouch token 'sub' (${vouchPayload.sub}) does not match subject token 'jti' (${subjectPayload.jti})`);
  }

  if (vouchPayload.vch_iss !== subjectPayload.iss) {
    throw new Error(`Vouch token 'vch_iss' (${vouchPayload.vch_iss}) does not match subject token 'iss' (${subjectPayload.iss})`);
  }

  // need to see if we are getting a different hash algorithm
  let [expectedHash, providedAlgorithm ] = vouchPayload.vch_sum.split('.');
  let alg = providedAlgorithm || 'sha256';

  let digest = await hashJwt(subjectJwt, alg);

  // if the algorithm is sha256, it may or may not have a suffix, so handle that
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
