import { verifyJwt, decodeJwt } from './jwt.mjs';
import { validateVouchToken, verifyVouchToken } from './vouch.mjs';
import jwt from 'jsonwebtoken';


/**
 * Build a resolveFn from an in-memory array of tokens.
 */
export function makeStaticResolver(tokens) {
  const map = new Map(); // key = `${iss}->${jti}`, value = token
  const reverse = new Map(); // key = `${iss}->${jti}`, value = [tokens that reference it]

  for (const token of tokens) {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded?.payload) continue;

    const { payload } = decoded;
    const key = `${payload.iss}->${payload.jti}`;
    if (payload.iss && payload.jti) map.set(key, token);

    if (payload.kind === 'vch' && payload.sub) {
      let subKey = `${payload.vch_iss}->${payload.sub}`
      if (!reverse.has(subKey)) reverse.set(subKey, []);
      reverse.get(subKey).push(token);
    }
  }
//  console.log('MAP', map);
//  console.log('REVERSE', reverse);

  return async function resolveFn(kind, iss, jti) {
    const key = `${iss}->${jti}`;
    if (kind === 'token') {
      const token = map.get(key);
      if (!token) throw new Error(`Token not found: ${key}`);
      return token;
    } else if (kind === 'ref') {
      return reverse.get(key) || [];
    } else {
      throw new Error(`Unknown resolve kind: ${kind}`);
    }
  };
}

export function createCompositeResolver(staticFn, dynamicFn) {
  return async function resolve(kind, iss, jti) {
    try {
      return await staticFn(kind, iss, jti);
    } catch (err) {
      if (dynamicFn) {
        return await dynamicFn(kind, iss, jti);
      }
      throw new Error(`Unable to resolve ${kind}:${iss}:${jti}`);
    }
  };
}

function extractEffectivePurposes(chain) {
  const purposes = chain
    .filter(p => p.kind === 'vch' && p.purpose)
    .map(p => new Set(p.purpose.split(/\s+/)));

//  console.log('chain', chain);
  //console.log('purposes', purposes);
  if (purposes.length === 0) return [];

  return [...purposes.reduce((acc, next) => {
    return new Set([...acc].filter(x => next.has(x)));
  })];
}

export async function verifyTrustChain(currentToken, trustedIssuers, {
  purposes = [],
  maxDepth = 10,
  resolveFn,
  tokenKey,
  tokens,
  findAll,
  chain = []
} = {}) {
  
//  console.warn('trustedIssuers', trustedIssuers);
  // abort immediately if we passed max depth
  if (maxDepth <= 0) {
//    console.warn(`⚠️ Max depth reached. Aborting at: ${currentToken}`);
    return { valid: false, reason: 'max-depth', chain };
  }
  // if we are handed a token array, create a resolver we can use from it
  if (tokens) {
//    console.warn('Making a static resolver');
    let newResolver = makeStaticResolver(tokens);
    if (typeof resolveFn == 'function') {
        newResolver = createCompositeResolver(newResolver, resolveFn);
    }
    resolveFn = newResolver;
  }
  

  let decodedToken;
  let tokenValidated = false;

  try {
    decodedToken = await verifyJwt(currentToken, { pubKeyOverride: tokenKey });
    tokenValidated = true;
  } catch (err) {
//    console.warn('🚫 Failed to validate token:', err.message);
    if (tokenKey) {
//        console.warn('🚫 Failed to validate token:', err.message);
        return { valid: false, reason: `Invalid token: ${err.message}` };
    } 
    decodedToken = await decodeJwt(currentToken, { pubKeyOverride: tokenKey });
  }
  //console.warn('AWOOOOGA', decodedToken);
  

  const currentKey = `${decodedToken.iss}->${decodedToken.jti}`;
//  console.log(`🔁 Evaluating token: ${currentKey}`);

  if (decodedToken.kind === 'vch') {
//    console.log(`📄 Token is a Vouchsafe token: ${currentKey}`);

    try {
      await validateVouchToken(currentToken);
    } catch (err) {
//      console.warn('🚫 Failed to validate vouch token:', err.message);
      return { valid: false, reason: `Invalid vouch: ${err.message}` };
    }
  }

  // if we are looking at a leaf token, we search the jti.  If we
  // are looking at a vouch token, we need to look up the original token
  // which is in the `sub` claim
  // revokes show up by looking up the original sub
  let subRefs = await resolveFn('ref', decodedToken.iss, decodedToken.sub);
  // vouches show up by looking at the jti
  let jtiRefs = await resolveFn('ref', decodedToken.iss, decodedToken.jti);
  let refs = subRefs.concat(jtiRefs);

  if (!tokenValidated) {
    // if our token has not yet been validated, then we need to use sub_key 
    // from the vouching token. So we should remove any ref that doesn't 
    // have a sub key... and try to validate against the sub_key in each one.
    // we remove any token from our refs list that doesn't validate against the 
    // original token
//    console.warn(`🚫 Token not validated, need to find a sub_key`);
    let newRefs = refs.filter( (refToken) => {
      let decoded = decodeJwt(refToken);
      if (typeof decoded.sub_key == 'string') {
        try {
          let newDecodedToken = verifyJwt(currentToken, { pubKeyOverride: decoded.sub_key });
          tokenValidated = true;
          return true;
        } catch(err) {
//            console.warn('🚫 Found token with sub_key but failed to validate original token: ', err.message);
        }
      } 
      return false;
    });
    refs = newRefs;
  }
    
  // if token is revoked, 
  if (await isRevoked(decodedToken, refs)) {
    //console.warn(`🚫 Token is revoked`);
    return { valid: false, reason: 'Vouch token is revoked' };
  }

  // ok, from here on out, we _might_ succeed. 
  let newChainLink = {
    token: currentToken,
    decoded: decodedToken,
    validated: tokenValidated
  }
/*
  console.log('checking decoded: ', decodedToken.iss);
  console.log('purposes: ', purposes);
*/
  if (isTrustedAnchor(decodedToken.iss, decodedToken.purpose, trustedIssuers, purposes)) {
//    console.log(`✅ Token is directly trusted by anchor: ${decodedToken.iss}`);
    return { valid: true, chain: chain.concat(newChainLink) };
  }

//  console.log('checking refs: ', refs);
  // if we are here, we didn't get revoked.. and we didn't land on a trust anchor, 
  // so we need to keep searching
  // Attempt to find a valid trust chain by following each ref
  let paths = [];
  for (let i = 0; i < refs.length ; i++) {
    let nextToken = refs[i];
//    console.log('checking nextToken: ', decodeJwt(nextToken));
    let result = await verifyTrustChain(nextToken, trustedIssuers, {
        purposes,
        maxDepth: maxDepth - 1,
        resolveFn,
        findAll,
        chain: chain.concat(newChainLink)
    });
//    console.warn(`Verify Recurse result: `, result.valid);
    if (result.valid == true) {
        if (!findAll) {
            return result;
        } else {
//            console.log('result is valid and in findall', result);
            paths.push(result);
        }
    } 
  }
//  console.warn('findall, paths', findAll, paths.length);
  if (findAll && paths.length > 0) {
    // if we were asked to find all, and we found at least one valid path, return valid + paths
    return { valid: true, chain: chain.concat(newChainLink), paths };
  } else {
      // if we are here, we ran off the end of refs without encountering any trust anchor.
      return { valid: false, reason: 'untrusted', chain: chain.concat(newChainLink) };
  }
}

export function isRevoked(tokenPayload, refList) {
  //console.log('Checking revocation for: ', tokenPayload);
  if (!Array.isArray(refList)) return false;
  let decoded;

  for (const refToken of refList) {
    try {
      decoded = decodeJwt(refToken);
      //console.log('ref: ', decoded);
      // shortcut immediately if we don't have a revokes field.
      if (decoded.revokes == tokenPayload.jti || decoded.revokes == 'all') {
        // we do have a revokes field, so check if everything else matches appropriately
        if (decoded.kind === 'vch' && 
            decoded.iss == tokenPayload.iss &&
            decoded.sub == tokenPayload.sub && 
            decoded.vch_iss == tokenPayload.vch_iss &&
            decoded.vch_sum == tokenPayload.vch_sum) {
          // everything matched, so our token is revoked.
          return { revokeToken: refToken, decoded: decoded };
        }
      }
    } catch(e) {
      continue;
    }
  }

  // found no revoke tokens in the list, so not revoked
  return undefined;
}

export function isTrustedAnchor(iss, tokenPurpose = [], trustedIssuers = {}, requiredPurposes = []) {
  const anchorPurposes = trustedIssuers?.[iss];
  if (!anchorPurposes) return false;

  if (anchorPurposes.includes('all')) return true;
  
  let tokenPurposes;
  if (Array.isArray(tokenPurpose)) {
    tokenPurposes - new Set(tokenPurpose);
  } else {
    tokenPurposes = new Set(
        typeof tokenPurpose === 'string' ? tokenPurpose.trim().split(/\s+/) : []
    );
  }
//  console.log('TokenPurposes', tokenPurposes, requiredPurposes);

  return requiredPurposes.some(p => tokenPurposes.has(p) && anchorPurposes.includes(p));
}

export async function canUseForPurpose(token, trustedIssuers, {
  tokens, 
  resolveFn,
  purposes,
  maxDepth = 10
}) {
  const result = await verifyTrustChain(token, trustedIssuers, {
    tokens,
    resolveFn,
    purposes: Array.isArray(purposes) ? purposes : [purposes],
    maxDepth
  });

  return result.valid;
}

