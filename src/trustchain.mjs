import { verifyJwt, decodeJwt } from './jwt.mjs';
import { validateVouchToken, verifyVouchToken } from './vouch.mjs';


/**
 * Build a resolveFn from an in-memory array of tokens.
 */
export function makeStaticResolver(tokens = []) {
    const map = {}; // key = `${iss}->${jti}`, value = token
    const reverse = {}; // key = `${iss}->${jti}`, value = [tokens that reference it]

    for (const token of tokens) {
        const decoded = decodeJwt(token, {
            full: true
        });
        if (!decoded?.payload) continue;

        const {
            payload
        } = decoded;
        const key = `${payload.iss}->${payload.jti}`;
        if (payload.iss && payload.jti) map[key] = token;

        if (payload.kind === 'vch' && payload.sub) {
            let subKey = `${payload.vch_iss}->${payload.sub}`
            if (!Array.isArray(reverse[subKey])) reverse[subKey] = [];
            reverse[subKey].push(token);
        }
    }
    //  console.log('MAP', map);
    //  console.log('REVERSE', reverse);

    return async function resolveFn(kind, iss, jti) {
        const key = `${iss}->${jti}`;
        if (kind === 'token') {
            const token = map[key];
            if (!token) throw new Error(`Token not found: ${key}`);
            return token;
        } else if (kind === 'ref') {
            return reverse[key] || [];
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
        console.warn(`⚠️ Max depth reached. Aborting at: ${currentToken}`);
        return {
            valid: false,
            reason: 'max-depth',
            chain
        };
    }
    // if we are handed a token array, create a resolver we can use from it
    if (tokens || typeof resolveFn == 'undefined') {
        let newResolver = makeStaticResolver(tokens);
        if (typeof resolveFn == 'function') {
            newResolver = createCompositeResolver(newResolver, resolveFn);
        }
        resolveFn = newResolver;
    }


    let decodedToken;
    let tokenValidated = false;

    try {
        decodedToken = await verifyJwt(currentToken, {
            pubKeyOverride: tokenKey
        });
        tokenValidated = true;
    } catch (err) {
        if (tokenKey) {
            // if we were provided a token key and we are in the catch, 
            // the token didn't verify, so we should error
            return {
                valid: false,
                reason: `Invalid token: ${err.message}`
            };
        }
        // if we weren't provided a token key, we can validate later using a vouches sub_key
        decodedToken = await decodeJwt(currentToken, {
            pubKeyOverride: tokenKey
        });
    }
    let newChainLink = {
        token: currentToken,
        decoded: decodedToken,
        validated: tokenValidated
    }
    //console.warn('AWOOOOGA', decodedToken);

    // immediately return if we trust the decoded token for purpose
    if (isTrustedAnchor(decodedToken.iss, decodedToken.purpose, trustedIssuers, purposes)) {
        //console.log(`✅ Token is directly trusted by anchor: ${decodedToken.iss}`);
        let final_result = {
            valid: true,
            chain: chain.concat(newChainLink)
        };

        final_result.purposes = extractEffectivePurposesFromChain(final_result.chain);

        return final_result;
    }

    const currentKey = `${decodedToken.iss}->${decodedToken.jti}`;
    //console.log(`🔁 Evaluating token: ${currentKey}`);

    if (decodedToken.kind === 'vch') {
        //console.log(`📄 Token is a Vouchsafe token: ${currentKey}`);
        try {
            await validateVouchToken(currentToken);
        } catch (err) {
            //console.warn('🚫 Failed to validate vouch token:', err.message);
            return {
                valid: false,
                reason: `Invalid vouch: ${err.message}`
            };
        }
    }

    let subRefs = []; // await resolveFn('ref', decodedToken.iss, decodedToken.sub);
    // vouches show up by looking at the jti
    let jtiRefs = await resolveFn('ref', decodedToken.iss, decodedToken.jti);
    let refs = subRefs.concat(jtiRefs);

    // loop over refs, create decoded refs, so we can do some evaluation.
    let revokeMap = {};
    let decodedRefs = [];
    for (let i = 0; i < refs.length; i++) {
        let refToken = refs[i];
        // refs.forEach( async (refToken) => {
        // everything in a ref should be a vouch token, so it should verify.
        try {
            let decoded = await verifyJwt(refToken)
            let tokenObj = {
                iss: decoded.iss,
                jti: decoded.jti,
                decoded: decoded,
                token: refToken
            };
            if (typeof decoded.revokes == 'string') {
                tokenObj.revokes = decoded.revokes;
            }
            if (typeof decoded.revokes == 'string') {
                revokeMap[decoded.iss + ":" + decoded.revokes] = tokenObj;
            } else {
                if (tokenValidated) {
                    decodedRefs.push(tokenObj);
                } else {
                    try {
                        // if our original token was not validated, we have to verify it against this
                        // tokens sub_key.. to make sure we are referring to the correct token.
                        let newDecodedToken = await verifyJwt(currentToken, {
                            pubKeyOverride: decoded.sub_key
                        });
                        decodedRefs.push(tokenObj);
                    } catch (err) {
                        console.warn('🚫 Found token with sub_key but failed to validate original token: ', err.message);
                    }
                }
            }
        } catch (e) {
            //console.log('catching');
            console.warn('token failed to validate: ', refToken);
        }
    };

    // ok.. we have a list of tokens associated with this token. 
    // let's remove anything that is revoked. and remove 
    // anything that doesn't match our purposes
    let validTokens = decodedRefs.filter((tokenObj) => {
        if (typeof revokeMap[tokenObj.iss + ":" + tokenObj.jti] == 'object' ||
            typeof revokeMap[tokenObj.iss + ":all"] == 'object') {
            return false;
        } else {
            // if we're here, this token is not revoked, but we need
            // to be sure it matches our required purposes.
            if (typeof tokenObj.decoded.purpose == 'string') {
                let tokenPurposes = {};
                tokenObj.decoded.purpose.trim().split(/\s+/).forEach((p) => {
                    tokenPurposes[p] = true;
                });
                return purposes.every((requiredPurpose) => {
                    return tokenPurposes[requiredPurpose] == true;
                });
            } else {
                // no purposes provided in this token, so assuming everything is allowed
                return true;
            }
        }
    });

    // ok, from here on out, we _might_ succeed. 
    //
    // if we are here, we didn't get revoked.. and we didn't land on a trust anchor, 
    // so we need to keep searching
    // Attempt to find a valid trust chain by following each ref
    let paths = [];
    for (let i = 0; i < validTokens.length; i++) {
        let nextToken = validTokens[i].token;
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
        return {
            valid: true,
            chain: chain.concat(newChainLink),
            paths
        };
    } else {
        // if we are here, we ran off the end of refs without encountering any trust anchor.
        return {
            valid: false,
            reason: 'untrusted',
            chain: chain.concat(newChainLink)
        };
    }
}

export function isRevoked(tokenPayload, refList) {
    //console.log('Checking revocation for: ', tokenPayload);
    if (!Array.isArray(refList)) return false;
    let decoded;

    for (const refToken of refList) {
        try {
            decoded = decodeJwt(refToken);
            // shortcut immediately if we don't have a revokes field.
            if (decoded.revokes == tokenPayload.jti || decoded.revokes == 'all') {
                // we do have a revokes field, so check if everything else matches appropriately
                if (decoded.kind === 'vch' &&
                    decoded.iss == tokenPayload.iss &&
                    decoded.sub == tokenPayload.sub &&
                    decoded.vch_iss == tokenPayload.vch_iss &&
                    decoded.vch_sum == tokenPayload.vch_sum) {
                    // everything matched, so our token is revoked.
                    return {
                        revokeToken: refToken,
                        decoded: decoded
                    };
                }
            }
        } catch (e) {
            continue;
        }
    }

    // found no revoke tokens in the list, so not revoked
    return undefined;
}

export function isTrustedAnchor(iss, tokenPurpose = [], trustedIssuers = {}, requiredPurposes = []) {
    const anchorPurposes = trustedIssuers?.[iss];
    if (!anchorPurposes) return false;

    const trustedPurposes = {};
    anchorPurposes.forEach(purpose => {
        trustedPurposes[purpose] = true;
    });

    if (trustedPurposes['*']) return true;

    let tokenPurposes = {};
    if (Array.isArray(tokenPurpose)) {
        tokenPurpose.forEach(purpose => {
            tokenPurposes[purpose] = true;
        });
    } else {
        if (typeof tokenPurpose == 'string') {
            tokenPurpose.trim().split(/\s+/).forEach(purpose => {
                tokenPurposes[purpose] = true;
            });
        }
    }

    return requiredPurposes.every(p => tokenPurposes[p] && trustedPurposes[p]);
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

function extractEffectivePurposesFromChain(chain) {
    let effective = null;

    chain.forEach(link => {
        const purposesRaw = link.decoded?.purpose;

        if (typeof purposesRaw === 'string') {
            const purposeList = purposesRaw.trim().split(/\s+/);
            const purposeMap = {};
            purposeList.forEach(p => {
                purposeMap[p] = true;
            });

            if (effective === null) {
                // Initialize effective list
                effective = purposeList.slice();
            } else {
                // Intersect with current list
                effective = effective.filter(p => purposeMap[p]);
            }
        }
        // If no purpose field, do nothing — it's unconstrained
    });

    return effective || [];
}
