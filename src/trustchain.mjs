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

    return async function resolveFn(kind, iss, jti) {
        const key = `${iss}->${jti}`;
        if (kind === 'token') {
            const token = map[key];
            return token; // return token or undefined if not found
        } else if (kind === 'ref') {
            return reverse[key] || [];
        } else {
            throw new Error(`Unknown resolve kind: ${kind}`);
        }
    };
}

export function createCompositeResolver(staticFn, dynamicFn) {
    return async function resolve(kind, iss, jti) {
        let result;
        let staticResult = [];
        let dynamicResult = [];
        if (kind == 'token') {
            result = await staticFn(kind, iss, jti);
	    if (!result) {
                result = await dynamicFn(kind, iss, jti);
            }
            return result;
        } else {
            // we are doing a ref lookup. We need both static and 
            // dynamic results.
            try {
                staticResult = await staticFn(kind, iss, jti);
            } catch(e) {
                // do nothing - we need to do a dynamic lookup anyway
            }
            // we want dynamicFn exceptions to bubble up.
            dynamicResult = await dynamicFn(kind, iss, jti);
            result = [].concat(staticResult, dynamicResult);
            return result;
        }
    };
}

// Helper: validate or decode a token
async function decodeOrVerify(token, providedKey) {
    let decoded, validated = false;
    try {
        decoded = await verifyJwt(token, {
            pubKeyOverride: providedKey
        });
        if (decoded.kind === 'vch') await validateVouchToken(token);
        validated = true;
    } catch (err) {
        if (providedKey) {
            // We were told exactly which key to use; failure is fatal.
            throw new Error(`Invalid token: ${err.message}`);
        }
        decoded = await decodeJwt(token, {
            pubKeyOverride: providedKey
        });
    }
    return {
        decoded,
        validated
    };
}

function reconstructChain(leafKey, endKey, parentMap, linkByKey) {
    const chain = [];
    let cur = endKey;
    while (cur) {
        const link = linkByKey.get(cur);
        if (!link) break;
        chain.push(link);
        cur = parentMap.get(cur);
    }
    // cur should be leafKey by now; push it if not already present
    if (chain.length === 0 || `${chain[chain.length - 1].decoded.iss}:${chain[chain.length - 1].decoded.jti}` !== leafKey) {
        const leafLink = linkByKey.get(leafKey);
        if (leafLink) chain.push(leafLink);
    }
    chain.reverse(); // leaf → ... → trustRoot
    return chain;
}

export async function verifyTrustChain(
    currentToken,
    trustedIssuers, {
        purposes = [],
        maxDepth = 10,
        resolveFn,
        tokenKey,
        tokens,
        findAll, // if true, returns { valid:true, paths:[...chains...] }
        trustAnchorLookup = isTrustedAnchor
    } = {}
) {
    if (maxDepth <= 0) {
        return {
            valid: false,
            reason: 'max-depth'
        };
    }

    // Build a resolver if needed (static list + optional composite)
    if (tokens || typeof resolveFn === 'undefined') {
        let tokenList = [currentToken];
        if (Array.isArray(tokens)) tokenList = tokenList.concat(tokens);
        let newResolver = makeStaticResolver(tokenList);
        if (typeof resolveFn === 'function') {
            newResolver = createCompositeResolver(newResolver, resolveFn);
        }
        resolveFn = newResolver;
    }


    // Leaf (the originally supplied token)
    let leafDecoded, leafValidated;
    try {
        ({
                decoded: leafDecoded,
                validated: leafValidated
            } =
            await decodeOrVerify(currentToken, tokenKey));
    } catch (err) {
        return {
            valid: false,
            reason: err.message || 'invalid'
        };
    }

    // Quick exit: if leaf is directly trusted
    if (await trustAnchorLookup(leafDecoded.iss, leafDecoded.purpose, trustedIssuers, purposes)) {
        const link = {
            token: currentToken,
            decoded: leafDecoded,
            validated: leafValidated,
            trusted: true
        };
        return {
            valid: true,
            leaf: link,
            trustRoot: link,
            chain: [link],
            purposes: extractEffectivePurposesFromChain([link]), 
        };
    }

    // We’ll do a bounded breadth-first search up to maxDepth.
    // Each queue item is { token, decoded, validated, depth }.
    // parentMap maps "iss:jti" to the parent key.
    const queue = [];
    const parentMap = new Map(); // childKey -> parentKey
    const linkByKey = new Map(); // key -> { token, decoded, validated, trusted? }
    const visited = new Set(); // key

    const leafKey = `${leafDecoded.iss}:${leafDecoded.jti}`;
    linkByKey.set(leafKey, {
        token: currentToken,
        decoded: leafDecoded,
        validated: leafValidated
    });
    queue.push({
        token: currentToken,
        decoded: leafDecoded,
        validated: leafValidated,
        depth: 0
    });
    visited.add(leafKey);

    // If findAll we collect all ending chains; else first one wins.
    const foundChains = [];

    while (queue.length > 0) {
        const {
            token,
            decoded,
            validated,
            depth
        } = queue.shift();

        if (depth >= maxDepth) continue;

        // Resolve refs: “vouches show up by looking at the jti”
        const refs = await resolveFn('ref', decoded.iss, decoded.jti) || [];

        // Verify/prepare refs, build revoke map first
        const revokeMap = {};
        const decodedRefs = [];

        for (const refToken of refs) {
            try {
                const refVerified = await verifyJwt(refToken);
                const tObj = {
                    iss: refVerified.iss,
                    jti: refVerified.jti,
                    decoded: refVerified,
                    token: refToken
                };

                if (typeof refVerified.revokes === 'string') {
                    tObj.revokes = refVerified.revokes;
                    revokeMap[`${refVerified.iss}:${refVerified.revokes}`] = tObj;
                } else {
                    // If our current node (the token we’re expanding) was not validated,
                    // confirm we’re referring to the correct token using sub_key.
                    if (!validated) {
                        try {
                            await verifyJwt(token, {
                                pubKeyOverride: refVerified.sub_key
                            });
                            decodedRefs.push(tObj);
                        } catch (e) {
                            // skip: this ref doesn't match our unvalidated parent by sub_key
                        }
                    } else {
                        decodedRefs.push(tObj);
                    }
                }
            } catch {
                // skip invalid ref tokens
            }
        }

        // Filter by revocation and purposes
        const validNext = decodedRefs.filter((tObj) => {
            if (revokeMap[`${tObj.iss}:${tObj.jti}`] || revokeMap[`${tObj.iss}:all`]) return false;

            const p = tObj.decoded.purpose;
            if (typeof p === 'string' && purposes.length) {
                const tokenPurposes = Object.create(null);
                p.trim().split(/\s+/).forEach((x) => (tokenPurposes[x] = true));
                return purposes.every((req) => tokenPurposes[req] === true);
            }
            return true;
        });

        // Enqueue next tokens, record parents, and check for trust anchors
        for (const next of validNext) {
            const nextKey = `${next.decoded.iss}:${next.decoded.jti}`;
            if (visited.has(nextKey)) continue;

            visited.add(nextKey);
            linkByKey.set(nextKey, {
                token: next.token,
                decoded: next.decoded,
                validated: true // we verified above with verifyJwt
            });
            parentMap.set(nextKey, `${decoded.iss}:${decoded.jti}`);

            // Anchor?
            const isAnchor = await trustAnchorLookup(next.decoded.iss, next.decoded.purpose, trustedIssuers, purposes);
            if (isAnchor) {
                // Reconstruct chain from leaf → this anchor
                const chain = reconstructChain(leafKey, nextKey, parentMap, linkByKey);
                // Mark trustRoot
                chain[chain.length - 1].trusted = true;

                if (findAll) {
                    foundChains.push(chain);
                    // Keep searching for more, but respect maxDepth naturally
                } else {
                    return {
                        valid: true,
                        leaf: chain[0],
                        trustRoot: chain[chain.length - 1],
                        chain,
                        purposes: extractEffectivePurposesFromChain(chain),
                    };
                }
            } else {
                // Continue traversal
                if (depth + 1 < maxDepth) {
                    queue.push({
                        token: next.token,
                        decoded: next.decoded,
                        validated: true,
                        depth: depth + 1
                    });
                }
            }
        }
    }

    if (findAll && foundChains.length) {
        // Normalize to the same shape as the single-path result, but with paths[]
        return {
            valid: true,
            leaf: foundChains[0][0],
            trustRoot: foundChains[0][foundChains[0].length - 1],
            chain: foundChains[0],
            paths: foundChains
        };
    }

    return {
        valid: false,
        reason: 'untrusted'
    };

    // ------- helpers --------

}

export function isRevoked(tokenPayload, refList) {
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

export async function isTrustedAnchor(iss, tokenPurpose = [], trustedIssuers = {}, requiredPurposes = []) {
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
