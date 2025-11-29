import { verifyJwt, decodeJwt } from './jwt.mjs';
import { validateVouchToken, verifyVouchToken, hashJwt } from './vouch.mjs';

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
    prepareTclean([currentToken].concat(tokens));

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

function isBurnToken(token) {
    if (token.kind == 'vch:burn') { 
        if (token.burns == token.iss) {
            return true;
        } else {
            throw new Error('Invalid Burn token, burns is defined but does not match issuer');
        }
    } else {
        return false;
    }
}

function isRevocationToken(token) {
    if (token.kind == 'vch:revoke') {
        if (typeof token.revokes == 'string') {
            return true;
        } else {
            throw new Error('Invalid Revoke token, no valid revoke target');
        }
    } else {
        return false;
    } 
}

// this just gives us a stable identifier for lookup.
// we use it in a lot of places, so this gives us 
// a consistent formulation of the lookup string.
function tokenId(iss, jti) {
    if (iss.length < 70) {
        throw new Error('invalid iss, too short: ', iss);
    }
    if (jti.length != 36) {
        throw new Error('invalid jti, too short:', jti);
    }
    return iss + "/" + jti;
}

export async function decodeToken(raw_token) {
    let token_obj = {
        token: raw_token
    };
    token_obj.decoded = await validateVouchToken(raw_token);
    token_obj.hash = await hashJwt(raw_token, "sha256");
    return token_obj;
}


export async function prepareTclean(rawTokens) {
    const validated = [];
    const seenIssJTI = new Set();
    const burnedIdentities = new Set();

    //console.log('raw', JSON.stringify(rawTokens, undefined, 4));
    // Step 1: Collect our valid tokens, validate, decode, compute token hash.
    // Deduplicate on jti.
    for (const raw of rawTokens) {
        let current_token;
        try {
            current_token = await decodeToken(raw);
        } catch(e) {
            console.error('Unable to decode token: ', e);
            continue;
        }
            
        //console.log('decoded: ', current_token);

        const issjti = tokenId(current_token.decoded.iss, current_token.decoded.jti)
        //console.log('issjti: ', issjti);

        if (seenIssJTI.has(issjti)) {
            continue;
        }
        seenIssJTI.add(issjti);

        // if we are here, the token decoded correctly and validated 
        // so add it to our valid token list
        validated.push(current_token);

        // if the token is a burn token, make note of it, we'll need it in a minute. 
        if (isBurnToken(current_token.decoded)) {
            burnedIdentities.add(current_token.decoded.iss);
        }
    }
    //console.log(validated);

    // Pass 3: Start building our graph structure - filling in by_jti and by_sub for all non-revocation tokens.
    const tokenGraph = {
        by_iss_jti: {},
        by_subject: {},
        burned_identities: burnedIdentities
    };
    const revocations = [];

    // loop over our valid tokens
    for (const v of validated) {
        const decoded = v.decoded;

        // Burn tokens always included, never filtered out
        const isBurn = isBurnToken(decoded);

        // If issuer is burned and this is not the burn token, skip it
        if (burnedIdentities.has(decoded.iss) && !isBurn) {
            continue;
        }

        if (isRevocationToken(decoded)) {
            revocations.push(v);
            continue;
        }

        const token_id = tokenId(decoded.iss, decoded.jti);
        // Index by jti
        tokenGraph.by_iss_jti[token_id] = v;

        const subject_iss = decoded.vch_iss || decoded.iss;
        // Index by sub for graph construction and revocation
        let iss_sub = tokenId(subject_iss, decoded.sub);

        if (!tokenGraph.by_subject[iss_sub]) {
            tokenGraph.by_subject[iss_sub] = [];
        }
        tokenGraph.by_subject[iss_sub].push(v);
    }

    // Pass 4: Apply revocations after full indexing
    for (const r of revocations) {
        const revoke_token = r.decoded;

        const target_id = tokenId(revoke_token.vch_iss, revoke_token.sub);

        // get all the tokens that reference this iss/sub
        const candidates = tokenGraph.by_subject[target_id];
        if (!candidates || candidates.length === 0) {
            continue;
        }

        // if our revokes field  have to revoke all - we find all 
        if (revoke_token.revokes === "all") {
            const remaining = [];
            for (const tok of candidates) {
                const candidate_token = tok.decoded;
                // we don't revoke burns or other revokes.
                if (isBurnToken(candidate_token) || isRevocationToken(candidate_token)) {
                    continue;
                }
                const candidate_id = tokenId(candidate_token.iss, candidate_token.jti);

                // We have to check multiple items to know if we can revoke.
                
                // First, revoke tokens can only revoke from the same issuer for the same subject.
                if ( candidate_token.iss === revoke_token.iss && candidate_token.sub === revoke_token.sub && 
                     candidate_token.kind === "vch:vouch" && revoke_token.vch_iss === candidate_token.vch_iss && 
                     revoke_token.vch_sum === candidate_token.vch_sum) {

                    delete tokenGraph.by_iss_jti[candidate_id];
                } else {
                    remaining.push(tok);
                }
            }
            tokenGraph.by_subject[target_id] = remaining;
        } else {
            const remaining = [];

            for (const tok of candidates) {
                const candidate_token = tok.decoded;
                const candidate_hash = tok.hash;
                if (isBurnToken(candidate_token) || isRevocationToken(candidate_token)) {
                    continue;
                }

                const candidate_id = tokenId(candidate_token.iss, candidate_token.jti);
                // First, revoke tokens can only revoke from the same issuer for the same subject.
                if ( candidate_token.jti === revoke_token.revokes && candidate_token.iss === revoke_token.iss && candidate_token.sub === revoke_token.sub ) {
                    // They must also have a matching sub, vch_iss, and vch_sum (to be sure they are referencing the correct token)
                    if (candidate_token.kind === "vch:vouch" && revoke_token.vch_iss === candidate_token.vch_iss && revoke_token.vch_sum === candidate_token.vch_sum) {
                        delete tokenGraph.by_iss_jti[candidate_id];
                    } else if (candidate_token.kind === "vch:attest" && revoke_token.vch_iss === candidate_token.iss && revoke_token.vch_sum === candidate_hash) {
                        // if revoking an attest, the vch_iss matches iss and vch_sum matches the hash of the canditate token
                        delete tokenGraph.by_iss_jti[candidate_id];
                    } else {
                        remaining.push(tok);
                    }
                } else {
                    remaining.push(tok);
                }
            }

            tokenGraph.by_subject[target_id] = remaining;
        }
    }

    //console.log(JSON.stringify(tokenGraph, undefined, 4));
    return tokenGraph;
}

// --------------------------------------------
// Build consistent subject identifier
// This is used for graph traversal.
// --------------------------------------------
function subjectIdOf(decoded) {
    const subjectIssuer = decoded.vch_iss || decoded.iss;
    const subjectJti    = decoded.sub;
    return subjectIssuer + "/" + subjectJti;
}


// --------------------------------------------
// Purpose extraction
// Three modes:
//   mode: "any"   — parent has no purpose field (no attenuation)
//   mode: "empty" — purpose: "" (delegates nothing)
//   mode: "set"   — explicit space-separated list
// --------------------------------------------
function purposeModeFromDecoded(decoded) {

    // CASE A: purpose omitted → treat as S_Any
    if (!decoded.hasOwnProperty("purpose")) {
        return { mode: "any", set: null };
    }

    const raw = decoded.purpose;

    // CASE B: explicit empty string
    if (typeof raw === "string" && raw.trim() === "") {
        return { mode: "empty", set: new Set() };
    }

    // CASE C: explicit space-separated list
    const parts = raw.trim().split(/\s+/);
    return { mode: "set", set: new Set(parts) };
}


// --------------------------------------------
// Intersect incoming purposeSet with parent’s
// delegation purpose model.
// Also handles S_Any, S_Empty.
// Returns null if delegation stops.
// --------------------------------------------
function attenuatePurposes(currentPurposes, parentPurposeModel) {

    // parent omitted purpose → S_Any → pass-through
    if (parentPurposeModel.mode === "any") {
        // NOTE (Mutation comment):
        // We clone the incoming purpose set to avoid accidentally altering
        // previously-existing evaluation state.
        return new Set(currentPurposes);
    }

    // parent purpose = "" → S_Empty → no delegation
    if (parentPurposeModel.mode === "empty") {
        return null; // halt delegation
    }

    // normal intersection case
    if (parentPurposeModel.mode === "set") {
        const intersection = new Set();
        for (const p of parentPurposeModel.set) {
            if (currentPurposes.has(p)) {
                intersection.add(p);
            }
        }
        if (intersection.size === 0) {
            return null; // attenuation eliminated all purposes
        }
        return intersection;
    }

    throw new Error("Invalid purpose model");
}


// --------------------------------------------
// Create visit key encoding (issuer/jti + purpose mode)
// Ensures evaluator does not revisit identical evaluation states.
// --------------------------------------------
function makeVisitKey(decoded, purposeSetOrModel) {

    const tokenId = decoded.iss + "/" + decoded.jti;

    if (purposeSetOrModel === "ANY") {
        return tokenId + "|ANY";
    }

    if (purposeSetOrModel === "EMPTY") {
        return tokenId + "|EMPTY";
    }

    // It's a concrete Set of purposes
    const arr = Array.from(purposeSetOrModel).sort();
    return tokenId + "|" + arr.join(",");
}

function vouchsafe_evaluate(trustGraph, startToken, trustedIssuers, purposes, maxDepth) {

    // Extract starting token's decoded payload
    const startDecoded = startToken.decoded;

    // Determine initial purpose model of the leaf token
    const startPurposeModel = purposeModeFromDecoded(startDecoded);

    // Determine initial concrete purpose set for traversal.
    // NOTE:
    //   S_Any (no purpose claim) means "pass through whatever comes in".
    //   For the leaf token, this typically results in an empty set unless
    //   the caller filters for specific purposes later.
    let initialPurposes;
    if (startPurposeModel.mode === "any") {
        initialPurposes = new Set();
    } else if (startPurposeModel.mode === "empty") {
        initialPurposes = new Set();
    } else {
        initialPurposes = new Set(startPurposeModel.set);
    }

    // Compute the subject ID for the starting token.
    const startSubjectId = subjectIdOf(startDecoded);

    // BFS queue
    const queue = [];
    queue.push({
        token: startToken,
        purposes: initialPurposes,
        chain: [ startToken ],
        depth: 0
    });

    // State to prevent revisiting identical evaluation states
    const visited = new Set();

    // Collect all valid upward chains that reach trusted issuers
    const validChains = [];

    // ============================================================
    // BFS Evaluation Loop
    // ============================================================

    while (queue.length > 0) {
        const frame = queue.shift();

        const currentToken     = frame.token;
        const currentDecoded   = currentToken.decoded;
        const currentPurposes  = frame.purposes;
        const currentChain     = frame.chain;
        const currentDepth     = frame.depth;

        const currentIssuer = currentDecoded.iss;

        // ========================================================
        // TRUST ROOT ACCEPTANCE
        // ========================================================
        if (trustedIssuers.hasOwnProperty(currentIssuer)) {

            const allowedPurposes = new Set(trustedIssuers[currentIssuer]);
            const effectivePurposes = new Set();

            // Determine intersection of currentPurposes with allowedPurposes
            for (const p of currentPurposes) {
                if (allowedPurposes.has(p)) {
                    effectivePurposes.add(p);
                }
            }

            if (effectivePurposes.size > 0) {
                // NOTE (Mutation):
                // clone the chain so stored result is not mutated by future BFS steps
                validChains.push({
                    chain: currentChain.slice(),
                    purposes: Array.from(effectivePurposes)
                });
            }
        }

        // ========================================================
        // DEPTH LIMIT
        // ========================================================
        if (typeof maxDepth === "number" && currentDepth >= maxDepth) {
            continue;
        }

        // ========================================================
        // UPWARD TRAVERSAL
        // ========================================================
        const subjectId = subjectIdOf(currentDecoded);

        // Parents are all tokens whose subject is this token
        const parents = trustGraph.by_subject[subjectId];
        if (!parents) {
            continue; // dead end, no more upward traversal
        }

        for (let i = 0; i < parents.length; i++) {
            const parentToken = parents[i];
            const parentDecoded = parentToken.decoded;

            // Only vch:vouch propagates trust upward
            if (parentDecoded.kind !== "vch:vouch") {
                continue;
            }

            // Get parent's purpose mode
            const parentPurposeModel = purposeModeFromDecoded(parentDecoded);

            // Apply attenuation rules
            const nextPurposes = attenuatePurposes(currentPurposes, parentPurposeModel);
            if (!nextPurposes) {
                // Parent does not propagate usable purposes
                continue;
            }

            // Build visit key (purpose mode must be encoded)
            let visitKey;
            if (parentPurposeModel.mode === "any") {
                visitKey = makeVisitKey(parentDecoded, "ANY");
            } else if (parentPurposeModel.mode === "empty") {
                visitKey = makeVisitKey(parentDecoded, "EMPTY");
            } else {
                visitKey = makeVisitKey(parentDecoded, nextPurposes);
            }

            // Prevent revisiting same state
            if (visited.has(visitKey)) {
                continue;
            }

            // NOTE (Mutation):
            // Mark as visited before enqueueing, ensuring deterministic traversal
            visited.add(visitKey);

            // NOTE (Mutation):
            // Clone previous chain to construct new BFS chain frame
            const nextChain = currentChain.slice();
            nextChain.push(parentToken);

            // Enqueue next BFS frame
            queue.push({
                token: parentToken,
                purposes: nextPurposes,
                chain: nextChain,
                depth: currentDepth + 1
            });
        }
    }

    // ============================================================
    // AGGREGATE RESULT
    // ============================================================
    const aggregate = new Set();
    for (let i = 0; i < validChains.length; i++) {
        const vc = validChains[i];
        for (let j = 0; j < vc.purposes.length; j++) {
            const p = vc.purposes[j];
            // If caller supplied purposes, restrict to those
            if (!purposes || purposes.includes(p)) {
                aggregate.add(p);
            }
        }
    }

    return {
        valid: aggregate.size > 0,
        chains: validChains,
        effectivePurposes: Array.from(aggregate)
    };
}

// ---------------------------------------------------------------------------
// validateTrustChain(tokens, startToken, trustedIssuers, purposes, maxDepth)
//
// This is the canonical entrypoint for Vouchsafe trust validation.
// Steps:
//   1.  Clean and normalize the raw token set (prepareTclean)
//   2.  Evaluate the trust graph starting from startToken
//   3.  Return the result of vouchsafe_evaluate
//
// Parameters:
//   tokens          : Array of raw JWT strings
//   startToken      : The parsed { token, decoded, hash } object for the
//                     leaf token whose trust we want to validate.
//   trustedIssuers  : Map of trusted roots -> allowed purposes
//                     e.g. { "urn:vouchsafe:root.ab...": ["msg-signing", ...] }
//   purposes        : Optional array of purposes to filter final output
//   maxDepth        : Optional integer limiting chain depth
//
// Returns:
//   {
//     valid: boolean,
//     chains: [...],
//     effectivePurposes: [...]
//   }
//
// ---------------------------------------------------------------------------

export async function validateTrustChain(tokens, startToken, trustedIssuers, purposes, maxDepth) {

    // start token may be a token string or a decoded token object. 
    // we need the latter so if we got a string, decode it ourselves.
    let realStartToken = startToken;
    if (typeof startToken == 'string') {
        realStartToken = decodeToken(startToken);
    }
    // -----------------------------------------------------------------------
    // Step 1:
    // Clean and normalize the token set.
    //
    // prepareTclean:
    //   - decodes tokens and removes any invalid tokens from the list
    //   - validates signatures and required fields
    //   - deduplicates tokens
    //   - detects burn tokens
    //   - removes tokens issued by burned identities
    //   - indexes tokens by (iss/jti) and by subject
    //   - pre-applies revocation tokens
    //
    // This produces a fully self-contained trustGraph suitable
    // for pure, offline ZI-CG evaluation.
    // -----------------------------------------------------------------------
    const trustGraph = await prepareTclean(tokens);

    // -----------------------------------------------------------------------
    // Step 2:
    // Evaluate trust using the pure evaluator.
    //
    // vouchsafe_evaluate:
    //   - performs BFS upward through vouch edges
    //   - applies purpose attenuation rules
    //   - respects revocation pruning already performed in Step 1
    //   - checks root trust constraints
    //   - collects all valid root-terminating chains
    //   - returns union-of-capabilities from roots
    //
    // No network access, no external state, no online resolution.
    // A perfect ZI-CG evaluation.
    // -----------------------------------------------------------------------
    const result = vouchsafe_evaluate(
        trustGraph,
        realStartToken,
        trustedIssuers,
        purposes,
        maxDepth
    );

    // -----------------------------------------------------------------------
    // Step 3:
    // Return final evaluation output.
    //
    // This includes:
    //   valid              → boolean: whether any trusted issuer granted a purpose
    //   chains             → all valid chains discovered
    //   effectivePurposes  → all purposes granted across all valid chains
    // -----------------------------------------------------------------------
    return result;
}

