import { verifyJwt, decodeJwt } from './jwt.mjs';
import { validateVouchToken, verifyVouchToken, hashJwt, isBurnToken, isRevocationToken } from './vouch.mjs';

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

async function prepareTclean(rawTokens, trustedIssuers) {
    const validated = [];
    const seenIssJTI = new Set();
    const burnedIdentities = new Set();
    let foundTrustedIssuerToken = false;

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

        if (trustedIssuers.hasOwnProperty(current_token.decoded.iss)) {
            foundTrustedIssuerToken = true;
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
    //
    // if we did not find a single trusted issuer in our full token set,
    // there is no way for DAG evaluation to succeed, so every token chain 
    // is effectively invalidated. If we detect this state, we throw an
    // error immediately, before we do any more work. 
    if (!foundTrustedIssuerToken) {
        throw new Error('No Trusted Issuer tokens found in token set, evaluation can not succeed');
    }

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

        // a token that refers to itself should not be form an edge, so should not be in by_subject
        if (!isBurn && decoded.sub != decoded.jti) {
            if (!tokenGraph.by_subject[iss_sub]) {
                tokenGraph.by_subject[iss_sub] = [];
            }
            tokenGraph.by_subject[iss_sub].push(v);
        }
    }

    // Pass 4: Apply revocations after full indexing
    for (const r of revocations) {
        const revoke_token = r.decoded;
        const target_id = tokenId(revoke_token.vch_iss, revoke_token.sub);

        let revoke_candidates = [];

        // get all the tokens that reference this iss/sub
        let vouch_candidates = tokenGraph.by_subject[target_id];
        if (vouch_candidates && vouch_candidates.length > 0) {
            revoke_candidates = [...vouch_candidates];
        }

        // we might be revoking an attestation, in which case
        // we need to look it up directly
        let attest_candidate = tokenGraph.by_iss_jti[target_id];
        if (attest_candidate) {
            revoke_candidates.push(attest_candidate);
        }

        if (!revoke_candidates || revoke_candidates.length === 0) {
            continue;
        }

        // if our revokes field  have to revoke all - we find all
        if (revoke_token.revokes === "all") {
            const remaining = [];
            for (const tok of revoke_candidates) {
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

            for (const tok of revoke_candidates) {
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
    return tokenId(subjectIssuer, subjectJti);
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
function attenuatePurposes(child, parent) {
    //
    // Case 1: Parent = ANY → pass through child unchanged
    //
    if (parent.mode === "any") {
        // clone child
        if (child.mode === "any") {
            return { mode: "any", set: null };
        }
        if (child.mode === "empty") {
            return { mode: "empty", set: new Set() };
        }
        return { mode: "set", set: new Set(child.set) };
    }

    //
    // Case 2: Parent = EMPTY → no delegation allowed at all
    //
    if (parent.mode === "empty") {
        return { mode: "empty", set: new Set() };
    }

    //
    // Case 3: Parent = SET
    //
    if (parent.mode === "set") {

        // If child = ANY → result is just the parent’s set
        if (child.mode === "any") {
            return { mode: "set", set: new Set(parent.set) };
        }

        // If child = EMPTY → stays empty
        if (child.mode === "empty") {
            return { mode: "empty", set: new Set() };
        }

        // child = SET → intersect the two
        const out = new Set();
        for (const p of child.set) {
            if (parent.set.has(p)) {
                out.add(p);
            }
        }

        if (out.size === 0) {
            return { mode: "empty", set: new Set() };
        }

        return { mode: "set", set: out };
    }

    throw new Error("Invalid purpose model: " + parent.mode);
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

function vouchsafeEvaluate(trustGraph, startToken, trustedIssuers, requiredPurposes, options = {}) {

    // Algorithm:
    // We perform a breadth–first search (BFS) over (token, purpose-set) states,
    // starting from the leaf token. Each queue entry represents “we have a concrete
    // path from the leaf to this token, with these effective purposes after all
    // attenuation so far”. On each step we: (1) check whether the current token’s
    // issuer is a trusted root and, if so, whether the accumulated purposes satisfy
    // the caller’s requirements; (2) if not done and within maxDepth, look up all
    // vouch tokens that reference this token as their subject, apply their purpose
    // rules to produce a new purpose-set, and enqueue those as new states. The
    // visited set ensures we never revisit the same token with the same effective
    // purposes, preventing cycles and redundant work.

    // ============================================================
    // OPTION DEFAULTING
    // ============================================================
    if (typeof options.returnAllValidChains === "undefined") {
        options.returnAllValidChains = false;
    }
    if (typeof options.maxDepth === "undefined") {
        options.maxDepth = undefined;  // no limit
    }

    // ============================================================
    // INITIAL LEAF PURPOSE HANDLING
    // ============================================================
    const startDecoded = startToken.decoded;
    const startPurposeModel = purposeModeFromDecoded(startDecoded);

    let initialPurposes;

    // Compute the subject ID (iss/sub pair) of the starting token
    const startSubjectId = subjectIdOf(startDecoded);

    // ============================================================
    // BFS INITIALIZATION
    // ============================================================
    const queue = [];
    queue.push({
        token: startToken,
        purposes: startPurposeModel,
        chain: [ startToken ],
        depth: 0
    });

    // prepareTclean will always produce a DAG, but if for some reason
    // we are given a bad trust graph as input, the visited set ensures we don't loop.

    const visited = new Set();         // mutation explicitly controlled
    const validChains = [];            // collect full valid chains when enabled

    // ============================================================
    // BFS LOOP
    // ============================================================
    while (queue.length > 0) {
        const frame = queue.shift();

        const currentToken    = frame.token;
        const currentDecoded  = currentToken.decoded;
        const currentPurposes = frame.purposes;
        const currentChain    = frame.chain;
        const currentDepth    = frame.depth;

        const currentIssuer = currentDecoded.iss;

        // tokens from burned identities should not have made it onto the graph,
        // so this shouldn't happen, but just in case it slips by somehow: immediately skip if identity is burned
        if (trustGraph.burned_identities.has(currentDecoded.iss)) {
            continue;
        }


        // ========================================================
        // TRUST ROOT CHECK
        // ========================================================
        if (trustedIssuers.hasOwnProperty(currentIssuer)) {

            const allowedRootPurposes = new Set(trustedIssuers[currentIssuer]);
            const effectivePurposes = new Set();

            // Determine which purposes survive at the trust root
            const iter = currentPurposes.set.values();
            while (true) {
                const next = iter.next();
                if (next.done) break;
                const p = next.value;
                if (allowedRootPurposes.has(p)) {
                    effectivePurposes.add(p);
                }
            }

            // If the root grants nothing → not valid
            if (effectivePurposes.size > 0) {

                let chainSatisfiesRequirements = true;

                // ===================================================================================
                // If we have a requiredPurposes, then ALL must be present for this chain to be valid
                // ===================================================================================
                if (Array.isArray(requiredPurposes) && requiredPurposes.length > 0) {
                    // QUICK FAIL:
                    // If the effective set is smaller than the number of required
                    // purposes, it is impossible for all to be present.
                    if (effectivePurposes.size < requiredPurposes.length) {
                        chainSatisfiesRequirements = false;
                    } else {
                        // FULL CHECK:
                        // Our effective set has the same number or more purposes, so we need to
                        // ensure that every required purpose is present in effectivePurposes.
                        for (let i = 0; i < requiredPurposes.length; i++) {
                            const req = requiredPurposes[i];
                            if (!effectivePurposes.has(req)) {
                                chainSatisfiesRequirements = false;
                                break;
                            }
                        }
                    }
                }

                if (chainSatisfiesRequirements) {
                    if (options.returnAllValidChains === true) {
                        // NOTE (Mutation):
                        // Store a *copy* of the chain because BFS will mutate future frames.
                        validChains.push({
                            chain: currentChain.slice(),
                            purposes: Array.from(effectivePurposes),
                            trustRoot: currentIssuer
                        });
                    } else {
                        return {
                            valid: true,
                            chains: [
                                {
                                    chain: currentChain.slice(),
                                    purposes: Array.from(effectivePurposes),
                                    trustRoot: currentIssuer
                                }
                            ],
                            effectivePurposes: Array.from(effectivePurposes),
                            subjectToken: startToken,
                            trustRoot: currentIssuer
                        };
                    }
                }
            }
        }

        // ========================================================
        // MAX DEPTH CHECK
        // ========================================================
        if (typeof options.maxDepth === "number" && currentDepth >= options.maxDepth) {
            continue;
        }

        // ========================================================
        // UPWARD TRAVERSAL
        // ========================================================

        // For upward traversal, the "subject" we are looking for is the
        // current token itself: any vouch tokens whose subject is this
        // token's (iss, jti) pair.
        //
        // prepareTclean() indexes by_subject using that (iss, jti) of the
        // *token being vouched for*, so we must use the current token's
        // own identity here.
        const subjectId = currentDecoded.iss + "/" + currentDecoded.jti;

        const parents = trustGraph.by_subject[subjectId];


        if (!parents) {
            continue; // No further edges upward
        }

        for (let i = 0; i < parents.length; i++) {
            const parentToken = parents[i];
            const parentDecoded = parentToken.decoded;

            // Only vouch tokens propagate upward
            if (parentDecoded.kind !== "vch:vouch") {
                continue;
            }

            const parentPurposeModel = purposeModeFromDecoded(parentDecoded);
            const nextPurposes = attenuatePurposes(currentPurposes, parentPurposeModel);

            if (!nextPurposes) {
                continue; // Parent wipes out all purposes
            }

            // Build visit key based on issuer + jti + purpose-mode
            let visitKey;
            if (parentPurposeModel.mode === "any") {
                visitKey = makeVisitKey(parentDecoded, "ANY");
            } else if (parentPurposeModel.mode === "empty") {
                visitKey = makeVisitKey(parentDecoded, "EMPTY");
            } else {
                visitKey = makeVisitKey(parentDecoded, nextPurposes);
            }

            if (visited.has(visitKey)) {
                continue;
            }

            // NOTE (Mutation):
            // Marking visited before enqueueing ensures we never requeue
            visited.add(visitKey);

            // NOTE (Mutation):
            // Construct new chain frame by cloning old chain
            const nextChain = currentChain.slice();
            nextChain.push(parentToken);

            // Enqueue upward step
            queue.push({
                token: parentToken,
                purposes: nextPurposes,
                chain: nextChain,
                depth: currentDepth + 1
            });
        }
    }

    // ============================================================
    // AGGREGATE / RETURN RESULTS
    // ============================================================

    // At this point, any chain in validChains has already satisfied
    // requiredPurposes (if provided). We do NOT aggregate permissions
    // across chains; each chain is evaluated independently and its
    // purposes are self-contained. The caller can union them if they
    // wish, but that is application policy, not core trust logic.

    if (validChains.length === 0) {
        return {
            valid: false,
            chains: [],
            effectivePurposes: []
        };
    }

    // We treat the purposes on the first valid chain as the effective
    // purposes for this evaluation. This is conservative: it never
    // grants more than a single justified chain supports.
    const primaryChain = validChains[0];

    return {
        valid: true,
        chains: validChains,
        effectivePurposes: Array.from(primaryChain.purposes),
        // if you’ve added trustRoot on each chain object, this gives the
        // caller enough data to know which issuer granted these purposes.
        subjectToken: startToken,
        trustRoot: primaryChain.trustRoot
    };
}




// ---------------------------------------------------------------------------
// validateTrustChain(tokens, startToken, trustedIssuers, purposes, options = {})
//
// This is the canonical entrypoint for Vouchsafe trust validation.
// Steps:
//   1.  Clean and normalize the raw token set (prepareTclean)
//   2.  Evaluate the trust graph starting from startToken
//   3.  Return the result of vouchsafeEvaluate
//
// Parameters:
//   tokens          : Array of raw JWT strings
//   startToken      : The parsed { token, decoded, hash } object for the
//                     leaf token whose trust we want to validate.
//   trustedIssuers  : Map of trusted roots -> allowed purposes
//                     e.g. { "urn:vouchsafe:root.ab...": ["msg-signing", ...] }
//   purposes        : Optional array of purposes to filter final output
//   options         : evaluator behavior controls:
//      maxDepth     : Optional integer limiting chain depth
//
// Returns:
//   {
//     valid: boolean,
//     chains: [...],
//     effectivePurposes: [...]
//   }
//
// ---------------------------------------------------------------------------

export async function validateTrustChain(tokens, givenStartToken, trustedIssuers, purposes, options = {}) {


    // our Token set must include the start token so the graph can be built.
    // if start token is already present → safe to use as-is - otherwise copy + append
    const tokenSet = tokens.includes(givenStartToken) ? tokens : [...tokens, givenStartToken];

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
    let trustGraph;
    try {
        trustGraph = await prepareTclean(tokenSet, trustedIssuers);
    } catch(e) {
        // an error here likely means we had bad tokens or we don't have
        // any trustedIssuer issued tokens. Either way, we can not
        // continue
        console.error('Error encountered while preparing Tclean: ', e);
        return {
            valid: false,
            chains: [],
            effectivePurposes: []
        };
    }


    // decode the given start token so we can ensure it's still part of the 
    // cleaned token graph
    let startToken = await decodeToken(givenStartToken);

    // load our start token from the graph
    let found_start_token = trustGraph.by_iss_jti[tokenId(startToken.decoded.iss, startToken.decoded.jti)];

    // if we didn't find our start token, 
    // it was likely revoked or burned. Fail immediately.
    if (typeof found_start_token != 'object') {
        return {
            valid: false,
            chains: [],
            effectivePurposes: []
        };
    };

    // -----------------------------------------------------------------------
    // Step 2:
    // Evaluate trust using the pure evaluator.
    //
    // vouchsafeEvaluate:
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
    const result = vouchsafeEvaluate(
        trustGraph,
        found_start_token,
        trustedIssuers,
        purposes,
        options
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

