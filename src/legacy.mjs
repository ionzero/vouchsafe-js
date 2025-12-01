import { validateTrustChain } from './trustchain.mjs';  // adjust path as needed

/**
 * Legacy-style verifyTrustChain wrapper.
 *
 * This preserves the older API:
 *
 *   const result = await verifyTrustChain(subject, trusted, {
 *       tokens: chainTokens,
 *       purposes,
 *       maxDepth,   // optional
 *       findAll     // optional: true => returnAllValidChains
 *   });
 *
 * Returned shape:
 * {
 *     valid: true/false,
 *     leaf: {
 *         token: <subjectToken.token>,
 *         payload: <subjectToken.decoded>
 *     },
 *     trustRoot: <last token object on the first valid chain>,
 *     chain: <array of token objects from subject → trust root>,
 *     purposes: <purposes that survived on that chain>
 * }
 */
export async function verifyTrustChain(subjectTokenInput, trustedIssuers, options) {

    if (!options) {
        options = {};
    }

    // ---------------------------------------------------------------------
    // 1. Normalize the token set.
    //    The legacy API passes `options.tokens` as the set of tokens
    //    available to the evaluator. We must ensure the subject token
    //    is also present in that set.
    // ---------------------------------------------------------------------
    const tokens = [];

    if (options.tokens && Array.isArray(options.tokens)) {
        for (let i = 0; i < options.tokens.length; i++) {
            tokens.push(options.tokens[i]);
        }
    }

    // NOTE (Mutation): prepend the subject token to the token list.
    // This guarantees the subject is included even if the caller forgot.
    // prepareTclean/validateTrustChain will handle deduplication.
    tokens.unshift(subjectTokenInput);

    // ---------------------------------------------------------------------
    // 2. Extract required purposes (legacy name: `purposes`).
    // ---------------------------------------------------------------------
    let requiredPurposes = null;
    if (options.purposes && Array.isArray(options.purposes)) {
        requiredPurposes = options.purposes;
    }

    // ---------------------------------------------------------------------
    // 3. Map legacy options → new evaluator options.
    //
    //    - maxDepth        → maxDepth
    //    - findAll: true   → returnAllValidChains: true
    // ---------------------------------------------------------------------
    const evalOptions = {};

    if (typeof options.maxDepth === "number") {
        evalOptions.maxDepth = options.maxDepth;
    }

    if (options.findAll === true) {
        evalOptions.returnAllValidChains = true;
    }

    // ---------------------------------------------------------------------
    // 4. Delegate to validateTrustChain.
    //    This performs:
    //      - token decoding + cleaning
    //      - graph construction
    //      - revocation/burn handling
    //      - BFS traversal and purpose intersection
    // ---------------------------------------------------------------------
    const evalResult = await validateTrustChain(
        tokens,
        subjectTokenInput,
        trustedIssuers,
        requiredPurposes,
        evalOptions
    );

    // If the evaluation failed, return a legacy-shaped failure result.
    if (!evalResult || evalResult.valid !== true) {
        return {
            valid: false,
            leaf: null,
            trustRoot: null,
            chain: [],
            purposes: []
        };
    }

    // ---------------------------------------------------------------------
    // 5. Extract the first valid chain and map to the legacy structure.
    //
    //    - leaf         → evalResult.subjectToken
    //    - trustRoot    → last token on the first valid chain
    //    - chain        → that chain's token list
    //    - purposes      → that chain's purposes
    // ---------------------------------------------------------------------
    let firstChain = null;

    if (evalResult.chains && Array.isArray(evalResult.chains) && evalResult.chains.length > 0) {
        firstChain = evalResult.chains[0];
    }

    const leafToken = evalResult.subjectToken || null;

    let chainArray = [];
    let trustRootToken = null;
    let chainPurposes = [];

    if (firstChain) {
        if (firstChain.chain && Array.isArray(firstChain.chain)) {
            chainArray = firstChain.chain;

            if (firstChain.chain.length > 0) {
                // The trust root is the last token on the chain.
                trustRootToken = firstChain.chain[firstChain.chain.length - 1];
            }
        }

        if (firstChain.purposes && Array.isArray(firstChain.purposes)) {
            chainPurposes = firstChain.purposes;
        }
    }

    // Legacy `leaf` shape: { token, payload }
    let legacyLeaf = null;
    if (leafToken) {
        legacyLeaf = {
            token: leafToken.token,
            payload: leafToken.decoded
        };
    }

    return {
        valid: true,
        leaf: legacyLeaf,
        trustRoot: trustRootToken,
        chain: chainArray,
        purposes: chainPurposes
    };
}
