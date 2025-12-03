/* eslint-env mocha */
import assert from 'assert';
import {
    createVouchsafeIdentity,
    createAttestation,
    createVouchToken,
    validateTrustChain,
    validateVouchToken
} from '../src/index.mjs';

// Utility: generate a "junk" vouch chain that should never validate
async function generateNoiseChain(count) {
    const ids = [];
    const tokens = [];

    // Create a bunch of random identities
    for (let i = 0; i < count; i++) {
        ids.push(await createVouchsafeIdentity(`noise${i}`));
    }

    // Make a simple chain:
    // attestation0 <- vouch1 <- vouch2 <- ... (none from trusted issuers)
    const leafAtt = await createAttestation(ids[0].urn, ids[0].keypair, {
        purpose: 'demo'
    });
    tokens.push(leafAtt);

    let subject = leafAtt;

    for (let i = 1; i < count; i++) {
        const v = await createVouchToken(subject, ids[i].urn, ids[i].keypair, {
            purpose: 'demo'
        });
        tokens.push(v);
        subject = v;
    }

    return tokens;
}

describe('Short-circuit trust-chain evaluation', function () {
    this.timeout(10000);

    it('fails immediately when the token set contains no trusted issuers', async () => {
        // Create a trusted issuer (not present in the noise token set)
        const trustedIssuer = await createVouchsafeIdentity('trusted-root');

        const trustedIssuers = {
            [trustedIssuer.urn]: ['demo']
        };

        // Generate a large token set with *zero* appearance of the trusted root
        const NOISE_COUNT = 30;   // bump to 500 or more for stress-testing
        const noiseTokens = await generateNoiseChain(NOISE_COUNT);

        // The "subject token" for validation will be the first token in the chain
        const subjectToken = noiseTokens[0];

        // Basic correctness: subject token must decode correctly
        const decoded = await validateVouchToken(subjectToken);
        assert.ok(decoded);

        // Run trust-chain evaluation
        const result = await validateTrustChain(
            noiseTokens,
            subjectToken,
            trustedIssuers,
            ['demo']
        );

        // EXPECTED: immediate failure, short-circuit applied
        assert.strictEqual(result.valid, false, 'Expected short-circuit failure');
        assert.deepStrictEqual(result.chains, [], 'No chains should be returned');
        assert.deepStrictEqual(
            result.effectivePurposes,
            [],
            'No purposes should propagate'
        );
    });

    it('passes when at least one token comes from a trusted issuer', async () => {
        // Create noise again
        const NOISE_COUNT = 8;
        const noiseTokens = await generateNoiseChain(NOISE_COUNT);

        // Add a real trusted issuer
        const trusted = await createVouchsafeIdentity('good-root');
        const trustedIssuers = {
            [trusted.urn]: ['demo']
        };

        // Create an attestation by the trusted root for the same purpose
        const trustedAtt = await createAttestation(
            trusted.urn,
            trusted.keypair,
            { purpose: 'demo' }
        );

        // Create a vouch linking trusted root → end of noise chain
        const lastNoiseToken = noiseTokens[noiseTokens.length - 1];

        // Insert the trusted path into the full set
        const fullSet = [...noiseTokens, trustedAtt ];
        const subjectToken = fullSet[0];

        const trustedVouch = await createVouchToken(
            subjectToken,
            trusted.urn,
            trusted.keypair,
            { purpose: 'demo' }
        );
        fullSet.push(trustedVouch);

        const result = await validateTrustChain(
            fullSet,
            subjectToken,
            trustedIssuers,
            ['demo']
        );

        assert.strictEqual(result.valid, true, 'Expected trust to validate');
        assert.ok(
            result.trustRoot,
            'A trustRoot must be present when validation succeeds'
        );
    });
});
