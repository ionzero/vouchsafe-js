import { strict as assert } from 'assert';
import {
    createVouchsafeIdentity,
    createAttestation,
    createVouchToken
} from '../src/index.mjs';

// This is your compatibility wrapper that calls validateTrustChain internally.
import { verifyTrustChain } from '../src/legacy.mjs';

describe('legacy verifyTrustChain compatibility', function () {

    let rootIdentity;
    let subjectIdentity;
    let rootUrn;
    let subjectUrn;

    let subjectToken;   // subject token we want to evaluate (formerly "leaf")
    let vouchToken;     // vouch from root → subject
    let trustedIssuers;

    beforeEach(async function () {

        // --------------------------------------------------------------
        // Create identities for:
        //   - root: the trusted anchor
        //   - subject: the identity being evaluated
        // --------------------------------------------------------------
        rootIdentity = await createVouchsafeIdentity('root');
        subjectIdentity = await createVouchsafeIdentity('subject');

        rootUrn = rootIdentity.urn;
        subjectUrn = subjectIdentity.urn;

        // --------------------------------------------------------------
        // Subject issues an attestation that it may be used for msg-signing.
        // This is the subject token we will evaluate in the trust chain.
        // --------------------------------------------------------------
        subjectToken = await createAttestation(subjectUrn, subjectIdentity.keypair, {
            purpose: 'msg-signing'
            // kind: 'vch:attest'  // implementation sets this automatically
        });

        // --------------------------------------------------------------
        // Root vouches for the subject token for the same purpose.
        // This creates a one-hop chain:
        //   root (trusted)  → vouch  → subject attestation
        // --------------------------------------------------------------
        vouchToken = await createVouchToken(subjectToken, rootUrn, rootIdentity.keypair, {
            purpose: 'msg-signing'
        });

        // Root is trusted for msg-signing.
        trustedIssuers = {
            [rootUrn]: ['msg-signing']
        };
    });

    it('accepts a valid single-hop chain using legacy verifyTrustChain', async function () {

        const purposes = ['msg-signing'];

        // NOTE:
        //  - subjectToken is the subject token we want evaluated
        //  - tokens includes the full token set used to build the trust graph
        const result = await verifyTrustChain(subjectToken, trustedIssuers, {
            tokens: [subjectToken, vouchToken],
            purposes
        });

        assert.equal(result.valid, true, 'expected chain to be valid');

        // Legacy API: leaf is { token, payload }
        assert.ok(result.leaf, 'leaf information should be present');
        assert.equal(result.leaf.token, subjectToken, 'leaf token must match subject token');

        // Chain should be an array from subject → trust root
        assert.ok(Array.isArray(result.chain), 'chain should be an array');
        assert.ok(result.chain.length >= 1, 'chain should have at least one element');

        const trustRoot = result.chain[result.chain.length - 1];
        assert.equal(
            trustRoot.decoded.iss,
            rootUrn,
            'trust root should be the configured root issuer'
        );

        // purposes is the final surviving purpose set for this chain
        assert.ok(Array.isArray(result.purposes), 'purposes should be an array');
        assert.ok(
            result.purposes.includes('msg-signing'),
            'msg-signing should survive to the trust root'
        );
    });

    it('rejects a chain when required purpose is not granted', async function () {

        // Ask for a purpose that the root is not trusted for.
        const purposes = ['file-storage'];

        const result = await verifyTrustChain(subjectToken, trustedIssuers, {
            tokens: [subjectToken, vouchToken],
            purposes
        });

        assert.equal(
            result.valid,
            false,
            'chain must be invalid when required purposes are not satisfied'
        );
    });

    it('rejects a chain when the vouching issuer is not trusted', async function () {

        const purposes = ['msg-signing'];

        // Configure a completely different (untrusted) root.
        const untrustedIssuers = {
            'urn:vouchsafe:some.other-root': ['msg-signing']
        };

        const result = await verifyTrustChain(subjectToken, untrustedIssuers, {
            tokens: [subjectToken, vouchToken],
            purposes
        });

        assert.equal(
            result.valid,
            false,
            'chain must be invalid when the trust root is not in trustedIssuers'
        );
    });
});
