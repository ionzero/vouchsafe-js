import assert from 'assert';
import util from 'util';
import {
    createVouchsafeIdentity,
    createJwt,
    createVouchToken,
    createAttestation,
    validateTrustChain
} from '../src/index.mjs';

describe('validateTrustChain()', function() {
    let leafIdentity, midIdentity, rootIdentity;
    let secondMidIdentity, secondRootIdentity;
    let leafToken, vouchToken, delegateToken;
    let secondVouchToken, secondAttestationToken;
    const trustedIssuers = {};
    const purpose = 'msg-signing';

    before(async function() {
        // Create identities
        leafIdentity = await createVouchsafeIdentity('leaf');
        midIdentity = await createVouchsafeIdentity('mid');
        secondMidIdentity = await createVouchsafeIdentity('secondMid');
        rootIdentity = await createVouchsafeIdentity('root');
        secondRootIdentity = await createVouchsafeIdentity('second');

        trustedIssuers[rootIdentity.urn] = ['msg-signing'];
        trustedIssuers[secondRootIdentity.urn] = ['msg-signing'];

        // Create JWT (leaf token)
        const now = Math.floor(Date.now() / 1000);
        const leafClaims = {
            iss: leafIdentity.urn,
            jti: crypto.randomUUID(),
            iat: now,
            purpose: 'msg-signing'
        };
        // console.log(leafIdentity);
        leafToken = await createAttestation(leafIdentity.urn, leafIdentity.keypair, leafClaims);

        // Mid identity vouches for leaf
        vouchToken = await createVouchToken(leafToken, midIdentity.urn, midIdentity.keypair, {
            sub_key: leafIdentity.keypair.publicKey,
            purpose
        });

        // Root identity vouches for mid's vouch
        delegateToken = await createVouchToken(vouchToken, rootIdentity.urn, rootIdentity.keypair, {
            //sub_key: midIdentity.keypair.publicKey,
            purpose
        });
        secondVouchToken = await createVouchToken(leafToken, secondMidIdentity.urn, secondMidIdentity.keypair, {
            //sub_key: leafIdentity.keypair.publicKey,
            purpose
        });
        secondAttestationToken = await createVouchToken(secondVouchToken, secondRootIdentity.urn, secondRootIdentity.keypair, {
            //sub_key: midIdentity.keypair.publicKey,
            purpose
        });
    });

/*
        const res = await validateTrustChain(
            tokens,
            leafAttest,
            trustedIssuers,
            undefined,
            {}
        );
*/
    it('should validate a trust path from leaf to root', async function() {
        const result = await validateTrustChain(
            [leafToken, vouchToken, delegateToken],
            leafToken,
            trustedIssuers,
            [purpose]
        );
        //console.warn('RESULT:', result);

        assert.strictEqual(result.valid, true);
        assert.ok(Array.isArray(result.chains));
        assert.strictEqual(result.chains[0].chain.length, 3);
        let final_link = result.chains[0].chain[result.chains[0].chain.length - 1];
        assert.strictEqual(final_link.decoded.iss, rootIdentity.urn);
    });

    it('should fail if no delegate is present', async function() {
        const result = await validateTrustChain(
            [leafToken, vouchToken],
            leafToken,
            trustedIssuers,
            [purpose]
        );

        //console.warn('result', result);
        assert.strictEqual(result.valid, false);
    });

    it('should fail if purpose does not match', async function() {
        const result = await validateTrustChain(
            [leafToken, vouchToken, delegateToken],
            leafToken,
            trustedIssuers,
            ['not-allowed']
        );

        //console.warn('result', result);
        assert.strictEqual(result.valid, false);
    });

    it('should return multiple paths when findAll is enabled', async function() {
        const result = await validateTrustChain(
            [leafToken, vouchToken, delegateToken],
            leafToken,
            trustedIssuers,
            [purpose],
            { returnAllValidChains: true }
        );
        //console.warn('result', util.inspect(result));

        assert.strictEqual(result.valid, true);
        assert.ok(result.chains.length >= 1);
    });

    it('should validate a trust path if leaf is trusted directly', async function() {
        let leafTrustedIssuers = trustedIssuers;
        leafTrustedIssuers[leafIdentity.urn] = ['msg-signing', 'do-stuff'];
        const result = await validateTrustChain(
            [leafToken],
            leafToken,
            trustedIssuers,
            [purpose]
        );
        //console.warn('result', util.inspect(result));

        assert.strictEqual(result.valid, true);
        assert.ok(Array.isArray(result.chains[0].chain));
        assert.strictEqual(result.chains[0].chain.length, 1);
        let final_link = result.chains[0].chain[result.chains[0].chain.length - 1];
        assert.strictEqual(final_link.decoded.iss, leafIdentity.urn);

    });
});
