import assert from 'assert';
import util from 'util';
import {
    createVouchsafeIdentity,
    createJwt,
    createVouchToken,
    verifyTrustChain
} from '../src/index.mjs';

describe('verifyTrustChain()', function() {
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
        leafToken = await createJwt(leafIdentity.urn, leafIdentity.keypair.publicKey, leafIdentity.keypair.privateKey, leafClaims);

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

    it('should validate a trust path from leaf to root', async function() {
        const result = await verifyTrustChain(leafToken, trustedIssuers, {
            tokens: [vouchToken, delegateToken],
            purposes: [purpose]
        });
        // console.warn('RESULT:', result);

        assert.strictEqual(result.valid, true);
        assert.ok(Array.isArray(result.chain));
        assert.strictEqual(result.chain.length, 3);
        let final_link = result.chain[result.chain.length - 1];
        assert.strictEqual(final_link.decoded.iss, rootIdentity.urn);
    });

    it('should fail if no delegate is present', async function() {
        const result = await verifyTrustChain(leafToken, trustedIssuers, {
            tokens: [vouchToken],
            purposes: [purpose]
        });

        // console.warn('result', result);
        assert.strictEqual(result.valid, false);
        assert.strictEqual(result.reason, 'untrusted');
    });

    it('should fail if purpose does not match', async function() {
        const result = await verifyTrustChain(leafToken, trustedIssuers, {
            tokens: [vouchToken, delegateToken],
            purposes: ['not-allowed']
        });

        assert.strictEqual(result.valid, false);
    });

    it('should return multiple paths when findAll is enabled', async function() {
        const result = await verifyTrustChain(leafToken, trustedIssuers, {
            tokens: [vouchToken, delegateToken],
            purposes: [purpose],
            findAll: true
        });
        // console.warn('result', util.inspect(result));

        assert.strictEqual(result.valid, true);
        assert.ok(result.paths.length >= 1);
    });

    it('should validate a trust path if leaf is trusted directly', async function() {
        let leafTrustedIssuers = trustedIssuers;
        leafTrustedIssuers[leafIdentity.urn] = ['msg-signing', 'do-stuff'];
        const result = await verifyTrustChain(leafToken, leafTrustedIssuers, {
            purposes: [purpose]
        });

        assert.strictEqual(result.valid, true);
        assert.ok(Array.isArray(result.chain));
        assert.strictEqual(result.chain.length, 1);
        let final_link = result.chain[result.chain.length - 1];
        assert.strictEqual(final_link.decoded.iss, leafIdentity.urn);

    });
});
