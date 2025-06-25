import assert from 'assert';
import {
    createVouchsafeIdentity,
    createJwt,
    createVouchToken,
    verifyTrustChain
} from '../src/index.mjs';

describe('verifyTrustChain() with purpose narrowing', function() {
    let leafIdentity, midIdentity, rootIdentity;
    let leafToken, vouchToken, rootVouchToken;
    const trustedIssuers = {};
    const fullPurpose = 'email-confirmation publish msg-signing';
    const narrowedPurpose = 'msg-signing publish';

    before(async function() {
        rootIdentity = await createVouchsafeIdentity('root');
        midIdentity = await createVouchsafeIdentity('mid');
        leafIdentity = await createVouchsafeIdentity('leaf');

        trustedIssuers[rootIdentity.urn] = ['msg-signing', 'publish', 'email-confirmation'];

        // Leaf JWT
        const now = Math.floor(Date.now() / 1000);
        const leafClaims = {
            iss: leafIdentity.urn,
            jti: crypto.randomUUID(),
            iat: now
        };
        leafToken = await createJwt(leafIdentity.urn, leafIdentity.keypair.publicKey, leafIdentity.keypair.privateKey, leafClaims);

        // Mid vouches for leaf, narrows purposes
        vouchToken = await createVouchToken(leafToken, midIdentity.urn, midIdentity.keypair, {
            sub_key: leafIdentity.keypair.publicKey,
            purpose: narrowedPurpose
        });

        // Root vouches for mid, grants full purpose set
        rootVouchToken = await createVouchToken(vouchToken, rootIdentity.urn, rootIdentity.keypair, {
            purpose: fullPurpose
        });
    });

    it('should validate the trust chain for msg-signing and report narrowed purposes', async function() {
        const result = await verifyTrustChain(leafToken, trustedIssuers, {
            tokens: [vouchToken, rootVouchToken],
            purposes: ['msg-signing']
        });

        assert.strictEqual(result.valid, true);
        assert.ok(Array.isArray(result.purposes));
        assert.deepStrictEqual(result.purposes.sort(), ['msg-signing', 'publish'].sort());
        assert.strictEqual(result.chain.length, 3);
    });

    it('should fail for a purpose that was not delegated by intermediate', async function() {
        const result = await verifyTrustChain(leafToken, trustedIssuers, {
            tokens: [vouchToken, rootVouchToken],
            purposes: ['email-confirmation']
        });

        assert.strictEqual(result.valid, false);
    });
});
