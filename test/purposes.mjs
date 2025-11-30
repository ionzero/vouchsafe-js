import assert from 'assert';
import {
    createVouchsafeIdentity,
    createJwt,
    createAttestation,
    createVouchToken,
    validateTrustChain
} from '../src/index.mjs';

describe('validateTrustChain() with purpose narrowing', function() {
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
//            purpose: "msg-signing"
        };
        leafToken = await createAttestation(leafIdentity.urn, leafIdentity.keypair, leafClaims);

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
        let tokens = [
            leafToken,
            vouchToken,
            rootVouchToken
        ];
        const result = await validateTrustChain(tokens, leafToken, trustedIssuers, ['msg-signing']);

        assert.strictEqual(result.valid, true);
        assert.ok(Array.isArray(result.effectivePurposes));
        assert.deepStrictEqual(result.effectivePurposes.sort(), ['msg-signing', 'publish'].sort());
        assert.strictEqual(result.chains[0].chain.length, 3);
    });

    it('should fail for a purpose that was not delegated by intermediate', async function() {
        let tokens = [
            leafToken,
            vouchToken,
            rootVouchToken
        ];
        const result = await validateTrustChain(tokens, leafToken, trustedIssuers, ['email-confirmation']);

        assert.strictEqual(result.valid, false);
    });
});
