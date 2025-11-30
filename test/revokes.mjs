import assert from 'assert';
import crypto from 'crypto';
import {
    createJwt,
    createAttestation,
    createVouchToken,
    revokeVouchToken,
    createRevokeToken,
    createVouchsafeIdentity,
    validateTrustChain
} from '../src/index.mjs';

function decodeJwt(token) {
    const [, payload] = token.split('.');
    return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

describe('validateTrustChain() - revocation cases', () => {
    let leafIdentity, midIdentity, rootIdentity;
    let leafToken, midVouch, rootVouch;
    const trustedIssuers = {};
    const purpose = 'msg-signing';

    before(async () => {
        // Create identities
        leafIdentity = await createVouchsafeIdentity('leaf');
        midIdentity = await createVouchsafeIdentity('mid');
        rootIdentity = await createVouchsafeIdentity('root');

        trustedIssuers[rootIdentity.urn] = [purpose];

        const now = Math.floor(Date.now() / 1000);
        const leafClaims = {
            purpose: purpose
        };

        leafToken = await createAttestation(
            leafIdentity.urn,
            leafIdentity.keypair,
            leafClaims
        );

        midVouch = await createVouchToken(leafToken, midIdentity.urn, midIdentity.keypair, {
            sub_key: leafIdentity.keypair.publicKey,
            purpose
        });

        rootVouch = await createVouchToken(midVouch, rootIdentity.urn, rootIdentity.keypair, {
            sub_key: midIdentity.keypair.publicKey,
            purpose
        });
    });

    it('should fail if mid token is revoked explicitly', async () => {
        const midDecoded = decodeJwt(midVouch);

        const revoke = await revokeVouchToken(midVouch, midIdentity.keypair);
        const revDecoded = decodeJwt(revoke);
        const tokens = [
            leafToken,
            midVouch,
            rootVouch,
            revoke
        ];

        const result = await validateTrustChain(tokens, leafToken, trustedIssuers, [purpose]);

        assert.strictEqual(result.valid, false, 'Expected failure due to explicit revocation');
    });

    it('should fail if root revokes all from mid (revokes: all)', async () => {
        const revokeAll = await revokeVouchToken(midVouch, midIdentity.keypair, {
            revokes: 'all'
        });
        const tokens = [
            leafToken,
            midVouch,
            rootVouch,
            revokeAll
        ];

        const result = await validateTrustChain(tokens, leafToken, trustedIssuers, [purpose]);

        assert.strictEqual(result.valid, false, 'Expected failure due to revokes: all');
    });

    it('should succeed when no revocation is present', async () => {
        const tokens = [
            leafToken,
            midVouch,
            rootVouch,
        ];

        const result = await validateTrustChain(tokens, leafToken, trustedIssuers, [purpose]);

        assert.strictEqual(result.valid, true, 'Expected success without revokes');
        assert.deepEqual(result.effectivePurposes, ['msg-signing'], 'Expected valid trust path without revocation');
    });
});
