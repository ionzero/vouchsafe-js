import assert from 'assert';
import { decodeJwt } from 'jose';
import {
    createVouchToken,
    createJwt,
    verifyJwt,
    createVouchsafeIdentity,
    verifyTrustChain,
    canUseForPurpose
} from '../src/index.mjs';

describe('verifyTrustChain() - deep chain with mid-anchor', () => {
    let leafIdentity, rootIdentity;
    let leafToken;
    const intermediates = [];
    const vouches = [];
    const trustedIssuers = {};
    const purpose = 'msg-signing';
    const chainLength = 5;
    const trustAtIndex = 2; // 0-based: the 3rd token (hop 3)

    before(async () => {
        // Create leaf and trusted root
        leafIdentity = await createVouchsafeIdentity('leaf');
        rootIdentity = await createVouchsafeIdentity('root');

        trustedIssuers[rootIdentity.urn] = [purpose];

        // Generate JWT leaf token
        const now = Math.floor(Date.now() / 1000);
        const leafClaims = {
            iss: leafIdentity.urn,
            jti: crypto.randomUUID(),
            iat: now
        };

        leafToken = await createJwt(
            leafIdentity.urn,
            leafIdentity.keypair.publicKey,
            leafIdentity.keypair.privateKey,
            leafClaims
        );

        // Create intermediate identities
        for (let i = 0; i < chainLength; i++) {
            intermediates.push(await createVouchsafeIdentity(`hop${i + 1}`));
        }

        // Create vouches in reverse order
        let subjectToken = leafToken;
        for (let i = chainLength - 1; i >= 0; i--) {
            const issuer = intermediates[i];
            const sub_key = (i === chainLength - 1) ?
                leafIdentity.keypair.publicKey :
                intermediates[i + 1].keypair.publicKey;

            const vouch = await createVouchToken(subjectToken, issuer.urn, issuer.keypair, {
                sub_key,
                purpose
            });

            vouches.unshift(vouch); // add to front
            subjectToken = vouch;
        }

        // Inject root vouching for the middle token
        const midToken = vouches[trustAtIndex];
        const midIssuer = intermediates[trustAtIndex];
        const rootVouch = await createVouchToken(midToken, rootIdentity.urn, rootIdentity.keypair, {
            sub_key: midIssuer.keypair.publicKey,
            purpose
        });

        vouches.push(rootVouch); // add to end
        vouches.forEach((vouch) => {
            let decoded = decodeJwt(vouch);
            //        console.log('iss:', decoded.iss, 'vch_iss:', decoded.vch_iss);
        });
    });

    it('should verify early due to mid-path trusted anchor (short-circuit)', async () => {
        const result = await verifyTrustChain(leafToken, trustedIssuers, {
            tokens: vouches,
            purposes: [purpose],
            maxDepth: 10,
            findAll: false
        });

        assert.ok(result.valid, 'Expected trust path to be valid');
        assert.ok(result.chain.length >= 1);
        const trustedPath = result.chain;
        const hopIssuers = trustedPath.map(t => t.decoded.iss);
        //    console.log('✅ Trusted path issuers:', hopIssuers);

        const trustedURN = rootIdentity.urn;
        assert.ok(hopIssuers.includes(trustedURN), 'Expected path to include trusted root');
        assert.ok(hopIssuers.indexOf(trustedURN) < vouches.length - 1, 'Expected early trust anchor');
    });

    it('canUseForPurpose should succeed via early trust match', async () => {
        const result = await canUseForPurpose(leafToken, trustedIssuers, {
            tokens: vouches,
            purposes: [purpose]
        });

        assert.strictEqual(result, true);
    });

});
