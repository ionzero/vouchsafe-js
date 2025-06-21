import assert from 'assert';
import crypto from 'crypto';
import {
  createJwt,
  createVouchToken,
  revokeVouchToken,
  createRevokeToken,
  createVouchsafeIdentity,
  verifyTrustChain,
  canUseForPurpose
} from '../src/index.mjs';

function decodeJwt(token) {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

describe('verifyTrustPaths() - revocation cases', () => {
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

    midVouch = await createVouchToken(leafToken, midIdentity.urn, midIdentity.keypair, {
      sub_key: leafIdentity.keypair.publicKey,
      purpose
    });

    rootVouch = await createVouchToken(midVouch, rootIdentity.urn, rootIdentity.keypair, {
      sub_key: midIdentity.keypair.publicKey,
      purpose
    });
  });

  it.skip('should fail if mid token is revoked explicitly', async () => {
    const midJti = decodeJwt(midVouch).jti;

    const revoke = await revokeVouchToken(midVouch, midIdentity.keypair);

    const result = await verifyTrustChain(leafToken, trustedIssuers, {
       tokens: [midVouch, rootVouch, revoke],
       purposes: [purpose]
    });

    assert.strictEqual(result.valid, false, 'Expected failure due to explicit revocation');
  });

  it.skip('should fail if root revokes all from mid (revokes: all)', async () => {
    const revokeAll = await revokeVouchToken(midVouch, midIdentity.keypair, {
      revokes: 'all'
    });

    const result = await verifyTrustChain(leafToken, trustedIssuers, {
      tokens: [midVouch, rootVouch, revokeAll],
      purposes: [purpose]
    });

    assert.strictEqual(result.valid, false, 'Expected failure due to revokes: all');
  });

  it('should succeed when no revocation is present', async () => {
    const vresult = await verifyTrustChain(leafToken, trustedIssuers, {
      tokens: [midVouch, rootVouch],
      purposes: [purpose]
    });
    //console.log('vresult:', vresult);
    
    const result = await canUseForPurpose(leafToken, trustedIssuers, {
      tokens: [midVouch, rootVouch],
      purposes: [purpose]
    });

    assert.strictEqual(result, true, 'Expected valid trust path without revocation');
  });
});

