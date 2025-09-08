import { strict as assert } from 'assert';
import { createVouchsafeIdentity, createJwt, verifyJwt } from '../src/index.mjs';

describe('createJwt', function () {
  let identity;

  before(async function () {
    identity = await createVouchsafeIdentity('tester');
  });

  it('creates a token including iss_key by default', async function () {
    const token = await createJwt(identity.urn, identity.keypair.publicKey, identity.keypair.privateKey, {
      foo: 'bar'
    });

    const decoded = await verifyJwt(token);
    assert.equal(decoded.iss, identity.urn);
    assert.equal(decoded.foo, 'bar');
    assert.ok(decoded.iss_key, 'iss_key should be present by default');
  });

  it('creates a token without iss_key when exclude_iss_key is true', async function () {
    const token = await createJwt(
      identity.urn,
      identity.keypair.publicKey,
      identity.keypair.privateKey,
      { foo: 'bar' },
      { exclude_iss_key: true }
    );

    const decoded = await verifyJwt(token, { pubKeyOverride: identity.keypair.publicKey });
    assert.equal(decoded.iss, identity.urn);
    assert.equal(decoded.foo, 'bar');
    assert.ok(!decoded.iss_key, 'iss_key should not be present when excluded');
  });

  it('creates a token without nbf and iat when explicitly set to null in claims', async function () {
    const token = await createJwt(
      identity.urn,
      identity.keypair.publicKey,
      identity.keypair.privateKey,
      { foo: 'bar', iat: null, nbf: null }, // override with null
      { exclude_iss_key: true }
    );

    const decoded = await verifyJwt(token, { pubKeyOverride: identity.keypair.publicKey });
    assert.equal(decoded.iss, identity.urn);
    assert.equal(decoded.foo, 'bar');
    assert.ok(!('iss_key' in decoded), 'iss_key should not be present when excluded');
    assert.ok(!('iat' in decoded), 'iat should not be present when set to null in claims');
    assert.ok(!('nbf' in decoded), 'nbf should not be present when set to null in claims');
  });
});

