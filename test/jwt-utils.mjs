import assert from 'assert';

import {
  createJwt,
  createVouchsafeIdentity,
  decodeJwt,
  getAppClaims,
  hashJwt,
  verifyJwt,
} from '../src/index.mjs';
import { base32Decode, base32Encode, fromBase64, isValidUUID, toBase64 } from '../src/utils.mjs';

describe('JWT and utility helpers', function () {
  let identity;

  before(async function () {
    identity = await createVouchsafeIdentity('jwt-utils');
  });

  it('returns a complete decoded JWT when full decoding is requested', async function () {
    const token = await createJwt(identity.urn, identity.keypair.publicKey, identity.keypair.privateKey, { order: 42 });

    const decoded = decodeJwt(token, { full: true });

    assert.deepStrictEqual(decoded.header, { alg: 'EdDSA' });
    assert.strictEqual(decoded.payload.order, 42);
  });

  it('rejects verification without an embedded issuer key', async function () {
    const token = await createJwt(
      identity.urn,
      identity.keypair.publicKey,
      identity.keypair.privateKey,
      {},
      { exclude_iss_key: true }
    );

    await assert.rejects(() => verifyJwt(token), /missing iss_key/i);
  });

  it('verifies a token without an embedded issuer key with a public-key override', async function () {
    const token = await createJwt(
      identity.urn,
      identity.keypair.publicKey,
      identity.keypair.privateKey,
      { audience: 'internal' },
      { exclude_iss_key: true }
    );

    const decoded = await verifyJwt(token, { pubKeyOverride: identity.keypair.publicKey });

    assert.strictEqual(decoded.audience, 'internal');
  });

  it('rejects a token verified with a different public-key override', async function () {
    const other = await createVouchsafeIdentity('jwt-other');
    const token = await createJwt(
      identity.urn,
      identity.keypair.publicKey,
      identity.keypair.privateKey,
      {},
      { exclude_iss_key: true }
    );

    await assert.rejects(() => verifyJwt(token, { pubKeyOverride: other.keypair.publicKey }), /signature verification failed/i);
  });

  it('returns only application claims including falsey values', function () {
    const claims = getAppClaims({
      iss: identity.urn,
      iss_key: identity.keypair.publicKey,
      jti: 'ignored',
      purpose: 'ignored',
      enabled: false,
      count: 0,
      note: '',
      metadata: { region: 'eu' },
    });

    assert.deepStrictEqual(claims, { enabled: false, count: 0, note: '', metadata: { region: 'eu' } });
  });

  it('returns an empty object for a non-object claim payload', function () {
    assert.deepStrictEqual(getAppClaims(null), {});
  });

  it('returns a stable lowercase SHA-256 JWT hash', async function () {
    const digest = await hashJwt('header.payload.signature');

    assert.strictEqual(digest, '256d04db4e5e4ac308751ed0885b722b758630567c53a7125ed9fbd068e5c3f6');
  });

  it('rejects unsupported JWT hash algorithms', async function () {
    await assert.rejects(() => hashJwt('token', 'sha512'), /unsupported hash algorithm: sha512/i);
  });

  it('round-trips base32 bytes that end on a partial group', function () {
    const bytes = new Uint8Array([0xff, 0x00, 0x2a]);

    assert.deepStrictEqual(base32Decode(base32Encode(bytes)), bytes);
  });

  it('accepts uppercase padded base32 input', function () {
    assert.deepStrictEqual(base32Decode('MY======'), new Uint8Array([0x66]));
  });

  it('rejects invalid base32 characters', function () {
    assert.throws(() => base32Decode('hello!'), /invalid base32 character/i);
  });

  it('round-trips binary base64 input', function () {
    const bytes = new Uint8Array([0, 1, 254, 255]);

    assert.deepStrictEqual(fromBase64(toBase64(bytes)), bytes);
  });

  it('rejects non-string base64 input', function () {
    assert.throws(() => fromBase64(new Uint8Array()), /base64-encoded string/i);
  });

  it('accepts lowercase UUIDs and rejects uppercase UUIDs', function () {
    assert.strictEqual(isValidUUID('123e4567-e89b-12d3-a456-426614174000'), true);
    assert.strictEqual(isValidUUID('123E4567-E89B-12D3-A456-426614174000'), false);
  });
});
