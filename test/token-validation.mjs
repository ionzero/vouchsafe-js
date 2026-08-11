import assert from 'assert';
import crypto from 'crypto';

import {
  createAttestation,
  createJwt,
  createVouchToken,
  createVouchsafeIdentity,
  isBurnToken,
  isRevocationToken,
  validateVouchToken,
  verifyVouchToken,
} from '../src/index.mjs';

describe('Vouchsafe token structural validation', function () {
  let issuer;
  let subjectIssuer;
  let subject;
  let vouch;

  before(async function () {
    issuer = await createVouchsafeIdentity('structure-issuer');
    subjectIssuer = await createVouchsafeIdentity('structure-subject');
    subject = await createAttestation(subjectIssuer.urn, subjectIssuer.keypair, { purpose: 'email-confirmation' });
    vouch = await createVouchToken(subject, issuer.urn, issuer.keypair, { purpose: 'email-confirmation' });
  });

  async function sign(claims) {
    return createJwt(issuer.urn, issuer.keypair.publicKey, issuer.keypair.privateKey, claims);
  }

  it('rejects attestations whose subject differs from their token ID', async function () {
    const token = await sign({ kind: 'vch:attest', jti: crypto.randomUUID(), sub: crypto.randomUUID() });

    await assert.rejects(() => validateVouchToken(token), /may not vouch.*unless they are attestations/i);
  });

  it('rejects attestations with vouch linkage claims', async function () {
    const jti = crypto.randomUUID();
    const token = await sign({ kind: 'vch:attest', jti, sub: jti, vch_iss: subjectIssuer.urn });

    await assert.rejects(() => validateVouchToken(token), /attestations may not have a vch_iss/i);
  });

  it('rejects vouches without a subject issuer', async function () {
    const token = await sign({ kind: 'vch:vouch', jti: crypto.randomUUID(), sub: crypto.randomUUID(), vch_sum: '0'.repeat(64) });

    await assert.rejects(() => validateVouchToken(token), /include vch_iss/i);
  });

  it('rejects vouches without a subject hash', async function () {
    const token = await sign({ kind: 'vch:vouch', jti: crypto.randomUUID(), sub: crypto.randomUUID(), vch_iss: subjectIssuer.urn });

    await assert.rejects(() => validateVouchToken(token), /have a vch_sum/i);
  });

  it('rejects vouch purposes with disallowed characters', async function () {
    const token = await sign({
      kind: 'vch:vouch',
      jti: crypto.randomUUID(),
      sub: crypto.randomUUID(),
      vch_iss: subjectIssuer.urn,
      vch_sum: '0'.repeat(64),
      purpose: 'email!',
    });

    await assert.rejects(() => validateVouchToken(token), /purpose may only contain/i);
  });

  it('rejects burn tokens that name a different burned identity', async function () {
    const jti = crypto.randomUUID();
    const token = await sign({ kind: 'vch:burn', jti, sub: jti, burns: subjectIssuer.urn });

    await assert.rejects(() => validateVouchToken(token), /different issuer/i);
  });

  it('rejects revocations with a non-UUID target', async function () {
    const token = await sign({
      kind: 'vch:revoke',
      jti: crypto.randomUUID(),
      sub: crypto.randomUUID(),
      vch_iss: subjectIssuer.urn,
      vch_sum: '0'.repeat(64),
      revokes: 'not-a-uuid',
    });

    await assert.rejects(() => validateVouchToken(token), /revokes field/i);
  });

  it('rejects revocations that carry a purpose', async function () {
    const token = await sign({
      kind: 'vch:revoke',
      jti: crypto.randomUUID(),
      sub: crypto.randomUUID(),
      vch_iss: subjectIssuer.urn,
      vch_sum: '0'.repeat(64),
      revokes: 'all',
      purpose: 'email-confirmation',
    });

    await assert.rejects(() => validateVouchToken(token), /revokes and purpose/i);
  });

  it('rejects a vouch presented with a different subject token', async function () {
    const otherSubject = await createAttestation(subjectIssuer.urn, subjectIssuer.keypair, { purpose: 'email-confirmation' });

    await assert.rejects(() => verifyVouchToken(vouch, otherSubject), /does not match subject token.*jti/i);
  });

  it('identifies valid burn and revocation payload shapes', function () {
    assert.strictEqual(isBurnToken({ kind: 'vch:burn', iss: issuer.urn, burns: issuer.urn }), true);
    assert.strictEqual(isRevocationToken({ kind: 'vch:revoke', revokes: 'all' }), true);
  });

  it('rejects malformed burn and revocation payload shapes in type guards', function () {
    assert.throws(() => isBurnToken({ kind: 'vch:burn', iss: issuer.urn, burns: subjectIssuer.urn }), /invalid burn token/i);
    assert.throws(() => isRevocationToken({ kind: 'vch:revoke' }), /invalid revoke token/i);
  });
});
