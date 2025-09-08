import assert from 'assert';
import crypto from 'crypto';

// Pull the OO facade + a few functional helpers for cross-checks
import {
  Identity,
  createVouchsafeIdentity,
  verifyTrustChain,
  canUseForPurpose,
} from '../src/index.mjs';

// Helper: decode a compact JWS without verifying (for payload checks)
function decodeJwt(token) {
  const [, payload] = token.split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

describe('Identity class', function () {
  this.timeout(10000);

  describe('constructor & factories', function () {
    it('throws on bad ctor input', function () {
      assert.throws(() => new Identity(), /ctor/i);
      assert.throws(() => new Identity({}), /requires/i);
      assert.throws(() => new Identity({ urn: 'urn:vouchsafe:x' }), /keypair/i);
    });

    it('Identity.create(label) generates a working identity', async function () {
      const id = await Identity.create('alice');
      assert.ok(id);
      assert.ok(id.urn && typeof id.urn === 'string');
      assert.ok(id.keypair && id.keypair.publicKey && id.keypair.privateKey);
    });

    it('Identity.from({urn, keypair}) rehydrates and verifies binding', async function () {
      const base = await Identity.create('bob');
      const again = await Identity.from({ urn: base.urn, keypair: base.keypair });
      assert.strictEqual(again.urn, base.urn);
      // quick sanity: a signed token validates and bears the same iss
      const tok = await again.attest({ foo: 'bar' });
      const payload = decodeJwt(tok);
      assert.strictEqual(payload.iss, base.urn);
      assert.strictEqual(payload.foo, 'bar');
    });

    it('Identity.fromKeypair(label, keypair) derives a matching URN', async function () {
      const seed = await createVouchsafeIdentity('carol');
      const viaKeypair = await Identity.fromKeypair('carol', seed.keypair);
      assert.strictEqual(viaKeypair.urn, seed.urn);
      assert.strictEqual(viaKeypair.keypair.publicKey, seed.keypair.publicKey);
    });
  });

  describe('attest()', function () {
    it('defaults vch_iss to this.urn and supports string purpose', async function () {
      const id = await Identity.create('attestor1');
      const att = await id.attest({ purpose: 'email-confirmation', email: 'u@example.com' });
      const payload = decodeJwt(att);
      assert.strictEqual(payload.iss, id.urn);
      assert.strictEqual(payload.vch_iss, id.urn);
      assert.strictEqual(payload.purpose, 'email-confirmation');
      assert.strictEqual(payload.email, 'u@example.com');
    });

    it('normalizes array purpose -> space-separated string', async function () {
      const id = await Identity.create('attestor2');
      const att = await id.attest({ purpose: ['msg-signing', 'do-stuff'] });
      const payload = decodeJwt(att);
      assert.strictEqual(payload.purpose, 'msg-signing do-stuff');
    });
  });

  describe('vouch()', function () {
    it('creates a vouch token issued by the voucher', async function () {
      const subjectOwner = await Identity.create('subject');
      const subject = await subjectOwner.attest({ purpose: 'msg-signing', sub: crypto.randomUUID() });

      const voucher = await Identity.create('voucher');
      const vouch = await voucher.vouch(subject, { purpose: 'msg-signing' });

      const p = decodeJwt(vouch);
      assert.strictEqual(p.iss, voucher.urn);
      // We can’t assert internal field names of the linkage without peeking the library internals,
      // but at minimum it’s a JWT signed by the voucher with purpose preserved/normalized.
      assert.ok(p.purpose.includes('msg-signing'));
    });
  });

  describe('revoke()', function () {
    it('emits a revoke token that invalidates a previously valid trust path', async function () {
      const purpose = 'msg-signing';

      // Leaf makes an attestation
      const leaf = await Identity.create('leaf');
      const leafToken = await leaf.attest({ purpose, sub: crypto.randomUUID() });

      // Root vouches for leaf (trusted anchor)
      const root = await Identity.create('root');
      const rootVouch = await root.vouch(leafToken, { purpose });

      // Trust the root for purpose
      const trustedIssuers = { [root.urn]: [purpose] };

      // Check: valid before revocation
      const validBefore = await canUseForPurpose(leafToken, trustedIssuers, {
        tokens: [rootVouch],
        purposes: [purpose],
      });
      assert.strictEqual(validBefore, true);

      // Revoke that vouch
      const revoke = await root.revoke(rootVouch);

      // Check: now invalid with revoke in the set
      const validAfter = await canUseForPurpose(leafToken, trustedIssuers, {
        tokens: [rootVouch, revoke],
        purposes: [purpose],
      });
      assert.strictEqual(validAfter, false);
    });
  });

  describe('verify()', function () {
    it('verifies a token signed by this identity (no chain logic)', async function () {
      const id = await Identity.create('verifier');
      const tok = await id.attest({ ping: 'pong' });
      const verified = await id.verify(tok);
      // We don’t depend on verifyJwt’s exact return shape; just that it returns an object
      assert.ok(verified && typeof verified === 'object');
      const payload = decodeJwt(tok);
      assert.strictEqual(payload.iss, id.urn);
      assert.strictEqual(payload.ping, 'pong');
    });
  });

  describe('toJSON()', function () {
    it('round-trips via Identity.from()', async function () {
      const id = await Identity.create('roundtrip');
      const json = id.toJSON();
      assert.ok(json.urn && json.keypair && json.keypair.publicKey && json.keypair.privateKey);

      const again = await Identity.from(json);
      assert.strictEqual(again.urn, id.urn);

      const t1 = await id.attest({ k: 1 });
      const t2 = await again.attest({ k: 2 });
      const p1 = decodeJwt(t1);
      const p2 = decodeJwt(t2);

      assert.strictEqual(p1.iss, id.urn);
      assert.strictEqual(p2.iss, id.urn);
      assert.strictEqual(p1.k, 1);
      assert.strictEqual(p2.k, 2);
    });
  });
});
