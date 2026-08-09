import assert from 'assert';

import {
  createVouchsafeIdentity,
  loadIdentity,
  serializeIdentity,
} from '../src/index.mjs';

describe('Identity files', function () {
  this.timeout(15000);

  it('writes and loads a spec-compliant unencrypted identity file', async function () {
    const identity = await createVouchsafeIdentity('plain-file');
    const file = await serializeIdentity(identity);

    assert.strictEqual(file.version, '1.4.0');
    assert.strictEqual(file.publicKeyHash, identity.publicKeyHash);
    assert.ok(file.keypair.privateKey);
    assert.ok(!file.keypair.encryptedPrivateKey);
    assert.deepStrictEqual(await loadIdentity(file), identity);
  });

  it('round-trips encrypted private keys and requires the passphrase', async function () {
    const identity = await createVouchsafeIdentity('encrypted-file');
    const file = await serializeIdentity(identity, { passphrase: 'p@ssphrase' });

    assert.ok(file.keypair.encryptedPrivateKey);
    assert.ok(!file.keypair.privateKey);
    await assert.rejects(() => loadIdentity(file), /passphrase is required/i);
    await assert.rejects(() => loadIdentity(file, { passphrase: 'incorrect' }), /Unable to decrypt identity private key/);
    assert.deepStrictEqual(await loadIdentity(file, { passphrase: 'p@ssphrase' }), identity);
  });

  it('rejects invalid key bindings and unsupported versions', async function () {
    const identity = await createVouchsafeIdentity('validation-file');
    const file = await serializeIdentity(identity);

    await assert.rejects(() => loadIdentity({ ...file, publicKeyHash: 'a'.repeat(52) }), /publicKeyHash/);
    await assert.rejects(() => loadIdentity({ ...file, version: '2.0.0' }), /Unsupported/);
    await assert.rejects(() => loadIdentity({ ...file, keypair: { ...file.keypair, encryptedPrivateKey: 'AAAA', privateKey: file.keypair.privateKey } }), /exactly one/);
  });

  it('loads legacy unencrypted JS identity data and normalizes it to 1.4.0', async function () {
    const identity = await createVouchsafeIdentity('legacy-file');
    const legacy = { urn: identity.urn, keypair: identity.keypair };

    const loaded = await loadIdentity(legacy);
    assert.strictEqual(loaded.version, '1.4.0');
    assert.strictEqual(loaded.publicKeyHash, identity.publicKeyHash);
  });
});
