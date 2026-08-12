import assert from 'assert';

import {
  createVouchsafeIdentity,
  loadIdentity,
  serializeIdentity,
} from '../src/index.mjs';

describe('Identity files', function () {
  this.timeout(15000);

  it('writes and loads an explicitly unprotected identity file', async function () {
    const identity = await createVouchsafeIdentity('plain-file');
    const file = await serializeIdentity(identity, { unprotected_private_key: true });

    assert.strictEqual(file.version, '2.1.0');
    assert.strictEqual(file.publicKeyHash, identity.publicKeyHash);
    assert.ok(file.keypair.privateKey);
    assert.ok(!file.keypair.encryptedPrivateKey);
    assert.deepStrictEqual(await loadIdentity(file), { ...identity, version: '2.1.0' });
  });

  it('round-trips encrypted private keys and requires the passphrase', async function () {
    const identity = await createVouchsafeIdentity('encrypted-file');
    const file = await serializeIdentity(identity, { passphrase: 'p@ssphrase' });

    assert.ok(file.keypair.encryptedPrivateKey);
    assert.ok(!file.keypair.privateKey);
    await assert.rejects(() => loadIdentity(file), /passphrase is required/i);
    await assert.rejects(() => loadIdentity(file, { passphrase: 'incorrect' }), /Unable to decrypt identity private key/);
    assert.deepStrictEqual(await loadIdentity(file, { passphrase: 'p@ssphrase' }), { ...identity, version: '2.1.0' });
  });

  it('rejects invalid key bindings', async function () {
    const identity = await createVouchsafeIdentity('validation-file');
    const file = await serializeIdentity(identity, { unprotected_private_key: true });

    await assert.rejects(() => loadIdentity({ ...file, publicKeyHash: 'a'.repeat(52) }), /publicKeyHash/);
    await assert.rejects(() => loadIdentity({ ...file, publicKeyHash: 1 }), /publicKeyHash must be a string/);
    await assert.rejects(() => loadIdentity({ ...file, keypair: { ...file.keypair, encryptedPrivateKey: 'AAAA', privateKey: file.keypair.privateKey } }), /exactly one/);
  });

  it('loads complete identity files with unknown versions or no publicKeyHash', async function () {
    const identity = await createVouchsafeIdentity('version-file');
    const file = await serializeIdentity(identity, { unprotected_private_key: true });

    const expected = { ...identity, version: '2.1.0' };
    assert.deepStrictEqual(await loadIdentity({ ...file, version: '2.0.0' }), expected);
    assert.deepStrictEqual(await loadIdentity({ ...file, version: 'future-format' }), expected);
    assert.deepStrictEqual(await loadIdentity({ urn: file.urn, keypair: file.keypair, version: '2.0.0' }), expected);
  });

  it('requires explicit encryption or unprotected-private-key serialization', async function () {
    const identity = await createVouchsafeIdentity('serialization-options');

    await assert.rejects(() => serializeIdentity(identity), /exactly one/);
    await assert.rejects(() => serializeIdentity(identity, { passphrase: '' }), /non-empty passphrase/);
    await assert.rejects(
      () => serializeIdentity(identity, { passphrase: 'passphrase', unprotected_private_key: true }),
      /exactly one/
    );
  });

  it('loads legacy unencrypted JS identity data and normalizes it to 2.1.0', async function () {
    const identity = await createVouchsafeIdentity('legacy-file');
    const legacy = { urn: identity.urn, keypair: identity.keypair };

    const loaded = await loadIdentity(legacy);
    assert.strictEqual(loaded.version, '2.1.0');
    assert.strictEqual(loaded.publicKeyHash, identity.publicKeyHash);
  });

  it('rejects non-object and incomplete identity-file shapes', async function () {
    await assert.rejects(() => loadIdentity(null), /JSON object with a keypair/);
    await assert.rejects(() => loadIdentity([]), /JSON object with a keypair/);
    await assert.rejects(() => loadIdentity({ keypair: {} }), /missing urn or keypair.publicKey/);
  });

  it('rejects an encrypted identity with malformed Base64 before decryption', async function () {
    const identity = await createVouchsafeIdentity('malformed-encrypted');
    const file = await serializeIdentity(identity, { passphrase: 'p@ssphrase' });
    file.keypair.encryptedPrivateKey = 'not base64!';

    await assert.rejects(
      () => loadIdentity(file, { passphrase: 'p@ssphrase' }),
      /Unable to decrypt identity private key/
    );
  });

  it('round-trips an encrypted identity with punctuation in the passphrase', async function () {
    const identity = await createVouchsafeIdentity('unicode-passphrase');
    const file = await serializeIdentity(identity, { passphrase: 'pa$$phrase-123' });

    assert.deepStrictEqual(await loadIdentity(file, { passphrase: 'pa$$phrase-123' }), { ...identity, version: '2.1.0' });
  });
});
