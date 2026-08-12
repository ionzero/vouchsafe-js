import fs from 'fs';
import assert from 'assert';
import os from 'os';
import path from 'path';

import { writeInteropCorpus } from '../test-support/interop-corpus.mjs';
import { validateInteropAssets } from '../test-support/interop-validator.mjs';

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}


describe('Runtime interoperability corpus', function () {
  this.timeout(15000);

  it('generates and validates a JS-produced asset corpus locally', async function () {
    const dir = makeTempDir('vouchsafe-js-interop-');
    const { manifest } = await writeInteropCorpus(dir, 'js');
    const protectedCases = manifest.test_cases.filter(testCase => testCase.type === 'identity_encrypted_roundtrip');
    assert.strictEqual(protectedCases.length, 2);
    for (const protectedCase of protectedCases) {
      const protectedIdentity = JSON.parse(fs.readFileSync(path.join(dir, protectedCase.assets.identity), 'utf8'));
      assert.ok(protectedIdentity.keypair.encryptedPrivateKey);
      assert.ok(!protectedIdentity.keypair.privateKey);
    }
    await validateInteropAssets(dir);
  });

  it('includes protocol boundary cases required for cross-language compatibility', async function () {
    const dir = makeTempDir('vouchsafe-js-interop-');
    const { manifest } = await writeInteropCorpus(dir, 'js');
    const caseNames = new Set(manifest.test_cases.map(testCase => testCase.name));
    const requiredCases = [
      'identity_protected_wrong_passphrase_rejected',
      'identity_protected_malformed_ciphertext_rejected',
      'identity_rejected_ambiguous_private_key_fields',
      'trust_chain_valid_permuted_bundle',
      'trust_chain_valid_bundle_without_subject',
      'trust_chain_rejected_revoke_all',
      'trust_chain_rejected_leaf_revoked',
      'trust_chain_valid_forged_revoke_ignored',
      'trust_chain_rejected_root_burned',
      'trust_chain_rejected_leaf_burned',
      'trust_chain_valid_omitted_purpose',
      'token_rejected_expired',
      'token_rejected_not_yet_valid',
      'token_rejected_tampered_signature',
      'vouch_rejected_wrong_subject_linkage',
      'vouch_rejected_wrong_issuer_linkage',
    ];

    for (const name of requiredCases) assert.ok(caseNames.has(name), `Missing interop case: ${name}`);
  });

  it('rejects expired and incompatible-schema corpus manifests before reading assets', async function () {
    const dir = makeTempDir('vouchsafe-js-interop-');
    const { manifest } = await writeInteropCorpus(dir, 'js');
    const manifestPath = path.join(dir, 'manifest.json');

    fs.writeFileSync(manifestPath, JSON.stringify({ ...manifest, expires_at: 0 }));
    await assert.rejects(() => validateInteropAssets(dir), /manifest has expired/);

    fs.writeFileSync(manifestPath, JSON.stringify({ ...manifest, schema_version: 999 }));
    await assert.rejects(() => validateInteropAssets(dir), /Unsupported interoperability schema version/);
  });

  it('validates a corpus with an unknown specification version after warning', async function () {
    const dir = makeTempDir('vouchsafe-js-interop-');
    const { manifest } = await writeInteropCorpus(dir, 'js');
    const warnings = [];
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({ ...manifest, spec_version: '2.0.1' }));

    const result = await validateInteropAssets(dir, { warn: (message) => warnings.push(message) });

    assert.strictEqual(result.failed, 0);
    assert.deepStrictEqual(warnings, ['Warning: attempting corpus with unrecognized Vouchsafe specification version: 2.0.1']);
  });

  it('rejects corpus assets that escape the corpus directory', async function () {
    const dir = makeTempDir('vouchsafe-js-interop-');
    const { manifest } = await writeInteropCorpus(dir, 'js');
    const testCases = structuredClone(manifest.test_cases);
    testCases[0].assets.identity = '../outside.json';
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({ ...manifest, test_cases: testCases }));

    await assert.rejects(() => validateInteropAssets(dir), /asset path escapes corpus directory/);
  });
});
