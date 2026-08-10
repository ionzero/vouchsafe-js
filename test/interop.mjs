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
});
