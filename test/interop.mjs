import fs from 'fs';
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
    await writeInteropCorpus(dir, 'js');
    await validateInteropAssets(dir);
  });
});
