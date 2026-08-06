import assert from 'assert';
import { execFile } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { promisify } from 'util';

import {
    createAttestation,
    createVouchsafeIdentity,
    createVouchToken,
} from '../src/index.mjs';

const execFileAsync = promisify(execFile);
const testDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(testDir, '..');

describe('Vouchsafe CLI tools', function () {
    this.timeout(15000);

    it('verify_vouchsafe_token parses inline trusted Vouchsafe URNs correctly', async function () {
        const leaf = await createVouchsafeIdentity('leaf');
        const root = await createVouchsafeIdentity('root');
        const purpose = 'msg-signing';
        const leafToken = await createAttestation(leaf.urn, leaf.keypair, { purpose });
        const rootVouch = await createVouchToken(leafToken, root.urn, root.keypair, { purpose });

        const { stdout } = await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/verify_vouchsafe_token.mjs'),
            '-E',
            '-p', purpose,
            '-T', leafToken,
            '-T', rootVouch,
            '--trusted-issuer', `${root.urn}=${purpose}`,
        ], { cwd: packageRoot });

        assert.strictEqual(stdout, '');
    });

    it('create_vouchsafe_token can create revoke tokens without requiring -e 0', async function () {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchsafe-revoke-'));
        const leaf = await createVouchsafeIdentity('leaf');
        const root = await createVouchsafeIdentity('root');
        const leafToken = await createAttestation(leaf.urn, leaf.keypair, { purpose: 'msg-signing' });
        const rootVouch = await createVouchToken(leafToken, root.urn, root.keypair, { purpose: 'msg-signing' });

        const identityPath = path.join(dir, 'root.json');
        const vouchPath = path.join(dir, 'root-vouch.jwt');
        fs.writeFileSync(identityPath, JSON.stringify({ urn: root.urn, keypair: root.keypair }), 'utf8');
        fs.writeFileSync(vouchPath, rootVouch, 'utf8');

        const { stdout } = await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_token.mjs'),
            '-i', identityPath,
            '--revoke',
            '-t', vouchPath,
        ], { cwd: packageRoot });

        assert.match(stdout, /^[^.]+\.[^.]+\.[^.]+\n$/);
    });

    it('creates private-key and token output files with owner-only permissions', async function () {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchsafe-permissions-'));
        const identityPath = path.join(dir, 'identity.json');
        const tokenPath = path.join(dir, 'token.jwt');

        await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_id.mjs'),
            '--label', 'owner-only',
            '--output', identityPath,
        ], { cwd: packageRoot });

        await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_token.mjs'),
            '--identity', identityPath,
            '--purpose', 'msg-signing',
            '--output', tokenPath,
        ], { cwd: packageRoot });

        assert.equal(fs.statSync(identityPath).mode & 0o777, 0o600);
        assert.equal(fs.statSync(tokenPath).mode & 0o777, 0o600);
    });
});
