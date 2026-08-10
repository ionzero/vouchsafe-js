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

        const { stderr } = await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_id.mjs'),
            '--label', 'owner-only',
            '--create-unencrypted-identity-file',
            '--output', identityPath,
        ], { cwd: packageRoot });

        assert.match(stderr, /Warning: creating an unencrypted identity file/);
        await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_token.mjs'),
            '--identity', identityPath,
            '--purpose', 'msg-signing',
            '--output', tokenPath,
        ], { cwd: packageRoot });

        assert.equal(fs.statSync(identityPath).mode & 0o777, 0o600);
        assert.equal(fs.statSync(tokenPath).mode & 0o777, 0o600);
    });

    it('creates and loads encrypted identity files using a passphrase file', async function () {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchsafe-encrypted-'));
        const identityPath = path.join(dir, 'identity.json');
        const tokenPath = path.join(dir, 'token.jwt');
        const passphrasePath = path.join(dir, 'passphrase');
        fs.writeFileSync(passphrasePath, 'correct horse battery staple\n', { mode: 0o600 });

        await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_id.mjs'),
            '--label', 'encrypted-cli',
            '--passphrase-file', passphrasePath,
            '--output', identityPath,
        ], { cwd: packageRoot });

        const file = JSON.parse(fs.readFileSync(identityPath, 'utf8'));
        assert.ok(file.keypair.encryptedPrivateKey);
        assert.ok(!file.keypair.privateKey);

        const { stdout } = await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_token.mjs'),
            '--identity', identityPath,
            '--passphrase-file', passphrasePath,
            '--purpose', 'msg-signing',
            '--output', tokenPath,
        ], { cwd: packageRoot });

        assert.strictEqual(stdout, '');
        assert.match(fs.readFileSync(tokenPath, 'utf8'), /^[^.]+\.[^.]+\.[^.]+\n$/);
    });

    it('uses VOUCHSAFE_ASKPASS with the SSH_ASKPASS prompt protocol', async function () {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchsafe-askpass-'));
        const identityPath = path.join(dir, 'identity.json');
        const askpassPath = path.join(dir, 'askpass.mjs');
        const promptsPath = path.join(dir, 'prompts');
        fs.writeFileSync(askpassPath, "#!/usr/bin/env node\nimport fs from 'node:fs';\nfs.appendFileSync(process.env.PROMPTS_PATH, process.argv[2] + '\\n');\nprocess.stdout.write('askpass-secret\\n');\n", { mode: 0o700 });

        await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_id.mjs'),
            '--label', 'askpass-cli',
            '--output', identityPath,
        ], {
            cwd: packageRoot,
            env: { ...process.env, VOUCHSAFE_ASKPASS: askpassPath, PROMPTS_PATH: promptsPath },
        });

        const prompts = fs.readFileSync(promptsPath, 'utf8').trim().split('\n');
        assert.strictEqual(prompts.length, 2);
        assert.match(prompts[0], /Enter passphrase/);
        assert.match(prompts[1], /same passphrase/i);
    });

    it('rejects empty VOUCHSAFE_ASKPASS output instead of writing a plaintext key', async function () {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchsafe-empty-askpass-'));
        const identityPath = path.join(dir, 'identity.json');
        const askpassPath = path.join(dir, 'askpass.mjs');
        fs.writeFileSync(askpassPath, "#!/usr/bin/env node\nprocess.stdout.write('\\n');\n", { mode: 0o700 });

        await assert.rejects(
            () => execFileAsync(process.execPath, [
                path.join(packageRoot, 'src/bin/create_vouchsafe_id.mjs'),
                '--label', 'empty-askpass-cli',
                '--output', identityPath,
            ], {
                cwd: packageRoot,
                env: { ...process.env, VOUCHSAFE_ASKPASS: askpassPath },
            }),
            error => {
                assert.match(error.stderr, /empty passphrase requires --create-unencrypted-identity-file/i);
                return true;
            }
        );
        assert.ok(!fs.existsSync(identityPath));
    });

    it('encrypts an unencrypted existing identity by default', async function () {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vouchsafe-existing-'));
        const sourcePath = path.join(dir, 'source.json');
        const outputPath = path.join(dir, 'output.json');
        const passphrasePath = path.join(dir, 'passphrase');
        fs.writeFileSync(passphrasePath, 'correct horse battery staple\n', { mode: 0o600 });

        await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_id.mjs'),
            '--label', 'existing-source',
            '--create-unencrypted-identity-file',
            '--output', sourcePath,
        ], { cwd: packageRoot });
        await execFileAsync(process.execPath, [
            path.join(packageRoot, 'src/bin/create_vouchsafe_id.mjs'),
            '--existing', sourcePath,
            '--passphrase-file', passphrasePath,
            '--output', outputPath,
        ], { cwd: packageRoot });

        const output = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
        assert.ok(output.keypair.encryptedPrivateKey);
        assert.ok(!output.keypair.privateKey);
    });
});
