#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { Command } from 'commander';
import { createVouchsafeIdentity, createVouchsafeIdentityFromKeypair, loadIdentity, serializeIdentity } from '../index.mjs';
import { getNewIdentityPassphrase, getPassphrase } from './passphrase.mjs';

const program = new Command();
const MAX_IDENTITY_FILE_BYTES = 16 * 1024 * 1024;

function toPem(label, base64Key) {
    const lines = base64Key.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

let status = function() {
    console.error(...arguments);
};

program.name('create_vouchsafe_id')
    .description('Create a new Vouchsafe identity with associated keypair.\n\n' +
        'By default creates a new keypair. To use an existing\n' +
        'keypair, use the --public and --private to provide them');

program
    .option('-l, --label <label>', 'Identity label (required unless --existing is used)')
    .option('-s, --separate', 'Output in separate files instead of json')
    .option('-q, --quiet', 'Do not output status messages')
    .option('-e, --existing <filename>', 'Load an existing identity file rather than creating from scratch')
    .option('-o, --output <filename>', 'output filename (or prefix in separate files mode)')
    .option('--public <filename>', 'existing public key PEM file')
    .option('--private <filename>', 'existing private key PEM file')
    .option('--passphrase-file <filename>', 'read the passphrase from a file')
    .option('--create-unencrypted-identity-file', 'create an unencrypted identity file (unsafe)')

program.parse(process.argv);

const options = program.opts();
const label = options.label;
const keyPrefix = options.output || label;

if (typeof label == 'undefined' && !options.existing) {
    status('!!! Identity label (-l label) is required\n');
    program.help();
    process.exit();
}

if (label !== undefined && label.length < 3) {
    status('Label must be at least 3 characters in length');
    process.exit();
}

if (options.quiet) {
    // override the status function if we are told to be quiet
    status = function() {
        // do nothing
    };
}

function readPemFile(filename) {
    const contents = fs.readFileSync(filename, 'utf8');
    return contents.replace(/^-----BEGIN .*?-----\n|\n-----END .*?-----\n?/g, '').replace(/\n/g, '');
}

function readIdentityFile(filename) {
    const stats = fs.statSync(filename);
    if (!stats.isFile() || stats.size > MAX_IDENTITY_FILE_BYTES) throw new Error('Identity file must be a regular file no larger than 16 MiB');
    return JSON.parse(fs.readFileSync(filename, 'utf8'));
}

async function writeFile(path_or_handle, data, encoding) {
    if (typeof path_or_handle !== 'string') {
        path_or_handle.write(data);
        return;
    }

    await new Promise((resolve, reject) => {
        const out = fs.createWriteStream(path_or_handle, {
            encoding,
            mode: 0o600
        });
        out.once('error', reject);
        out.end(data, () => {
            // mode only affects new files; tighten permissions when overwriting too.
            fs.chmodSync(path_or_handle, 0o600);
            resolve();
        });
    });
}

try {
    let identity;
    let encrypt;
    let passphrase;
    if (options.public && options.private) {
        const pubKey = readPemFile(options.public);
        const privKey = readPemFile(options.private);
        identity = await createVouchsafeIdentityFromKeypair(label, { publicKey: pubKey, privateKey: privKey });
      encrypt = !options.createUnencryptedIdentityFile;
      passphrase = await getNewIdentityPassphrase(options);
    } else if (options.existing) {
        const identityFromFile = readIdentityFile(options.existing);
        const sourceIsEncrypted = typeof identityFromFile?.keypair?.encryptedPrivateKey === 'string';
        if (sourceIsEncrypted) {
            passphrase = await getPassphrase({
                passphraseFile: options.passphraseFile,
                prompt: 'Enter passphrase for existing identity: ',
            });
        } else if (!options.createUnencryptedIdentityFile) {
            passphrase = await getNewIdentityPassphrase(options);
        } else if (options.passphraseFile) {
            throw new Error('--create-unencrypted-identity-file cannot be used with --passphrase-file for an unencrypted source identity');
        }
        identity = await loadIdentity(identityFromFile, { passphrase });
        encrypt = !options.createUnencryptedIdentityFile;
    } else {
        identity = await createVouchsafeIdentity(label);
        encrypt = !options.createUnencryptedIdentityFile;
        passphrase = await getNewIdentityPassphrase(options);
    }

    if (options.separate && encrypt) throw new Error('--separate cannot be used for encrypted identity files; use --create-unencrypted-identity-file to opt in');
    if (!encrypt) console.error('Warning: creating an unencrypted identity file exposes private-key material.');

    const identityFile = await serializeIdentity(identity, encrypt ? { passphrase } : { unprotected_private_key: true });

    status(`Created identity: ${identity.urn}`);
    if (!options.separate) {
        let json_output = JSON.stringify(identityFile, undefined, 4);
        let output_filename = options.output || identity.urn.match(/^urn:vouchsafe:([^.]*)/)?.[1] + '.json';
        if (output_filename == '-') {
            output_filename = process.stdout;
        }
        if (options.existing == output_filename) {
            throw new Error('Stubbornly refusing to overwrite original identity file');
        }
        await writeFile(output_filename, json_output, 'utf8');

        if (options.output != '-') {
            status(`Saved to: ${output_filename}`);
        }
    } else {
        const pubPem = toPem('PUBLIC KEY', identityFile.keypair.publicKey);
        const privPem = toPem('PRIVATE KEY', identityFile.keypair.privateKey);
        let urnFilename = `${keyPrefix}.urn`;
        let pubKeyFilename = `${keyPrefix}.public.pem`;
        let privateKeyFilename = `${keyPrefix}.private.pem`;
        if (keyPrefix == '-') {
            urnFilename = process.stdout;
            pubKeyFilename = process.stdout;
            privateKeyFilename = process.stdout;
        }
        await writeFile(urnFilename, identityFile.urn + '\n', 'utf8');
        await writeFile(privateKeyFilename, privPem, 'utf8');
        await writeFile(pubKeyFilename, pubPem, 'utf8');

        if (keyPrefix != '-') {
            status(`Saved to: ${keyPrefix}.urn, ${keyPrefix}.private.pem and ${keyPrefix}.public.pem `);
        }
    }
} catch (err) {
    status('Error:', err);
    process.exit(1);
}
