#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { Command } from 'commander';
import { createVouchsafeIdentity } from '../index.mjs';

const program = new Command();

function toPem(label, base64Key) {
  const lines = base64Key.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

let status = function() {
    console.error(...arguments);
};

program.name('create-vouchsafe-id')
  .description('Create a new Vouchsafe identity with associated keypair')
  .version('1.0.0')

program
  .option('-l, --label <label>', 'Identity label')
  .option('-s, --separate', 'Output in separate files instead of json')
  .option('-q, --quiet', 'Do not output status messages')
  .option('-o, --output <filename>', 'output filename (or prefix in separate files mode)')
  
program.parse(process.argv);

const options = program.opts();
const label = options.label;
const keyPrefix = options.output || label;

if (typeof label == 'undefined') {
    status('!!! Identity label (-l label) is required\n');
    program.help();
    process.exit();
}

if (label.length < 3) {
    status('Label must be at least 3 characters in length');
    process.exit();
}


if (options.quiet) {
    // override the status function if we are told to be quiet
    status = function() {
        // do nothing
    };
}

function writeFile(path_or_handle, data, encoding) {
    let out = path_or_handle;
    let type = 'handle';
    if (typeof path_or_handle == 'string') {
        out = fs.createWriteStream(path_or_handle, { encoding });
        type = 'file'
    }
    out.write(data);
    if (type == 'file') {
        out.end();
    }
}

try {
  const identity = await createVouchsafeIdentity(label);
  const pubPem = toPem('PUBLIC KEY', identity.keypair.publicKey);
  const privPem = toPem('PRIVATE KEY', identity.keypair.privateKey);

  status(`Created identity: ${identity.urn}`);
  if (!options.separate) {
      let json_output = JSON.stringify(identity, undefined, 4);
      let output_filename = options.output || label + '.json';
      if (output_filename == '-') {
          output_filename = process.stdout; 
      } 
      await writeFile(
          output_filename,
          json_output,
          'utf8'
      );
      if (options.output != '-') {
          status(`Saved to: ${output_filename}`);
      }
  } else {
      let urnFilename = `${keyPrefix}.urn`;
      let pubKeyFilename = `${keyPrefix}.public.pem`;
      let privateKeyFilename = `${keyPrefix}.private.pem`;
      if (keyPrefix == '-') {
          urnFilename = process.stdout; 
          pubKeyFilename = process.stdout; 
          privateKeyFilename = process.stdout; 
      } 
      await writeFile(
        urnFilename,
        identity.urn + '\n',
        'utf8'
      );
      await writeFile(
        privateKeyFilename,
        privPem,
        'utf8'
      );
      await writeFile(
        pubKeyFilename,
        pubPem,
        'utf8'
      );
      if (keyPrefix != '-') {
        status(`Saved to: ${keyPrefix}.urn, ${keyPrefix}.private.pem and ${keyPrefix}.public.pem `);
      }
  }
} catch(err) {
  status('Error:', err);
  process.exit(1);
}
