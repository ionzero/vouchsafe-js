#!/usr/bin/env node

import fs from 'fs';
import { Command } from 'commander';
import { Identity } from '../index.mjs';

const program = new Command();



program
  .name('create-vouchsafe-token')
  .description(
    'Create a Vouchsafe token from an identity file and claims.\n' +
      'Token types:\n' +
      '  * attest (default) - issue an attestation\n' +
      '  * vouch            - vouch for an existing token (-t or -T required)\n' +
      '  * revoke           - revoke a previous vouch (-t or -T required)\n' +
      'Claims may be provided via a JSON file (-f) and/or key=value pairs (-c).\n' +
      'Use -p to set a purpose (repeatable; for attest/vouch).\n' +
      'Expiration defaults to 1 day; -e 0 disables exp.\n' +
      'Outputs the JWT to stdout by default or to a file with -o.\n'
  )
  .option('-i, --identity <file>', 'Path to identity JSON file (required)')
  .option('-f, --claims <file>', 'Path to claims JSON file')
  .option('-c, --claim <key=value>', 'Additional claim (repeatable)', collectClaims, {})
  .option('-p, --purpose <purpose>', 'Purpose for the token (repeatable)', collectStrings, [])
  .option('-e, --expires <seconds>', 'Expiration in seconds (default 86400, 0 = no exp)')
  .option('-o, --output <file>', 'Write token to this file instead of stdout')
  .option('-q, --quiet', 'Suppress warnings and status output')
  .option('-v, --verbose', 'Give extra status output')
  // token subject inputs (for vouch/revoke)
  .option('-t, --token-file <file>', 'Subject token file (for --vouch/--revoke)')
  .option('-T, --token <string>', 'Subject token string (for --vouch/--revoke)')
  // type switches
  .option('--attest', 'Create an attestation token (default)')
  .option('--vouch', 'Create a vouch token (requires -t or -T)')
  .option('--revoke', 'Create a revoke token (requires -t or -T)')
  .helpOption('-h, --help', 'Display help');

program.parse(process.argv);
const opts = program.opts();

function verbose(...args) {
  if (opts.verbose) {
      console.error(...args);
  }
};

function error(...args) {
  console.error(...args);
};

if (!opts.identity) {
  error('!!! Identity file (-i) is required\n');
  program.help();
  process.exit(1);
}

function collectClaims(value, previous) {
  const idx = value.indexOf('=');
  if (idx === -1) {
    throw new Error(`Invalid claim: ${value}. Expected key=value`);
  }
  const key = value.slice(0, idx).trim();
  const raw = value.slice(idx + 1);
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = raw;
  }
  previous[key] = parsed;
  return previous;
}

function collectStrings(value, previous) {
  previous.push(value);
  return previous;
}

function parseClaimsFile(filename) {
  const txt = fs.readFileSync(filename, 'utf8');
  try {
    const obj = JSON.parse(txt);
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) return obj;
  } catch (e) {
    // fall through
  }
  throw new Error(`Claims file must be a JSON object: ${filename}`);
}

function writeOut(pathOrStdout, data) {
  if (!pathOrStdout || pathOrStdout === '-') {
    process.stdout.write(data);
    if (!data.endsWith('\n')) process.stdout.write('\n');
    return;
  }
  fs.writeFileSync(pathOrStdout, data + (data.endsWith('\n') ? '' : '\n'), 'utf8');
}

function toSeconds(val, def = 86400) {
  if (val === undefined || val === null) return def; // default 1 day
  const n = Number(val);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`Invalid expires value: ${val}. Use seconds (0 = no exp).`);
  }
  return Math.floor(n);
}

function loadSubjectToken() {
  if (opts.token) return opts.token;
  if (opts.tokenFile) return fs.readFileSync(opts.tokenFile, 'utf8').trim();
  throw new Error('Subject token required: use -t <file> or -T <token>');
}

function resolveAction() {
  const picks = [opts.attest ? 'attest' : null, opts.vouch ? 'vouch' : null, opts.revoke ? 'revoke' : null].filter(Boolean);
  if (picks.length === 0) return 'attest';
  if (picks.length > 1) throw new Error('Choose only one of --attest, --vouch, or --revoke');
  return picks[0];
}

(async () => {
  try {
    const action = resolveAction();

    // Load identity
    const idJson = JSON.parse(fs.readFileSync(opts.identity, 'utf8'));
    const identity = await Identity.from(idJson);

    // Merge claims: file first, then -c overrides
    const claims = {};
    if (opts.claims) Object.assign(claims, parseClaimsFile(opts.claims));
    if (opts.claim) Object.assign(claims, opts.claim);

    // Purpose: string or array (attest & vouch)
    if (action === 'attest' || action === 'vouch') {
      if(opts.purpose && opts.purpose.length) {
          claims.purpose = opts.purpose.length === 1 ? opts.purpose[0] : opts.purpose;
      } else if (!opts.quiet) {
          error('Warning: no purpose defined, which means all permissions granted')
      }
    }

    // Timestamps
    const iat = Math.floor(Date.now() / 1000);
    claims.iat ??= iat;

    const expSeconds = toSeconds(opts.expires, 86400);
    if (expSeconds > 0) {
      claims.exp = iat + expSeconds;
    }

    let token;
    if (action === 'attest') {
      token = await identity.attest(claims);
    } else if (action === 'vouch') {
      const subject = loadSubjectToken();
      token = await identity.vouch(subject, claims);
    } else if (action === 'revoke') {
      const subject = loadSubjectToken();
      token = await identity.revoke(subject, claims);
    }

    // Output
    writeOut(opts.output, token);

    if (opts.output && opts.output !== '-' && !opts.quiet) {
      verbose(`Saved token to: ${opts.output}`);
    }
  } catch (err) {
    error('Error:', err?.message || err);
    process.exit(1);
  }
})();
