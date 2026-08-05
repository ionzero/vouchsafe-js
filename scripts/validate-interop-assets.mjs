#!/usr/bin/env node

import path from 'path';

import { validateInteropAssets } from '../test-support/interop-validator.mjs';

const args = process.argv.slice(2);
const skipUnknownTypes = args.includes('--skip-unknown-types');
const tap = args.includes('--tap');
const dirArg = args.find((arg) => !arg.startsWith('--'));

if (!dirArg) {
  console.error('Usage: node scripts/validate-interop-assets.mjs <asset-dir> [--skip-unknown-types] [--tap]');
  process.exit(2);
}

const result = await validateInteropAssets(path.resolve(dirArg), {
  skipUnknownTypes,
  continueOnFailure: tap,
});

if (tap) {
  process.stdout.write('TAP version 13\n');
  process.stdout.write(`1..${result.results.length}\n`);
  result.results.forEach((entry, index) => {
    if (entry.status === 'passed') {
      process.stdout.write(`ok ${index + 1} - ${entry.name}\n`);
      return;
    }
    if (entry.status === 'skipped') {
      process.stdout.write(`ok ${index + 1} - ${entry.name} # SKIP unknown test type ${entry.type}\n`);
      return;
    }
    process.stdout.write(`not ok ${index + 1} - ${entry.name}\n`);
    process.stdout.write(`  ---\n`);
    process.stdout.write(`  message: ${JSON.stringify(entry.error)}\n`);
    process.stdout.write(`  ...\n`);
  });
} else {
  process.stdout.write(JSON.stringify({ passed: result.passed, failed: result.failed, skipped: result.skipped }, null, 2) + '\n');
}

process.exit(result.failed > 0 ? 1 : 0);
