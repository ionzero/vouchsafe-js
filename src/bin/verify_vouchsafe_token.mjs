#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { Command } from 'commander';
import {
  validateVouchToken,
  verifyTrustChain,
} from '../index.mjs'; // same import style as your other CLI

const program = new Command();

let status = (...args) => console.error(...args);

program
  .name('verify_vouchsafe_token')
  .description(
    'Verify a Vouchsafe token.\n\n' +
      'Default: validate a single token (signature, URN binding, timestamps).\n' +
      'Extended (-E): require trust for -p purpose(s) using a trusted set and optional extra tokens.'
  )
  .option('-q, --quiet', 'Suppress warnigns and status output')
  .option('-v, --verbose', 'Give extra status output')
  .option('-t, --token-file <filename>', 'File containing one or more tokens (first = subject; rest = extra)', collect, [])
  .option('-T, --token <tokenstring>', 'Token string (first seen = subject; rest = extra)', collect, [])
  .option('-O, --output <format>', 'Output format: json | unix', /^(json|unix)$/i)
  .option('-f, --field <dotpath>', 'Output only this field (may be repeated)', collect, [])
  .option('-E, --extended', 'Extended verification (require trust for -p purpose)')
  .option('-P, --prefix <prefix>', 'prefix to use with unix output, (default vs_)', 'vs_')
  .option('--trusted <filename>', 'Trusted issuers/purposes file (JSON or plain text)')
  .option('--trusted-issuer <issuer:purpose[,purpose2...]>', 'Inline trusted issuer:purpose(s) (may be repeated)', collect, [])
  .option('-p, --purpose <purpose>', 'Purpose to evaluate (may be repeated)', collect, [])
  .addHelpText('after', `Examples:
  # Basic validation; exit code 0 if valid
  verify_vouchsafe_token -t tokens.txt

  # Output decoded claims as JSON (only if valid)
  verify_vouchsafe_token -T "$TOKEN" -O json

  # Output specific fields (one per line)
  verify_vouchsafe_token -T "$TOKEN" -f iss -f jti -f email

  # Extended verification with trusted issuers file and extra tokens
  verify_vouchsafe_token -E -p email-confirmation --trusted trusted.json -t chain.txt -O unix

Trusted file formats:
  JSON:  { "urn:vouchsafe:alice...": ["email-confirmation","webhook:order_placed"], "urn:vouchsafe:bob...": ["email-confirmation"] }
  Text:  urn:vouchsafe:alice... email-confirmation webhook:order_placed
         urn:vouchsafe:bob...   email-confirmation
`);

program.parse(process.argv);
const opts = program.opts();
let prefix = opts.prefix; // || 'vs_';

function verbose(...args) {
  if (opts.verbose) {
      console.error(...args);
  }
};

function error(...args) {
  console.error(...args);
};

(async () => {
  try {
    // 1) Gather tokens (subject first, then extras)
    const allTokens = [];
    for (const f of opts.tokenFile || []) {
      const { subject, extras } = readTokenFile(f);
      if (subject) allTokens.push(subject);
      allTokens.push(...extras);
    }
    for (const s of opts.token || []) {
      if (s && s.trim()) allTokens.push(s.trim());
    }

    if (allTokens.length === 0) {
      error('!!! No tokens provided. Use -t <file> and/or -T <tokenstring>.');
      program.help({ error: true });
    }

    const subject = allTokens[0];
    const extras = uniqPreserveOrder(allTokens.slice(1));

    // 2) Decide verification mode
    let valid = false;
    let payload = null;

    if (opts.extended) {
      // Extended requires purposes + trusted configuration
      const purposes = Array.from(opts.purpose || []).filter(Boolean);
      if (purposes.length === 0) {
        error('!!! Extended verification (-E) requires at least one -p <purpose>.');
        process.exit(2);
      }
      const trusted = await loadTrusted(opts.trusted, Array.from(opts.trustedIssuer || []));

      // Build token set for chain resolution (include subject too, dedup)
      const chainTokens = uniqPreserveOrder([subject, ...extras]);

      const result = await verifyTrustChain(subject, trusted, {
        tokens: chainTokens,
        purposes,
      });

      valid = !!(result && result.valid);
      payload = result && result.payload ? result.payload : null;
    } else {
      // Basic validation of a single Vouchsafe token
      // Validates structure, URN<->key binding, signature, timestamps. Throws on error.
      // (Same call shown in the README quick validation example.)
      payload = await validateVouchToken(subject);
      valid = !!payload;
    }

    // 3) Output rules
    if (!valid) {
      // MUST print nothing on failure (unless verbose is on), and return non-zero
      verbose('Token is invalid')
      process.exit(1);
    }

    const fields = Array.from(opts.field || []);
    if (fields.length > 0) {
      // Output *only* the requested fields, one per line, in the order specified
      for (const p of fields) {
        const v = getByPath(payload, p);
        if (v === undefined || v === null) {
          process.stdout.write('\n'); // missing -> empty line
        } else if (typeof v === 'object') {
          // Objects/arrays: print compact JSON
          process.stdout.write(`${JSON.stringify(v)}\n`);
        } else {
          process.stdout.write(String(v) + '\n');
        }
      }
      process.exit(0);
    }

    if (/^json$/i.test(opts.output)) {
      process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
    } else if (/^unix$/i.test(opts.output)) {
      // Flatten to vs_<path_with_dots_replaced_by_underscores>=value
      const flat = flatten(payload);
      for (const [k, v] of Object.entries(flat)) {
        const name = prefix + k.replaceAll('.', '_');
        const val = (typeof v === 'object') ? JSON.stringify(v) : String(v);
        process.stdout.write(`${name}=${val}\n`);
      }
    } else {
      // No output requested -> just exit code 0 unless we are told to be verbose
      verbose('Token is valid')
    }

    process.exit(0);
  } catch (err) {
    // On any thrown error during validation, do not output data, return non-zero
    if (!opts.quiet) error('Error:', err?.message || err);
    process.exit(1);
  }
})();

/* ------------------------ helpers ------------------------ */

function collect(value, previous) {
  previous.push(value);
  return previous;
}

function readTokenFile(filename) {
  const raw = fs.readFileSync(filename, 'utf8');
  // Accept tokens split by any whitespace; ignore blank lines and lines starting with '#'
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));

  // If the file is a single long blob with whitespace, split it further; otherwise each nonempty line is a token
  const tokens = lines.length === 1 ? lines[0].split(/\s+/).filter(Boolean) : lines;

  const subject = tokens[0] || null;
  const extras = tokens.slice(1);
  return { subject, extras };
}

async function loadTrusted(filePath, inlinePairs) {
  const map = Object.create(null);

  // 1) From --trusted file (JSON object OR space-separated text)
  if (filePath) {
    const text = fs.readFileSync(filePath, 'utf8').trim();
    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = null;
    }

    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      // JSON: { urn: [purpose, ...] } or { urn: "space separated" }
      for (const [urn, v] of Object.entries(parsed)) {
        addTrusted(map, urn, normalizePurposes(v));
      }
    } else {
      // Plain text: "urn purpose1 purpose2 ..."
      const lines = text.split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const parts = trimmed.split(/\s+/);
        const urn = parts.shift();
        addTrusted(map, urn, parts);
      }
    }
  }

  // 2) From repeated --trusted-issuer <urn:purpose[,purpose2,...]>
  for (const pair of inlinePairs) {
    const s = String(pair);
    const idx = s.indexOf(':');
    if (idx === -1) continue;
    const urn = s.slice(0, idx).trim();
    const purp = s.slice(idx + 1).trim();
    const list = purp.split(',').map((p) => p.trim()).filter(Boolean);
    addTrusted(map, urn, list);
  }

  return map;
}

function addTrusted(map, urn, purposes) {
  if (!urn || !purposes || purposes.length === 0) return;
  if (!map[urn]) map[urn] = [];
  for (const p of purposes) {
    if (!map[urn].includes(p)) map[urn].push(p);
  }
}

function normalizePurposes(v) {
  if (Array.isArray(v)) return v.filter(Boolean).map(String);
  if (typeof v === 'string') return v.split(/\s+/).filter(Boolean);
  return [];
}

function uniqPreserveOrder(arr) {
  const seen = new Set();
  const out = [];
  for (const x of arr) {
    if (!seen.has(x)) {
      seen.add(x);
      out.push(x);
    }
  }
  return out;
}

function getByPath(obj, dotpath) {
  try {
    const parts = String(dotpath).split('.').filter(Boolean);
    let cur = obj;
    for (const seg of parts) {
      const key = isFiniteIndex(seg) ? Number(seg) : seg;
      if (cur == null || !(key in cur)) return undefined;
      cur = cur[key];
    }
    return cur;
  } catch {
    return undefined;
  }
}

function isFiniteIndex(s) {
  return /^[0-9]+$/.test(s);
}

function flatten(obj, prefix = '') {
  const out = {};
  const isPrimitive = (v) =>
    v == null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';

  const helper = (val, pfx) => {
    if (isPrimitive(val)) {
      out[pfx || 'value'] = val;
      return;
    }
    if (Array.isArray(val)) {
      val.forEach((v, i) => helper(v, pfx ? `${pfx}.${i}` : String(i)));
      return;
    }
    if (typeof val === 'object') {
      const keys = Object.keys(val);
      if (keys.length === 0) {
        out[pfx || 'value'] = {}; // empty object
        return;
      }
      for (const k of keys) {
        helper(val[k], pfx ? `${pfx}.${k}` : k);
      }
    }
  };

  helper(obj, prefix);
  return out;
}
