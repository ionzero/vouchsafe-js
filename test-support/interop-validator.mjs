import assert from 'assert';
import fs from 'fs';
import path from 'path';

import {
  Identity,
  VOUCHSAFE_SPEC_VERSION,
  validateTrustChain,
  validateVouchToken,
  verifyUrnMatchesKey,
  verifyVouchToken,
} from '../src/index.mjs';
import { INTEROP_SCHEMA_VERSION } from './interop-corpus.mjs';

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function readToken(filePath) {
  return fs.readFileSync(filePath, 'utf8').trim();
}

function readBundle(filePath) {
  return fs.readFileSync(filePath, 'utf8').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function resolveAsset(rootDir, relativePath) {
  if (typeof relativePath !== 'string' || !relativePath) {
    throw new Error('Interop asset path must be a non-empty relative path');
  }
  const resolvedRoot = path.resolve(rootDir);
  const resolvedAsset = path.resolve(resolvedRoot, relativePath);
  if (path.isAbsolute(relativePath) || (resolvedAsset !== resolvedRoot && !resolvedAsset.startsWith(`${resolvedRoot}${path.sep}`))) {
    throw new Error(`Interop asset path escapes corpus directory: ${relativePath}`);
  }
  if (!fs.existsSync(resolvedAsset)) {
    throw new Error(`Interop asset does not exist: ${relativePath}`);
  }
  return resolvedAsset;
}

function validateManifest(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('Interop manifest must be a JSON object');
  if (manifest.schema_version !== INTEROP_SCHEMA_VERSION) throw new Error(`Unsupported interoperability schema version: ${manifest.schema_version}`);
  if (manifest.spec_version !== VOUCHSAFE_SPEC_VERSION) throw new Error(`Unsupported Vouchsafe specification version: ${manifest.spec_version}`);
  if (typeof manifest.expires_at !== 'number' || !Number.isFinite(manifest.expires_at)) throw new Error('Interop manifest must include a numeric expires_at');
  if (manifest.expires_at <= Math.floor(Date.now() / 1000)) throw new Error('Interop manifest has expired');
  if (!Array.isArray(manifest.test_cases)) throw new Error('Interop manifest test_cases must be an array');

  const names = new Set();
  for (const testCase of manifest.test_cases) {
    if (!testCase || typeof testCase !== 'object' || Array.isArray(testCase)) throw new Error('Interop test case must be an object');
    if (typeof testCase.name !== 'string' || !testCase.name) throw new Error('Interop test case must include a name');
    if (names.has(testCase.name)) throw new Error(`Duplicate interoperability test case name: ${testCase.name}`);
    names.add(testCase.name);
    if (typeof testCase.type !== 'string' || !testCase.type) throw new Error(`Interop test case ${testCase.name} must include a type`);
    if (!testCase.assets || typeof testCase.assets !== 'object' || Array.isArray(testCase.assets)) throw new Error(`Interop test case ${testCase.name} must include assets`);
    if (testCase.expected !== undefined && (!testCase.expected || typeof testCase.expected !== 'object' || Array.isArray(testCase.expected))) throw new Error(`Interop test case ${testCase.name} has an invalid expected value`);
  }
}

async function runIdentityRoundtrip(rootDir, testCase) {
  const identityData = readJson(resolveAsset(rootDir, testCase.assets.identity));
  const hydrated = await Identity.from(identityData);
  assert.strictEqual(hydrated.urn, identityData.urn);
  assert.strictEqual(await verifyUrnMatchesKey(identityData.urn, identityData.keypair.publicKey), true);
}

async function runEncryptedIdentityRoundtrip(rootDir, testCase) {
  const identityData = readJson(resolveAsset(rootDir, testCase.assets.identity));
  assert.ok(identityData.keypair.encryptedPrivateKey);
  assert.ok(!identityData.keypair.privateKey);
  const hydrated = await Identity.from(identityData, { passphrase: testCase.expected.passphrase });
  assert.strictEqual(hydrated.urn, identityData.urn);
  const token = await hydrated.attest({ purpose: 'interop-encrypted-identity' });
  assert.strictEqual((await validateVouchToken(token)).iss, hydrated.urn);
}

async function runIdentityReject(rootDir, testCase) {
  const identityData = readJson(resolveAsset(rootDir, testCase.assets.identity));
  await assert.rejects(() => Identity.from(identityData, { passphrase: testCase.expected?.passphrase }));
}

async function runTokenValidate(rootDir, testCase) {
  const token = readToken(resolveAsset(rootDir, testCase.assets.token));
  const decoded = await validateVouchToken(token);
  if (testCase.expected.kind) {
    assert.strictEqual(decoded.kind, testCase.expected.kind);
  }
}

async function runVouchValidate(rootDir, testCase) {
  await runTokenValidate(rootDir, testCase);
  const token = readToken(resolveAsset(rootDir, testCase.assets.token));
  const subjectToken = readToken(resolveAsset(rootDir, testCase.assets.subject_token));
  const result = await verifyVouchToken(token, subjectToken);
  assert.strictEqual(result.valid, true);
}

async function runTrustChain(rootDir, testCase, expectedValid) {
  const tokens = readBundle(resolveAsset(rootDir, testCase.assets.tokens_bundle));
  const subjectToken = readToken(resolveAsset(rootDir, testCase.assets.subject_token));
  const trustedIssuers = readJson(resolveAsset(rootDir, testCase.assets.trusted_issuers));
  const requiredPurposes = testCase.expected.required_purposes || [];
  const result = await validateTrustChain(tokens, subjectToken, trustedIssuers, requiredPurposes);
  assert.strictEqual(result.valid, expectedValid);
  if (expectedValid) {
    for (const purpose of requiredPurposes) {
      assert.ok(result.effectivePurposes.includes(purpose));
    }
  }
}

async function runTokenReject(rootDir, testCase) {
  const token = readToken(resolveAsset(rootDir, testCase.assets.token));
  await assert.rejects(() => validateVouchToken(token));
}

async function runVouchReject(rootDir, testCase) {
  const issuer = await Identity.from(readJson(resolveAsset(rootDir, testCase.assets.issuer_identity)));
  const subjectToken = readToken(resolveAsset(rootDir, testCase.assets.subject_token));
  await assert.rejects(() => issuer.vouch(subjectToken, { purpose: testCase.expected.purpose }));
}

async function runVouchVerifyReject(rootDir, testCase) {
  const token = readToken(resolveAsset(rootDir, testCase.assets.token));
  const subjectToken = readToken(resolveAsset(rootDir, testCase.assets.subject_token));
  await assert.rejects(() => verifyVouchToken(token, subjectToken));
}

export async function validateInteropAssets(rootDir, options = {}) {
  const { skipUnknownTypes = false, continueOnFailure = false } = options;
  const manifest = readJson(path.join(rootDir, 'manifest.json'));
  validateManifest(manifest);
  const results = [];

  for (const testCase of manifest.test_cases || []) {
    try {
      switch (testCase.type) {
        case 'identity_roundtrip':
          await runIdentityRoundtrip(rootDir, testCase);
          break;
        case 'identity_encrypted_roundtrip':
          await runEncryptedIdentityRoundtrip(rootDir, testCase);
          break;
        case 'identity_reject':
          await runIdentityReject(rootDir, testCase);
          break;
        case 'token_validate':
          await runTokenValidate(rootDir, testCase);
          break;
        case 'vouch_validate':
          await runVouchValidate(rootDir, testCase);
          break;
        case 'trust_chain_validate':
          await runTrustChain(rootDir, testCase, true);
          break;
        case 'trust_chain_reject':
          await runTrustChain(rootDir, testCase, false);
          break;
        case 'token_reject':
          await runTokenReject(rootDir, testCase);
          break;
        case 'vouch_reject':
          await runVouchReject(rootDir, testCase);
          break;
        case 'vouch_verify_reject':
          await runVouchVerifyReject(rootDir, testCase);
          break;
        default:
          if (skipUnknownTypes) {
            results.push({ name: testCase.name, type: testCase.type, status: 'skipped' });
            continue;
          }
          throw new Error(`Unknown interoperability test type: ${testCase.type}`);
      }
      results.push({ name: testCase.name, type: testCase.type, status: 'passed' });
    } catch (error) {
      const message = `${testCase.name}: ${error.message}`;
      if (!continueOnFailure) {
        error.message = message;
        throw error;
      }
      results.push({ name: testCase.name, type: testCase.type, status: 'failed', error: message });
    }
  }

  return {
    manifest,
    results,
    passed: results.filter((result) => result.status === 'passed').length,
    failed: results.filter((result) => result.status === 'failed').length,
    skipped: results.filter((result) => result.status === 'skipped').length,
  };
}
