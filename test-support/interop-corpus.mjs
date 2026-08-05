import crypto from 'crypto';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';

import {
  Identity,
  VOUCHSAFE_SPEC_VERSION,
  createBurnToken,
  createJwt,
  decodeJwt,
} from '../src/index.mjs';

export const INTEROP_SCHEMA_VERSION = 1;

function rel(rootDir, targetPath) {
  return path.relative(rootDir, targetPath).split(path.sep).join('/');
}

async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

async function writeJson(filePath, value) {
  await fs.writeFile(filePath, JSON.stringify(value, null, 2), 'utf8');
}

async function writeText(filePath, value) {
  await fs.writeFile(filePath, value, 'utf8');
}

async function writeBundle(rootDir, bundlesDir, name, tokens) {
  const bundlePath = path.join(bundlesDir, `${name}.tokens`);
  await writeText(bundlePath, tokens.join('\n') + '\n');
  return rel(rootDir, bundlePath);
}

function buildTestCase(name, type, assets, expected = {}) {
  return { name, type, assets, expected };
}

export async function createInteropAssetDirectory(outputDir) {
  if (outputDir) {
    const resolved = path.resolve(outputDir);
    await ensureDir(resolved);
    return resolved;
  }
  return fs.mkdtemp(path.join(os.tmpdir(), 'vouchsafe-js-interop-'));
}

export async function writeInteropCorpus(outputDir, producer = 'js') {
  const rootDir = await createInteropAssetDirectory(outputDir);
  const identitiesDir = path.join(rootDir, 'identities');
  const tokensDir = path.join(rootDir, 'tokens');
  const bundlesDir = path.join(rootDir, 'bundles');
  const trustedDir = path.join(rootDir, 'trusted');

  await Promise.all([
    ensureDir(identitiesDir),
    ensureDir(tokensDir),
    ensureDir(bundlesDir),
    ensureDir(trustedDir),
  ]);

  const now = Math.floor(Date.now() / 1000);
  const expiry = now + 300;

  const leaf = await Identity.create('leaf');
  const intermediate = await Identity.create('intermediate');
  const root = await Identity.create('root');
  const external = await Identity.create('external');

  const validPurpose = 'msg-signing';
  const broadPurpose = 'file-storage msg-signing';

  const leafAttestation = await leaf.attest({ purpose: validPurpose, exp: expiry });
  const intermediateVouch = await intermediate.vouch(leafAttestation, { purpose: validPurpose, exp: expiry });
  const rootVouch = await root.vouch(intermediateVouch, { purpose: validPurpose, exp: expiry });
  const rootRevoke = await root.revoke(rootVouch);
  const intermediateBurn = await createBurnToken(intermediate.urn, intermediate.keypair);

  const broadAttestation = await leaf.attest({ purpose: broadPurpose, exp: expiry, jti: crypto.randomUUID() });
  const attenuatedVouch = await intermediate.vouch(broadAttestation, { purpose: validPurpose, exp: expiry });
  const attenuatedRootVouch = await root.vouch(attenuatedVouch, { purpose: broadPurpose, exp: expiry });

  const leafDecoded = decodeJwt(leafAttestation);
  const tamperedVouch = await createJwt(
    root.urn,
    root.keypair.publicKey,
    root.keypair.privateKey,
    {
      kind: 'vch:vouch',
      jti: crypto.randomUUID(),
      sub: leafDecoded.jti,
      vch_iss: leafDecoded.iss,
      vch_sum: '0'.repeat(64),
      purpose: validPurpose,
      exp: expiry,
    }
  );

  const badRevokeWithExp = await createJwt(
    root.urn,
    root.keypair.publicKey,
    root.keypair.privateKey,
    {
      kind: 'vch:revoke',
      jti: crypto.randomUUID(),
      sub: leafDecoded.jti,
      revokes: leafDecoded.jti,
      vch_iss: leafDecoded.iss,
      vch_sum: '0'.repeat(64),
      exp: expiry,
    }
  );

  const externalJwt = await createJwt(
    external.urn,
    external.keypair.publicKey,
    external.keypair.privateKey,
    {
      sub: 'external-subject',
      jti: crypto.randomUUID(),
      exp: expiry,
    }
  );

  const identities = {
    leaf: leaf.toJSON(),
    intermediate: intermediate.toJSON(),
    root: root.toJSON(),
    external: external.toJSON(),
  };

  const identityPaths = {};
  for (const [name, identity] of Object.entries(identities)) {
    const filePath = path.join(identitiesDir, `${name}.json`);
    await writeJson(filePath, identity);
    identityPaths[name] = rel(rootDir, filePath);
  }

  const tokenValues = {
    leafAttestation,
    intermediateVouch,
    rootVouch,
    rootRevoke,
    intermediateBurn,
    broadAttestation,
    attenuatedVouch,
    attenuatedRootVouch,
    tamperedVouch,
    badRevokeWithExp,
    externalJwt,
  };

  const tokenFilenames = {
    leafAttestation: 'leaf-attestation.jwt',
    intermediateVouch: 'intermediate-vouch.jwt',
    rootVouch: 'root-vouch.jwt',
    rootRevoke: 'root-revoke.jwt',
    intermediateBurn: 'intermediate-burn.jwt',
    broadAttestation: 'broad-attestation.jwt',
    attenuatedVouch: 'attenuated-vouch.jwt',
    attenuatedRootVouch: 'attenuated-root-vouch.jwt',
    tamperedVouch: 'tampered-vouch.jwt',
    badRevokeWithExp: 'bad-revoke-with-exp.jwt',
    externalJwt: 'external-nonvouchsafe.jwt',
  };

  const tokenPaths = {};
  for (const [name, filename] of Object.entries(tokenFilenames)) {
    const filePath = path.join(tokensDir, filename);
    await writeText(filePath, tokenValues[name] + '\n');
    tokenPaths[name] = rel(rootDir, filePath);
  }

  const trustedMsgSigningPath = path.join(trustedDir, 'msg-signing.json');
  const trustedMsgAndStoragePath = path.join(trustedDir, 'msg-and-storage.json');
  await writeJson(trustedMsgSigningPath, { [root.urn]: [validPurpose] });
  await writeJson(trustedMsgAndStoragePath, { [root.urn]: ['msg-signing', 'file-storage'] });

  const bundlePaths = {
    valid: await writeBundle(rootDir, bundlesDir, 'valid', [leafAttestation, intermediateVouch, rootVouch]),
    revoked: await writeBundle(rootDir, bundlesDir, 'revoked', [leafAttestation, intermediateVouch, rootVouch, rootRevoke]),
    burned: await writeBundle(rootDir, bundlesDir, 'burned', [leafAttestation, intermediateVouch, rootVouch, intermediateBurn]),
    tamperedVouchSum: await writeBundle(rootDir, bundlesDir, 'tampered-vouch-sum', [leafAttestation, tamperedVouch]),
    purposeAttenuated: await writeBundle(rootDir, bundlesDir, 'purpose-attenuated', [broadAttestation, attenuatedVouch, attenuatedRootVouch]),
  };

  const manifest = {
    schema_version: INTEROP_SCHEMA_VERSION,
    producer,
    spec_version: VOUCHSAFE_SPEC_VERSION,
    generated_at: now,
    expires_at: expiry,
    test_cases: [
      buildTestCase('identity_leaf_roundtrip', 'identity_roundtrip', {
        identity: identityPaths.leaf,
      }),
      buildTestCase('attestation_leaf_valid', 'token_validate', {
        token: tokenPaths.leafAttestation,
      }, {
        kind: 'vch:attest',
      }),
      buildTestCase('vouch_intermediate_over_leaf_valid', 'vouch_validate', {
        token: tokenPaths.intermediateVouch,
        subject_token: tokenPaths.leafAttestation,
      }, {
        kind: 'vch:vouch',
      }),
      buildTestCase('vouch_root_over_intermediate_valid', 'vouch_validate', {
        token: tokenPaths.rootVouch,
        subject_token: tokenPaths.intermediateVouch,
      }, {
        kind: 'vch:vouch',
      }),
      buildTestCase('trust_chain_valid_msg_signing', 'trust_chain_validate', {
        tokens_bundle: bundlePaths.valid,
        subject_token: tokenPaths.leafAttestation,
        trusted_issuers: rel(rootDir, trustedMsgSigningPath),
      }, {
        required_purposes: [validPurpose],
      }),
      buildTestCase('trust_chain_rejected_revoked', 'trust_chain_reject', {
        tokens_bundle: bundlePaths.revoked,
        subject_token: tokenPaths.leafAttestation,
        trusted_issuers: rel(rootDir, trustedMsgSigningPath),
      }, {
        required_purposes: [validPurpose],
      }),
      buildTestCase('trust_chain_rejected_burned', 'trust_chain_reject', {
        tokens_bundle: bundlePaths.burned,
        subject_token: tokenPaths.leafAttestation,
        trusted_issuers: rel(rootDir, trustedMsgSigningPath),
      }, {
        required_purposes: [validPurpose],
      }),
      buildTestCase('trust_chain_rejected_tampered_vch_sum', 'trust_chain_reject', {
        tokens_bundle: bundlePaths.tamperedVouchSum,
        subject_token: tokenPaths.leafAttestation,
        trusted_issuers: rel(rootDir, trustedMsgSigningPath),
      }, {
        required_purposes: [validPurpose],
      }),
      buildTestCase('trust_chain_valid_purpose_attenuated', 'trust_chain_validate', {
        tokens_bundle: bundlePaths.purposeAttenuated,
        subject_token: tokenPaths.broadAttestation,
        trusted_issuers: rel(rootDir, trustedMsgAndStoragePath),
      }, {
        required_purposes: [validPurpose],
      }),
      buildTestCase('trust_chain_rejected_purpose_expansion', 'trust_chain_reject', {
        tokens_bundle: bundlePaths.purposeAttenuated,
        subject_token: tokenPaths.broadAttestation,
        trusted_issuers: rel(rootDir, trustedMsgAndStoragePath),
      }, {
        required_purposes: ['msg-signing', 'file-storage'],
      }),
      buildTestCase('token_rejected_revoke_with_exp', 'token_reject', {
        token: tokenPaths.badRevokeWithExp,
      }),
      buildTestCase('token_rejected_external_non_vouchsafe', 'token_reject', {
        token: tokenPaths.externalJwt,
      }),
      buildTestCase('vouch_rejected_external_non_vouchsafe_subject', 'vouch_reject', {
        issuer_identity: identityPaths.root,
        subject_token: tokenPaths.externalJwt,
      }, {
        purpose: validPurpose,
      }),
    ],
  };

  await writeJson(path.join(rootDir, 'manifest.json'), manifest);
  return { outputDir: rootDir, manifest };
}
