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
  hashJwt,
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

function randomCharacters(alphabet, length) {
  const characters = Array.from(alphabet);
  return Array.from({ length }, () => characters[crypto.randomInt(characters.length)]).join('');
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
  const attacker = await Identity.create('attacker');
  const external = await Identity.create('external');
  const protectedAsciiIdentity = await Identity.create('protected-ascii');
  const protectedUtf8Identity = await Identity.create('protected-utf8');
  const protectedAsciiPassphrase = randomCharacters('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+', 32);
  const protectedUtf8Passphrase = `vouchsafe-${randomCharacters('aeiou', 8)}-${randomCharacters(['é', 'ø', '漢', '字', '🔐', '🗝️', 'कुंजी'], 8)}`;

  const validPurpose = 'msg-signing';
  const broadPurpose = 'file-storage msg-signing';

  const leafAttestation = await leaf.attest({ purpose: validPurpose, exp: expiry });
  const intermediateVouch = await intermediate.vouch(leafAttestation, { purpose: validPurpose, exp: expiry });
  const rootVouch = await root.vouch(intermediateVouch, { purpose: validPurpose, exp: expiry });
  const rootRevoke = await root.revoke(rootVouch);
  const intermediateRevokeAll = await intermediate.revoke(intermediateVouch, { revokes: 'all' });
  const leafRevoke = await leaf.revoke(leafAttestation);
  const forgedRevoke = await createJwt(
    attacker.urn,
    attacker.keypair.publicKey,
    attacker.keypair.privateKey,
    {
      kind: 'vch:revoke',
      jti: crypto.randomUUID(),
      sub: decodeJwt(rootVouch).sub,
      revokes: decodeJwt(rootVouch).jti,
      vch_iss: decodeJwt(rootVouch).vch_iss,
      vch_sum: decodeJwt(rootVouch).vch_sum,
    }
  );
  const intermediateBurn = await createBurnToken(intermediate.urn, intermediate.keypair);
  const rootBurn = await createBurnToken(root.urn, root.keypair);
  const leafBurn = await createBurnToken(leaf.urn, leaf.keypair);

  const broadAttestation = await leaf.attest({ purpose: broadPurpose, exp: expiry, jti: crypto.randomUUID() });
  const attenuatedVouch = await intermediate.vouch(broadAttestation, { purpose: validPurpose, exp: expiry });
  const attenuatedRootVouch = await root.vouch(attenuatedVouch, { purpose: broadPurpose, exp: expiry });
  const anyAttestation = await leaf.attest({ exp: expiry, jti: crypto.randomUUID() });
  const anyIntermediateVouch = await intermediate.vouch(anyAttestation, { exp: expiry });
  const anyRootVouch = await root.vouch(anyIntermediateVouch, { exp: expiry });

  const expiredAttestation = await leaf.attest({ purpose: validPurpose, exp: now - 1, jti: crypto.randomUUID() });
  const futureAttestation = await leaf.attest({ purpose: validPurpose, nbf: now + 3600, exp: now + 7200, jti: crypto.randomUUID() });

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
  const wrongSubjectVouch = await createJwt(
    root.urn,
    root.keypair.publicKey,
    root.keypair.privateKey,
    {
      kind: 'vch:vouch',
      jti: crypto.randomUUID(),
      sub: crypto.randomUUID(),
      vch_iss: leafDecoded.iss,
      vch_sum: await hashJwt(leafAttestation),
      purpose: validPurpose,
      exp: expiry,
    }
  );
  const wrongIssuerVouch = await createJwt(
    root.urn,
    root.keypair.publicKey,
    root.keypair.privateKey,
    {
      kind: 'vch:vouch',
      jti: crypto.randomUUID(),
      sub: leafDecoded.jti,
      vch_iss: external.urn,
      vch_sum: await hashJwt(leafAttestation),
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
  const [jwtHeader, jwtPayload, jwtSignature] = leafAttestation.split('.');
  const tamperedSignature = `${jwtHeader}.${jwtPayload}.${jwtSignature[0] === 'A' ? 'B' : 'A'}${jwtSignature.slice(1)}`;

  const identities = {
    leaf: await leaf.toObject({ unprotected_private_key: true }),
    intermediate: await intermediate.toObject({ unprotected_private_key: true }),
    root: await root.toObject({ unprotected_private_key: true }),
    external: await external.toObject({ unprotected_private_key: true }),
    protectedAscii: await protectedAsciiIdentity.toObject({ passphrase: protectedAsciiPassphrase }),
    protectedUtf8: await protectedUtf8Identity.toObject({ passphrase: protectedUtf8Passphrase }),
  };
  const malformedProtectedIdentity = structuredClone(identities.protectedAscii);
  malformedProtectedIdentity.keypair.encryptedPrivateKey = 'not base64!';
  const ambiguousPrivateKeyIdentity = structuredClone(identities.protectedAscii);
  ambiguousPrivateKeyIdentity.keypair.privateKey = leaf.keypair.privateKey;

  const identityPaths = {};
  for (const [name, identity] of Object.entries(identities)) {
    const filePath = path.join(identitiesDir, `${name}.json`);
    await writeJson(filePath, identity);
    identityPaths[name] = rel(rootDir, filePath);
  }
  for (const [name, identity] of Object.entries({ malformedProtected: malformedProtectedIdentity, ambiguousPrivateKey: ambiguousPrivateKeyIdentity })) {
    const filePath = path.join(identitiesDir, `${name}.json`);
    await writeJson(filePath, identity);
    identityPaths[name] = rel(rootDir, filePath);
  }

  const tokenValues = {
    leafAttestation,
    intermediateVouch,
    rootVouch,
    rootRevoke,
    intermediateRevokeAll,
    leafRevoke,
    forgedRevoke,
    intermediateBurn,
    rootBurn,
    leafBurn,
    broadAttestation,
    attenuatedVouch,
    attenuatedRootVouch,
    anyAttestation,
    anyIntermediateVouch,
    anyRootVouch,
    expiredAttestation,
    futureAttestation,
    tamperedVouch,
    wrongSubjectVouch,
    wrongIssuerVouch,
    badRevokeWithExp,
    externalJwt,
    tamperedSignature,
  };

  const tokenFilenames = {
    leafAttestation: 'leaf-attestation.jwt',
    intermediateVouch: 'intermediate-vouch.jwt',
    rootVouch: 'root-vouch.jwt',
    rootRevoke: 'root-revoke.jwt',
    intermediateRevokeAll: 'intermediate-revoke-all.jwt',
    leafRevoke: 'leaf-revoke.jwt',
    forgedRevoke: 'forged-revoke.jwt',
    intermediateBurn: 'intermediate-burn.jwt',
    rootBurn: 'root-burn.jwt',
    leafBurn: 'leaf-burn.jwt',
    broadAttestation: 'broad-attestation.jwt',
    attenuatedVouch: 'attenuated-vouch.jwt',
    attenuatedRootVouch: 'attenuated-root-vouch.jwt',
    anyAttestation: 'any-attestation.jwt',
    anyIntermediateVouch: 'any-intermediate-vouch.jwt',
    anyRootVouch: 'any-root-vouch.jwt',
    expiredAttestation: 'expired-attestation.jwt',
    futureAttestation: 'future-attestation.jwt',
    tamperedVouch: 'tampered-vouch.jwt',
    wrongSubjectVouch: 'wrong-subject-vouch.jwt',
    wrongIssuerVouch: 'wrong-issuer-vouch.jwt',
    badRevokeWithExp: 'bad-revoke-with-exp.jwt',
    externalJwt: 'external-nonvouchsafe.jwt',
    tamperedSignature: 'tampered-signature.jwt',
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
    validPermuted: await writeBundle(rootDir, bundlesDir, 'valid-permuted', [rootVouch, leafAttestation, intermediateVouch]),
    validWithoutSubject: await writeBundle(rootDir, bundlesDir, 'valid-without-subject', [intermediateVouch, rootVouch]),
    revoked: await writeBundle(rootDir, bundlesDir, 'revoked', [leafAttestation, intermediateVouch, rootVouch, rootRevoke]),
    revokeAll: await writeBundle(rootDir, bundlesDir, 'revoke-all', [leafAttestation, intermediateVouch, rootVouch, intermediateRevokeAll]),
    leafRevoked: await writeBundle(rootDir, bundlesDir, 'leaf-revoked', [leafAttestation, intermediateVouch, rootVouch, leafRevoke]),
    forgedRevoke: await writeBundle(rootDir, bundlesDir, 'forged-revoke', [leafAttestation, intermediateVouch, rootVouch, forgedRevoke]),
    burned: await writeBundle(rootDir, bundlesDir, 'burned', [leafAttestation, intermediateVouch, rootVouch, intermediateBurn]),
    rootBurned: await writeBundle(rootDir, bundlesDir, 'root-burned', [leafAttestation, intermediateVouch, rootVouch, rootBurn]),
    leafBurned: await writeBundle(rootDir, bundlesDir, 'leaf-burned', [leafAttestation, intermediateVouch, rootVouch, leafBurn]),
    tamperedVouchSum: await writeBundle(rootDir, bundlesDir, 'tampered-vouch-sum', [leafAttestation, tamperedVouch]),
    purposeAttenuated: await writeBundle(rootDir, bundlesDir, 'purpose-attenuated', [broadAttestation, attenuatedVouch, attenuatedRootVouch]),
    purposeAny: await writeBundle(rootDir, bundlesDir, 'purpose-any', [anyAttestation, anyIntermediateVouch, anyRootVouch]),
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
      buildTestCase('identity_protected_ascii_roundtrip', 'identity_encrypted_roundtrip', {
        identity: identityPaths.protectedAscii,
      }, {
        passphrase: protectedAsciiPassphrase,
      }),
      buildTestCase('identity_protected_utf8_roundtrip', 'identity_encrypted_roundtrip', {
        identity: identityPaths.protectedUtf8,
      }, {
        passphrase: protectedUtf8Passphrase,
      }),
      buildTestCase('identity_protected_wrong_passphrase_rejected', 'identity_reject', { identity: identityPaths.protectedAscii }, { passphrase: 'wrong-passphrase' }),
      buildTestCase('identity_protected_malformed_ciphertext_rejected', 'identity_reject', { identity: identityPaths.malformedProtected }, { passphrase: protectedAsciiPassphrase }),
      buildTestCase('identity_rejected_ambiguous_private_key_fields', 'identity_reject', { identity: identityPaths.ambiguousPrivateKey }),
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
      buildTestCase('trust_chain_valid_permuted_bundle', 'trust_chain_validate', { tokens_bundle: bundlePaths.validPermuted, subject_token: tokenPaths.leafAttestation, trusted_issuers: rel(rootDir, trustedMsgSigningPath) }, { required_purposes: [validPurpose] }),
      buildTestCase('trust_chain_valid_bundle_without_subject', 'trust_chain_validate', { tokens_bundle: bundlePaths.validWithoutSubject, subject_token: tokenPaths.leafAttestation, trusted_issuers: rel(rootDir, trustedMsgSigningPath) }, { required_purposes: [validPurpose] }),
      buildTestCase('trust_chain_rejected_revoked', 'trust_chain_reject', {
        tokens_bundle: bundlePaths.revoked,
        subject_token: tokenPaths.leafAttestation,
        trusted_issuers: rel(rootDir, trustedMsgSigningPath),
      }, {
        required_purposes: [validPurpose],
      }),
      buildTestCase('trust_chain_rejected_revoke_all', 'trust_chain_reject', { tokens_bundle: bundlePaths.revokeAll, subject_token: tokenPaths.leafAttestation, trusted_issuers: rel(rootDir, trustedMsgSigningPath) }, { required_purposes: [validPurpose] }),
      buildTestCase('trust_chain_rejected_leaf_revoked', 'trust_chain_reject', { tokens_bundle: bundlePaths.leafRevoked, subject_token: tokenPaths.leafAttestation, trusted_issuers: rel(rootDir, trustedMsgSigningPath) }, { required_purposes: [validPurpose] }),
      buildTestCase('trust_chain_valid_forged_revoke_ignored', 'trust_chain_validate', { tokens_bundle: bundlePaths.forgedRevoke, subject_token: tokenPaths.leafAttestation, trusted_issuers: rel(rootDir, trustedMsgSigningPath) }, { required_purposes: [validPurpose] }),
      buildTestCase('trust_chain_rejected_burned', 'trust_chain_reject', {
        tokens_bundle: bundlePaths.burned,
        subject_token: tokenPaths.leafAttestation,
        trusted_issuers: rel(rootDir, trustedMsgSigningPath),
      }, {
        required_purposes: [validPurpose],
      }),
      buildTestCase('trust_chain_rejected_root_burned', 'trust_chain_reject', { tokens_bundle: bundlePaths.rootBurned, subject_token: tokenPaths.leafAttestation, trusted_issuers: rel(rootDir, trustedMsgSigningPath) }, { required_purposes: [validPurpose] }),
      buildTestCase('trust_chain_rejected_leaf_burned', 'trust_chain_reject', { tokens_bundle: bundlePaths.leafBurned, subject_token: tokenPaths.leafAttestation, trusted_issuers: rel(rootDir, trustedMsgSigningPath) }, { required_purposes: [validPurpose] }),
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
      buildTestCase('trust_chain_valid_omitted_purpose', 'trust_chain_validate', { tokens_bundle: bundlePaths.purposeAny, subject_token: tokenPaths.anyAttestation, trusted_issuers: rel(rootDir, trustedMsgSigningPath) }, { required_purposes: [validPurpose] }),
      buildTestCase('token_rejected_expired', 'token_reject', { token: tokenPaths.expiredAttestation }),
      buildTestCase('token_rejected_not_yet_valid', 'token_reject', { token: tokenPaths.futureAttestation }),
      buildTestCase('vouch_rejected_wrong_subject_linkage', 'vouch_verify_reject', { token: tokenPaths.wrongSubjectVouch, subject_token: tokenPaths.leafAttestation }),
      buildTestCase('vouch_rejected_wrong_issuer_linkage', 'vouch_verify_reject', { token: tokenPaths.wrongIssuerVouch, subject_token: tokenPaths.leafAttestation }),
      buildTestCase('token_rejected_revoke_with_exp', 'token_reject', {
        token: tokenPaths.badRevokeWithExp,
      }),
      buildTestCase('token_rejected_external_non_vouchsafe', 'token_reject', {
        token: tokenPaths.externalJwt,
      }),
      buildTestCase('token_rejected_tampered_signature', 'token_reject', {
        token: tokenPaths.tamperedSignature,
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
