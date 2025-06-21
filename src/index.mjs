export { VOUCHSAFE_SPEC_VERSION } from './version.mjs';
export { createVouchsafeIdentity, verifyUrnMatchesKey, createVouchsafeIdentityFromKeypair } from './urn.mjs';
export { createJwt, verifyJwt } from './jwt.mjs';
export {
  createVouchToken,
  revokeVouchToken,
  createRevokeToken,
  validateVouchToken,
  verifyVouchToken
} from './vouch.mjs';
export {
//  verifyChain,
  makeStaticResolver,
  isTrustedAnchor,
  isRevoked,
  verifyTrustChain,
  canUseForPurpose,
} from './trustchain.mjs'; // or wherever you place it

