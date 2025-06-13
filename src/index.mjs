export { createVouchsafeIdentity, verifyUrnMatchesKey } from './urn.mjs';
export { createJwt, verifyJwt } from './jwt.mjs';
export {
  createVouchToken,
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

