export {
    VOUCHSAFE_SPEC_VERSION
} from './version.mjs';

export {
    createVouchsafeIdentity,
    verifyUrnMatchesKey,
    createVouchsafeIdentityFromKeypair
} from './urn.mjs';

export {
    createJwt,
    verifyJwt,
    decodeJwt,
    getAppClaims
} from './jwt.mjs';

export {
    createAttestation,
    createVouchToken,
    revokeVouchToken,
    createRevokeToken,
    createBurnToken,
    validateVouchToken,
    verifyVouchToken,
    isBurnToken, 
    isRevocationToken, 
} from './vouch.mjs';

export {
    validateTrustChain,
    decodeToken,
} from './trustchain.mjs'; 

// legacy verifyTrustChain from earlier version of
// the module implemented via offical validateTrustChain.
// Here only for backwards compatibility. 
// DON'T USE verifyTrustChain IN NEW CODE.
export {
    verifyTrustChain,
} from './legacy.mjs'; 

export { Identity } from './Identity.mjs';

