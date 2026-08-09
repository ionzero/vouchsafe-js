export {
    VOUCHSAFE_SPEC_VERSION
} from './version.mjs';

export {
    createVouchsafeIdentity,
    verifyUrnMatchesKey,
    createVouchsafeIdentityFromKeypair,
    validateIssuerString
} from './urn.mjs';

export {
    VOUCHSAFE_IDENTITY_FILE_VERSION,
    loadIdentity,
    serializeIdentity,
} from './identity-file.mjs';

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
    hashJwt,
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
