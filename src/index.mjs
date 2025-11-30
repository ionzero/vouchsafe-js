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
} from './trustchain.mjs'; // or wherever you place it

export { Identity } from './Identity.mjs';

