const assert = require('assert');
const vouchsafe = require('../dist/index.js');

describe('CommonJS export compatibility', () => {
    it('should expose all expected functions', () => {
        const expectedExports = [
            'createVouchsafeIdentity',
            'verifyUrnMatchesKey',
            'createJwt',
            'verifyJwt',
            'createVouchToken',
            'createRevokeToken',
            'validateVouchToken',
            'verifyVouchToken',
            'makeStaticResolver',
            'isTrustedAnchor',
            'isRevoked',
            'verifyTrustChain',
            'canUseForPurpose'
        ];

        for (const name of expectedExports) {
            assert.strictEqual(typeof vouchsafe[name], 'function', `${name} should be a function`);
        }
    });
});
