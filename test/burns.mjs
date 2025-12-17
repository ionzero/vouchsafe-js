import assert from 'assert';
import crypto from 'crypto';
import {
    createJwt,
    createAttestation,
    createVouchToken,
    createBurnToken,
    revokeVouchToken,
    createRevokeToken,
    createVouchsafeIdentity,
    validateTrustChain
} from '../src/index.mjs';

function decodeJwt(token) {
    const [, payload] = token.split('.');
    return JSON.parse(Buffer.from(payload, 'base64url').toString());
}

describe('Identity burn cases', () => {
    let leafIdentity, midIdentity, rootIdentity;
    let leafToken, midVouch, rootVouch;
    const trustedIssuers = {};
    const purpose = 'msg-signing';

    before(async () => {
    });

    it("Burning a trusted issuer invalidates its delegated authority", async function () {

        const A = await createVouchsafeIdentity("AAA");
        const B = await createVouchsafeIdentity("BBB");
        const R = await createVouchsafeIdentity("RRR");

        // A issues the base attestation
        const attest = await createAttestation(
            A.urn,
            A.keypair,
            { purpose: "file-storage msg-signing" }
        );

        // B attenuates to msg-signing
        const v1 = await createVouchToken(
            attest,
            B.urn,
            B.keypair,
            { purpose: "msg-signing" }
        );

        // R vouches without further restriction
        const v2 = await createVouchToken(
            v1,
            R.urn,
            R.keypair,
            { purpose: "msg-signing" }
        );

        const tokens = [attest, v1, v2];

        // R is a trusted issuer
        const trusted = {
            [R.urn]: ["msg-signing"]
        };

        // Sanity check: chain is valid before burn
        const res = await validateTrustChain(
            tokens,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );

        // R burns itself
        const burnR = await createBurnToken(
            R.urn,
            R.keypair
        );

        const tokensAfterBurn = [burnR].concat(tokens);

        const resAfterBurn = await validateTrustChain(
            tokensAfterBurn,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );

        assert.equal(res.valid, true);
        assert.equal(resAfterBurn.valid, false);
    });

    it("Burning an intermediate identity invalidates the delegation chain", async function () {

        const A = await createVouchsafeIdentity("AAA");
        const B = await createVouchsafeIdentity("BBB");
        const R = await createVouchsafeIdentity("RRR");

        const attest = await createAttestation(
            A.urn,
            A.keypair,
            { purpose: "file-storage msg-signing" }
        );

        const v1 = await createVouchToken(
            attest,
            B.urn,
            B.keypair,
            { purpose: "msg-signing" }
        );

        const v2 = await createVouchToken(
            v1,
            R.urn,
            R.keypair,
            { purpose: "msg-signing" }
        );

        const tokens = [attest, v1, v2];

        const trusted = {
            [R.urn]: ["msg-signing"]
        };

        // Baseline: chain is valid
        const res = await validateTrustChain(
            tokens,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );

        // Burn the intermediate delegator
        const burnB = await createBurnToken(
            B.urn,
            B.keypair
        );

        const tokensAfterBurn = [burnB].concat(tokens);

        const resAfterBurn = await validateTrustChain(
            tokensAfterBurn,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );

        assert.equal(res.valid, true);
        assert.equal(resAfterBurn.valid, false);
    });

    it("Burning the subject identity invalidates authorization", async function () {

        const A = await createVouchsafeIdentity("AAA");
        const B = await createVouchsafeIdentity("BBB");
        const R = await createVouchsafeIdentity("RRR");

        const attest = await createAttestation(
            A.urn,
            A.keypair,
            { purpose: "file-storage msg-signing" }
        );

        const v1 = await createVouchToken(
            attest,
            B.urn,
            B.keypair,
            { purpose: "msg-signing" }
        );

        const v2 = await createVouchToken(
            v1,
            R.urn,
            R.keypair,
            { purpose: "msg-signing" }
        );

        const tokens = [attest, v1, v2];

        const trusted = {
            [R.urn]: ["msg-signing"]
        };

        // Baseline: subject is authorized
        const res = await validateTrustChain(
            tokens,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );

        // Subject burns itself
        const burnA = await createBurnToken(
            A.urn,
            A.keypair
        );

        const tokensAfterBurn = [burnA].concat(tokens);

        const resAfterBurn = await validateTrustChain(
            tokensAfterBurn,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );

        assert.equal(res.valid, true);
        assert.equal(resAfterBurn.valid, false);
    });

});
