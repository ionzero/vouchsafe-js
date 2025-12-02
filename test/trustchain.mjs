/* eslint-env mocha */
import { strict as assert } from "assert";

import {
    validateVouchToken,
    createVouchsafeIdentity,
    createAttestation,
    createVouchToken,
    createBurnToken,
    decodeToken,
    validateTrustChain
} from "../src/index.mjs";


// Helper: create vouch A → B
async function vouch(issuer, issuerKeyPair, subjectJwt, purpose = "msg-signing") {
    return await createVouchToken(
        subjectJwt,                 // subjectJwt (the token we are vouching for)
        issuer,                     // issuer URN
        issuerKeyPair,              // issuer private keypair
        {
            kind: "vch:vouch",
            purpose: purpose
        }
    );
}


describe("Vouchsafe evaluator - fresh-minted identities each test", function () {

    let leaf;
    let hop1, hop2, hop3, hop4, hop5;
    let v1, v2, v3, v4, v5;
    let root;

    let tokens;
    let trustGraph;
    let leafAttest;
    let trustedIssuers;


    before(async function () {

        // ---------------------------------------------------------
        // 1. Create identities and keypairs
        // ---------------------------------------------------------
        leaf = await createVouchsafeIdentity("leaf");
        hop5 = await createVouchsafeIdentity("hop5");
        hop4 = await createVouchsafeIdentity("hop4");
        hop3 = await createVouchsafeIdentity("hop3");
        hop2 = await createVouchsafeIdentity("hop2");
        hop1 = await createVouchsafeIdentity("hop1");
        root = await createVouchsafeIdentity("root");

        // ---------------------------------------------------------
        // 2. Leaf attestation (root of evaluator)
        // ---------------------------------------------------------
        leafAttest = await createAttestation(
            leaf.urn,                  // issuer URN
            leaf.keypair,              // issuer keypair
            {
                purpose: "msg-signing",
            }
        );

        // ---------------------------------------------------------
        // 3. Build upward vouch chain:
        // leaf <- hop5 <- hop4 <- hop3 <- hop2 <- hop1 <- root
        // ---------------------------------------------------------

        v5 = await vouch(hop5.urn, hop5.keypair, leafAttest, "msg-signing");
        v4 = await vouch(hop4.urn, hop4.keypair, v5, "msg-signing");
        v3 = await vouch(hop3.urn, hop3.keypair, v4, "msg-signing");
        v2 = await vouch(hop2.urn, hop2.keypair, v3, "msg-signing");
        v1 = await vouch(hop1.urn, hop1.keypair, v2, "msg-signing");

        // root vouched for hop3, not hop1 — gives two possible tops
        const vroot = await vouch(root.urn, root.keypair, v3, "msg-signing");

        tokens = [
            leafAttest,
            v5, v4, v3, v2, v1,
            vroot
        ];

        // ---------------------------------------------------------
        // 4. Trusted issuers
        // ---------------------------------------------------------
        trustedIssuers = {};
        trustedIssuers[root.urn] = ["msg-signing", "admin", "storage"];
    });


    // ============================================================
    // 1. Simple validation (no required purposes)
    // ============================================================
    it("validates a simple chain without requiredPurposes", async function () {

        const res = await validateTrustChain(
            tokens,
            leafAttest,
            trustedIssuers,
            undefined,
            {}
        );

        assert.equal(res.valid, true);
        assert.ok(res.chains.length >= 1);
    });


    // ============================================================
    // 2. Validation requiring msg-signing
    // ============================================================
    it("validates when requiredPurposes=['msg-signing'] and chain grants it", async function () {

        const res = await validateTrustChain(
            tokens,
            leafAttest,
            trustedIssuers,
            ["msg-signing"],
            {}
        );

        assert.equal(res.valid, true);
        assert.deepEqual(res.effectivePurposes, ["msg-signing"]);
    });


    // ============================================================
    // 3. Required purpose not available → fail
    // ============================================================
    it("fails when requiredPurposes includes an unsupported purpose", async function () {

        const res = await validateTrustChain(
            tokens,
            leafAttest,
            trustedIssuers,
            ["admin"],    // Not granted by chain
            {}
        );

        assert.equal(res.valid, false);
        assert.deepEqual(res.effectivePurposes, []);
    });


    // ============================================================
    // 4. Purpose omitted ⇒ S_ANY semantics
    // ============================================================
    it("supports S_ANY propagation when purpose omitted from a vouch", async function () {

        const hop0 = await createVouchsafeIdentity("hop0");

        const a = await createAttestation(
            leaf.urn,
            leaf.keypair,
            { purpose: "msg-signing" }
        );

        // vouch with NO purpose field
        const v0 = await createVouchToken(
            a,
            hop0.urn,
            hop0.keypair,
            { }  // S_ANY
        );

        let newTokens = [a, v0]


        const trusted = {
            [hop0.urn]: ["msg-signing", "storage"]
        };


        const res = await validateTrustChain(
            newTokens,
            a,
            trusted,
            ["msg-signing"],
            {}
        );

        assert.equal(res.valid, true);
    });


    // ============================================================
    // 5. Attenuation behavior
    // ============================================================
    it("attenuates when an intermediate hop restricts purposes", async function () {

        const A = await createVouchsafeIdentity("AAA");
        const B = await createVouchsafeIdentity("BBB");
        const R = await createVouchsafeIdentity("RRR");

        const attest = await createAttestation(
            A.urn, A.keypair,
            { purpose: "file-storage msg-signing" }
        );

        // B attenuates to msg-signing only
        const v1 = await createVouchToken(
            attest,
            B.urn,
            B.keypair,
            { purpose: "msg-signing" }
        );

        // root makes no further restriction
        const v2 = await createVouchToken(
            v1,
            R.urn,
            R.keypair,
            { purpose: "msg-signing" }
        );

        const newTokens = [attest, v1, v2];

        const trusted = {
            [R.urn]: ["msg-signing"]
        };


        const res = await validateTrustChain(
            newTokens,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );
        const res2 = await validateTrustChain(
            newTokens,
            attest,
            trusted,
            ["msg-signing", "file-storage"],
            {}
        );

        assert.equal(res.valid, true);
        assert.equal(res2.valid, false);
    });

    it("attenuates when a vouch vouches for another vouch from the same issuer", async function () {

        const A = await createVouchsafeIdentity("AAA");
        const B = await createVouchsafeIdentity("BBB");
        const R = await createVouchsafeIdentity("RRR");

        const attest = await createAttestation(
            A.urn, A.keypair,
            { purpose: "file-storage msg-signing" }
        );

        // B attenuates to msg-signing only
        const v1 = await createVouchToken(
            attest,
            B.urn,
            B.keypair,
            { purpose: "file-storage msg-signing" }
        );

        // B vouches for their Vouch
        const v2 = await createVouchToken(
            v1,
            B.urn,
            B.keypair,
            { purpose: "msg-signing" }
        );

        const v3 = await createVouchToken(
            v2,
            R.urn,
            R.keypair,
            { purpose: "file-storage msg-signing" }
        );

        const newTokens = [attest, v1, v2, v3];

        const trusted = {
            [R.urn]: ["msg-signing", "file-storage"]
        };


        const res = await validateTrustChain(
            newTokens,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );
        const res2 = await validateTrustChain(
            newTokens,
            attest,
            trusted,
            ["msg-signing", "file-storage"],
            {}
        );

        assert.equal(res.valid, true);
        assert.equal(res2.valid, false);
    });

    it("purpose can not expand when a vouch vouches for another vouch from the same issuer", async function () {

        const A = await createVouchsafeIdentity("AAA");
        const B = await createVouchsafeIdentity("BBB");
        const R = await createVouchsafeIdentity("RRR");

        const attest = await createAttestation(
            A.urn, A.keypair,
            { purpose: "msg-signing" }
        );

        // B attenuates to msg-signing only
        const v1 = await createVouchToken(
            attest,
            B.urn,
            B.keypair,
            { purpose: "msg-signing" }
        );

        // B vouches for their Vouch
        const v2 = await createVouchToken(
            v1,
            B.urn,
            B.keypair,
            { purpose: "file-storage msg-signing" }
        );

        const v3 = await createVouchToken(
            v2,
            R.urn,
            R.keypair,
            { purpose: "file-storage msg-signing" }
        );

        const newTokens = [attest, v1, v2, v3];

        const trusted = {
            [R.urn]: ["msg-signing"]
        };


        const res = await validateTrustChain(
            newTokens,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );
        const res2 = await validateTrustChain(
            newTokens,
            attest,
            trusted,
            ["msg-signing", "file-storage"],
            {}
        );

        assert.equal(res.valid, true);
        assert.equal(res2.valid, false);
    });

    it("Burn token prevents delegation", async function () {

        const A = await createVouchsafeIdentity("AAA");
        const B = await createVouchsafeIdentity("BBB");
        const R = await createVouchsafeIdentity("RRR");

        const attest = await createAttestation(
            A.urn, A.keypair,
            { purpose: "file-storage msg-signing" }
        );

        // B attenuates to msg-signing only
        const v1 = await createVouchToken(
            attest,
            B.urn,
            B.keypair,
            { purpose: "msg-signing" }
        );

        // root makes no further restriction
        const v2 = await createVouchToken(
            v1,
            R.urn,
            R.keypair,
            { purpose: "msg-signing" }
        );

        const newTokens = [attest, v1, v2];

        const trusted = {
            [R.urn]: ["msg-signing"]
        };

        const burn1 = await createBurnToken(
            B.urn,
            B.keypair,
        );

        const res = await validateTrustChain(
            newTokens,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );
        const newTokens2 = [burn1].concat(newTokens);

        const res2 = await validateTrustChain(
            newTokens2,
            attest,
            trusted,
            ["msg-signing"],
            {}
        );

        assert.equal(res.valid, true);
        assert.equal(res2.valid, false);
    });

    // ============================================================
    // 6. maxDepth blocking the chain
    // ============================================================
    it("fails when maxDepth prevents reaching a trusted issuer", async function () {


        const res = await validateTrustChain(
            tokens,
            leafAttest,
            trustedIssuers,
            ["msg-signing"],
            { maxDepth: 1 }   // far too small
        );

        assert.equal(res.valid, false);
    });


    // ============================================================
    // 7. Returning all valid chains
    // ============================================================
    it("returns all valid chains when returnAllValidChains=true", async function () {


        const hop0 = await createVouchsafeIdentity("hop0");

        // vouch with NO purpose field
        const v0 = await createVouchToken(
            v3,
            hop0.urn,
            hop0.keypair,
            { purpose: "msg-signing" } 
        );

        
        const newTokens = [v0].concat(tokens);


        const trusted = {
            ...trustedIssuers,
        };
        trusted[hop0.urn] = ["msg-signing", "file-storage"];

        const res = await validateTrustChain(
            newTokens,
            leafAttest,
            trusted,
            ["msg-signing"],
            { returnAllValidChains: true }
        );

        assert.equal(res.valid, true);
        assert.ok(res.chains.length >= 1);
    });

});

