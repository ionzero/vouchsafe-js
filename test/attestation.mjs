import { SignJWT,  importPKCS8 } from 'jose';
import assert from 'assert';
import { createVouchsafeIdentity, createAttestation, validateVouchToken, decodeJwt } from '../src/index.mjs';

function chunk(str, len = 64) {
    return str.match(new RegExp(`.{1,${len}}`, 'g')).join('\n');
}

function toPem(input, type = 'PRIVATE') {
    if (typeof input === 'string') {
        if (input.includes('BEGIN')) {
            return input; // already PEM
        }
        // assume it's base64 already (no re-encoding)
        return `-----BEGIN ${type} KEY-----\n${chunk(input)}\n-----END ${type} KEY-----`;
    }

    if (input instanceof Uint8Array) {
        const b64 = toBase64(input);
        return `-----BEGIN ${type} KEY-----\n${chunk(b64)}\n-----END ${type} KEY-----`;
    }

    throw new Error(`Unsupported key input type: ${typeof input}`);
}

describe('createAttestation()', function() {
    let issuerIdentity, attestationToken;

    before(async function() {
        issuerIdentity = await createVouchsafeIdentity('attestor');
        attestationToken = await createAttestation(issuerIdentity.urn, issuerIdentity.keypair, {
            purpose: 'email-confirmation',
            email: 'user@example.com'
        });
    });

    it('should create and validate an attestation token', async function() {
        // Should decode cleanly
        // Should validate cryptographically
        const decoded = await validateVouchToken(attestationToken);
        assert.strictEqual(decoded.kind, 'vch:attest');
        assert.strictEqual(decoded.purpose, 'email-confirmation');
        assert.strictEqual(decoded.email, 'user@example.com');
        assert.strictEqual(decoded.iss, issuerIdentity.urn);
        assert.strictEqual(decoded.sub, decoded.jti); // Attestation: sub == jti
    });

    it('should fail to validate a tampered attestation token', async function() {
        // Tamper with the attestation token — change one character in the payload
        const parts = attestationToken.split('.');
        assert.strictEqual(parts.length, 3, 'Token should have 3 parts');

        // Decode, tamper, re-encode
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        payload.email = 'hacker@example.com'; // malicious change

        const newPayloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const tamperedToken = `${parts[0]}.${newPayloadB64}.${parts[2]}`; // reuse original sig

        // Should throw on validation
        try {
            await validateVouchToken(tamperedToken);
            assert.fail('Expected validation to fail but it succeeded');
        } catch (err) {
            assert.ok(/signature verification/i.test(err.message), `Expected invalid signature error, got: ${err.message}`);
        }
    });

    it('should reject token if iss does not match iss_key (forged issuer)', async function() {
        // Create a real identity and attestation
        const realIdentity = await createVouchsafeIdentity('real');
        const token = await createAttestation(realIdentity.urn, realIdentity.keypair, {
            purpose: 'email-confirmation',
            email: 'victim@example.com'
        });

        // Decode the original token
        const parts = token.split('.');
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

        // Tamper: change the issuer to something that doesn't match the key
        const forgedIdentity = await createVouchsafeIdentity('faker');
        payload.iss = forgedIdentity.urn;

        // Re-encode and re-sign using jose with the real private key
        const privateKey = await importPKCS8(toPem(realIdentity.keypair.privateKey), 'EdDSA');

        const forgedJwt = await new SignJWT(payload)
            .setProtectedHeader(header)
            .sign(privateKey);

        // Try to validate — should fail due to iss_key mismatch
        try {
            await validateVouchToken(forgedJwt);
            assert.fail('Expected validation to fail due to forged issuer');
        } catch (err) {
            assert.ok(/iss.*key/i.test(err.message), `Expected issuer mismatch error, got: ${err.message}`);
        }
    });


});
