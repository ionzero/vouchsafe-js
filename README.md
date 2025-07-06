# Vouchsafe JS

[Vouchsafe](https://getvouchsafe.org/) is **coherent, portable identity and trust — without the need for central servers or key distribution.**

Vouchsafe lets you represent and communicate identity and trust in a standardized, cryptographically secure way — without relying on central authorities, shared secrets, or online lookups.

Whether you're authenticating users, confirming purchases, issuing verifiable attestations, or sending tamper-proof webhooks — Vouchsafe makes it easy to prove who did what, and why they’re allowed to do it.

Vouchsafe tokens are standard JWTs, enhanced with embedded public keys and self-validating identity URNs. They carry everything needed for verification — identity, proof, and trust — right inside the token.

> Built for decentralized systems. Useful anywhere identity and trust matter.

This library implements Vouchsafe in JavaScript for both Node.js and browser environments.

---

## 📦 Installation

```bash
npm install vouchsafe
````

---

## 🛠️ Quickstart

You can issue a standalone attestation, then have another identity vouch for it — forming a portable, verifiable trust graph.

```js
import {
  createVouchsafeIdentity,
  createAttestation,
  createVouchToken,
  validateVouchToken,
  verifyVouchToken
} from 'vouchsafe';

// Step 1: Attestor creates an attestation token
const attestor = await createVouchsafeIdentity('attestor');

// You attest that your email is user@example.com
const attestation = await createAttestation(attestor.urn, attestor.keypair, {
  purpose: 'email-confirmation',
  email: 'user@example.com'
});

// Step 2: A second identity vouches for the attestation token
const notary = await createVouchsafeIdentity('notary');

// Notary perhaps confirms the email in your attestation.
// Notary vouches for your attestation.  Now anyone who trusts
// Notary can trust your email attestation token.
const vouch = await createVouchToken(attestation, notary.urn, notary.keypair, {
  purpose: 'email-confirmation'
});

const trusted = {
  [notary.urn]: ['email-confirmation']
};

// validateVouchToken returns the decoded token if the token is valid, 
// signed and matches vouchsafe identity, otherwise throws an error.
const decoded = await validateVouchToken(attestationToken);                                                    
console.log(decoded.email);  // "user@example.com"

// Verify the full trust chain
const result = await verifyTrustChain(attestation, trusted, {
  tokens: [vouch, attestation],
  purposes: ['email-confirmation']
});

console.log(result.valid);  // true if chain is trusted
```

# Trust delegation

An example where one identity trusts another to make decisions
for a given purpose.

```js
import {
  createVouchsafeIdentity,
  createJwt,
  createVouchToken,
  verifyTrustChain
} from 'vouchsafe';

// Create identities
const leaf = await createVouchsafeIdentity('leaf');
const mid = await createVouchsafeIdentity('mid');
const root = await createVouchsafeIdentity('root');

// Define trusted anchor(s) 
// We trust root to say who can do msg-signing

const trusted = {
  [root.urn]: ['msg-signing']
};

// Create a JWT issued by the leaf identity
const leafToken = await createJwt(
  leaf.urn,
  leaf.keypair.publicKey,
  leaf.keypair.privateKey,
  {
    iss: leaf.urn,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000)
  }
);

// Mid vouches that leaf can perform msg-signing for mid.
const vouch = await createVouchToken(leafToken, mid.urn, mid.keypair, {
  sub_key: leaf.keypair.publicKey,
  purpose: 'msg-signing'
});

// Root vouches for mid's vouch - indicationg that root trusts mid for msg-signing
const attestation = await createVouchToken(vouch, root.urn, root.keypair, {
  purpose: 'msg-signing'
});

// Verify the full trust chain
const result = await verifyTrustChain(leafToken, trusted, {
  tokens: [vouch, attestation],
  purposes: ['msg-signing']
});

console.log(result.valid);  // true if chain is trusted
```


---

## 🔧 CLI Tool: `create-vouchsafe-id`

This package includes a CLI utility to generate Vouchsafe identities from the terminal.

### Usage

```bash
create-vouchsafe-id --label alice -o alice.json
```

### Output (default mode)

```json
{
  "urn": "urn:vouchsafe:alice.tp5yr5uvfgbmwba3jdmqrar4rqu5rsbkz6nqqyuw75zxpdzgvhsq",
  "keypair": {
    "publicKey": "MCowBQYDK2VwAyEAo47M4fApUZQV3KwI6Y2kLEFxpX/3M1OqZNGIZwXxKdQ=",
    "privateKey": "MC4CAQAwBQYDK2VwBCIEIG/9DEl2+cTWQFW+oZvqxd8pOP21u/MIYe5maaFEtyvi"
  },
  "publicKeyHash": "tp5yr5uvfgbmwba3jdmqrar4rqu5rsbkz6nqqyuw75zxpdzgvhsq",
  "version": "1.3.0"
}
```

### Options

```text
Usage: create-vouchsafe-id [options]

Create a new Vouchsafe identity with associated keypair.

Options:
  -l, --label <label>      Identity label (required)
  -s, --separate           Output public/private key files separately
  -o, --output <filename>  Output filename or prefix (defaults to [label].json)
  --public <file>          Use an existing public key (PEM)
  --private <file>         Use an existing private key (PEM)
  -q, --quiet              Suppress status output
  -h, --help               Display help
```

### Example: Separate Files Mode

```bash
create-vouchsafe-id -l agent42 -s -o agent42
```

Produces:

* `agent42.urn` – contains the URN
* `agent42.pub.pem` – PEM-encoded public key
* `agent42.priv.pem` – PEM-encoded private key

You can re-use these with the `--public` and `--private` options to regenerate the URN or use consistent identities across environments. 

---

## API Reference

### Identity

* `createVouchsafeIdentity(label, [hashAlg])`
  → Generates a new keypair and URN

* `createVouchsafeIdentityFromKeypair(label, keypair)`
  → Creates a URN from an existing keypair

* `verifyUrnMatchesKey(urn, publicKey)`
  → Confirms that a URN matches its public key

---

### Token Creation

* `createJwt(iss, iss_key, privateKey, claims)`
  Creates a signed JWT using a Vouchsafe identity

* `createAttestation(issuerUrn, keypair, claims)`
  Issues an attestation directly from an identity

* `createVouchToken(subjectJwt, issuerUrn, keypair, claims)`
  Vouches for a token (attestation, external JWT, or vouch)

* `createRevokeToken(subjectJwt, issuerUrn, keypair, opts)`
  Creates a revocation for a previous vouch

---

### Validation

* `verifyJwt(token)`
  Validates a signed JWT and returns decoded claims

* `validateVouchToken(token)`
  Validates Vouchsafe vouch/attestation/revocation structure

* `verifyVouchToken(vouchToken, subjectToken)`
  Verifies that a vouch is valid and references its subject correctly

* `verifyTrustChain(token, trustedIssuers, opts)`
  Walks a vouch chain to verify trust for a given purpose

* `canUseForPurpose(token, trustedIssuers, opts)`
  Convenience wrapper to test if a token is trusted for a specific purpose

---

### Utilities

* `makeStaticResolver(tokens)`
  → Creates a trust resolver from an in-memory list of tokens

* `createCompositeResolver(a, b)`
  Combines multiple resolvers

* `isTrustedAnchor(urn, purpose, map, requiredPurposes)`
  Determines if an identity is a trusted anchor

* `isRevoked(payload, revokeList)`
  Checks whether a token has been revoked

---

## Running Tests

```bash
npm test
```

---

##  Learn More

* 🌐 [getvouchsafe.org](https://getvouchsafe.org) – Conceptual overview and use cases
* 📖 [Vouchsafe Specification](https://github.com/ionzero/vouchsafe) – Token structure, URN format, trust chain rules
* 💬 [Join the Discord](https://discord.gg/BwanESEZVf) – Community questions & discussion

---

## License

BSD 3-Clause License
© 2025 [Jay Kuri](https://jaykuri.com) / [Ionzero](https://ionzero.com)

---

> Vouchsafe: identity you can prove, trust you can carry.
