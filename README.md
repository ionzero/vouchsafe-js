# Vouchsafe JS

A minimal JavaScript/Node.js implementation of the
[Vouchsafe](https://github.com/ionzero/vouchsafe) decentralized identity
and trust verification system.

It provides tools for generating Vouchsafe identities, issuing Vouchsafe JWT
tokens, creating vouches/revocations, and verifying trust chains.

## Installation

``` 
npm install vouchsafe 
```

## Usage

```
import {
  createVouchsafeIdentity,
  createJwt,
  createVouchToken,
  verifyTrustChain
} from 'vouchsafe';

// create identities
const leaf = await createVouchsafeIdentity('leaf');
const mid = await createVouchsafeIdentity('mid');
const root = await createVouchsafeIdentity('root');

// map of trusted issuers and the purposes they permit
const trusted = {
  [root.urn]: ['msg-signing']
};

// create a JWT bound to the leaf identity
const leafClaims = {
  iss: leaf.urn,
  jti: crypto.randomUUID(),
  iat: Math.floor(Date.now() / 1000)
};

const leafToken = await createJwt(
  leaf.urn,
  leaf.keypair.publicKey,
  leaf.keypair.privateKey,
  leafClaims
);

// mid vouches for the leaf token
const vouch = await createVouchToken(leafToken, mid.urn, mid.keypair, {
  sub_key: leaf.keypair.publicKey,
  purpose: 'msg-signing'
});

// root attests to the mid vouch
const attestation = await createVouchToken(vouch, root.urn, root.keypair, {
  purpose: 'msg-signing'
});

// verify a trust chain for the specified purpose
const result = await verifyTrustChain(leafToken, trusted, {
  tokens: [vouch, attestation],
  purposes: ['msg-signing']
});

console.log(result.valid);  // true if the chain is trusted

```


## API

The library exposes the following functions (see src/index.mjs):

 * `createVouchsafeIdentity(label, [hashAlg])` – Generate a new identity and URN.

 * `verifyUrnMatchesKey(urn, publicKey)` – Ensure a public key matches the URN.

 * `createJwt(iss, iss_key, privateKey, claims, [options])` – Create a signed JWT.

 * `verifyJwt(token, [options])` – Validate and decode a JWT.

 * `createVouchToken(subjectJwt, issuerUrn, issuerKeyPair, [args])` – Issue a vouch for another token.

 * `createRevokeToken(args, issuerUrn, issuerKeyPair)` – Produce a revocation token.

 * `validateVouchToken(token, [opts])` – Check the structure of a vouch/revocation.

 * `verifyVouchToken(vouchJwt, subjectJwt, [opts])` – Validate a vouch against its subject token.

 * `makeStaticResolver(tokens)` and `createCompositeResolver(a, b)` – Build resolvers for trust-chain lookups.

 * `isTrustedAnchor(iss, tokenPurpose, trustedIssuers, requiredPurposes)` – Determine if an issuer is a trusted anchor for a purpose.

 * `isRevoked(tokenPayload, refList)` – Check if a token is revoked.

 * `verifyTrustChain(token, trustedIssuers, [options])` – Walk a chain of vouches to confirm trust.

 * `canUseForPurpose(token, trustedIssuers, [opts])` – Convenience wrapper around verifyTrustChain for a single purpose.

## Running Tests

```
npm test
```

The test suite uses Mocha and demonstrates usage patterns found in test/basic.mjs and test/trustchain.mjs.

## License

This project is distributed under the BSD 3-Clause License.
See the [LICENSE](./LICENSE) file for details.

© 2025 Jay Kuri / Ionzero.
