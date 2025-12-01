[![npm version](https://badge.fury.io/js/vouchsafe.svg)](https://www.npmjs.com/package/vouchsafe) [![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](./LICENSE)

# Vouchsafe

[Vouchsafe](https://getvouchsafe.org/) is **portable, self-verifying identity and authorization in a single token.**

It takes the familiar JWT format and extends it into a complete,
offline-capable trust system.  A Vouchsafe token isn't just a signed blob of
claims, it is a **cryptographically self-contained identity + proof +
authorization statement** that needs **no infrastructure** to validate.

**Vouchsafe makes JWTs radically simpler while giving them real-world superpowers.**

Each Vouchsafe token is "just a JWT", but enhanced with:

* a **self-validating URN** that cryptographically proves the issuer's identity  
* the **public key embedded inside the token**  
* a signature that binds identity, key, and claims into a single verifiable object  

Because all trust material is carried *inside* the token, a Vouchsafe token
**carries everything needed for verification:**  identity, proof, and
authorization with:

* no registries  
* no key servers  
* no OIDC handshakes  
* no online lookups  
* no infrastructure dependencies at all  

You declare **who is allowed to do what** with a simple, explicit mapping:

```js
const trustedIssuers = {
    'urn:vouchsafe:alice.tp5y...vhsq': [
        'webhook:order_placed'
    ]
};
```

Vouchsafe guarantees that if a token claims it came from `alice`, then:

 * the embedded URN matches the embedded public key  
 * the public key matches the signature  
 * and the claims are tied to that identity with no possibility of spoofing  

Beyond basic authentication, Vouchsafe gives you powerful **authorization primitives**:
 * **attestations** (statements of fact)  
 * **vouches** (delegation and trust propagation)  
 * **revocations** (withdraw trust cleanly and formally)  
 * **multi-hop trust chains** (with purpose attenuation)  

Whether you're authenticating users, sending secure offline messages, verifying
webhooks, or delegating permissions safely, Vouchsafe lets you validate **who
sent what, and what they are allowed to do**  even across multiple
intermediaries.

> Designed for zero-infrastructure and offline environments, but useful
> anywhere identity and trust matter.

This library implements Vouchsafe in JavaScript for both Node.js and browser
environments.

---

## Installation

```bash
npm install vouchsafe
```

```js
import {
    Identity,

    // low-level helpers
    createVouchsafeIdentity,
    createVouchsafeIdentityFromKeypair,
    verifyUrnMatchesKey,

    // token helpers
    createAttestation,
    createVouchToken,
    createRevokeToken,
    createBurnToken,
    validateVouchToken,
    verifyVouchToken,
    isRevocationToken,
    isBurnToken,

    // JWT helpers
    createJwt,
    verifyJwt,
    decodeJwt,
    decodeToken,
    getAppClaims,

    // trust evaluation
    validateTrustChain
} from 'vouchsafe';
```

---

## Quickstart (Identity Interface)

Most developers should start with the **`Identity`** interface.
It covers the 90% path: create identities, issue tokens, and validate trust chains.

### Example: Sending & Verifying a Webhook with Vouchsafe

One challenge with webhooks is verifying that the sender is both **authentic**
and **authorized**.

Vouchsafe makes this straightforward.

#### Step 1: Sender creates an attestation token with the webhook payload

```js
import fs from 'fs';
import { Identity } from 'vouchsafe';

// Generated once via CLI:
//   create_vouchsafe_id -l alice -o alice.json
// Store alice.json securely (vault, env, etc.).

const idData = JSON.parse(fs.readFileSync('alice.json', 'utf8'));
const alice = await Identity.from(idData);

// Create an attestation token containing your webhook data.
// "purpose" expresses why this token exists and how it can be used.
const webhookToken = await alice.attest({
    purpose: 'webhook:order_placed',
    orderId: '12345',
    amount: 4999
});

// Send `webhookToken` as the webhook body or header
console.log(webhookToken);
```

#### Step 2: Receiver validates the token and checks trust for the purpose

```js
import {
    validateTrustChain,
    decodeToken,
    getAppClaims
} from 'vouchsafe';

// Issuers and purposes you trust
const trustedIssuers = {
    'urn:vouchsafe:alice.tp5y...vhsq': [
        'webhook:order_placed'
    ]
};

// The token received in the webhook (subject token)
const subjectTokenString = req.body.token;

// The full token set involved in trust evaluation.
// For a simple case this is just the subject token itself.
const tokens = [ subjectTokenString ];

// Required purposes for this call
const requiredPurposes = [ 'webhook:order_placed' ];

// Validate:
//  - the JWT signature and URN binding
//  - the trust chain up to a configured trust root
const result = await validateTrustChain(
    tokens,
    subjectTokenString,
    trustedIssuers,
    requiredPurposes
);

if (!result.valid) {
    console.error('Untrusted webhook source');
    res.status(403).end();
    return;
}

// On success, result.subjectToken is the decoded subject token object
const subjectToken = result.subjectToken;

// `getAppClaims` returns the application-level payload,
// excluding Vouchsafe/JWT housekeeping claims.
const appClaims = getAppClaims(subjectToken.decoded);

console.log('Trusted webhook from:', subjectToken.decoded.iss);
console.log('Webhook data:', appClaims);
```

**There is no Step 3.**

---

## What Vouchsafe Tokens Can Represent

Vouchsafe tokens come in a few simple types that can be combined
into powerful trust relationships:

* **Attestations** - "I assert this fact."

  Example: Alice attests that her email is `alice@example.com`
  or that an order was successfully created.

* **Vouches** - "I vouch for someone else's token."

  Example: Bob vouches that Alice's attestation is valid
  (if you trust Bob for a purpose, you can transitively trust Alice via his vouch).

* **Revocations** - "I withdraw a previous vouch or attestation I issued."

  Example: Bob later revokes his earlier vouch if Alice's email is compromised.

* **Burn tokens** - "I am permanently destroying this identity."

  A burn token is an issuer's suicide note: a final statement that
  no future tokens from that identity should ever be trusted.

Each token is self-contained, cryptographically bound to its issuer, and can be
passed around freely. By chaining them together, you can express richer trust graphs:

* Webhooks signed by a service operator.
* Email confirmations verified by external identity providers.
* Delegated permissions that expire or are revocable.
* Offline credentials that can be checked later without talking to the issuer.

You decide **who** to trust (`iss` URNs) and **for what** (purposes).
The evaluator handles the rest.

---

## Examples

### Example 1: Attestation

An **attestation** is the simplest kind of Vouchsafe token:

> A signed token that says *"I claim these things, and you can verify that with my embedded public key and URN."*

```js
import {
    Identity,
    validateVouchToken,
    getAppClaims
} from 'vouchsafe';

// Alice creates an attestation
const alice = await Identity.create('alice');

const emailAttestation = await alice.attest({
    purpose: 'email-confirmation',
    email: 'alice@example.com'
});

// Anyone can validate the attestation later:
const decoded = await validateVouchToken(emailAttestation);

// Extract only application claims (ignoring Vouchsafe / JWT housekeeping claims)
const appClaims = getAppClaims(decoded);

console.log(appClaims);
// { email: "alice@example.com" }
```

Attestations alone already cover most common JWT use cases, with the added
benefit that the identity (`iss`) is cryptographically self-verifying.

---

### Example 2: Attestation + Vouch + Trust Check

Sometimes "I said this" is not enough. You want someone *you* trust to
stand behind that statement.

Example: Bob attests to his email, Alice vouches for that attestation,
and some third party verifies trust by trusting Alice for the relevant purpose.

```js
import {
    Identity,
    validateVouchToken,
    validateTrustChain,
    getAppClaims
} from 'vouchsafe';

// Step 1: Bob creates an attestation token
const bob = await Identity.create('bob');

const emailAttestation = await bob.attest({
    purpose: 'email-confirmation',
    email: 'bob@example.com'
});

// Step 2: Alice vouches for Bob's attestation
const alice = await Identity.create('alice');

const vouch = await alice.vouch(emailAttestation, {
    purpose: 'email-confirmation'
});

// Step 3: A verifier trusts Alice for email confirmation
const trustedIssuers = {
    [alice.urn]: [ 'email-confirmation' ]
};

// Quick structural validation of the subject token
const decodedAttestation = await validateVouchToken(emailAttestation);
console.log(getAppClaims(decodedAttestation)); // { email: "bob@example.com" }

// Step 4: Full trust-chain validation
const tokens = [ emailAttestation, vouch ];
const requiredPurposes = [ 'email-confirmation' ];

const result = await validateTrustChain(
    tokens,
    emailAttestation,      // subject token
    trustedIssuers,
    requiredPurposes
);

console.log(result.valid); // true if a valid chain to a trusted issuer exists

if (result.valid) {
    console.log('Email is trusted via:', result.trustRoot);
}
```

---

### Example 3: Revoking a Vouch

Trust can change. If Alice no longer wants to stand behind Bob's email claim,
she can issue a **revoke token**. When the verifier includes that revoke in the
token set, the chain will no longer validate.

```js
import {
    Identity,
    validateTrustChain
} from 'vouchsafe';

const bob   = await Identity.create('bob');
const alice = await Identity.create('alice');

// Bob attests
const emailAttestation = await bob.attest({
    purpose: 'email-confirmation',
    email: 'bob@example.com'
});

// Alice vouches for Bob
const vouch = await alice.vouch(emailAttestation, {
    purpose: 'email-confirmation'
});

const trustedIssuers = {
    [alice.urn]: [ 'email-confirmation' ]
};

// Initially: chain is trusted
let result = await validateTrustChain(
    [ emailAttestation, vouch ],
    emailAttestation,
    trustedIssuers,
    [ 'email-confirmation' ]
);

console.log(result.valid); // true

// Now Alice revokes her vouch
const revoke = await alice.revoke(vouch);

// Re-check, now including the revoke token
result = await validateTrustChain(
    [ emailAttestation, vouch, revoke ],
    emailAttestation,
    trustedIssuers,
    [ 'email-confirmation' ]
);

console.log(result.valid); // false, vouch has been revoked
```

Revocations are processed during the **prepare/clean** step inside
`validateTrustChain`, so you do not have to manually manage
revocation logic.

---

### Example 4: Delegation with Constraints

Vouch tokens can also encode additional claims, making it easy to delegate
permissions in a constrained way.

Suppose Alice is a file storage owner and is trusted for `file:write`.
She wants to allow Bob to upload *one specific file* without handing over her key.

```js
import {
    Identity,
    validateTrustChain,
    getAppClaims
} from 'vouchsafe';

const alice = await Identity.create('alice'); // storage owner
const bob   = await Identity.create('bob');   // user who wants to upload

const now = Math.floor(Date.now() / 1000);

// Bob describes his intended action in an attestation
const uploadRequest = await bob.attest({
    purpose: 'file:write',
    filename: 'report.pdf',
    size: 3 * 1024 * 1024,   // 3 MB
    exp: now + 600           // token expires in 10 minutes
});

// Alice decides to allow this upload, with constraints.
// She issues a vouch for Bob's upload request.
const constrainedVouch = await alice.vouch(uploadRequest, {
    purpose: 'file:write',
    maxUses: 1,
    maxSize: 5 * 1024 * 1024,  // up to 5 MB
    exp: now + 300             // vouch itself expires in 5 minutes
});

// At the storage service:
const trustedIssuers = {
    [alice.urn]: [ 'file:write' ]
};

const tokens = [ uploadRequest, constrainedVouch ];
const requiredPurposes = [ 'file:write' ];

const result = await validateTrustChain(
    tokens,
    uploadRequest,      // subject token
    trustedIssuers,
    requiredPurposes
);

if (!result.valid) {
    throw new Error('Upload not authorized');
}

const claims = getAppClaims(result.subjectToken.decoded);
console.log('Authorized upload of:', claims.filename);
```

The storage system can enforce additional constraints (e.g. `maxSize`,
`maxUses`) at the application level. Vouchsafe ensures that the identity and
delegated permission are cryptographically valid and revocation-aware.

---

## Validation API

Vouchsafe gives you two main layers of validation:

1. **Token-level validation** - "Is this a properly formed Vouchsafe token?"
2. **Trust-chain validation** - "Is this subject token trusted for these purposes by someone I trust?"

### 1) Token-level validation

Use `validateVouchToken` when you want to treat a Vouchsafe token like a
"better JWT":

```js
import {
    validateVouchToken,
    getAppClaims
} from 'vouchsafe';

const decoded = await validateVouchToken(compactJwt);

// If this returns without throwing, the token is:
//   * structurally valid as a Vouchsafe token
//   * signed correctly with the embedded public key
//   * correctly bound to its URN (iss + iss_key)

const appClaims = getAppClaims(decoded);
console.log(appClaims);
```

This is suitable when you control the issuer directly or when trust is handled
by policy elsewhere (e.g. allow-listing issuers in your own application).

### 2) Trust-chain validation with `validateTrustChain`

Use `validateTrustChain` when you want to ask:

> "Given this subject token and this set of other tokens, is there a valid trust chain from the subject to any of these trusted issuers *for this set of purposes*?"

Signature:

```ts
async function validateTrustChain(
    tokens: Array<string | TokenObject>,
    subjectToken: string | TokenObject,
    trustedIssuers: { [urn: string]: string[] },
    requiredPurposes?: string[] | null,
    options?: {
        maxDepth?: number;
        returnAllValidChains?: boolean;
    }
): Promise<{
    valid: boolean;
    subjectToken: TokenObject;
    trustRoot?: string;
    chains?: Array<{
        chain: TokenObject[];
        purposes: string[];
        trustRoot: string;     // URN of the root that granted access
    }>;
    effectivePurposes?: string[];
}>;
```

* `tokens` - array of all tokens you have available (including the subject).
* `subjectToken` - the token you are evaluating for trust.
* `trustedIssuers` - map of URN array of purposes that URN is trusted for.
* `requiredPurposes` - array of purposes you require (`['msg-signing']`, etc.);
  if omitted or empty, the evaluator treats this as "S_ANY" (any purpose that survives is acceptable).
* `options.maxDepth` - optional bound on how many vouch hops the evaluator is allowed to follow.
* `options.returnAllValidChains` - if `true`, the evaluator will return all valid chains instead of stopping at the first one that satisfies the required purposes.

**Result fields (conceptual):**

* `valid` - `true` if at least one chain from the subject token to a trusted issuer satisfied all `requiredPurposes`.
* `subjectToken` - the decoded form of the subject token (for convenience).
* `trustRoot`: URN of the issuer that granted trust on that chain
* `chains` - when `returnAllValidChains` is `true`, an array of valid chains, each with:
  * `chain`: tokens from subject ... trust root
  * `purposes`: purposes that survived along that specific chain
  * `trustRoot`: URN of the issuer that granted trust on that chain
* `effectivePurposes` - the purposes granted by the chain(s) that satisfied `requiredPurposes`.
  This is the set of purposes on the first valid chain found.

The evaluator always operates on a **cleaned** trust graph; `validateTrustChain`
internally calls `prepareTclean` to:

* decode tokens
* verify signatures
* enforce structural rules (including revocations / burns)
* deduplicate tokens
* construct an acyclic graph for evaluation

If you bypass this cleaning step, you are outside the Vouchsafe model.

---

## CLI Tools

The npm package also provides CLI utilities that let you work with identities
and tokens entirely from the shell:

* **`create_vouchsafe_id`** - generate a new Vouchsafe identity (URN + keypair).
* **`create_vouchsafe_token`** - mint attestations, vouches, revocations, and burns.
* **`verify_vouchsafe_token`** - validate and trust-check tokens, including multi-hop chains.

They are ideal for scripting, prototyping, automation, or bootstrapping
a trust environment before integrating the JS library into your application.

### `create_vouchsafe_id`

Generate a new identity:

```bash
create_vouchsafe_id --label alice -o alice.json
```

Example output:

```json
{
  "urn": "urn:vouchsafe:alice.tp5yr5uvfgbmwba3jdmqrar4rqu5rsbkz6nqqyuw75zxpdzgvhsq",
  "keypair": {
    "publicKey": "MCowBQYDK2VwAyEAo47M4fApUZQV3KwI6Y2kLEFxpX/3M1OqZNGIZwXxKdQ=",
    "privateKey": "MC4CAQAwBQYDK2VwBCIEIG/9DEl2+cTWQFW+oZvqxd8pOP21u/MIYe5maaFEtyvi"
  },
  "publicKeyHash": "tp5yr5uvfgbmwba3jdmqrar4rqu5rsbkz6nqqyuw75zxpdzgvhsq",
  "version": "1.5.0"
}
```

Options (summary):

```text
Usage: create_vouchsafe_id [options]

Create a new Vouchsafe identity with associated keypair.

Options:
  -l, --label <label>        Identity label (required)
  -s, --separate             Output in separate files instead of JSON
  -q, --quiet                Suppress status output
  -e, --existing <filename>  Load an existing identity file rather than creating from scratch
  -o, --output <filename>    Output filename (or prefix in separate files mode)
  -h, --help                 Display help
```

### `create_vouchsafe_token`

Create a token from an identity:

```bash
Usage: create_vouchsafe_token [options]

Token types:
  --attest   (default)  Issue an attestation
  --vouch              Vouch for an existing token
  --revoke             Revoke a previous vouch
  --burn               Burn an identity

Key options:
  -i, --identity <file>    Identity JSON (required)
  -f, --claims <file>      Claims JSON file
  -c, --claim <k=v>        Additional claim (repeatable)
  -p, --purpose <purpose>  Purpose (repeatable; attest/vouch)
  -e, --expires <seconds>  Expiration (default 86400; 0 = no exp)
  -t, --token-file <file>  Subject token (vouch/revoke/burn)
  -T, --token <string>     Subject token string (vouch/revoke/burn)
```

Examples:

```bash
# Attestation with a purpose
create_vouchsafe_token -i alice.json -p msg-signing > token.jwt

# Vouch for an existing token
create_vouchsafe_token -i alice.json --vouch -t subject.jwt -p email-confirmation -o vouch.jwt

# Revoke a previous vouch
create_vouchsafe_token -i alice.json --revoke -t vouch.jwt -o revoke.jwt
```

### `verify_vouchsafe_token`

Verify a Vouchsafe token from the shell:

```bash
Usage: verify_vouchsafe_token [options]

Options:
  -t, --token-file <file>     File with one or more tokens (first = subject)
  -T, --token <string>        Token string (first = subject)
  -O, --output <format>       json | unix
  -f, --field <dotpath>       Output only this field (repeatable)
  -E, --extended              Extended verification (require trust for purpose)
  -p, --purpose <purpose>     Purpose(s) to require (repeatable)
  --trusted <file>            Trusted issuers file (JSON or text)
  --trusted-issuer <issuer:purpose[,purpose2...]>  Inline trusted issuer entry
```

Example:

```bash
# Just validate structure & signature
verify_vouchsafe_token -t token.jwt

# Extended trust evaluation with purposes and extra tokens
verify_vouchsafe_token -E -p email-confirmation \
    --trusted trusted.json \
    -t chain.txt -O unix
```

Trusted issuers file (JSON):

```json
{
  "urn:vouchsafe:alice...": ["email-confirmation", "webhook:order_placed"],
  "urn:vouchsafe:bob...":   ["email-confirmation"]
}
```

---

## Identity Class API (High-level)

The `Identity` class wraps common patterns:

```js
import { Identity } from 'vouchsafe';
```

Key methods:

* `Identity.create(label)` - generate a new identity (URN + keypair).
* `Identity.from({ urn, keypair })` - rehydrate from JSON.
* `Identity.fromKeypair(label, keypair)` - build from an existing keypair.
* `identity.urn` - self-verifying URN (safe to share).
* `identity.attest(claims)` - create an attestation token.
* `identity.vouch(subjectToken, claims)` - create a vouch token.
* `identity.revoke(vouchToken, claims?)` - revoke a vouch.
* `identity.verify(token)` - verify a single Vouchsafe token (signature + URN).
* `identity.toJSON()` - export `{ urn, keypair }` for storage.

The Identity class is the recommended entry point unless you need low-level control.

---

## Functional API (Low-level)

For advanced use  you can call the building blocks directly.

### Identity helpers

* `createVouchsafeIdentity(label, hashAlg?)`
  `{ urn, keypair }`

* `createVouchsafeIdentityFromKeypair(label, keypair, hashAlg?)`
  `{ urn, keypair }`

* `verifyUrnMatchesKey(urn, publicKeyBase64)`
  Throws if the URN does not match the given public key.

* `validateIssuerString(iss)`
  Validate that a string is a syntactically correct Vouchsafe URN.

### JWT helpers

* `createJwt(iss, iss_key, privateKey, claims = {}, options = {})`
  Create a signed JWT. If `options.exclude_iss_key` is true, omit `iss_key`
  (useful for non-Vouchsafe compatibility).

* `verifyJwt(token, opts = {})`
  Verify a signed JWT against its embedded key.

* `decodeJwt(token, opts?)` / `decodeToken(rawToken)`
  Decode a token into `{ header, payload, signature }` and computed metadata.

* `getAppClaims(decodedToken)`
  Strip Vouchsafe and JWT housekeeping claims, returning only the application payload.

* `hashJwt(jwt, alg = 'sha256')`
  Compute a stable hash of a compact JWT.

### Token creation

* `createAttestation(issuerUrn, keypair, claims = {})`
  Issue an attestation token.

* `createVouchToken(subjectJwt, issuerUrn, keypair, args = {})`
  Issue a vouch for the subject token.

* `createRevokeToken(args, issuerUrn, keypair)`
  Issue a revocation token targeting a previous attestation or vouch by the same issuer.

* `createBurnToken(issuerUrn, keypair, args = {})`
  Issue a burn token that permanently terminates an identity.

* `revokeVouchToken(vouchToken, issuerKeyPair, args = {})`
  Helper for constructing a revocation that specifically targets a given vouch.

### Token validation

* `validateVouchToken(token)`
  Full Vouchsafe validation of a single token (structure, URN binding, signature).

* `verifyVouchToken(vouchJwt, subjectJwt)`
  Confirm that a vouch correctly references its subject.

* `isRevocationToken(token)` / `isBurnToken(token)`
  Type guards for token kinds.

### Trust-chain evaluation

* `validateTrustChain(tokens, subjectToken, trustedIssuers, requiredPurposes?, options?)`
  High-level API described in the Validation section above.
  Runs cleaning, graph construction, BFS traversal, revocation/burn handling,
  and purpose intersection.

> NOTE: Internal graph helpers like `prepareTclean` and the raw evaluator are
> not part of the stable public API. Use `validateTrustChain` unless you are
> deliberately experimenting with graph construction.

---

## Learn More

* [getvouchsafe.org](https://getvouchsafe.org) - Conceptual overview and use cases
* [Vouchsafe Specification](https://github.com/ionzero/vouchsafe) - Token format, URN rules, trust-chain semantics

---

Vouchsafe is designed to be:

* **Self-contained** - tokens carry their own proof.
* **Zero-infrastructure** - works without CAs, DID resolvers, or online key servers.
* **Human-scale** - maps naturally to how humans think about trust and delegation.

> **Vouchsafe:** identity you can prove, trust you can carry.

---

## License

BSD 3-Clause License
© 2025 [Jay Kuri](https://jaykuri.com) / [Ionzero](https://ionzero.com)
