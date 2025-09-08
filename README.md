# Vouchsafe JS

[Vouchsafe](https://getvouchsafe.org/) is **portable, self-verifying identity and trust - in a single token.**

**Vouchsafe makes JWTs easier while giving them superpowers!**

Each Vouchsafe token is just a JWT, but enhanced with:

* a **self-validating URN** that proves the issuer's identity
* the **public key embedded inside the token**
* a cryptographic signature binding it all together

That means a Vouchsafe token **carries everything needed for verification** -
identity, proof, and trust - right inside the token. No registries, no key
servers, no online lookups.

You read that right. Meaningful issuers, no pushing public keys around, and
simple verification that works even entirely offline.

So instead of worrying about managing key blobs, or wiring up key management infrastructure, 
you just configure **who is allowed to do what**:

```js
const trustedIssuers = {
  'urn:vouchsafe:alice.tp5y...vhsq': [
    'webhook:order_placed'
  ]
};
```

Vouchsafe guarantees that if a token says it came from `alice`, the URN and key
inside it really do match - and the signature proves it.

Whether you're authenticating users, confirming purchases, issuing verifiable
attestations, or sending tamper-proof webhooks, Vouchsafe makes it easy to
verify **who sent what, and what they're allowed to do.**

> Built for decentralized systems. Useful anywhere identity and trust matter.

This library implements Vouchsafe in JavaScript for both Node.js and browser
environments.

---

##  Installation

```bash
npm install vouchsafe
```

---

##  Quickstart (Identity Interface)

Most developers should start with the **Identity** interface. It's ergonomic and covers the 90% path. The lower-level functional API remains available for advanced flows.

### Example: Sending & Verifying a Webhook with Vouchsafe

One challenge with webhooks is verifying they should be accepted and processed. 
Vouchsafe makes that easy. 

#### Step 1: **Sender** creates an attestation token with the webhook payload.

```js
import fs from 'fs';
import { Identity } from 'vouchsafe';

// Generate your identity once with:
//   create_vouchsafe_id -l alice -o alice.json
// Store the file securely (vault, env, etc.) and load it when needed.

const idData = JSON.parse(fs.readFileSync('alice.json', 'utf8'));
const alice = await Identity.from(idData);

// Create an attestation token containing your webhook data
const token = await alice.attest({
  purpose: 'webhook:order_placed',
  orderId: '12345',
  amount: 4999
});

// Send `token` as the webhook body or header
console.log(token);
```

#### Step 2: **Receiver** verifies the token and checks if the issuer is trusted for the purpose:

```js
import { verifyTrustChain } from 'vouchsafe';

// URN + purposes you trust
const trustedIssuers = {
  'urn:vouchsafe:alice.tp5y...vhsq': [
    'webhook:order_placed'
  ]
};

// The token received in the webhook
const token = req.body.token;

// Verify the token's signature, self-verifying URN, and trust for this purpose
const result = await verifyTrustChain(token, trustedIssuers, {
  purposes: ['webhook:order_placed']
});

if (result.valid) {
  console.log('Trusted webhook from', result.leaf.decoded.iss);

  // getAppClaims returns all application related claims (IE those not related to vouchsafe or token expiration)
  console.log('Webhook data:', getAppClaims(result.leaf.decoded));
} else {
  console.log('Untrusted webhook source');
}
```

**There is no Step 3.**

---

##  What Vouchsafe Can Do

Vouchsafe tokens come in a few simple types that can be combined to represent powerful trust relationships:

* **Attestations** - "I assert this fact." - this is like your 'normal' jwt
  Example: Alice attests that her email is `alice@example.com`.

* **Vouches** - "I vouch for someone else's attestation." - If you trust me, you can trust them. 
  Example: Bob vouches that Alice's email address has been verified.

* **Revocations** - "I withdraw a previous vouch." - I no longer trust them.
  Example: Bob later revokes his vouch if Alice's email is compromised.

Each token is self-contained, cryptographically bound to its issuer, and can be passed around freely.
By chaining them together, you can express richer relationships:

* **Webhooks** - Alice signs the webhook payload, and you trust Alice for `webhook:order_placed`.
* **Email confirmations** - Alice attests to her email, Bob vouches that it was verified.
* **Purchase confirmations** - A store attests "order #123 paid," a payment processor vouches the payment cleared.

You decide who to trust (URNs) and for what (purposes). The tokens do the heavy
lifting — and because each token carries its own proof, they can be issued at
one time and verified much later, even if the issuer or verifier is offline at
the moment of use.

---

### Example: Attestation

An **attestation** is the simplest kind of Vouchsafe token.
It’s directly analogous to how most JWTs are used today:

> A signed token that says *“I claim these things, and you can verify that with my signature.”*

The difference is that with Vouchsafe, the token itself proves the claim really
came from the issuer. The embedded URN and key binding make it impossible for
anyone else to forge that identity **or that token**.

```js
import { Identity, validateVouchToken, getAppClaims } from 'vouchsafe';

// Alice creates an attestation
const alice = await Identity.create('alice');

const attestation = await alice.attest({
  purpose: 'email-confirmation',
  email: 'alice@example.com'
});

// Anyone can validate the token later
const decoded = await validateVouchToken(attestation);

// Extract only application claims (ignoring Vouchsafe-specific claims)
console.log(getAppClaims(decoded)); 
// { email: "alice@example.com" }
```

Attestations alone already cover most common JWT use cases, making them a
natural starting point for using Vouchsafe.

### Example: Attestation + Vouch (Identity Interface)

Sometimes it isn't enough to simply prove "I said this."
You also want a second party to confirm it - for example, Alice attests to her
email, and Bob vouches that he verified it.

```js
import { Identity, validateVouchToken, verifyTrustChain } from 'vouchsafe';

// Step 1: Alice creates an attestation token
const alice = await Identity.create('alice');

// Alice attests that her email is alice@example.com
const attestation = await alice.attest({
  purpose: 'email-confirmation',
  email: 'alice@example.com'
});

// Step 2: Bob vouches for Alice's attestation
const bob = await Identity.create('bob');

// Bob confirms Alice's email address and vouches for her attestation.
// Now anyone who trusts Bob for 'email-confirmation' can trust Alice's claim.
const vouch = await bob.vouch(attestation, { purpose: 'email-confirmation' });

// Trusted issuers: Bob is trusted for confirming emails
const trusted = {
  [bob.urn]: ['email-confirmation']
};

// Quick validation: check that the attestation is well-formed and self-verifying
const decoded = await validateVouchToken(attestation);
console.log(decoded.email);  // "alice@example.com"

// Verify the full trust chain
const result = await verifyTrustChain(attestation, trusted, {
  tokens: [vouch, attestation],
  purposes: ['email-confirmation']
});

console.log(result.valid);  // true if the chain is trusted
```

---

### Example: Revoking a Vouch

But trust can change. What if Bob no longer wants to stand behind Alice's claim?
Vouchsafe makes this easy with a **revoke token**. Bob can issue a revocation that cancels his earlier vouch, and anyone verifying the chain will see the claim as no longer trusted.

```js
// Bob revokes his earlier vouch
const revoke = await bob.revoke(vouch);

// Now verify the chain again, but include the revoke
const resultAfterRevoke = await verifyTrustChain(attestation, trusted, {
  tokens: [vouch, attestation, revoke],
  purposes: ['email-confirmation']
});

console.log(resultAfterRevoke.valid);  // false, because Bob's vouch was revoked
```

---

### Example: Delegation with Constraints

Vouchsafe vouches can carry **additional claims**, making it easy to delegate permissions in a controlled way.

Suppose Bob wants to upload a file on Alice's behalf. Alice is trusted for `file:write`, but instead of sharing her key, she issues Bob a vouch that delegates that permission - with constraints.

```js
import { Identity, verifyTrustChain } from 'vouchsafe';

// Step 1: Alice is the trusted storage owner
const alice = await Identity.create('alice');

// Step 2: Bob is another user who wants to upload a file
const bob = await Identity.create('bob');

let now = Math.floor(Date.now()/1000);

// Bob creates a token describing his action
const uploadRequest = await bob.attest({
  exp: now + 600,  // expire the token after 10 minutes
  purpose: 'file:write',
  filename: 'report.pdf',
  size: 1024 * 1024 * 3   // 3 MB
});

// Bob presents his upload request token to Alice.
// Alice decides to allow it, and issues a vouch with constraints.
const constrainedVouch = await alice.vouch(uploadRequest, {
  exp: now + 300,  // expire the vouch after 5 minutes.
  purpose: 'file:write',
  maxUses: 1,
  maxSize: 1024 * 1024 * 5   // 5 MB
});

// Alice gives Bob the vouch token.
// Bob can now present *both* tokens (his upload request + Alice's vouch)
// to the file storage system, which will honor it until the vouch expires.
```

**Verification (at the storage system):**

```js
// The file storage system trusts Alice for file:write
const trustedIssuers = {
  [alice.urn]: ['file:write']
};

// The storage system receives Bob's uploadRequest and Alice's vouch
const result = await verifyTrustChain(uploadRequest, trustedIssuers, {
  tokens: [uploadRequest, constrainedVouch],
  purposes: ['file:write']
});

if (result.valid) {
  console.log('Upload request trusted:', result.leaf.decoded.filename);
}
```

 **Notes:**

* Vouchsafe tokens are just JWTs under the hood. For example, the `jti` (JWT ID) claim can be used to enforce **single-use tokens** - you simply record which `jti`s you've already seen, and reject duplicates.
* Once Alice issues the vouch, Bob can use it later, even if Alice isn't online. No further communication with Alice is required for verification - the proof travels entirely in the tokens.
* This **time-separated token issuance and usage** demonstrates Vouchsafe’s particular usefulness in **offline-capable or decentralized systems**, where the issuer and verifier may never communicate directly.

## Validation

Vouchsafe gives you three practical ways to validate, plus optional dynamic lookups and custom trust anchoring:

1. **Manual validation** — Treat it like a “regular JWT, but better.”
2. **Full Vouchsafe trust verification (single-hop)** — Accept tokens issued directly by your anchors.
3. **Full delegated trust verification (multi-hop)** — Allow issuers to be vouched for across multiple levels.
4. **Dynamic lookup & custom trust anchors** — Bring your own async resolvers and/or anchoring logic.

### 1) Manual validation (no chaining)

The simplest path: validate the token, then look up the issuer however you like (config, DB, etc.). No purpose checking shown here to keep it minimal.

```js
import { validateVouchToken } from 'vouchsafe';
// Optional helper if you want just your app payload:
// import { getAppClaims } from './jwt.mjs';

const decoded = await validateVouchToken(compactJwt);
// ↑ If this returns without throwing, the signature was verified using the
//   included public key and that key was matched (cryptographically) to `iss`.
//   No external key lookup needed.

// Example: look up issuer in your own config/DB:
const isTrusted = await db.isIssuerTrusted(decoded.iss); // or a simple config map

if (!isTrusted) throw new Error('issuer not allowed by local policy');

// const appClaims = getAppClaims(decoded); // optional, for business payload only
```

This is “just like a regular JWT,” except `iss` is a **self-verifying URN** bound to the signing key, so you can trust it without out-of-band key distribution.

### 2) Vouchsafe trust verification (single-hop)

Use `verifyTrustChain` when your policy is an allowlist of issuers and the **purposes** they’re trusted for. If the leaf token is issued directly by one of these anchors, you’re done.

```js
import { verifyTrustChain } from 'vouchsafe-js';

// Expected format for verifyTrustChain:
// keys are issuer URNs; values are arrays of purposes that issuer is trusted for.
const trustedIssuers = {
  'urn:vouchsafe:root.bzjxi3tj...': ['msg-signing', 'store-data'],
  // add more anchors as needed
};

// the purposes you want to validate this token against
const purposes = ['msg-signing']; 

const result = await verifyTrustChain(leafToken, trustedIssuers, { purposes });

if (!result.valid) throw new Error('untrusted');

// result.leaf       // the original link
// result.trustRoot  // the trusted link (final hop)
// result.chain      // [leaf → trustRoot]
// result.purposes   // effective purposes after intersection
```


### 3) Full delegated trust verification (multi-hop)

Allow an untrusted issuer to be **vouched for** by a trusted issuer—potentially across multiple levels. Use `maxDepth` to limit how far a “vouch → vouch → vouch” chain can go. Revocations are honored automatically.

```js
import { verifyTrustChain } from 'vouchsafe-js';

const trustedIssuers = {
  'urn:vouchsafe:root.bzjxi3tj...': ['msg-signing']
};

const purposes = ['msg-signing'];

// Seed with any tokens you already have (leaf + vouches/revokes)
const tokens = [leafToken, ...someVouchTokens, ...someRevokeTokens];

const result = await verifyTrustChain(leafToken, trustedIssuers, {
  purposes,
  tokens,        // seeds a static resolver
  maxDepth: 3 ,  // bound how far delegation can go
  findAll: false // first valid chain wins (true => return all chains)
});

if (result.valid) {
   console.log("Token is trusted");
} else {
   throw new Error('no valid chain to a permitted issuer');
}
```

**Result fields (summary):**

* `valid: boolean`
* `leaf: Link` — original token `{ token, decoded, validated }`
* `trustRoot: Link` — final trusted link `{ ..., trusted: true }`
* `chain: Link[]` — **leaf → … → trustRoot**, de-duplicated
* `purposes: string[]` — final purpose intersection


### 4) Dynamic lookup & custom trust anchors

If you need more advanced behavior, the `verifyTrustChain` allows you to do **dynamic token/ref lookup** 
and/or override how trust anchors are checked. You do this by providing the `resolveFn` option and/or
the `trustAnchorLookup` option.

#### Dynamic token lookup (`resolveFn`)

If provided, `resolveFn` will be called when trust verification requires additional
tokens.  The function is called as `resolveFn(type, iss, jti)` where `type` is
the type of lookup being done. 

If `type` is `token` you should attempt to retrieve a token with the given `iss` and `jti` 
and return it. If no matching token is found your function should return undefined.

If `type` is `ref` you should attempt to retrieve any tokens (vouch or revoke) that reference
the given `iss` and `jti` and return them in an array. If no matching tokens are found your function 
should return an empty array.

**Using `tokens` and `resolveFn` together**

* For **`token`** lookups: the **static `tokens` list always takes precedence**; resolver is fallback.
* For **`ref`** lookups: results from **both** sources are combined (deduped).

```js
const resolveFn = async (type, iss, jti) => {
  if (type === 'ref')   return await db.findRefs(iss, jti);
  if (type === 'token') return await db.getToken(iss, jti);
};

const result = await verifyTrustChain(leafToken, trustedIssuers, {
  purposes: ['msg-signing'],
  tokens: [leafToken, ...seedVouches],
  resolveFn
});
```

#### Custom trust anchoring (`trustAnchorLookup`)

If you want to provide a dynamic trust lookup, you can replace the built-in anchor check by 
providing `trustAnchorLookup`. It is invoked with the **token’s** issuer/purpose, 
your passed `trustedIssuers`, and the required purposes for this evaluation).

> Exact signature used by the verifier:
> `isTrustedAnchor(iss, tokenPurposes = [], trustedIssuers = {}, requiredPurposes = [])`

* `tokenPurposes` is the array of purposes in the original token being evaluated. 
* Return **true** if the anchor identity `iss` is trusted for **all** `requiredPurposes` 
* Return **false** otherwise.

**Example: trust only if `iss` exists in `trustedIssuers` and covers all `requiredPurposes`:**

```js
const trustAnchorLookup = (iss, tokenPurpose = [], trustedIssuers = {}, requiredPurposes = []) => {
  const trustedPurposes = trustedIssuers[iss] || [];
  return requiredPurposes.every(p => tokenPurposes.includes(p) && trustedPurposes.includes(p));
};

// You can use trustAnchorLookup with or without resolveFn
const result = await verifyTrustChain(leafToken, trustedIssuers, {
  purposes: ['msg-signing'],
  trustAnchorLookup,
  // resolveFn, tokens: optional
});
```

This lets you centralize anchor policy however you like (config, DB, PDP), while still leveraging the verifier for chain traversal, revocations, purpose intersection, and max-depth control.

---
## Command Line Tools

Vouchsafe comes with three CLI utilities that let you manage identities and
tokens entirely from the command line. Together, they give you everything you
need to **create identities**, **issue tokens**, and **verify trust** without
writing a single line of code.

* **`create_vouchsafe_id`** - generate a new Vouchsafe identity (URN + keypair).
* **`create_vouchsafe_token`** - mint attestations, vouches, or revocations from an identity.
* **`verify_vouchsafe_token`** - validate and trust-check tokens, including multi-hop chains.

These tools are ideal for scripting, prototyping, automation, or bootstrapping
a trust environment before integrating the Vouchsafe library into your
application.

###  CLI Tool: `create_vouchsafe_id`

This package includes a CLI utility to generate Vouchsafe identities from the terminal.

> **Important:** The output of this command contains a **private key**.
> Treat it like a password or API secret - store it securely (vault, environment variable, encrypted storage).
> Never commit it to source control.

 The `urn` (your Vouchsafe ID) is safe to share freely. It's what others will use in their `trustedIssuers` configuration.

#### Usage

```bash
create_vouchsafe_id --label alice -o alice.json
```

#### Output (default mode)

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

#### Options

```text
Usage: create_vouchsafe_id [options]

Create a new Vouchsafe identity with associated keypair.

By default creates a new keypair. To use an existing
identity file, use -e <file>.

Options:
  -l, --label <label>        Identity label (required)
  -s, --separate             Output in separate files instead of JSON
  -q, --quiet                Suppress status output
  -e, --existing <filename>  Load an existing identity file rather than creating from scratch
  -o, --output <filename>    Output filename (or prefix in separate files mode)
  -h, --help                 Display help
```

#### Example: Separate Files Mode

Use this mode to produce **PEM-encoded keys** compatible with JWT libraries or tools that expect PEM files.

```bash
create_vouchsafe_id -l agent42 -s -o agent42
```

Produces three files:

* `agent42.urn` - contains the URN (safe to share)
* `agent42.pub.pem` - PEM-encoded public key (safe to distribute)
* `agent42.priv.pem` - PEM-encoded private key ( keep secret)

#### Example: Using an Existing Identity

You can also generate new output files from an existing identity file:

```bash
create_vouchsafe_id -l agent42 -e alice.json -s -o agent42
```

* The `-l` (label) option is still required.
* If you re-use the same label, consider `-o` to avoid overwriting your original file.

####  Best Practices for Identity Lifecycle

* **Generate once, re-use often.** Create an identity for a service or user and keep re-using it. You rarely need to generate new keys.
* **Keep it secret, keep it safe.** The private key in your identity file is as sensitive as a password or API secret.
   **If someone else gets your private key, they can impersonate you with impunity.**
* **Share only the URN.** Others only need your URN (Vouchsafe ID) in their `trustedIssuers` config. **You *NEVER* need to send your private key or even your public key**.

---

## `create_vouchsafe_token`

Create a Vouchsafe token from an identity file and a set of claims.

**Token types:**

* **attest** (default) — issue an attestation
* **vouch** — vouch for an existing token (`-t` or `-T` required)
* **revoke** — revoke a previous vouch (`-t` or `-T` required)

Claims may be provided in a JSON file (`-f`) and/or as `key=value` pairs (`-c`).
Use `-p` to set a purpose (repeatable).
Expiration defaults to 1 day; use `-e 0` to disable.

```bash
Usage: create_vouchsafe_token [options]

Options:
  -i, --identity <file>    Path to identity JSON file (required)
  -f, --claims <file>      Path to claims JSON file
  -c, --claim <k=v>        Additional claim (repeatable)
  -p, --purpose <purpose>  Purpose (repeatable; for attest/vouch)
  -e, --expires <seconds>  Expiration in seconds (default 86400; 0 = no exp)
  -o, --output <file>      Write token to file instead of stdout
  -t, --token-file <file>  Subject token file (for vouch/revoke)
  -T, --token <string>     Subject token string (for vouch/revoke)
  --attest                 Create an attestation token (default)
  --vouch                  Create a vouch token
  --revoke                 Create a revoke token
  -q, --quiet              Suppress warnings and status output
  -v, --verbose            Extra status output
  -h, --help               Show help
```

**Examples:**

```bash
# Create a simple attestation token with one purpose
create_vouchsafe_token -i myid.json -p msg-signing > token.jwt

# Create a vouch token for an existing token
create_vouchsafe_token -i myid.json --vouch -t subject.jwt -p email-confirmation -o vouch.jwt

# Create a revocation token for a previous vouch
create_vouchsafe_token -i myid.json --revoke -t vouch.jwt -o revoke.jwt
```

---

## `verify_vouchsafe_token`

Verify a Vouchsafe token.
By default, it validates **signature, URN binding, and timestamps**.
With `-E` (extended mode), it also evaluates trust against required purposes and a trusted issuers set.

```bash
Usage: verify_vouchsafe_token [options]

Options:
  -t, --token-file <file>     File with one or more tokens (first = subject, rest = extras)
  -T, --token <string>        Token string (first = subject, rest = extras)
  -O, --output <format>       Output: json | unix
  -f, --field <dotpath>       Output only this field (repeatable)
  -E, --extended              Extended verification (require trust for -p purpose)
  -p, --purpose <purpose>     Purpose(s) to require (repeatable)
  --trusted <file>            Trusted issuers file (JSON or text format)
  --trusted-issuer <issuer:purpose[,purpose2...]>  Inline trusted issuer entry (repeatable)
  -P, --prefix <prefix>       Prefix for unix output (default: vs_)
  -q, --quiet                 Suppress warnings
  -v, --verbose               Extra output
  -h, --help                  Show help
```

**Examples:**

```bash
# Basic validation; exit code 0 if valid
verify_vouchsafe_token -t token.jwt

# Output decoded claims as JSON
verify_vouchsafe_token -T "$TOKEN" -O json

# Output specific fields (one per line)
verify_vouchsafe_token -T "$TOKEN" -f iss -f jti -f email

# Extended verification with trusted issuers and extra tokens
verify_vouchsafe_token -E -p email-confirmation \
  --trusted trusted.json \
  -t chain.txt -O unix
```

**Trusted issuers file formats:**

* **JSON:**

```json
{
  "urn:vouchsafe:alice...": ["email-confirmation", "webhook:order_placed"],
  "urn:vouchsafe:bob...":   ["email-confirmation"]
}
```

* **Text:**

```
urn:vouchsafe:alice... email-confirmation webhook:order_placed
urn:vouchsafe:bob...   email-confirmation
```

---

Together, `create_vouchsafe_token` and `verify_vouchsafe_token` give you a quick, scriptable way to mint, vouch, revoke, and validate tokens directly from the command line.


---

##  API Reference

### Identity Class

The `Identity` class is the easiest way to work with Vouchsafe. It wraps all the core functionality into a simple, developer-friendly interface.

```js
import { Identity } from 'vouchsafe';
```

#### Common Patterns

* **Attest a fact** `identity.attest()`
  > "I assert this fact."

* **Vouch for someone else's token** `identity.vouch()`
  > "I confirm this token is valid for this purpose."

* **Revoke a vouch** `identity.revoke()`
  > "I withdraw my earlier confirmation."

* **Verify a token** `identity.verify()`

  > "Check that this JWT is correctly signed and self-verifying."

---

#### `Identity.create(label: string) Promise<Identity>`

Generate a new Vouchsafe identity with the given label.
Returns an `Identity` instance containing a `urn` and `keypair`.

```js
const alice = await Identity.create('alice');
console.log(alice.urn); // urn:vouchsafe:alice...
```

---

#### `Identity.from(data: { urn, keypair }) Promise<Identity>`

Rehydrate an existing identity from a JSON object (like one created by `create_vouchsafe_id`).
Useful for loading identities from disk, vaults, or environment variables.

```js
const data = JSON.parse(fs.readFileSync('alice.json', 'utf8'));
const alice = await Identity.from(data);
```

---

#### `Identity.fromKeypair(label: string, keypair) Promise<Identity>`

Create an identity from an existing keypair.
Usually only needed if you are managing raw key material directly.

---

#### `identity.urn: string`

The self-verifying URN that uniquely identifies this identity.
Safe to share - this is what goes in `trustedIssuers`.

---

#### `identity.keypair: { publicKey, privateKey }`

The cryptographic keypair for this identity.
 Keep the `privateKey` secret - if leaked, others can impersonate you.

---

#### `identity.attest(claims: object) Promise<token>`

Create an **attestation token**: "I assert this fact."
Adds `purpose` (string or array), and defaults `vch_iss` to this identity's URN.

```js
const alice = await Identity.create('alice');
const attestation = await alice.attest({
  purpose: 'email-confirmation',
  email: 'alice@example.com'
});
console.log(attestation);
```

---

#### `identity.vouch(subjectToken: string, opts?: object) Promise<token>`

Create a **vouch token** for another token.
This proves: "I vouch for this token being valid for this purpose."

`opts` may include:

* `purpose: string | string[]` - purposes you are vouching for
* Any additional claims (e.g. `maxUses`, `maxSize`)

```js
const alice = await Identity.create('alice');
const bob = await Identity.create('bob');

const emailAttestation = await bob.attest({
  purpose: 'email-confirmation',
  email: 'bob@example.com'
});

const vouch = await alice.vouch(emailAttestation, { purpose: 'email-confirmation' });
console.log(vouch);
```

---

#### `identity.revoke(vouchToken: string, opts?: object) Promise<token>`

Create a **revoke token** that invalidates a vouch.
This lets issuers withdraw trust they previously granted.

`opts` may include:

* `all: true` - revoke all vouches for the same subject
* `nbf: <timestamp>` - revocation not valid before this time

```js
const alice = await Identity.create('alice');
const bob = await Identity.create('bob');

const claim = await bob.attest({ purpose: 'email-confirmation', email: 'bob@example.com' });
const vouch = await alice.vouch(claim, { purpose: 'email-confirmation' });

const revoke = await alice.revoke(vouch);
console.log(revoke);
```

---

#### `identity.verify(token: string) Promise<object>`

Lightweight JWT verification.
Checks the signature against the embedded key and returns the decoded claims.

```js
const alice = await Identity.create('alice');
const token = await alice.attest({ purpose: 'demo', value: 42 });

const verified = await alice.verify(token);
console.log(verified); // decoded claims if valid
```

> For full trust-chain evaluation, use `verifyTrustChain`.

---

#### `identity.toJSON() { urn, keypair }`

Export this identity in JSON form (the same format used by the CLI).

```js
const alice = await Identity.create('alice');
fs.writeFileSync('alice.json', JSON.stringify(alice.toJSON(), null, 2));
```

---

##  Functional API (Advanced)

The functional interface exposes all the underlying building blocks. Most users should stick with the `Identity` class, but these functions are useful if you need low-level control or want to integrate with other crypto flows.

### Identity

* **`createVouchsafeIdentity(label, [hashAlg]) { urn, keypair }`**
  Generate a new keypair and a self-verifying URN.

* **`createVouchsafeIdentityFromKeypair(label, keypair) { urn, keypair }`**
  Create a URN from an existing Ed25519 keypair.

* **`verifyUrnMatchesKey(urn, publicKey)`**
  Throws if the URN does not match the given public key.

---

### Token Creation

* **`createJwt(iss, iss_key, privateKey, claims, options) token`**
  Create a signed JWT with arbitrary claims. Returns the encoded token string. If `options.exclude_iss_key` is true, the `iss_key` will be omitted (for compatibility with non-vouchsafe systems)

* **`createAttestation(issuerUrn, keypair, claims) token`**
  Issue an **attestation**: "I assert this fact." Returns a signed token.

* **`createVouchToken(subjectJwt, issuerUrn, keypair, claims) token`**
  Create a **vouch** for another token (attestation, vouch, or plain JWT).
  Returns a signed token that references the subject.

* **`createRevokeToken(subjectJwt, issuerUrn, keypair, opts) token`**
  Issue a **revocation** for a previous vouch. Returns a signed token.

---

### Validation

* **`verifyJwt(token) payload`**
  Validates a signed JWT using the embedded key and returns decoded claims.

* **`validateVouchToken(token) payload`**
  Validates structure, checks URN key binding, and signature. Throws on error.

* **`verifyVouchToken(vouchToken, subjectToken) boolean`**
  Confirms that a vouch correctly references its subject.

* **`verifyTrustChain(token, trustedIssuers, opts) { valid, leaf, trustRoot, chain }`**
  Walks a vouch chain and confirms whether the token is trusted for the given purpose(s).

* **`canUseForPurpose(token, trustedIssuers, opts) boolean`**
  Shorthand: true/false if the token is trusted for the specified purpose(s).

---

### Utilities

* **`makeStaticResolver(tokens) resolver`**
  Creates an in-memory resolver that supplies tokens for chain verification.

* **`createCompositeResolver(a, b) resolver`**
  Combine multiple resolvers into one.

* **`isTrustedAnchor(urn, purpose, map, requiredPurposes) boolean`**
  Checks whether an identity is a trusted root for a given purpose.

* **`isRevoked(payload, revokeList) boolean`**
  Checks whether a token is revoked by any token in the revoke list.

---

## Learn More

*  [getvouchsafe.org](https://getvouchsafe.org) - Conceptual overview and use cases
*  [Vouchsafe Specification](https://github.com/ionzero/vouchsafe) - Token structure, URN format, trust chain rules
*  [Join the Discord](https://discord.gg/sC5CU7N4D3) - Community questions & discussion

---

### Beyond the Basics

What you've seen here is just the surface: attest, vouch, revoke, and verify.
Vouchsafe can also model **delegated permissions**, **portable trust anchors**, and **offline or air-gapped verification** - all without central servers, registries, or online lookups.

As you explore, you'll find that Vouchsafe is not only simpler than traditional key management - it's also more expressive.

> **Vouchsafe:** identity you can prove, trust you can carry.

---

## License

BSD 3-Clause License
© 2025 [Jay Kuri](https://jaykuri.com) / [Ionzero](https://ionzero.com)
