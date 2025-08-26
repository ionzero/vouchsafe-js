// src/identity.mjs
// Minimal OO wrapper around the existing functional API 

import {
  createVouchsafeIdentity,
  createVouchsafeIdentityFromKeypair,
  verifyUrnMatchesKey
} from './urn.mjs';

import { createJwt, verifyJwt } from './jwt.mjs';

import {
  createAttestation,
  createVouchToken,
  revokeVouchToken
} from './vouch.mjs';

function normalizePurpose(purpose) {
  if (!purpose) return undefined;
  return Array.isArray(purpose) ? purpose.join(' ') : purpose;
}

/**
 * Usage:
 *   // rehydrate from existing material
 *   const id = new Identity({ urn, keypair });
 *
 *   // or generate:
 *   const id = await Identity.create('alice');
 *
 *   // or derive a URN from an existing keypair + label:
 *   const id = await Identity.fromKeypair('alice', keypair);
 */
export class Identity {
  constructor(init) {
    if (!init || typeof init !== 'object') {
      throw new TypeError('Identity ctor expects { urn, keypair }');
    }
    const { urn, keypair } = init;
    if (!urn || !keypair || !keypair.publicKey || !keypair.privateKey) {
      throw new Error('Identity requires a valid { urn, keypair:{ publicKey, privateKey } }');
    }
    this.urn = urn;
    this.keypair = keypair;
  }

  // --- factories (async) ---

  static async create(label, ...rest) {
    // passthrough any extra args (e.g., hashAlg) as your createVouchsafeIdentity supports
    const { urn, keypair } = await createVouchsafeIdentity(label, ...rest);
    return new Identity({ urn, keypair });
  }

  static async from(init, { verify = true } = {}) {
    // Rehydrate from { urn, keypair } and (optionally) verify the binding
    if (!init || !init.urn || !init.keypair) {
      throw new Error('Identity.from requires { urn, keypair }');
    }
    if (verify) {
      await verifyUrnMatchesKey(init.urn, init.keypair.publicKey);
    }
    return new Identity(init);
  }

  static async fromKeypair(label, keypair) {
    const { urn, keypair: kp } = await createVouchsafeIdentityFromKeypair(label, keypair);
    return new Identity({ urn, keypair: kp });
  }

  // --- token creation ---

  async sign(claims = {}) {
    // Convenience: default iss/iat if not provided
    const now = Math.floor(Date.now() / 1000);
    const c = {
      iat: claims.iat ?? now,
      iss: claims.iss ?? this.urn,
      ...claims
    };
    return createJwt(this.urn, this.keypair.publicKey, this.keypair.privateKey, c);
  }

  async attest(claims = {}) {
    // Default vch_iss to this identity when omitted
    const c = {
      ...claims,
      vch_iss: claims.vch_iss ?? this.urn,
      purpose: normalizePurpose(claims.purpose)
    };
    return createAttestation(this.urn, this.keypair, c);
  }

  async vouch(subjectToken, opts = {}) {
    const c = {
      ...opts,
      purpose: normalizePurpose(opts.purpose)
    };
    return createVouchToken(subjectToken, this.urn, this.keypair, c);
  }

  async revoke(vouchToken, opts = {}) {
    // Revoke a specific vouch, or pass { revokes: 'all' } to revoke all for that subject
    return revokeVouchToken(vouchToken, this.keypair, opts);
  }

  // --- lightweight verify helper (kept separate from trust-chain) ---

  async verify(token) {
    return verifyJwt(token);
  }

  // --- utilities ---

  toJSON() {
    return { urn: this.urn, keypair: this.keypair };
  }
}
