// src/identity.mjs
// Minimal OO wrapper around the existing functional API 

import {
  createVouchsafeIdentity,
  createVouchsafeIdentityFromKeypair,
} from './urn.mjs';
import { loadIdentity, serializeIdentity } from './identity-file.mjs';

import { createJwt, verifyJwt } from './jwt.mjs';

import {
  createAttestation,
  createVouchToken,
  validateVouchToken,
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
    const { urn, keypair, publicKeyHash, version } = init;
    if (!urn || !keypair || !keypair.publicKey || !keypair.privateKey) {
      throw new Error('Identity requires a valid { urn, keypair:{ publicKey, privateKey } }');
    }
    this.urn = urn;
    this.keypair = keypair;
    this.publicKeyHash = publicKeyHash;
    this.version = version;
  }

  // --- factories (async) ---

  static async create(label, ...rest) {
    // passthrough any extra args (e.g., hashAlg) as your createVouchsafeIdentity supports
    return new Identity(await createVouchsafeIdentity(label, ...rest));
  }

  static async from(init, options = {}) {
    return new Identity(await loadIdentity(init, options));
  }
  // JAYK: TODO: Consider adding a 'get_label()' or 'for_display()' 
  // to make it easier to display a urn

  static async fromKeypair(label, keypair) {
    return new Identity(await createVouchsafeIdentityFromKeypair(label, keypair));
  }

  // --- token creation ---

  async attest(claims = {}) {
    // Default vch_iss to this identity when omitted
    const c = {
      ...claims,
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

  async verify(token) {
    return validateVouchToken(token);
  }
  // --- utilities ---
  async toObject(options) {
    return serializeIdentity(this, options);
  }

  async toIdentityFile(options = {}) {
    return this.toObject(options);
  }

  toJSON() {
    return {
      urn: this.urn,
      keypair: { publicKey: this.keypair.publicKey },
      publicKeyHash: this.publicKeyHash,
      version: this.version,
    };
  }
}
