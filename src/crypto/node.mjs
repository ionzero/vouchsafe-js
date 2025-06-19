import { generateKeyPairSync, createSign, createVerify, createHash, webcrypto } from 'node:crypto';

export async function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }),
  };
}

export async function sign(data, privateKeyDer) {
  const key = crypto.createPrivateKey({ key: privateKeyDer, format: 'der', type: 'pkcs8' });
  const sig = createSign('sha256').update(data).sign(key);
  return sig;
}

export async function verify(data, signature, publicKeyDer) {
  const key = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
  return createVerify('sha256').update(data).verify(key, signature);
}

export async function sha256(data) {
  return createHash('sha256').update(data).digest();
}

export async function sha512(data) {
  return createHash('sha512').update(data).digest();
}

export async function getKeyBytes(type, base64Der) {
  const der = Buffer.from(base64Der, 'base64');

  try {
    let key;
    let raw;

    if (type === 'public') {
      key = await webcrypto.subtle.importKey(
        'spki',
        der,
        { name: 'Ed25519' },
        true,
        ['verify']
      );
      raw = new Uint8Array(await webcrypto.subtle.exportKey('raw', key));

      if (raw.length !== 32) {
        throw new Error('Public key must be 32 bytes');
      }

    } else if (type === 'private') {
      key = await webcrypto.subtle.importKey(
        'pkcs8',
        der,
        { name: 'Ed25519' },
        true,
        ['sign']
      );
      raw = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', key));

      if (raw.length < 32) {
        throw new Error('Private key DER structure is too short');
      }

    } else {
      throw new Error(`Unsupported key type: ${type}`);
    }

    return raw;
  } catch (err) {
    throw new Error(`Invalid Ed25519 ${type} key (node): ${err.message}`);
  }
}

