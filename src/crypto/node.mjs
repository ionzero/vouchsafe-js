import { generateKeyPairSync, createSign, createVerify, createHash } from 'node:crypto';

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
