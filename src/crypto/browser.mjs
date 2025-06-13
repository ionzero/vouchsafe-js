export async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519', namedCurve: 'Ed25519' },
    true,
    ['sign', 'verify']
  );
  const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  return { publicKey, privateKey };
}

export async function sign(data, privateKeyPkcs8) {
  const key = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyPkcs8,
    { name: 'Ed25519' },
    false,
    ['sign']
  );
  return await crypto.subtle.sign({ name: 'Ed25519' }, key, data);
}

export async function verify(data, signature, publicKeyRaw) {
  const key = await crypto.subtle.importKey(
    'raw',
    publicKeyRaw,
    { name: 'Ed25519' },
    false,
    ['verify']
  );
  return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, data);
}

export async function sha256(data) {
  return await crypto.subtle.digest('SHA-256', data);
}

export async function sha512(data) {
  return await crypto.subtle.digest('SHA-512', data);
}
