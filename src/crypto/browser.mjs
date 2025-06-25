export async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey({
            name: 'Ed25519',
            namedCurve: 'Ed25519'
        },
        true, ['sign', 'verify']
    );
    const publicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    return {
        publicKey,
        privateKey
    };
}

export async function sign(data, privateKeyPkcs8) {
    const key = await crypto.subtle.importKey( 'pkcs8', privateKeyPkcs8, { name: 'Ed25519' }, false, ['sign']);
    return await crypto.subtle.sign({ name: 'Ed25519' }, key, data);
}

export async function verify(data, signature, publicKeyRaw) {
    const key = await crypto.subtle.importKey( 'raw', publicKeyRaw, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, data);
}

export async function sha256(data) {
    return await crypto.subtle.digest('SHA-256', data);
}

export async function sha512(data) {
    return await crypto.subtle.digest('SHA-512', data);
}

export async function getKeyBytes(type, base64Der) {
    const der = Uint8Array.from(atob(base64Der), c => c.charCodeAt(0));

    try {
        let key;
        let raw;

        if (type === 'public') {
            key = await crypto.subtle.importKey( 'spki', der.buffer, { name: 'Ed25519' }, true, ['verify']);
            raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));

            if (raw.length !== 32) {
                throw new Error('Public key must be 32 bytes');
            }

        } else if (type === 'private') {
            key = await crypto.subtle.importKey( 'pkcs8', der.buffer, { name: 'Ed25519' }, true, ['sign']);
            raw = new Uint8Array(await crypto.subtle.exportKey('pkcs8', key));

            if (raw.length < 64) {
                throw new Error('Private key DER structure is too short');
            }

        } else {
            throw new Error(`Unsupported key type: ${type}`);
        }

        return raw;
    } catch (err) {
        throw new Error(`Invalid Ed25519 ${type} key (browser): ${err.message}`);
    }
}
