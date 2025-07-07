// crypto/index.mjs

let cryptoImpl = null;

async function loadImpl() {
    if (cryptoImpl) return cryptoImpl;

    const isNode =
        typeof process !== 'undefined' &&
        process.versions?.node &&
        typeof window === 'undefined';

    cryptoImpl = isNode
        ? await import('./node.mjs')
        : await import('./browser.mjs');

    return cryptoImpl;
}

export const generateKeyPair = async function(...args) {
    const { generateKeyPair } = await loadImpl();
    return generateKeyPair(...args);
};
export const sign = async function(...args) {
    const { sign } = await loadImpl();
    return sign(...args);
};
export const verify = async function(...args) {
    const { verify } = await loadImpl();
    return verify(...args);
};
export const sha256 = async function(...args) {
    const { sha256 } = await loadImpl();
    return sha256(...args);
};
export const sha512 = async function(...args) {
    const { sha512 } = await loadImpl();
    return sha512(...args);
};
export const getKeyBytes = async function(...args) {
    const { getKeyBytes } = await loadImpl();
    return getKeyBytes(...args);
};

