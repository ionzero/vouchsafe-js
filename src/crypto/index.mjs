// crypto/index.mjs
export const {
  generateKeyPair,
  sign,
  verify,
  sha256,
  sha512,
  getKeyBytes
} = await (async () => {
    const isNode =
      typeof process !== 'undefined' &&
      process.versions?.node &&
      typeof window === 'undefined';

    const impl = isNode
        ? await import('./node.mjs')
        : await import('./browser.mjs');

    return impl;
})();

