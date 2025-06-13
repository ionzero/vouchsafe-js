const isNode =
  typeof process !== 'undefined' &&
  process.versions?.node &&
  typeof window === 'undefined';

let cryptoImpl;
if (isNode) {
  cryptoImpl = await import('./node.mjs');
} else {
  cryptoImpl = await import('./browser.mjs');
}

export const {
  generateKeyPair,
  sign,
  verify,
  sha256,
  sha512
} = cryptoImpl;
