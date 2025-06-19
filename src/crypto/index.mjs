// crypto/index.mjs
import * as nodeImpl from './node.mjs';
import * as browserImpl from './browser.mjs';

const isNode =
  typeof process !== 'undefined' &&
  process.versions?.node &&
  typeof window === 'undefined';

const cryptoImpl = isNode ? nodeImpl : browserImpl;

export const {
  generateKeyPair,
  sign,
  verify,
  sha256,
  sha512,
  getKeyBytes
} = cryptoImpl;
