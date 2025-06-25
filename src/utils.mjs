const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/**
 * Encode a byte array into base32 (RFC 4648, lowercase, no padding)
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function base32Encode(bytes) {
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;

        while (bits >= 5) {
            output += ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }

    if (bits > 0) {
        output += ALPHABET[(value << (5 - bits)) & 31];
    }

    return output;
}

/**
 * Decode a base32 string (RFC 4648, lowercase, no padding) into a byte array
 * @param {string} str
 * @returns {Uint8Array}
 */
export function base32Decode(str) {
    const clean = str.toLowerCase().replace(/=+$/, '');
    let bits = 0;
    let value = 0;
    const output = [];

    for (let i = 0; i < clean.length; i++) {
        const idx = ALPHABET.indexOf(clean[i]);
        if (idx === -1) throw new Error(`Invalid base32 character: ${clean[i]}`);
        value = (value << 5) | idx;
        bits += 5;

        if (bits >= 8) {
            output.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }

    return new Uint8Array(output);
}

export function toBase64(input) {
    if (typeof input === 'string') {
        // Assume it's already base64 (classic or url-safe) — return as-is
        return input;
    }

    if (!(input instanceof Uint8Array)) {
        throw new Error('Expected Uint8Array or base64 string');
    }

    if (typeof window === 'undefined') {
        // Node.js
        return Buffer.from(input).toString('base64');
    } else {
        // Browser
        return btoa(String.fromCharCode(...input));
    }
}

export function fromBase64(input) {
    if (typeof input !== 'string') {
        throw new Error('Expected base64-encoded string');
    }

    if (typeof window === 'undefined') {
        // Node.js
        return new Uint8Array(Buffer.from(input, 'base64'));
    } else {
        // Browser
        const binaryStr = atob(input);
        const len = binaryStr.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryStr.charCodeAt(i);
        }
        return bytes;
    }
}
