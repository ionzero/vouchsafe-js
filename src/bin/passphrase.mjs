import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

function removeTrailingLineEnding(value) {
  return value.endsWith('\r\n') ? value.slice(0, -2) : value.endsWith('\n') ? value.slice(0, -1) : value;
}

async function askTerminal(prompt) {
  if (!process.stdin.isTTY) {
    throw new Error('A passphrase is required; use --passphrase-file or set VOUCHSAFE_ASKPASS');
  }
  process.stderr.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let value = '';
    const finish = () => {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stderr.write('\n');
      resolve(value);
    };
    const onData = chunk => {
      for (const character of chunk.toString('utf8')) {
        if (character === '\r' || character === '\n') return finish();
        if (character === '\u0003') {
          process.stdin.off('data', onData);
          process.stdin.setRawMode(false);
          process.stdin.pause();
          return reject(new Error('Passphrase entry cancelled'));
        }
        if (character === '\u007f' || character === '\b') {
          value = Array.from(value).slice(0, -1).join('');
        } else {
          value += character;
        }
      }
    };
    process.stdin.on('data', onData);
  });
}

/** Obtain a passphrase using the SSH_ASKPASS-compatible prompt protocol. */
export async function getPassphrase({ passphraseFile, prompt }) {
  if (passphraseFile) return removeTrailingLineEnding(await readFile(passphraseFile, 'utf8'));
  if (process.env.VOUCHSAFE_ASKPASS) {
    try {
      const { stdout } = await execFileAsync(process.env.VOUCHSAFE_ASKPASS, [prompt], { encoding: 'utf8' });
      return removeTrailingLineEnding(stdout);
    } catch {
      throw new Error('VOUCHSAFE_ASKPASS failed to provide a passphrase');
    }
  }
  return askTerminal(prompt);
}

export async function getNewIdentityPassphrase(options) {
  if (options.createUnencryptedIdentityFile) {
    if (options.passphraseFile) throw new Error('--create-unencrypted-identity-file cannot be used with --passphrase-file');
    return '';
  }
  if (options.passphraseFile) {
    const passphrase = await getPassphrase({ passphraseFile: options.passphraseFile, prompt: '' });
    if (passphrase.length === 0) throw new Error('An empty passphrase requires --create-unencrypted-identity-file');
    return passphrase;
  }
  const passphrase = await getPassphrase({ prompt: 'Enter passphrase for new identity (empty for no passphrase): ' });
  const confirmation = await getPassphrase({ prompt: 'Enter same passphrase again: ' });
  if (passphrase !== confirmation) throw new Error('Passphrases do not match');
  if (passphrase.length === 0) throw new Error('An empty passphrase requires --create-unencrypted-identity-file');
  return passphrase;
}
