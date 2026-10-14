import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

/** sha256("hello"): the digest used throughout the tests and the README. */
export const TEST_DIGEST_HEX = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
export const TEST_DIGEST = HexConverter.decode(TEST_DIGEST_HEX);
/** sha256("test"), for mismatch cases. */
export const OTHER_DIGEST_HEX = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
export const OTHER_DIGEST = HexConverter.decode(OTHER_DIGEST_HEX);

/** Fixed secp256k1 test key and its compressed public key. */
export const TEST_PRIVATE_KEY_HEX = '01'.repeat(32);
export const TEST_PRIVATE_KEY = HexConverter.decode(TEST_PRIVATE_KEY_HEX);
export const TEST_PUBLIC_KEY_HEX = '031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f';

const handedOut: string[] = [];

/** Fresh temporary directory under the OS temp root, removed when the file finishes. */
export async function tempDir(prefix = 'proof-cli-'): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), prefix));
  handedOut.push(directory);
  return directory;
}

export async function removeTempDirs(): Promise<void> {
  await Promise.all(handedOut.splice(0).map((directory) => rm(directory, { force: true, recursive: true })));
}
