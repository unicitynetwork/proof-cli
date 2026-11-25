import { readFile } from 'node:fs/promises';
import { buffer } from 'node:stream/consumers';

import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { ICommandContext } from './context.js';
import { EXIT_VERIFICATION_FAILED } from '../errors.js';
import { errorMessage } from '../lib/errors.js';
import { notATokenJson, notATokenText, toJsonLine } from '../output.js';

const HEX_TEXT = /^[0-9a-fA-F\s]+$/;

/**
 * Read a token from a file or stdin (`-`). Hex text is accepted as well as raw CBOR.
 *
 * @param {string} file Path, or `-`.
 * @param {NodeJS.ReadableStream} stdin Standard input.
 * @returns {Promise<Uint8Array>} Token bytes.
 */
export async function readTokenInput(file: string, stdin: NodeJS.ReadableStream): Promise<Uint8Array> {
  return tokenBytesFromInput(new Uint8Array(file === '-' ? await buffer(stdin) : await readFile(file)));
}

/**
 * Turn the contents of a token file into token bytes: hex text is decoded, anything else is taken as raw CBOR.
 *
 * @param {Uint8Array} bytes File contents.
 * @returns {Uint8Array} Token bytes.
 */
export function tokenBytesFromInput(bytes: Uint8Array): Uint8Array {
  const text = new TextDecoder('latin1').decode(bytes);
  if (text.trim() !== '' && HEX_TEXT.test(text)) {
    const compact = text.replace(/\s+/g, '');
    if (compact.length % 2 === 0) {
      return HexConverter.decode(compact);
    }
  }
  return bytes;
}

export type DecodedToken =
  { readonly error: string; readonly token: null } | { readonly error: null; readonly token: Token };

/**
 * Decode token bytes, turning the SDK's decoding errors into a message instead of an exception.
 *
 * @param {Uint8Array} bytes Token bytes.
 * @returns {Promise<DecodedToken>} Token, or why it is not one.
 */
export async function decodeToken(bytes: Uint8Array): Promise<DecodedToken> {
  try {
    return { error: null, token: await Token.fromCBOR(bytes) };
  } catch (error) {
    return { error: `not a token (${errorMessage(error)})`, token: null };
  }
}

/**
 * Report input that is not a token, in the command's output format.
 *
 * @param {ICommandContext} context Streams.
 * @param {string} command Command name for the JSON envelope.
 * @param {string} reason Decoder message.
 * @returns {number} Exit code.
 */
export function reportNotAToken(context: ICommandContext, command: string, reason: string): number {
  context.stdout.write(context.json ? toJsonLine(notATokenJson(command, reason)) : `${notATokenText(reason)}\n`);
  return EXIT_VERIFICATION_FAILED;
}
