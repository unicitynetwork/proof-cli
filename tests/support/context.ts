import { ICommandContext } from '../../src/commands/context.js';
import { IWriter } from '../../src/output.js';

export interface ITestContext {
  readonly context: ICommandContext;
  /** What the command put on stdout, parsed as the one object `--json` promises. */
  json(): Record<string, unknown>;
  stderr(): string;
  stdout(): string;
}

function sink(chunks: string[]): IWriter {
  return {
    write(chunk: string | Uint8Array): boolean {
      chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
      return true;
    },
  };
}

/**
 * A command context that keeps both streams in memory, so a test can run a
 * command the way the entry point does and then read what it wrote.
 *
 * @param {object} options Context options.
 * @param {boolean} [options.json] Whether the command should emit JSON.
 * @returns {ITestContext} The context and accessors for what it captured.
 */
export function testContext({ json = false }: { json?: boolean } = {}): ITestContext {
  const out: string[] = [];
  const error: string[] = [];
  return {
    context: {
      interrupt: new AbortController().signal,
      json,
      stderr: sink(error),
      stdin: process.stdin,
      stdout: sink(out),
    },
    json: (): Record<string, unknown> => JSON.parse(out.join('')) as Record<string, unknown>,
    stderr: (): string => error.join(''),
    stdout: (): string => out.join(''),
  };
}
