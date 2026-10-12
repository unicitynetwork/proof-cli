#!/usr/bin/env node
import { Command, CommanderError } from 'commander';

import { ICommandContext } from './commands/context.js';
import { runInspect } from './commands/inspect.js';
import { IKeygenFlags, runKeygen } from './commands/keygen.js';
import { runStamp } from './commands/stamp.js';
import { IVerifyFlags, runVerify } from './commands/verify.js';
import { IStampFlags, loadEnvironment } from './config.js';
import { describeError, EXIT_USAGE, toExitCode } from './errors.js';
import { warningLine } from './output.js';
import { VERSION } from './version.js';

interface IGlobalFlags {
  readonly dotenv?: string;
  readonly json?: boolean;
}

const controller = new AbortController();
process.once('SIGINT', () => {
  controller.abort(new Error('Interrupted.'));
});

const program = new Command();
program
  .name('unicity-timestamp')
  .description('Timestamp a SHA-256 hash on the Unicity Network and verify the resulting token offline.')
  .version(VERSION)
  .option('--json', 'machine-readable output on stdout; everything else goes to stderr')
  .option('--dotenv <path>', 'load this env file instead of ./.env')
  .exitOverride()
  .hook('preAction', () => {
    const loaded = loadEnvironment(program.opts<IGlobalFlags>().dotenv);
    if (loaded.refusedTrustBasePath !== undefined) {
      // Said out loud rather than dropped quietly: whoever put it there needs to
      // know why it had no effect, and anyone else needs to know it was tried.
      process.stderr.write(
        warningLine(
          `ignored UNICITY_TRUST_BASE=${loaded.refusedTrustBasePath} from ./.env; the root of trust is not ` +
            'taken from an env file found in the working directory. Pass --trust-base, or --dotenv to opt in.',
        ),
      );
    }
  });

function context(): ICommandContext {
  return {
    interrupt: controller.signal,
    json: program.opts<IGlobalFlags>().json ?? false,
    stderr: process.stderr,
    stdin: process.stdin,
    stdout: process.stdout,
  };
}

program
  .command('stamp')
  .description('certify a SHA-256 digest on the network and write the token')
  .argument('[sha256-hex]', 'digest to stamp; alternatively use --file')
  .option('--file <path>', 'hash this file locally instead of passing a digest')
  .option('--key-file <path>', 'sign with this secp256k1 private key (64 hex); or UNICITY_PRIVATE_KEY')
  .option('--anonymous', 'unsigned stamp even when a key is configured')
  .option('--sign', 'fail unless a key is configured')
  .option('--out <file>', 'output path; default token_<first 16 hex of digest>.cbor; "-" writes the token to stdout')
  .option('--force', 'overwrite the output file')
  .option('--network <name>', 'mainnet or testnet2; or UNICITY_NETWORK (default mainnet)')
  .option('--gateway <url>', 'override the gateway URL; or UNICITY_GATEWAY_URL')
  .option('--api-key <key>', 'gateway API key; or UNICITY_API_KEY')
  .option('--trust-base <path>', 'override the bundled trust base; or UNICITY_TRUST_BASE')
  .option('--timeout <seconds>', 'wait for the inclusion proof; or UNICITY_TIMEOUT (default 60)')
  .option('--allow-insecure', 'permit the API key over plain HTTP (local development only)')
  .action(async (digest: string | undefined, flags: IStampFlags) => {
    process.exitCode = await runStamp(digest, flags, context());
  });

program
  .command('verify')
  .description('verify a timestamp token offline and print what it proves')
  .argument('<token-file>', 'token file, or "-" for stdin; raw CBOR or hex text')
  .option('--hash <sha256-hex>', 'assert the token is for this digest')
  .option('--file <path>', 'assert the token is for this file, hashed locally')
  .option('--network <name>', "use this network's bundled trust base instead of the one matching the token")
  .option('--trust-base <path>', 'use this trust base file; or UNICITY_TRUST_BASE')
  .action(async (file: string, flags: IVerifyFlags) => {
    process.exitCode = await runVerify(file, flags, context());
  });

program
  .command('inspect')
  .description('decode a token and print its fields without verifying anything')
  .argument('<token-file>', 'token file, or "-" for stdin; raw CBOR or hex text')
  .action(async (file: string) => {
    process.exitCode = await runInspect(file, context());
  });

program
  .command('keygen')
  .description('generate a secp256k1 private key for signed stamps')
  .option('--out <path>', 'key file; default unicity-timestamp.key; "-" prints the key to stdout')
  .option('--force', 'overwrite the key file')
  .action(async (flags: IKeygenFlags) => {
    process.exitCode = await runKeygen(flags, context());
  });

async function main(): Promise<void> {
  try {
    await program.parseAsync(process.argv);
  } catch (error) {
    if (error instanceof CommanderError) {
      // Commander has already printed help, the version, or the usage message.
      process.exitCode = error.exitCode === 0 ? 0 : EXIT_USAGE;
      return;
    }
    process.stderr.write(`${describeError(error)}\n`);
    process.exitCode = toExitCode(error, controller.signal.aborted);
  }
}

void main();
