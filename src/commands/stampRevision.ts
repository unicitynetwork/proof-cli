import { lstat, stat } from 'node:fs/promises';

import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { CertifiedTransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedTransferTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { ICommandContext } from './context.js';
import { IDurableFileSystem, NODE_FILE_SYSTEM, writeFileDurably } from './durableFile.js';
import {
  hasErrorCode,
  IPendingRevision,
  journalPath,
  journalStanding,
  pendingRevision,
  readJournal,
  removeJournal,
  writeJournal,
} from './revisionJournal.js';
import { decodeToken, tokenBytesFromInput } from './tokenInput.js';
import { IStampRevisionConfig, IStampRevisionFlags, resolveStampRevisionConfig } from '../config.js';
import { CliError, EXIT_OK, EXIT_VERIFICATION_FAILED, usageError } from '../errors.js';
import { errorMessage, StampError } from '../lib/errors.js';
import {
  assertValidLineage,
  certifyRevision,
  createOrRecoverLineage,
  currentProducerKey,
  findSuccessor,
  isSameRevision,
  LineageError,
  prepareRevision,
  recoverRevision,
  SuccessorLookup,
} from '../lib/LineageClient.js';
import { networkNameForId } from '../lib/networks.js';
import { ICertifyOptions } from '../lib/TimestampClient.js';
import {
  existingLineageNote,
  networkLabel,
  PendingRevisionContext,
  pendingRevisionLines,
  recoveredRevisionLine,
  revisionJson,
  revisionRecoveryLines,
  revisionText,
  supersededLineageMessage,
  toJsonLine,
  warningLine,
} from '../output.js';

/**
 * Explain an exclusive create of a new lineage's token file that found something
 * in the way: a file that appeared since the checks, or a symlink to a missing
 * file (which looked absent to them). The genesis is certified either way, and the
 * same command recovers it, so say where it can be run again.
 *
 * @param {string} tokenFile Absolute token file path.
 * @param {unknown} cause The EEXIST.
 * @returns {Promise<Error>} A usage error.
 */
async function tokenFileInTheWay(tokenFile: string, cause: unknown): Promise<Error> {
  const dangling =
    (await lstat(tokenFile).then(
      (stats) => stats.isSymbolicLink(),
      () => false,
    )) &&
    (await stat(tokenFile).then(
      () => false,
      () => true,
    ));
  const certified = 'The new lineage is certified; running the same command again recovers it';
  return usageError(
    dangling
      ? `${tokenFile} is a symlink to a missing file, so the new lineage was not written. ${certified}: ` +
          'pass --force to create the file the symlink points to, or use another --token-file.'
      : `${tokenFile} appeared while the new lineage was being certified, and was not overwritten. ${certified} ` +
          'with another --token-file.',
    { cause },
  );
}

/**
 * Persist a lineage token whose newest revision has already been certified, with
 * {@link writeFileDurably}: the token file never holds a partial token, a
 * replaced one keeps its mode, and once this returns the write survives a power
 * loss. The file is the only copy of every revision's transaction, so an append
 * writes through a symlink at the path rather than replacing the symlink: a link
 * into a shared folder keeps working.
 *
 * A new lineage is linked into place, so a file that appeared since the checks is
 * never clobbered, nor a symlink to a missing file written through, unless
 * `--force`, which replaces the one and writes through the other. Whatever goes
 * wrong, the full token is printed as hex before the error propagates.
 *
 * @param {string} tokenFile Absolute token file path.
 * @param {Uint8Array} bytes Encoded token.
 * @param {boolean} created Whether this is a new lineage.
 * @param {ICommandContext} context Streams.
 * @param {boolean} [force] For a new lineage, overwrite whatever is at the path, or write through a symlink.
 * @param {IDurableFileSystem} [fs] File operations, for tests.
 */
export async function writeRevisionToken(
  tokenFile: string,
  bytes: Uint8Array,
  created: boolean,
  context: ICommandContext,
  force = false,
  fs: IDurableFileSystem = NODE_FILE_SYSTEM,
): Promise<void> {
  const exclusive = created && !force;
  try {
    await writeFileDurably(
      tokenFile,
      bytes,
      { followSymlinks: !exclusive, publish: exclusive ? 'create' : 'replace' },
      fs,
    );
  } catch (error) {
    // First, before anything awaited, so nothing can get between the error and the recovered bytes.
    context.stderr.write(revisionRecoveryLines(bytes));
    if (exclusive && hasErrorCode(error, 'EEXIST')) {
      throw await tokenFileInTheWay(tokenFile, error);
    }
    throw error;
  }
}

function writePending(
  context: ICommandContext,
  pending: IPendingRevision,
  journalFile: string,
  why: PendingRevisionContext,
): void {
  context.stderr.write(pendingRevisionLines({ ...pending, journalFile }, why));
}

/**
 * The lineage passes to someone after a recovered revision; say who.
 *
 * @param {Token} token Token ending in the recovered revision.
 * @returns {string} Where the lineage stands now.
 */
function standingAfter(token: Token): string {
  const next = currentProducerKey(token);
  return next === null ? 'the lineage is now finalized' : `the lineage now passes to ${HexConverter.encode(next)}`;
}

/**
 * A revision from an earlier run was recovered, but it is not the one asked for:
 * the token file now holds it, and the requested revision was not appended.
 *
 * @param {bigint} revision Index of the recovered revision.
 * @param {Token} token Token ending in it.
 * @param {string} tokenFile Where it was written.
 * @returns {LineageError} The error to throw.
 */
function recoveredOtherRevision(revision: bigint, token: Token, tokenFile: string): LineageError {
  return new LineageError(
    `Revision ${revision} of this lineage was already certified with different content by an earlier ` +
      `interrupted run. It was recovered and written to ${tokenFile}; the requested revision was not appended, ` +
      `and ${standingAfter(token)}.`,
    'ALREADY_CERTIFIED',
  );
}

/** What an append produced. */
interface IAppendOutcome {
  /** True when an earlier run had certified the revision, and this run recovered it. */
  readonly recovered: boolean;
  /** Key that signed the appended transfer. */
  readonly signer: Uint8Array;
  readonly token: Token;
}

/**
 * Append the requested revision, journaling it first, so that a run interrupted
 * after certification can be recovered by the next one.
 *
 * - A journal left by an earlier run is dealt with first. If its revision was
 *   certified, it is written to the token file; if it was not, the journal is
 *   dropped, but kept in memory in case it is certified while this run is going.
 * - The requested revision is then journaled, echoed to stderr unless `--quiet`,
 *   submitted, written to the token file, and the journal removed.
 * - If its slot turns out to be taken (`ALREADY_CERTIFIED`), the journal is
 *   removed, since it was never certified, and the revision is echoed whatever
 *   `--quiet` says, so the user can see what this run tried.
 *
 * @param {IStampRevisionConfig} config Resolved configuration.
 * @param {StateTransitionClient} client Aggregator client.
 * @param {ICommandContext} context Streams.
 * @param {ICertifyOptions} options Certification options.
 * @param {Token} token The token file's lineage.
 * @returns {Promise<IAppendOutcome>} The appended token.
 */
async function appendJournaled(
  config: IStampRevisionConfig,
  client: StateTransitionClient,
  context: ICommandContext,
  options: ICertifyOptions,
  token: Token,
): Promise<IAppendOutcome> {
  const trustBase = config.network.trustBase;
  const journalFile = journalPath(config.tokenFile);
  // Before the journal is acted on, in either direction.
  await assertValidLineage(token, trustBase);

  // A recovered revision is written and its journal removed, and then either it was
  // the revision asked for, or the request cannot go ahead.
  const settle = async (
    pending: IPendingRevision,
    recovered: Token,
    transaction: TransferTransaction,
  ): Promise<IAppendOutcome> => {
    await writeRevisionToken(config.tokenFile, recovered.toCBOR(), false, context);
    await removeJournal(journalFile);
    if (await isSameRevision(transaction, pending.revision, config.digest, config.recipientKey)) {
      context.stderr.write(recoveredRevisionLine(pending.revision, journalFile));
      return { recovered: true, signer: currentProducerKey(token) as Uint8Array, token: recovered };
    }
    writePending(context, pending, journalFile, 'recovered');
    throw recoveredOtherRevision(pending.revision, recovered, config.tokenFile);
  };

  let unconfirmed: { pending: IPendingRevision; transaction: TransferTransaction } | null = null;
  const earlier = await readJournal(journalFile);
  if (earlier !== null) {
    const standing = await journalStanding(journalFile, earlier, token, config.tokenFile);
    if (standing.kind === 'next') {
      let recovered: Token | null = null;
      try {
        recovered = await recoverRevision(client, trustBase, token, standing.transaction, options);
      } catch (error) {
        // Its slot holds another transfer: the journaled one was never certified.
        if (!(error instanceof LineageError && error.code === 'ALREADY_CERTIFIED')) {
          throw error;
        }
      }
      if (recovered !== null) {
        return settle(earlier, recovered, standing.transaction);
      }
      unconfirmed = { pending: earlier, transaction: standing.transaction };
    }
    await removeJournal(journalFile);
  }

  const prepared = await prepareRevision(token, trustBase, config.digest, config.privateKey, config.recipientKey);
  const pending = pendingRevision(token, prepared, config.digest, config.recipientKey);
  await writeJournal(journalFile, pending);
  if (!config.quiet) {
    writePending(context, pending, journalFile, 'submitting');
  }

  let appended: Token;
  let replayed = false;
  try {
    appended = await certifyRevision(client, trustBase, token, prepared, {
      ...options,
      onAlreadyCertified: (): void => {
        replayed = true;
      },
    });
  } catch (error) {
    if (error instanceof StampError) {
      // Refused outright: nothing was certified.
      await removeJournal(journalFile);
    } else if (error instanceof LineageError && error.code === 'ALREADY_CERTIFIED') {
      await removeJournal(journalFile);
      writePending(context, pending, journalFile, 'rejected');
      if (unconfirmed !== null) {
        // The earlier run's revision was still waiting for its round when this run looked.
        const recovered = await recoverRevision(client, trustBase, token, unconfirmed.transaction, options).catch(
          () => null,
        );
        if (recovered !== null) {
          return settle(unconfirmed.pending, recovered, unconfirmed.transaction);
        }
      }
    }
    throw error;
  }

  await writeRevisionToken(config.tokenFile, appended.toCBOR(), false, context);
  await removeJournal(journalFile);
  return { recovered: replayed, signer: new SigningService(config.privateKey).publicKey, token: appended };
}

/**
 * Refuse to hand out a recovered genesis whose lineage has moved on: a file with
 * only revision 0 would be out of date, yet look like a fresh lineage. When the
 * aggregator cannot be asked, or shows a proof that does not verify, the genesis
 * is written anyway, with a warning: it is certified and correct, and losing a
 * good recovery over a secondary check would be worse.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the token's network.
 * @param {Token} token The recovered genesis.
 * @param {ICommandContext} context Streams and interrupt signal.
 * @throws {LineageError} `SUPERSEDED` if the aggregator proves a later revision exists.
 */
async function assertNotSuperseded(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  token: Token,
  context: ICommandContext,
): Promise<void> {
  let lookup: SuccessorLookup;
  try {
    lookup = await findSuccessor(client, trustBase, token, context.interrupt);
  } catch (error) {
    context.stderr.write(
      warningLine(`Could not check whether the lineage has later revisions: ${errorMessage(error)}`),
    );
    return;
  }
  if (lookup.kind === 'spent') {
    throw new LineageError(
      supersededLineageMessage(token.id.bytes, lookup.proof.referenceTime, currentProducerKey(token)),
      'SUPERSEDED',
    );
  }
  if (lookup.kind === 'unverified') {
    context.stderr.write(
      warningLine(
        'The gateway showed a proof of a later revision that does not verify; could not check whether the ' +
          'lineage has moved on.',
      ),
    );
  }
}

function latestCertified(token: Token): CertifiedMintTransaction | CertifiedTransferTransaction {
  return token.transactions.at(-1) ?? token.genesis;
}

/**
 * Say what to change when the token file is from another network than the one
 * this run is set to. Not inferred from the token: the network also picks the
 * gateway the API key is sent to, so the user chooses it, as for a genesis.
 *
 * @param {string} tokenFile Token file path, for the message.
 * @param {number} tokenNetworkId Network id the token carries.
 * @param {number} configuredNetworkId Network id of the configured trust base.
 * @param {string|null} trustBasePath The configured trust base file, or null for a bundled one.
 * @returns {Error|null} A usage error, or null when the networks agree.
 */
export function networkMismatch(
  tokenFile: string,
  tokenNetworkId: number,
  configuredNetworkId: number,
  trustBasePath: string | null,
): Error | null {
  if (tokenNetworkId === configuredNetworkId) {
    return null;
  }
  const bundled = networkNameForId(tokenNetworkId);
  const lineage =
    bundled === undefined
      ? `${tokenFile} is a lineage on network ${tokenNetworkId}, which has no bundled trust base`
      : `${tokenFile} is a ${networkLabel(tokenNetworkId)} lineage`;
  const configured =
    trustBasePath === null
      ? `this run is set to ${networkLabel(configuredNetworkId)}`
      : `the trust base ${trustBasePath} is for ${networkLabel(configuredNetworkId)}`;
  let advice: string;
  if (bundled === undefined) {
    advice =
      trustBasePath === null
        ? "Pass --trust-base with that network's trust base, and --gateway with its gateway."
        : "Pass --trust-base with that network's trust base instead.";
  } else {
    advice =
      trustBasePath === null
        ? `Pass --network ${bundled}, or set UNICITY_NETWORK=${bundled}.`
        : `Pass a trust base for ${bundled}, or drop the trust base (--trust-base or UNICITY_TRUST_BASE) ` +
          `and pass --network ${bundled}.`;
  }
  return usageError(`${lineage}, but ${configured}. ${advice} Nothing was submitted.`);
}

/**
 * The part of `stamp-revision` after configuration: certify, write, report. Takes
 * the client as a parameter so it can run against an in-memory aggregator.
 *
 * @param {IStampRevisionConfig} config Resolved configuration.
 * @param {StateTransitionClient} client Aggregator client for `config.network`.
 * @param {ICommandContext} context Streams and interrupt signal.
 * @returns {Promise<number>} Exit code.
 */
export async function stampRevisionWith(
  config: IStampRevisionConfig,
  client: StateTransitionClient,
  context: ICommandContext,
): Promise<number> {
  const trustBase = config.network.trustBase;
  const options = {
    onWarning: (message: string): void => {
      context.stderr.write(warningLine(message));
    },
    signal: context.interrupt,
    timeoutMs: config.timeoutMs,
  };

  let token: Token;
  let signer = new SigningService(config.privateKey).publicKey;
  let recovered: boolean;
  const created = config.tokenBytes === null;
  if (config.tokenBytes === null) {
    ({ recovered, token } = await createOrRecoverLineage(
      client,
      trustBase,
      config.digest,
      config.privateKey,
      config.recipientKey,
      options,
    ));
    if (recovered) {
      await assertNotSuperseded(client, trustBase, token, context);
    }
    await writeRevisionToken(config.tokenFile, token.toCBOR(), true, context, config.force);
    if (recovered) {
      // Not subject to --quiet: without it, two files can pass for two lineages.
      context.stderr.write(existingLineageNote(token.id.bytes));
    }
  } else {
    const decoded = await decodeToken(tokenBytesFromInput(config.tokenBytes));
    if (decoded.token === null) {
      throw new CliError(
        `${config.tokenFile} is ${decoded.error}. If an earlier stamp-revision run failed while creating a new ` +
          'lineage, move this file away and run the same command again: the lineage is recovered.',
        EXIT_VERIFICATION_FAILED,
      );
    }
    // Before the journal is read: a journal is only acted on against the right network.
    const mismatch = networkMismatch(
      config.tokenFile,
      decoded.token.networkId.id,
      trustBase.networkId.id,
      config.trustBasePath,
    );
    if (mismatch !== null) {
      throw mismatch;
    }
    ({ recovered, signer, token } = await appendJournaled(config, client, context, options, decoded.token));
  }

  const latest = latestCertified(token);
  const certificate = latest.inclusionProof.unicityCertificate;
  const summary = {
    created,
    digest: config.digest,
    epoch: certificate.unicitySeal.epoch,
    gatewayUrl: config.network.gatewayUrl,
    networkId: token.networkId.id,
    nextProducer: config.recipientKey,
    recovered,
    referenceTime: latest.referenceTime,
    revision: BigInt(token.transactions.length),
    roundNumber: certificate.inputRecord.roundNumber,
    roundTimestamp: certificate.inputRecord.timestamp,
    signer,
    tokenFile: config.tokenFile,
    tokenId: token.id.bytes,
  };
  context.stdout.write(context.json ? toJsonLine(revisionJson(summary)) : `${revisionText(summary)}\n`);
  return EXIT_OK;
}

/**
 * `stamp-revision`: create a document lineage token for an initial revision, or
 * append the next revision to an existing one.
 *
 * @param {string} [digestArgument] Positional digest.
 * @param {IStampRevisionFlags} flags Command flags.
 * @param {ICommandContext} context Streams and interrupt signal.
 * @returns {Promise<number>} Exit code.
 */
export async function runStampRevision(
  digestArgument: string | undefined,
  flags: IStampRevisionFlags,
  context: ICommandContext,
): Promise<number> {
  const config = await resolveStampRevisionConfig(digestArgument, flags);
  const client = new StateTransitionClient(
    new AggregatorClient(config.network.gatewayUrl, config.apiKey, config.allowInsecure),
  );
  return stampRevisionWith(config, client, context);
}
