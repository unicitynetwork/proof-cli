import { randomBytes } from 'node:crypto';
import { rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { CertifiedTransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedTransferTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { ICommandContext } from './context.js';
import {
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
import { CliError, EXIT_OK, EXIT_VERIFICATION_FAILED } from '../errors.js';
import { StampError } from '../lib/errors.js';
import {
  assertValidLineage,
  certifyRevision,
  createLineage,
  currentProducerKey,
  isSameRevision,
  LineageError,
  prepareRevision,
  recoverRevision,
} from '../lib/LineageClient.js';
import { ICertifyOptions } from '../lib/TimestampClient.js';
import {
  PendingRevisionContext,
  pendingRevisionLines,
  recoveredRevisionLine,
  revisionJson,
  revisionRecoveryLines,
  revisionText,
  toJsonLine,
  warningLine,
} from '../output.js';

/**
 * Persist a lineage token whose newest revision has already been certified.
 *
 * A new lineage is written with an exclusive create, so a file that appeared
 * since the checks is never clobbered. An existing lineage is replaced through a
 * temporary file and `rename`, so the previous version stays intact until the new
 * one is complete: truncating it in place and then failing would lose the whole
 * history, not just the new revision. Whatever goes wrong, the full token is
 * printed as hex before the error propagates.
 *
 * @param {string} tokenFile Absolute token file path.
 * @param {Uint8Array} bytes Encoded token.
 * @param {boolean} created Whether this is a new lineage.
 * @param {ICommandContext} context Streams.
 */
export async function writeRevisionToken(
  tokenFile: string,
  bytes: Uint8Array,
  created: boolean,
  context: ICommandContext,
): Promise<void> {
  const temporary = path.join(
    path.dirname(tokenFile),
    `.${path.basename(tokenFile)}.${randomBytes(8).toString('hex')}`,
  );
  try {
    if (created) {
      await writeFile(tokenFile, bytes, { flag: 'wx' });
    } else {
      await writeFile(temporary, bytes, { flag: 'wx' });
      await rename(temporary, tokenFile);
    }
  } catch (error) {
    // First, before anything awaited, so nothing can get between the error and the recovered bytes.
    context.stderr.write(revisionRecoveryLines(bytes));
    if (!created) {
      await rm(temporary, { force: true }).catch(() => undefined);
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
      return { signer: currentProducerKey(token) as Uint8Array, token: recovered };
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
  try {
    appended = await certifyRevision(client, trustBase, token, prepared, options);
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
  return { signer: new SigningService(config.privateKey).publicKey, token: appended };
}

function latestCertified(token: Token): CertifiedMintTransaction | CertifiedTransferTransaction {
  return token.transactions.at(-1) ?? token.genesis;
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
  const created = config.tokenBytes === null;
  if (config.tokenBytes === null) {
    token = await createLineage(client, trustBase, config.digest, config.privateKey, config.recipientKey, options);
    await writeRevisionToken(config.tokenFile, token.toCBOR(), true, context);
  } else {
    const decoded = await decodeToken(tokenBytesFromInput(config.tokenBytes));
    if (decoded.token === null) {
      throw new CliError(`${config.tokenFile} is ${decoded.error}.`, EXIT_VERIFICATION_FAILED);
    }
    ({ signer, token } = await appendJournaled(config, client, context, options, decoded.token));
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
