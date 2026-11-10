import { randomBytes } from 'node:crypto';
import { rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { CertifiedTransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedTransferTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';

import { ICommandContext } from './context.js';
import { decodeToken, tokenBytesFromInput } from './tokenInput.js';
import { IStampRevisionConfig, IStampRevisionFlags, resolveStampRevisionConfig } from '../config.js';
import { CliError, EXIT_OK, EXIT_VERIFICATION_FAILED } from '../errors.js';
import { appendRevision, createLineage } from '../lib/LineageClient.js';
import { revisionJson, revisionRecoveryLines, revisionText, toJsonLine, warningLine } from '../output.js';

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
  const created = config.tokenBytes === null;
  if (config.tokenBytes === null) {
    token = await createLineage(client, trustBase, config.digest, config.privateKey, config.recipientKey, options);
  } else {
    const decoded = await decodeToken(tokenBytesFromInput(config.tokenBytes));
    if (decoded.token === null) {
      throw new CliError(`${config.tokenFile} is ${decoded.error}.`, EXIT_VERIFICATION_FAILED);
    }
    token = await appendRevision(
      client,
      trustBase,
      decoded.token,
      config.digest,
      config.privateKey,
      config.recipientKey,
      options,
    );
  }

  const bytes = token.toCBOR();
  await writeRevisionToken(config.tokenFile, bytes, created, context);

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
    signer: new SigningService(config.privateKey).publicKey,
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
