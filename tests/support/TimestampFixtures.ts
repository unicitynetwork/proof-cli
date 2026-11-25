import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import type { IPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/IPredicate.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import type { IMintOptions } from '@unicitylabs/state-transition-sdk/lib/transaction/IMintOptions.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';

import { TestAggregatorClient } from './TestAggregatorClient.js';
import { TIMESTAMP_RECIPIENT, TIMESTAMP_TOKEN_TYPE } from '../../src/lib/constants.js';
import { certifyMintTransaction, stampWith } from '../../src/lib/TimestampClient.js';
import { createVerificationContext } from '../../src/lib/verification.js';

/**
 * Mint through the in-memory aggregator and return the certified genesis,
 * without running the token-level verification. Lets tests build genesis
 * transactions that the issuance verifier must reject.
 */
export async function certifyMint(
  aggregator: TestAggregatorClient,
  recipient: IPredicate = TIMESTAMP_RECIPIENT,
  options: IMintOptions = {},
): Promise<CertifiedMintTransaction> {
  const transaction = await MintTransaction.create(NetworkId.LOCAL, recipient, {
    tokenType: TIMESTAMP_TOKEN_TYPE,
    ...options,
  });
  return certifyMintTransaction(
    new StateTransitionClient(aggregator),
    createVerificationContext(aggregator.rootTrustBase),
    transaction,
    { pollIntervalMs: 10 },
  );
}

/**
 * Stamp `digest` anonymously through `aggregator`, as `stamp` would, and return
 * the verified token.
 */
export function createTimestampToken(aggregator: TestAggregatorClient, digest: Uint8Array): Promise<Token> {
  return stampWith(new StateTransitionClient(aggregator), aggregator.rootTrustBase, digest, {
    pollIntervalMs: 10,
    timeoutMs: 2_000,
  });
}
