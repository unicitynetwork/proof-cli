import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import {
  CertificationResponse,
  CertificationStatus,
} from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import type { IAggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/IAggregatorClient.js';
import { InclusionProofResponse } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProofResponse.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { SleepError } from '@unicitylabs/state-transition-sdk/lib/util/InclusionProofUtils.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { StampError } from '../../../src/lib/errors.js';
import { bundledTrustBase } from '../../../src/lib/networks.js';
import { describeToken, stampWith, verificationFailure, verify } from '../../../src/lib/TimestampClient.js';
import { OTHER_DIGEST, TEST_DIGEST, TEST_DIGEST_HEX } from '../../support/fixtures.js';
import { TestAggregatorClient } from '../../support/TestAggregatorClient.js';

type Submit = (data: CertificationData, inner: TestAggregatorClient) => Promise<CertificationResponse>;

/** Serves proofs from the in-memory aggregator but lets a test script the certification response. */
class ScriptedSubmitClient implements IAggregatorClient {
  public constructor(
    private readonly inner: TestAggregatorClient,
    private readonly submit: Submit,
  ) {}

  public getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    return this.inner.getInclusionProof(stateId);
  }

  public submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    return this.submit(certificationData, this.inner);
  }
}

describe('TimestampClient', () => {
  const aggregator = TestAggregatorClient.create();
  const client = new StateTransitionClient(aggregator);
  const trustBase = aggregator.rootTrustBase;
  const fast = { pollIntervalMs: 10, timeoutMs: 2_000 };
  const scripted = (submit: Submit): StateTransitionClient =>
    new StateTransitionClient(new ScriptedSubmitClient(aggregator, submit));
  /** Accepts every request but never certifies it, so no proof ever appears. */
  const silent = scripted(() => Promise.resolve(CertificationResponse.create(CertificationStatus.SUCCESS)));

  it('stamps anonymously and verifies the token offline', async () => {
    const token = await stampWith(client, trustBase, TEST_DIGEST, fast);
    const description = describeToken(token);
    expect(description.payload?.isSigned).toBe(false);
    expect(HexConverter.encode(description.payload!.digest)).toEqual(TEST_DIGEST_HEX);
    expect(description.recipientIsTimestampBurn).toBe(true);
    expect(description.tokenTypeIsTimestamp).toBe(true);
    expect(description.transferCount).toBe(0);
    expect(description.referenceTime).toBeGreaterThan(0n);
    expect(description.roundTimestamp).toBeGreaterThanOrEqual(description.referenceTime);

    const result = await verify(await Token.fromCBOR(token.toCBOR()), trustBase);
    expect(result.status).toEqual('OK');
    expect(result.reason).toBeNull();
    expect(result.expectedDigestMatches).toBeNull();
    expect(result.details?.status).toEqual(VerificationStatus.OK);
  });

  it('stamps with a signer and reports the signer key', async () => {
    const signer = SigningService.generate();
    const token = await stampWith(client, trustBase, TEST_DIGEST, { ...fast, signer });
    const result = await verify(token, trustBase, { expectedDigest: TEST_DIGEST });
    expect(result.status).toEqual('OK');
    expect(result.expectedDigestMatches).toBe(true);
    expect(HexConverter.encode(result.payload!.signer!)).toEqual(HexConverter.encode(signer.publicKey));
  });

  it('fails verification on a hash mismatch while the token itself is valid', async () => {
    const token = await stampWith(client, trustBase, TEST_DIGEST, fast);
    const result = await verify(token, trustBase, { expectedDigest: OTHER_DIGEST });
    expect(result.status).toEqual('FAIL');
    expect(result.expectedDigestMatches).toBe(false);
    expect(result.reason).toEqual('Hash mismatch: the token certifies a different digest.');
    expect(result.details?.status).toEqual(VerificationStatus.OK);
  });

  it('explains a trust base from the wrong network', async () => {
    const token = await stampWith(client, trustBase, TEST_DIGEST, fast);
    const result = await verify(token, bundledTrustBase('mainnet'));
    expect(result.status).toEqual('FAIL');
    expect(result.reason).toEqual(
      'Mint network does not match trust base. The token is for network 3 and the trust base for network 1; select the matching network or trust base.',
    );
  });

  it('builds a failed result around a description', async () => {
    const token = await stampWith(client, trustBase, TEST_DIGEST, fast);
    const failure = verificationFailure(describeToken(token), 'because');
    expect(failure).toMatchObject({ details: null, expectedDigestMatches: null, reason: 'because', status: 'FAIL' });
    expect(failure.tokenId.equals(token.id)).toBe(true);
  });

  it('throws StampError on a known failure status', async () => {
    const refusing = scripted(() => Promise.resolve(CertificationResponse.create(CertificationStatus.REQUEST_EXPIRED)));
    await expect(stampWith(refusing, trustBase, TEST_DIGEST, fast)).rejects.toMatchObject({
      message: 'Aggregator rejected the certification request: REQUEST_EXPIRED',
      name: 'StampError',
      status: 'REQUEST_EXPIRED',
    });
    await expect(stampWith(refusing, trustBase, TEST_DIGEST, fast)).rejects.toBeInstanceOf(StampError);
  });

  it('warns on an unknown status and still completes when the proof appears', async () => {
    const warnings: string[] = [];
    const odd = scripted(async (data, inner) => {
      await inner.submitCertificationRequest(data);
      return CertificationResponse.create('SOMETHING_NEW');
    });
    const token = await stampWith(odd, trustBase, TEST_DIGEST, {
      ...fast,
      onWarning: (message) => warnings.push(message),
    });
    expect(warnings).toEqual([
      "Aggregator returned unknown status 'SOMETHING_NEW'; waiting for the inclusion proof anyway.",
    ]);
    expect((await verify(token, trustBase)).status).toEqual('OK');
  });

  it('times out with SleepError when the proof never arrives', async () => {
    await expect(stampWith(silent, trustBase, TEST_DIGEST, { pollIntervalMs: 10, timeoutMs: 100 })).rejects.toThrow(
      SleepError,
    );
  });

  it('stops when the caller aborts', async () => {
    const controller = new AbortController();
    const pending = stampWith(silent, trustBase, TEST_DIGEST, {
      pollIntervalMs: 10,
      signal: controller.signal,
      timeoutMs: 5_000,
    });
    setTimeout(() => controller.abort(new Error('user interrupt')), 30);
    await expect(pending).rejects.toThrow(SleepError);
  });
});
