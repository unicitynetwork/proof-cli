import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import {
  CertificationResponse,
  CertificationStatus,
} from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import type { IAggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/IAggregatorClient.js';
import { InclusionCertificate } from '@unicitylabs/state-transition-sdk/lib/api/InclusionCertificate.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { InclusionProofResponse } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProofResponse.js';
import { calculateLeafValue } from '@unicitylabs/state-transition-sdk/lib/api/LeafValue.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { DataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasher.js';
import { DataHasherFactory } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasherFactory.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { PredicateVerifierService } from '@unicitylabs/state-transition-sdk/lib/predicate/verification/PredicateVerifierService.js';
import { SparseMerkleTree } from '@unicitylabs/state-transition-sdk/lib/smt/radix/SparseMerkleTree.js';
import { BitString } from '@unicitylabs/state-transition-sdk/lib/util/BitString.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { createRootTrustBase } from './RootTrustBaseFixture.js';
import { createUnicityCertificate } from './UnicityCertificateFixture.js';
import { STATE_ID_EXISTS_STATUS } from '../../src/lib/TimestampClient.js';

/** Lifetime granted to a request without its own deadline, matching the aggregator's default. */
const REQUEST_TTL = 3600n;

/**
 * In-memory aggregator: every accepted request becomes a leaf in a sparse
 * Merkle tree whose root is sealed by a single-node LOCAL trust base. Proofs
 * verify with the real SDK rules. Ported from the SDK's functional tests.
 */
export class TestAggregatorClient implements IAggregatorClient {
  public readonly rootTrustBase: RootTrustBase;
  private readonly predicateVerifier: PredicateVerifierService;
  private referenceTime: bigint = BigInt(Math.floor(Date.now() / 1000));
  private readonly requests: Map<bigint, { certificationData: CertificationData; referenceTime: bigint }> = new Map();

  private constructor(
    private readonly smt: SparseMerkleTree,
    private readonly signingService: SigningService,
  ) {
    this.rootTrustBase = createRootTrustBase(this.signingService.publicKey);
    this.predicateVerifier = PredicateVerifierService.create();
  }

  public static create(privateKey: Uint8Array = SigningService.generatePrivateKey()): TestAggregatorClient {
    return new TestAggregatorClient(
      new SparseMerkleTree(new DataHasherFactory(HashAlgorithm.SHA256, DataHasher)),
      new SigningService(privateKey),
    );
  }

  private static pathOf(stateId: StateId): bigint {
    return BitString.fromBytesBigEndian(stateId.data).toBigInt();
  }

  public async getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    const root = await this.smt.calculateRoot();
    const unicityCertificate = await createUnicityCertificate(root.hash, this.signingService, this.referenceTime);
    const record = this.requests.get(TestAggregatorClient.pathOf(stateId));
    if (!record) {
      return InclusionProofResponse.notCertified(1n, unicityCertificate);
    }
    return InclusionProofResponse.certified(
      1n,
      new InclusionProof(
        record.certificationData,
        record.referenceTime,
        InclusionCertificate.create(root, stateId.data),
        unicityCertificate,
      ),
    );
  }

  public async submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    const stateId = await StateId.fromCertificationData(certificationData);

    const result = await this.predicateVerifier.verify(
      certificationData.lockScript,
      this.referenceTime,
      certificationData.sourceStateHash,
      certificationData.transactionHash,
      certificationData.unlockScript,
    );
    if (result.status !== VerificationStatus.OK) {
      return CertificationResponse.create(CertificationStatus.SIGNATURE_VERIFICATION_FAILED);
    }

    const effectiveTimeout = certificationData.expiresAt ?? this.referenceTime + REQUEST_TTL;
    if (this.referenceTime >= effectiveTimeout) {
      return CertificationResponse.create(CertificationStatus.REQUEST_EXPIRED);
    }

    // Like aggregator-go: a state id it already holds is answered with STATE_ID_EXISTS,
    // whether the request is the same transaction again or another one.
    const path = TestAggregatorClient.pathOf(stateId);
    if (this.requests.has(path)) {
      return CertificationResponse.create(STATE_ID_EXISTS_STATUS);
    }
    const referenceTime = this.referenceTime;
    const leafValue = await calculateLeafValue(certificationData.transactionHash, referenceTime);
    await this.smt.addLeaf(stateId.data, leafValue.data);
    this.requests.set(path, { certificationData, referenceTime });
    this.referenceTime += 1n;

    return CertificationResponse.create(CertificationStatus.SUCCESS);
  }
}
