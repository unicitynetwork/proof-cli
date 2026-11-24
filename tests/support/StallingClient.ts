import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import {
  CertificationResponse,
  CertificationStatus,
} from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import type { IAggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/IAggregatorClient.js';
import { InclusionProofResponse } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProofResponse.js';
import type { IRequestOptions } from '@unicitylabs/state-transition-sdk/lib/api/IRequestOptions.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';

import { TestAggregatorClient } from './TestAggregatorClient.js';

/**
 * A gateway that stalls: from the `stallFrom`-th proof lookup on (counting from
 * 0), a lookup never answers, and ends only when its signal aborts. With
 * `dropRequests`, a request is answered SUCCESS without reaching the aggregator,
 * as aggregator-go answers a repeat it will drop; otherwise it is passed on.
 */
export class StallingClient implements IAggregatorClient {
  private lookups = 0;

  public constructor(
    private readonly inner: TestAggregatorClient,
    private readonly stallFrom: number,
    private readonly dropRequests: boolean,
  ) {}

  public getInclusionProof(stateId: StateId, options?: IRequestOptions): Promise<InclusionProofResponse> {
    const lookup = this.lookups;
    this.lookups += 1;
    if (lookup < this.stallFrom) {
      return this.inner.getInclusionProof(stateId);
    }
    return new Promise((_, reject) => {
      const signal = options?.signal;
      signal?.addEventListener('abort', () => reject(signal.reason as Error), { once: true });
    });
  }

  public submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    return this.dropRequests
      ? Promise.resolve(CertificationResponse.create(CertificationStatus.SUCCESS))
      : this.inner.submitCertificationRequest(certificationData);
  }
}
