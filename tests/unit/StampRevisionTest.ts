import { lstat, readdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import {
  CertificationResponse,
  CertificationStatus,
} from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import type { IAggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/IAggregatorClient.js';
import { InclusionProofResponse } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProofResponse.js';
import { JsonRpcNetworkError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcNetworkError.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { SleepError } from '@unicitylabs/state-transition-sdk/lib/util/InclusionProofUtils.js';

import { pendingRevision, writeJournal } from '../../src/commands/revisionJournal.js';
import { networkMismatch, stampRevisionWith } from '../../src/commands/stampRevision.js';
import { IStampRevisionConfig } from '../../src/config.js';
import { EXIT_USAGE, EXIT_VERIFICATION_FAILED, toExitCode } from '../../src/errors.js';
import { StampError } from '../../src/lib/errors.js';
import { appendRevision, prepareRevision } from '../../src/lib/LineageClient.js';
import { verifyLineage } from '../../src/lib/LineageVerification.js';
import { bundledTrustBase } from '../../src/lib/networks.js';
import {
  existingLineageNote,
  IRevisionSummary,
  pendingRevisionLines,
  recoveredRevisionLine,
  revisionJson,
  revisionRecoveryLines,
  revisionText,
  supersededLineageMessage,
} from '../../src/output.js';
import { testContext } from '../support/context.js';
import {
  OTHER_DIGEST,
  OTHER_DIGEST_HEX,
  tempDir,
  TEST_DIGEST,
  TEST_DIGEST_HEX,
  TEST_PRIVATE_KEY,
  TEST_PUBLIC_KEY_HEX,
} from '../support/fixtures.js';
import { StallingClient } from '../support/StallingClient.js';
import { TestAggregatorClient } from '../support/TestAggregatorClient.js';

/** Passes the request on, then loses every proof lookup: the run fails after certification. */
class InterruptingClient implements IAggregatorClient {
  public constructor(private readonly inner: TestAggregatorClient) {}

  public getInclusionProof(): Promise<InclusionProofResponse> {
    return Promise.reject(new JsonRpcNetworkError(502, 'bad gateway'));
  }

  public submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    return this.inner.submitCertificationRequest(certificationData);
  }
}

/** Loses every request before the aggregator sees it, but answers lookups. */
class LostSubmitClient implements IAggregatorClient {
  public constructor(private readonly inner: TestAggregatorClient) {}

  public getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    return this.inner.getInclusionProof(stateId);
  }

  public submitCertificationRequest(): Promise<CertificationResponse> {
    return Promise.reject(new JsonRpcNetworkError(502, 'bad gateway'));
  }
}

/**
 * Queues requests the way aggregator-go does. A state already certified is
 * answered with STATE_ID_EXISTS; any other request, even a repeat for a state
 * whose first request is still waiting for its round, gets SUCCESS. The round then
 * certifies the first request for each state and silently drops the rest. With
 * `roundOnRepeat`, the round runs at the first lookup after a repeat was admitted.
 */
class QueueingClient implements IAggregatorClient {
  private readonly queue: { data: CertificationData; key: string }[] = [];
  private roundDue = false;

  public constructor(
    private readonly inner: TestAggregatorClient,
    private readonly roundOnRepeat: boolean,
  ) {}

  private static async keyOf(data: CertificationData): Promise<string> {
    return HexConverter.encode((await StateId.fromCertificationData(data)).data);
  }

  public async getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    if (this.roundDue) {
      await this.runRound();
    }
    return this.inner.getInclusionProof(stateId);
  }

  public async runRound(): Promise<void> {
    this.roundDue = false;
    const certified = new Set<string>();
    for (const { data, key } of this.queue.splice(0)) {
      if (!certified.has(key)) {
        certified.add(key);
        await this.inner.submitCertificationRequest(data);
      }
    }
  }

  public async submitCertificationRequest(data: CertificationData): Promise<CertificationResponse> {
    const stateId = await StateId.fromCertificationData(data);
    if ((await this.inner.getInclusionProof(stateId)).inclusionProof !== null) {
      return this.inner.submitCertificationRequest(data);
    }
    const key = await QueueingClient.keyOf(data);
    if (this.roundOnRepeat && this.queue.some((queued) => queued.key === key)) {
      this.roundDue = true;
    }
    this.queue.push({ data, key });
    return CertificationResponse.create(CertificationStatus.SUCCESS);
  }
}

/**
 * Holds a run at its first submission or its first proof lookup until released,
 * so another run, or a test, can act on the token file meanwhile.
 */
class GatedClient implements IAggregatorClient {
  public readonly reached: Promise<void>;
  private arrive!: () => void;
  private readonly gate: Promise<void>;
  private held = false;
  private open!: () => void;

  public constructor(
    private readonly inner: TestAggregatorClient,
    private readonly at: 'lookup' | 'submit',
  ) {
    this.reached = new Promise((resolve) => (this.arrive = resolve));
    this.gate = new Promise((resolve) => (this.open = resolve));
  }

  public async getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    await this.hold('lookup');
    return this.inner.getInclusionProof(stateId);
  }

  public release(): void {
    this.open();
  }

  public async submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    await this.hold('submit');
    return this.inner.submitCertificationRequest(certificationData);
  }

  private async hold(step: 'lookup' | 'submit'): Promise<void> {
    if (step === this.at && !this.held) {
      this.held = true;
      this.arrive();
      await this.gate;
    }
  }
}

/** Refuses every request outright with a status the SDK knows, so the run gets a StampError. */
class RefusingClient implements IAggregatorClient {
  public constructor(private readonly inner: TestAggregatorClient) {}

  public getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    return this.inner.getInclusionProof(stateId);
  }

  public submitCertificationRequest(): Promise<CertificationResponse> {
    return Promise.resolve(CertificationResponse.create(CertificationStatus.REQUEST_EXPIRED));
  }
}

/**
 * Lets another transfer take the slot first: on the run's submission it certifies
 * `rival` directly, then passes the run's request on, which the aggregator answers
 * with STATE_ID_EXISTS. Lookups pass through until `goodLookups` have been answered;
 * every one after that fails, as a gateway dropping requests would.
 */
class RacingClient implements IAggregatorClient {
  private lookups = 0;

  public constructor(
    private readonly inner: TestAggregatorClient,
    private readonly rival: CertificationData,
    private readonly goodLookups: number,
  ) {}

  public getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    this.lookups += 1;
    return this.lookups > this.goodLookups
      ? Promise.reject(new JsonRpcNetworkError(502, 'bad gateway'))
      : this.inner.getInclusionProof(stateId);
  }

  public async submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    await this.inner.submitCertificationRequest(this.rival);
    return this.inner.submitCertificationRequest(certificationData);
  }
}

type Lookup = (stateId: StateId) => Promise<InclusionProofResponse>;

/** Answers the n-th proof lookup with the n-th scripted answer, and the rest from the aggregator. */
class ScriptedLookupClient implements IAggregatorClient {
  private lookups = 0;

  public constructor(
    private readonly inner: TestAggregatorClient,
    private readonly script: (Lookup | null)[],
  ) {}

  public getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    const scripted = this.script[this.lookups];
    this.lookups += 1;
    return scripted ? scripted(stateId) : this.inner.getInclusionProof(stateId);
  }

  public submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    return this.inner.submitCertificationRequest(certificationData);
  }
}

describe('stampRevisionWith', () => {
  const bob = SigningService.generatePrivateKey();
  const bobPublic = new SigningService(bob).publicKey;
  // A fresh aggregator per test: a genesis is deterministic in its issuer, digest
  // and recipient, so tests sharing one would all continue the same lineage.
  let aggregator: TestAggregatorClient;
  let client: StateTransitionClient;
  let directory: string;

  beforeEach(async () => {
    aggregator = TestAggregatorClient.create();
    client = new StateTransitionClient(aggregator);
    directory = await tempDir('proof-cli-revision-');
  });

  function config(overrides: Partial<IStampRevisionConfig>): IStampRevisionConfig {
    return {
      allowInsecure: false,
      apiKey: 'key',
      digest: TEST_DIGEST,
      force: false,
      network: { gatewayUrl: 'https://gateway.test', preset: 'testnet2', trustBase: aggregator.rootTrustBase },
      privateKey: TEST_PRIVATE_KEY,
      quiet: false,
      recipientKey: bobPublic,
      timeoutMs: 2_000,
      tokenBytes: null,
      tokenFile: path.join(directory, 'doc.lineage'),
      trustBasePath: null,
      ...overrides,
    };
  }

  it('creates the token file, then appends to it', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    const first = testContext({ json: true });
    expect(await stampRevisionWith(config({}), client, first.context)).toBe(0);
    expect(first.json()).toMatchObject({
      command: 'stamp-revision',
      created: true,
      hash: { algorithm: 'SHA-256', digest: TEST_DIGEST_HEX },
      nextProducer: HexConverter.encode(bobPublic),
      recovered: false,
      revision: '0',
      signer: TEST_PUBLIC_KEY_HEX,
      tokenFile,
    });
    expect(first.stderr()).toEqual('');

    const second = testContext();
    const tokenBytes = new Uint8Array(await readFile(tokenFile));
    expect(
      await stampRevisionWith(
        config({
          digest: OTHER_DIGEST,
          privateKey: bob,
          recipientKey: HexConverter.decode(TEST_PUBLIC_KEY_HEX),
          tokenBytes,
        }),
        client,
        second.context,
      ),
    ).toBe(0);
    expect(second.stdout()).toContain('Revision       1\n');
    expect(second.stdout()).toContain(`Stamped        SHA-256 ${OTHER_DIGEST_HEX}`);
    expect(await readdir(directory)).toEqual(['doc.lineage']);

    const token = await Token.fromCBOR(new Uint8Array(await readFile(tokenFile)));
    expect(token.transactions).toHaveLength(1);
    expect((await verifyLineage(token, aggregator.rootTrustBase)).status).toEqual('OK');
  });

  it('finalizes a lineage, after which nothing can be appended', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    await stampRevisionWith(config({}), client, testContext().context);
    const tokenBytes = new Uint8Array(await readFile(tokenFile));

    const sealed = testContext({ json: true });
    expect(
      await stampRevisionWith(
        config({ digest: OTHER_DIGEST, privateKey: bob, recipientKey: null, tokenBytes }),
        client,
        sealed.context,
      ),
    ).toBe(0);
    expect(sealed.json()).toMatchObject({ finalized: true, nextProducer: null, revision: '1' });

    const text = testContext();
    const finalBytes = new Uint8Array(await readFile(tokenFile));
    // Back to the copy from before the seal, as if the sealed file had never been written.
    await writeFile(tokenFile, tokenBytes);
    expect(
      await stampRevisionWith(
        config({ digest: OTHER_DIGEST, privateKey: bob, recipientKey: null, tokenBytes }),
        client,
        text.context,
      ),
    ).toBe(0);
    // The same seal again: the aggregator already holds it, so this run only recovers it.
    expect(text.stdout()).toContain('Revision       1  (recovered)  (final)\n');
    expect(text.stdout()).toContain('Next producer  none; the lineage is finalized');

    expect(new Uint8Array(await readFile(tokenFile))).toEqual(finalBytes);
    const attempt = stampRevisionWith(
      config({ privateKey: bob, tokenBytes: finalBytes }),
      client,
      testContext().context,
    );
    await expect(attempt).rejects.toThrow(/finalized/);
    expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
  });

  it('creates a lineage that is final from the start', async () => {
    const sink = testContext({ json: true });
    expect(await stampRevisionWith(config({ recipientKey: null }), client, sink.context)).toBe(0);
    expect(sink.json()).toMatchObject({ created: true, finalized: true, nextProducer: null, revision: '0' });
  });

  it('accepts a token file holding hex text', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    await stampRevisionWith(config({}), client, testContext().context);
    const hex = HexConverter.encode(new Uint8Array(await readFile(tokenFile)));
    await writeFile(tokenFile, `${hex}\n`);
    await expect(
      stampRevisionWith(
        config({ privateKey: bob, tokenBytes: new TextEncoder().encode(`${hex}\n`) }),
        client,
        testContext().context,
      ),
    ).resolves.toBe(0);
  });

  it('refuses a key that is not the named producer, leaving the file alone', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    await stampRevisionWith(config({}), client, testContext().context);
    const before = await readFile(tokenFile);
    const attempt = stampRevisionWith(config({ tokenBytes: new Uint8Array(before) }), client, testContext().context);
    await expect(attempt).rejects.toThrow(/does not match the producer/);
    expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
    expect(await readFile(tokenFile)).toEqual(before);
  });

  describe('a genesis that was already certified', () => {
    let tokenFile: string;
    let genesisBytes: Uint8Array;
    let tokenIdHex: string;

    beforeEach(async () => {
      tokenFile = path.join(directory, 'doc.lineage');
      await stampRevisionWith(config({}), client, testContext().context);
      genesisBytes = new Uint8Array(await readFile(tokenFile));
      tokenIdHex = HexConverter.encode((await Token.fromCBOR(genesisBytes)).id.bytes);
      await rm(tokenFile);
    });

    async function bobAppends(): Promise<void> {
      const genesis = await Token.fromCBOR(genesisBytes);
      await appendRevision(client, aggregator.rootTrustBase, genesis, OTHER_DIGEST, bob, bobPublic, {
        pollIntervalMs: 10,
      });
    }

    it('is recovered and written, marked as the existing lineage, with a note even under --quiet', async () => {
      const sink = testContext({ json: true });
      expect(await stampRevisionWith(config({ quiet: true }), client, sink.context)).toBe(0);
      expect(sink.json()).toMatchObject({ created: true, recovered: true, revision: '0', tokenId: tokenIdHex });
      expect(sink.stderr()).toEqual(existingLineageNote(HexConverter.decode(tokenIdHex)));
      expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);

      await rm(tokenFile);
      const text = testContext();
      await stampRevisionWith(config({}), client, text.context);
      expect(text.stdout()).toContain('Revision       0  (existing lineage, recovered)\n');
    });

    it('is not written once the lineage has moved on, and the error says so', async () => {
      await bobAppends();
      const attempt = stampRevisionWith(config({ quiet: true }), client, testContext().context);
      await expect(attempt).rejects.toMatchObject({ code: 'SUPERSEDED' });
      const error = (await attempt.catch((caught: unknown) => caught)) as Error;
      expect(toExitCode(error)).toBe(EXIT_VERIFICATION_FAILED);
      expect(error.message).toContain(`Revision 0 of lineage ${tokenIdHex} was certified by an earlier run`);
      expect(error.message).toContain(`by the next producer ${HexConverter.encode(bobPublic)}`);
      expect(error.message).toContain('name a different first producer');
      expect(await readdir(directory)).toEqual([]);
    });

    it('is written with a warning when the check for later revisions fails', async () => {
      await bobAppends();
      const failing = new StateTransitionClient(
        new ScriptedLookupClient(aggregator, [
          null,
          (): Promise<InclusionProofResponse> => Promise.reject(new JsonRpcNetworkError(502, 'bad gateway')),
        ]),
      );
      const sink = testContext();
      expect(await stampRevisionWith(config({}), failing, sink.context)).toBe(0);
      expect(sink.stderr()).toContain('warning: Could not check whether the lineage has later revisions: ');
      expect(sink.stderr()).toContain('not a new one.');
      // Revision 0 of the same lineage; its proof is now served under a later root.
      const written = await Token.fromCBOR(new Uint8Array(await readFile(tokenFile)));
      expect(HexConverter.encode(written.id.bytes)).toEqual(tokenIdHex);
      expect(written.transactions).toHaveLength(0);
    });

    it('is written with a warning when the proof of a later revision does not verify', async () => {
      // Revision 1 certified by an aggregator outside the trust base.
      const elsewhere = TestAggregatorClient.create();
      const genesis = await Token.fromCBOR(genesisBytes);
      const forged = await prepareRevision(genesis, aggregator.rootTrustBase, OTHER_DIGEST, bob, bobPublic);
      await elsewhere.submitCertificationRequest(forged.certificationData);
      const forging = new StateTransitionClient(
        new ScriptedLookupClient(aggregator, [
          null,
          (stateId): Promise<InclusionProofResponse> => elsewhere.getInclusionProof(stateId),
        ]),
      );
      const sink = testContext();
      expect(await stampRevisionWith(config({}), forging, sink.context)).toBe(0);
      expect(sink.stderr()).toContain('warning: The gateway showed a proof of a later revision that does not verify');
      expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);
    });
  });

  describe('journal', () => {
    let tokenFile: string;
    let journal: string;
    let genesisBytes: Uint8Array;

    beforeEach(async () => {
      tokenFile = path.join(directory, 'doc.lineage');
      // Where a test writes a journal by hand; a run names its own after its transfer.
      journal = path.join(directory, '.doc.lineage.0000000000000000.pending');
      await stampRevisionWith(config({}), client, testContext().context);
      genesisBytes = new Uint8Array(await readFile(tokenFile));
    });

    /** Revision 1, by bob, passing to the test key. */
    const append = (overrides: Partial<IStampRevisionConfig> = {}): IStampRevisionConfig =>
      config({
        digest: OTHER_DIGEST,
        privateKey: bob,
        recipientKey: HexConverter.decode(TEST_PUBLIC_KEY_HEX),
        tokenBytes: genesisBytes,
        ...overrides,
      });

    async function interrupted(): Promise<void> {
      const interrupting = new StateTransitionClient(new InterruptingClient(aggregator));
      await expect(stampRevisionWith(append(), interrupting, testContext().context)).rejects.toThrow(/bad gateway/);
      const journals = await journalFiles();
      expect(journals).toHaveLength(1);
      journal = journals[0];
      expect(await readdir(directory)).toEqual([path.basename(journal), 'doc.lineage']);
      expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);
    }

    async function journalFiles(): Promise<string[]> {
      return (await readdir(directory))
        .filter((name) => /^\.doc\.lineage\.[0-9a-f]{16}\.pending$/.test(name))
        .map((name) => path.join(directory, name));
    }

    async function revisions(): Promise<string[]> {
      const token = await Token.fromCBOR(new Uint8Array(await readFile(tokenFile)));
      return (await verifyLineage(token, aggregator.rootTrustBase)).description.revisions.map((revision) =>
        HexConverter.encode(revision.digest!),
      );
    }

    it('echoes the pending revision to stderr, and removes the journal once the token is written', async () => {
      expect(await readdir(directory)).toEqual(['doc.lineage']);
      const sink = testContext();
      expect(await stampRevisionWith(append(), client, sink.context)).toBe(0);
      expect(sink.stderr()).toContain('Submitting revision 1 of lineage ');
      expect(sink.stderr()).toContain(`Stamped        SHA-256 ${OTHER_DIGEST_HEX}`);
      expect(sink.stderr()).toContain(`Next producer  ${TEST_PUBLIC_KEY_HEX}`);
      expect(sink.stderr()).toMatch(/Journal {8}\S+\/\.doc\.lineage\.[0-9a-f]{16}\.pending\n/);
      expect(await readdir(directory)).toEqual(['doc.lineage']);
    });

    it('leaves the pending revision off stderr with --quiet', async () => {
      const sink = testContext();
      expect(await stampRevisionWith(append({ quiet: true }), client, sink.context)).toBe(0);
      expect(sink.stderr()).toEqual('');
      expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX]);
    });

    it('keeps the journal when interrupted after submitting, and the next run recovers from it', async () => {
      await interrupted();
      const recorded = JSON.parse(await readFile(journal, 'utf8')) as Record<string, unknown>;
      expect(recorded).toMatchObject({
        digest: OTHER_DIGEST_HEX,
        format: 'unicity-proof/pending-revision',
        nextProducer: TEST_PUBLIC_KEY_HEX,
        revision: '1',
        version: 1,
      });

      const sink = testContext();
      expect(await stampRevisionWith(append({ quiet: true }), client, sink.context)).toBe(0);
      expect(sink.stderr()).toEqual(`Recovered revision 1 from the journal ${journal} of an interrupted run.\n`);
      expect(sink.stdout()).toContain('Revision       1  (recovered)\n');
      expect(await readdir(directory)).toEqual(['doc.lineage']);
      expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX]);
    });

    it('recovers the journaled revision when re-run with other inputs, and refuses the request', async () => {
      await interrupted();
      const sink = testContext();
      const attempt = stampRevisionWith(append({ digest: TEST_DIGEST, quiet: true }), client, sink.context);
      await expect(attempt).rejects.toMatchObject({ code: 'ALREADY_CERTIFIED' });
      const error = await attempt.catch((caught: unknown) => caught);
      expect((error as Error).message).toMatch(
        new RegExp(
          `recovered and written to ${tokenFile}; the requested revision was not appended, ` +
            `and the lineage now passes to ${TEST_PUBLIC_KEY_HEX}\\.$`,
        ),
      );
      expect(toExitCode(error)).toBe(EXIT_VERIFICATION_FAILED);
      // The notes come out despite --quiet: they say what the token file now holds.
      expect(sink.stderr()).toContain('Recovered revision 1 of lineage ');
      expect(sink.stderr()).toContain(`SHA-256 ${OTHER_DIGEST_HEX}`);
      expect(await readdir(directory)).toEqual(['doc.lineage']);
      expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX]);
    });

    it('without the journal, reports the taken slot and echoes what it tried, even with --quiet', async () => {
      await interrupted();
      await rm(journal);
      const sink = testContext();
      const attempt = stampRevisionWith(append({ digest: TEST_DIGEST, quiet: true }), client, sink.context);
      await expect(attempt).rejects.toThrow(
        /already certified with different content.*that run's digest and next producer/,
      );
      expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_VERIFICATION_FAILED);
      expect(sink.stderr()).toContain('as this run submitted it (not certified)');
      expect(sink.stderr()).toContain(`SHA-256 ${TEST_DIGEST_HEX}`);
      expect(await readdir(directory)).toEqual(['doc.lineage']);
      expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);

      // With the inputs the interrupted run used, the revision is recovered after all.
      expect(await stampRevisionWith(append(), client, testContext().context)).toBe(0);
      expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX]);
    });

    describe('an earlier run whose outcome is not known yet', () => {
      const UNRESOLVED = 'submitted by an earlier run and not certified yet:';

      /** Run 1: bob's revision 1 (OTHER_DIGEST) is journaled, but its request never reaches the aggregator. */
      async function lost(): Promise<void> {
        await expect(
          stampRevisionWith(
            append({ quiet: true }),
            new StateTransitionClient(new LostSubmitClient(aggregator)),
            testContext().context,
          ),
        ).rejects.toThrow(/bad gateway/);
        expect(await journalFiles()).toHaveLength(1);
      }

      // MastaP on PR #16: nothing pinned the `created` guard before the removal on a refusal.
      it("keeps an earlier run's journal for the same transfer when this run's own request is refused", async () => {
        await lost();
        const [earlier] = await journalFiles();
        const attempt = stampRevisionWith(
          append({ quiet: true }),
          new StateTransitionClient(new RefusingClient(aggregator)),
          testContext().context,
        );
        await expect(attempt).rejects.toBeInstanceOf(StampError);
        expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(3);
        // The earlier request was a separate one, and may still be certified.
        expect(await journalFiles()).toEqual([earlier]);
      });

      it('removes its own journal when its request is refused, having created it', async () => {
        const attempt = stampRevisionWith(
          append({ quiet: true }),
          new StateTransitionClient(new RefusingClient(aggregator)),
          testContext().context,
        );
        await expect(attempt).rejects.toBeInstanceOf(StampError);
        expect(await readdir(directory)).toEqual(['doc.lineage']);
      });

      // MastaP on PR #16: nothing pinned removeKept() in settle. Journals are tried in
      // name order, and an uncertified one tried before the certified one is removed by
      // the ALREADY_CERTIFIED branch first; here it sorts last, so only settle can remove
      // it. findJournals matches names by pattern only, so a test can choose the order.
      it('removes every other journal for the revision once one is recovered', async () => {
        await interrupted();
        const certified = path.join(directory, '.doc.lineage.0000000000000000.pending');
        await rename(journal, certified);
        const genesis = await Token.fromCBOR(genesisBytes);
        const never = await prepareRevision(genesis, aggregator.rootTrustBase, TEST_DIGEST, bob, null);
        await writeJournal(
          path.join(directory, '.doc.lineage.ffffffffffffffff.pending'),
          pendingRevision(genesis, never, TEST_DIGEST, null),
        );
        expect(await journalFiles()).toHaveLength(2);

        expect(await stampRevisionWith(append({ quiet: true }), client, testContext().context)).toBe(0);
        expect(await readdir(directory)).toEqual(['doc.lineage']);
        expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX]);
      });

      // MastaP on PR #16: nothing pinned the tolerant branch of recoverKept. After
      // ALREADY_CERTIFIED, a failed lookup of a kept journal keeps that journal, and the
      // run still ends with the outcome it knows, not the network error.
      it('keeps a journal whose lookup fails after ALREADY_CERTIFIED, and still reports ALREADY_CERTIFIED', async () => {
        await lost();
        const [earlier] = await journalFiles();
        const genesis = await Token.fromCBOR(genesisBytes);
        const rival = await prepareRevision(genesis, aggregator.rootTrustBase, TEST_DIGEST, bob, null);
        // Good lookups: run 1's journal at start, then the conflict lookup after STATE_ID_EXISTS.
        const racing = new StateTransitionClient(new RacingClient(aggregator, rival.certificationData, 2));

        const sink = testContext();
        const attempt = stampRevisionWith(append({ digest: TEST_DIGEST, quiet: true }), racing, sink.context);
        await expect(attempt).rejects.toMatchObject({ code: 'ALREADY_CERTIFIED' });
        expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_VERIFICATION_FAILED);
        expect(sink.stderr()).toContain(UNRESOLVED);
        expect(sink.stderr()).toContain('as this run submitted it (not certified)');
        expect(await journalFiles()).toEqual([earlier]);
      });

      /** Run 1: bob's revision 1 (OTHER_DIGEST) is submitted, and the run times out while it is queued. */
      async function timedOut(queueing: QueueingClient): Promise<void> {
        const attempt = stampRevisionWith(
          append({ quiet: true, timeoutMs: 300 }),
          new StateTransitionClient(queueing),
          testContext().context,
        );
        await expect(attempt).rejects.toBeInstanceOf(SleepError);
        expect(await journalFiles()).toHaveLength(1);
      }

      // MastaP's reproduction on PR #16: run 2, with other inputs, used to delete run 1's
      // journal, then lose its own request to run 1's and fail with a plain hash mismatch.
      it("keeps its journal, and recovers its revision when the round certifies it instead of this run's", async () => {
        const queueing = new QueueingClient(aggregator, true);
        await timedOut(queueing);

        const sink = testContext();
        const attempt = stampRevisionWith(
          append({ digest: TEST_DIGEST, quiet: true }),
          new StateTransitionClient(queueing),
          sink.context,
        );
        await expect(attempt).rejects.toMatchObject({ code: 'ALREADY_CERTIFIED' });
        expect(((await attempt.catch((error: unknown) => error)) as Error).message).toContain(
          `recovered and written to ${tokenFile}; the requested revision was not appended`,
        );
        // Despite --quiet: the earlier run's revision while open, then this run's as rejected.
        expect(sink.stderr()).toContain(UNRESOLVED);
        expect(sink.stderr()).toContain('as this run submitted it (not certified)');
        expect(sink.stderr()).toContain('Recovered revision 1 of lineage ');
        expect(await journalFiles()).toEqual([]);
        expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX]);
      });

      it('keeps both journals when the second run times out too, and the next run recovers the certified one', async () => {
        const queueing = new QueueingClient(aggregator, false);
        await timedOut(queueing);
        const sink = testContext();
        await expect(
          stampRevisionWith(
            append({ digest: TEST_DIGEST, quiet: true, timeoutMs: 300 }),
            new StateTransitionClient(queueing),
            sink.context,
          ),
        ).rejects.toBeInstanceOf(SleepError);
        expect(sink.stderr()).toContain(UNRESOLVED);
        expect(sink.stderr()).toContain(`SHA-256 ${OTHER_DIGEST_HEX}`);
        expect(await journalFiles()).toHaveLength(2);

        await queueing.runRound();
        const attempt = stampRevisionWith(append({ digest: TEST_DIGEST, quiet: true }), client, testContext().context);
        await expect(attempt).rejects.toMatchObject({ code: 'ALREADY_CERTIFIED' });
        expect(await journalFiles()).toEqual([]);
        expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX]);
      });

      it("removes its journal once this run's revision is certified in its place", async () => {
        await expect(
          stampRevisionWith(
            append({ quiet: true }),
            new StateTransitionClient(new LostSubmitClient(aggregator)),
            testContext().context,
          ),
        ).rejects.toThrow(/bad gateway/);
        expect(await journalFiles()).toHaveLength(1);

        const sink = testContext();
        expect(await stampRevisionWith(append({ digest: TEST_DIGEST, quiet: true }), client, sink.context)).toBe(0);
        expect(sink.stderr()).toContain(UNRESOLVED);
        expect(await journalFiles()).toEqual([]);
        expect(await revisions()).toEqual([TEST_DIGEST_HEX, TEST_DIGEST_HEX]);
      });

      it('removes its journal once a proof shows its slot holds another transfer', async () => {
        await expect(
          stampRevisionWith(
            append({ quiet: true }),
            new StateTransitionClient(new LostSubmitClient(aggregator)),
            testContext().context,
          ),
        ).rejects.toThrow(/bad gateway/);
        const genesis = await Token.fromCBOR(genesisBytes);
        await appendRevision(client, aggregator.rootTrustBase, genesis, TEST_DIGEST, bob, null, {
          timeoutMs: 2_000,
        });

        const sink = testContext();
        const attempt = stampRevisionWith(append({ digest: TEST_DIGEST, quiet: true }), client, sink.context);
        await expect(attempt).rejects.toThrow(/that run's digest and next producer/);
        expect(sink.stderr()).not.toContain(UNRESOLVED);
        expect(await journalFiles()).toEqual([]);
        expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);
      });
    });

    it('keeps its journal and exits 3 when the conflict lookup stalls past the timeout', async () => {
      const genesis = await Token.fromCBOR(genesisBytes);
      const other = await prepareRevision(genesis, aggregator.rootTrustBase, TEST_DIGEST, bob, null);
      await aggregator.submitCertificationRequest(other.certificationData);
      const attempt = stampRevisionWith(
        append({ quiet: true, timeoutMs: 200 }),
        new StateTransitionClient(new StallingClient(aggregator, 1, true)),
        testContext().context,
      );
      await expect(attempt).rejects.toBeInstanceOf(SleepError);
      expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(3);
      expect(await journalFiles()).toHaveLength(1);
      expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);
    });

    // MastaP on PR #16: a slower run wrote its token over a file another run had moved
    // on, and a revision certified and written in between vanished from it.
    describe('concurrent runs', () => {
      const lockFile = (): string => path.join(directory, '.doc.lineage.lock');

      it('refuses a second append while one holds the lock, and the first completes', async () => {
        const gated = new GatedClient(aggregator, 'submit');
        const slow = stampRevisionWith(
          append({ quiet: true }),
          new StateTransitionClient(gated),
          testContext().context,
        );
        await gated.reached;
        expect(JSON.parse(await readFile(lockFile(), 'utf8'))).toMatchObject({
          format: 'unicity-proof/append-lock',
          pid: process.pid,
        });

        const second = stampRevisionWith(append({ quiet: true }), client, testContext().context);
        await expect(second).rejects.toThrow(
          new RegExp(
            `^Another stamp-revision run is appending to ${tokenFile} \\(pid ${process.pid} on .*\\); ` +
              'nothing was submitted\\. .*delete the lock file .*\\.doc\\.lineage\\.lock: it holds no data\\.$',
          ),
        );
        expect(toExitCode(await second.catch((error: unknown) => error))).toBe(EXIT_USAGE);
        expect(await journalFiles()).toHaveLength(1);

        gated.release();
        expect(await slow).toBe(0);
        expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX]);
        expect(await readdir(directory)).toEqual(['doc.lineage']);
      });

      it('refuses, before submitting, a token file that changed since the run read it', async () => {
        await stampRevisionWith(append({ quiet: true }), client, testContext().context);
        const attempt = stampRevisionWith(append({ quiet: true }), client, testContext().context);
        await expect(attempt).rejects.toThrow(`${tokenFile} changed since this run read it, so nothing was submitted.`);
        expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
        expect(await readdir(directory)).toEqual(['doc.lineage']);
      });

      /** Revisions 0–2, written by a writer that ignores the lock: bob's revision 1 as `append()` makes it, then 2. */
      async function movedOn(): Promise<Uint8Array> {
        const genesis = await Token.fromCBOR(genesisBytes);
        const fast = { timeoutMs: 2_000 };
        const first = await appendRevision(client, aggregator.rootTrustBase, genesis, OTHER_DIGEST, bob, testKey, fast);
        const second = await appendRevision(
          client,
          aggregator.rootTrustBase,
          first,
          TEST_DIGEST,
          TEST_PRIVATE_KEY,
          bobPublic,
          fast,
        );
        return second.toCBOR();
      }
      const testKey = HexConverter.decode(TEST_PUBLIC_KEY_HEX);

      it("leaves a file that moved on alone when it already holds this run's revision", async () => {
        const gated = new GatedClient(aggregator, 'submit');
        const sink = testContext();
        const slow = stampRevisionWith(append({ quiet: true }), new StateTransitionClient(gated), sink.context);
        await gated.reached;
        const newer = await movedOn();
        await writeFile(tokenFile, newer);

        gated.release();
        expect(await slow).toBe(0);
        expect(sink.stderr()).toEqual(
          `${tokenFile} changed while this run was working, and already holds revision 1: another run wrote it. ` +
            'The file was left as it is.\n',
        );
        expect(new Uint8Array(await readFile(tokenFile))).toEqual(newer);
        expect(await readdir(directory)).toEqual(['doc.lineage']);
      });

      it.each([
        ['its own append', 'submit'],
        ['a revision recovered from a journal', 'lookup'],
      ] as const)(
        'never replaces a file that changed into something else, writing %s; prints the token and keeps the journal',
        async (_, at) => {
          if (at === 'lookup') {
            await interrupted();
          }
          const gated = new GatedClient(aggregator, at);
          const sink = testContext();
          const slow = stampRevisionWith(append({ quiet: true }), new StateTransitionClient(gated), sink.context);
          await gated.reached;
          await writeFile(tokenFile, 'replaced by hand');

          gated.release();
          await expect(slow).rejects.toThrow(
            `${tokenFile} changed while this run was working, so it was not replaced.`,
          );
          expect(toExitCode(await slow.catch((error: unknown) => error))).toBe(EXIT_USAGE);
          expect(sink.stderr()).toContain('the revision was certified');
          expect(await readFile(tokenFile, 'utf8')).toEqual('replaced by hand');
          expect(await journalFiles()).toHaveLength(1);
          expect(await readdir(directory)).not.toContain('.doc.lineage.lock');
        },
      );
    });

    it('drops a journal whose revision the token file already holds', async () => {
      await interrupted();
      const leftover = await readFile(journal);
      await stampRevisionWith(append(), client, testContext().context);
      await writeFile(journal, leftover);

      const sink = testContext();
      const tokenBytes = new Uint8Array(await readFile(tokenFile));
      expect(
        await stampRevisionWith(
          config({ digest: TEST_DIGEST, quiet: true, recipientKey: null, tokenBytes }),
          client,
          sink.context,
        ),
      ).toBe(0);
      expect(sink.stderr()).toEqual('');
      expect(await readdir(directory)).toEqual(['doc.lineage']);
      expect(await revisions()).toEqual([TEST_DIGEST_HEX, OTHER_DIGEST_HEX, TEST_DIGEST_HEX]);
    });

    it('refuses a journal it cannot place, and leaves it alone', async () => {
      const tokenId = HexConverter.encode((await Token.fromCBOR(genesisBytes)).id.bytes);
      const entry = (fields: Record<string, unknown>): string =>
        JSON.stringify({
          digest: OTHER_DIGEST_HEX,
          format: 'unicity-proof/pending-revision',
          nextProducer: null,
          revision: '1',
          tokenId,
          transaction: '00',
          version: 1,
          ...fields,
        });
      const cases: [string, RegExp][] = [
        [entry({ tokenId: '00'.repeat(32) }), /is for lineage 0{64}, but .* holds lineage /],
        [entry({ revision: '5' }), /is for revision 5, but .* ends at revision 0: the token file is out of date/],
        [entry({}), /is not a pending lineage revision \(bad transaction\)/],
        ['garbage', /is not a pending lineage revision \(not JSON\)/],
        [entry({ version: 2 }), /is not a pending lineage revision \(unknown format\)/],
      ];
      for (const [contents, message] of cases) {
        await writeFile(journal, contents);
        const attempt = stampRevisionWith(append(), client, testContext().context);
        await expect(attempt).rejects.toThrow(message);
        expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
        expect(await readFile(journal, 'utf8')).toEqual(contents);
      }
      expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);
    });

    it('does not touch a journal next to a token file that is not a valid lineage', async () => {
      await interrupted();
      const leftover = await readFile(journal);
      const other = TestAggregatorClient.create();
      const attempt = stampRevisionWith(
        append({ network: { gatewayUrl: 'https://gateway.test', preset: 'testnet2', trustBase: other.rootTrustBase } }),
        new StateTransitionClient(other),
        testContext().context,
      );
      await expect(attempt).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
      expect(await readFile(journal)).toEqual(leftover);
    });

    it.each([
      [
        null,
        /, but this run is set to mainnet \(1\)\. Pass --trust-base with that network's trust base, and --gateway/,
      ],
      [
        '/keys/mainnet.json',
        /, but the trust base \/keys\/mainnet\.json is for mainnet \(1\)\. Pass --trust-base .* instead\./,
      ],
    ])(
      'refuses, with exit 2, a token from another network than the configured one (trust base file %s)',
      async (trustBasePath, advice) => {
        await interrupted();
        const leftover = await readFile(journal);
        const mainnet = {
          network: {
            gatewayUrl: 'https://gateway.test',
            preset: 'mainnet' as const,
            trustBase: bundledTrustBase('mainnet'),
          },
          trustBasePath,
        };
        const sink = testContext();
        const attempt = stampRevisionWith(append(mainnet), client, sink.context);
        await expect(attempt).rejects.toThrow(
          new RegExp(`^${tokenFile} is a lineage on network 3, which has no bundled trust base`),
        );
        await expect(attempt).rejects.toThrow(advice);
        await expect(attempt).rejects.toThrow(/ Nothing was submitted\.$/);
        expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
        expect(sink.stderr()).toEqual('');
        expect(await readFile(journal)).toEqual(leftover);
        expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);
      },
    );
  });

  describe('a token file in the way of a new lineage', () => {
    /** Runs `blocker` on the token file path while the genesis is being certified. */
    function blockingClient(blocker: (tokenFile: string) => Promise<void>): StateTransitionClient {
      const tokenFile = path.join(directory, 'doc.lineage');
      return new StateTransitionClient({
        getInclusionProof: async (stateId: StateId): Promise<InclusionProofResponse> => {
          await blocker(tokenFile);
          return aggregator.getInclusionProof(stateId);
        },
        submitCertificationRequest: (data: CertificationData): Promise<CertificationResponse> =>
          aggregator.submitCertificationRequest(data),
      });
    }

    const appear = async (tokenFile: string): Promise<void> => {
      await writeFile(tokenFile, 'someone else');
    };

    it('leaves a file that appeared alone, and says to run again with another --token-file', async () => {
      const sink = testContext();
      const attempt = stampRevisionWith(config({}), blockingClient(appear), sink.context);
      await expect(attempt).rejects.toThrow(
        /doc\.lineage appeared while the new lineage was being certified, and was not overwritten\. .* with another --token-file\.$/,
      );
      expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
      expect(await readFile(path.join(directory, 'doc.lineage'), 'utf8')).toEqual('someone else');
      expect(sink.stderr()).toContain('the revision was certified');

      const elsewhere = path.join(directory, 'other.lineage');
      const again = testContext({ json: true });
      expect(await stampRevisionWith(config({ tokenFile: elsewhere }), client, again.context)).toBe(0);
      expect(again.json()).toMatchObject({ created: true, recovered: true, revision: '0' });
    });

    it('overwrites a file that appeared with --force', async () => {
      const sink = testContext({ json: true });
      expect(await stampRevisionWith(config({ force: true }), blockingClient(appear), sink.context)).toBe(0);
      const token = await Token.fromCBOR(new Uint8Array(await readFile(path.join(directory, 'doc.lineage'))));
      expect((await verifyLineage(token, aggregator.rootTrustBase)).status).toEqual('OK');
    });

    it('says --force writes through a dangling symlink, and it does', async () => {
      const tokenFile = path.join(directory, 'doc.lineage');
      const target = path.join(directory, 'target.lineage');
      await symlink(target, tokenFile);
      const attempt = stampRevisionWith(config({}), client, testContext().context);
      await expect(attempt).rejects.toThrow(
        /doc\.lineage is a symlink to a missing file, so the new lineage was not written\. .*: pass --force to create the file the symlink points to, or use another --token-file\.$/,
      );
      expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);

      const sink = testContext({ json: true });
      expect(await stampRevisionWith(config({ force: true }), client, sink.context)).toBe(0);
      expect(sink.json()).toMatchObject({ created: true, recovered: true });
      expect((await lstat(tokenFile)).isSymbolicLink()).toBe(true);
      const token = await Token.fromCBOR(new Uint8Array(await readFile(target)));
      expect((await verifyLineage(token, aggregator.rootTrustBase)).status).toEqual('OK');
    });
  });

  describe('networkMismatch', () => {
    it('accepts a token from the configured network', () => {
      expect(networkMismatch('/d/doc.lineage', 4, 4, null)).toBeNull();
      expect(networkMismatch('/d/doc.lineage', 3, 3, '/keys/local.json')).toBeNull();
    });

    it('names both networks and the setting to change', () => {
      expect(networkMismatch('/d/doc.lineage', 4, 1, null)?.message).toEqual(
        '/d/doc.lineage is a testnet2 (4) lineage, but this run is set to mainnet (1). ' +
          'Pass --network testnet2, or set UNICITY_NETWORK=testnet2. Nothing was submitted.',
      );
      expect(networkMismatch('/d/doc.lineage', 1, 3, '/keys/local.json')?.message).toEqual(
        '/d/doc.lineage is a mainnet (1) lineage, but the trust base /keys/local.json is for unknown network (3). ' +
          'Pass a trust base for mainnet, or drop the trust base (--trust-base or UNICITY_TRUST_BASE) ' +
          'and pass --network mainnet. Nothing was submitted.',
      );
    });

    it('is a usage error', () => {
      expect(toExitCode(networkMismatch('/d/doc.lineage', 4, 1, null))).toBe(EXIT_USAGE);
    });
  });

  it('refuses a file that is not a token', async () => {
    const attempt = stampRevisionWith(
      config({ tokenBytes: new TextEncoder().encode('hello') }),
      client,
      testContext().context,
    );
    await expect(attempt).rejects.toThrow(
      /is not a token.*\. If an earlier stamp-revision run failed while creating a new lineage, move this file away and run the same command again: the lineage is recovered\.$/,
    );
    expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_VERIFICATION_FAILED);
  });
});

describe('stamp-revision output', () => {
  const producer = HexConverter.decode(TEST_PUBLIC_KEY_HEX);
  const next = new SigningService(SigningService.generatePrivateKey()).publicKey;
  const summary: IRevisionSummary = {
    created: false,
    digest: TEST_DIGEST,
    epoch: 1n,
    gatewayUrl: 'https://gateway.test',
    networkId: 4,
    nextProducer: next,
    recovered: false,
    referenceTime: 1791200527n,
    revision: 2n,
    roundNumber: 184233n,
    roundTimestamp: 1791200528n,
    signer: producer,
    tokenFile: '/docs/doc.lineage',
    tokenId: new Uint8Array(32).fill(0xaa),
  };

  it('reports the revision, who signed it and who may produce the next', () => {
    expect(revisionText(summary)).toEqual(
      [
        'Revision       2',
        `Stamped        SHA-256 ${TEST_DIGEST_HEX}`,
        'Network        testnet2 (4) via https://gateway.test',
        `Signed by      ${TEST_PUBLIC_KEY_HEX}`,
        `Next producer  ${HexConverter.encode(next)}`,
        'Certified at   2026-10-05T11:42:07Z  (reference time 1791200527)',
        'Round          184233  (round timestamp 1791200528, epoch 1)',
        `Token id       ${'aa'.repeat(32)}`,
        'Written        /docs/doc.lineage',
      ].join('\n'),
    );
  });

  it('marks a new lineage and a final revision', () => {
    const created = revisionText({ ...summary, created: true, revision: 0n });
    expect(created).toContain('Revision       0  (new lineage)\n');
    expect(created).toContain(`Token id       ${'aa'.repeat(32)}  (identifies this lineage; give it to verifiers)\n`);
    expect(revisionText(summary)).toContain(`Token id       ${'aa'.repeat(32)}\n`);
    const final = revisionText({ ...summary, nextProducer: null });
    expect(final).toContain('Revision       2  (final)\n');
    expect(final).toContain('Next producer  none; the lineage is finalized (sealed and burned)\n');
    expect(revisionText({ ...summary, created: true, nextProducer: null, revision: 0n })).toContain(
      'Revision       0  (new lineage)  (final)\n',
    );
  });

  it('renders the same fields as JSON, big integers as decimal strings', () => {
    expect(revisionJson(summary)).toEqual({
      command: 'stamp-revision',
      created: false,
      finalized: false,
      hash: { algorithm: 'SHA-256', digest: TEST_DIGEST_HEX },
      network: { gateway: 'https://gateway.test', id: 4, name: 'testnet2' },
      nextProducer: HexConverter.encode(next),
      recovered: false,
      referenceTime: '1791200527',
      referenceTimeIso: '2026-10-05T11:42:07Z',
      revision: '2',
      round: { epoch: '1', number: '184233', timestamp: '1791200528' },
      signer: TEST_PUBLIC_KEY_HEX,
      tokenFile: '/docs/doc.lineage',
      tokenId: 'aa'.repeat(32),
    });
    expect(revisionJson({ ...summary, nextProducer: null })).toMatchObject({ finalized: true, nextProducer: null });
    expect(revisionJson({ ...summary, referenceTime: 10n ** 30n }).referenceTimeIso).toBeNull();
  });

  it('hands back a token it could not write, in a form --token-file accepts', () => {
    const lines = revisionRecoveryLines(new Uint8Array([0xd9, 0x01, 0x00]));
    expect(lines).toEqual(
      'error: the revision was certified but the token file could not be written.\n' +
        'Save the token below; `stamp-revision --token-file` accepts hex text.\n' +
        'd90100\n',
    );
  });

  it('marks a recovered revision, and a recovered genesis as an existing lineage', () => {
    expect(revisionText({ ...summary, recovered: true })).toContain('Revision       2  (recovered)\n');
    expect(revisionText({ ...summary, nextProducer: null, recovered: true })).toContain(
      'Revision       2  (recovered)  (final)\n',
    );
    expect(revisionText({ ...summary, created: true, recovered: true, revision: 0n })).toContain(
      'Revision       0  (existing lineage, recovered)\n',
    );
    expect(revisionText({ ...summary, created: true, revision: 0n })).toContain('Revision       0  (new lineage)\n');
    expect(revisionJson({ ...summary, recovered: true }).recovered).toBe(true);
  });

  it('says a recovered genesis is an existing lineage, and how to start a separate one', () => {
    expect(existingLineageNote(new Uint8Array(32).fill(0xaa))).toEqual(
      `This genesis was already certified: the token file holds revision 0 of the existing lineage ${'aa'.repeat(32)}, ` +
        'not a new one. To start a separate lineage from the same document, name a different first producer ' +
        '(or sign with a different issuer key).\n',
    );
  });

  it('explains a superseded genesis: when the lineage moved on, to whom, and what still holds', () => {
    const message = supersededLineageMessage(new Uint8Array(32).fill(0xaa), 1791200527n, producer);
    expect(message).toEqual(
      `Revision 0 of lineage ${'aa'.repeat(32)} was certified by an earlier run, and the lineage has moved on: ` +
        `revision 1 was certified at 2026-10-05T11:42:07Z by the next producer ${TEST_PUBLIC_KEY_HEX}. ` +
        'A token file holding only revision 0 would be out of date, so none was written. Get the current token ' +
        'file from whoever holds the lineage; the token id above still identifies the lineage. To start a ' +
        'separate lineage from the same document, name a different first producer (or sign with a different ' +
        'issuer key).',
    );
    expect(supersededLineageMessage(new Uint8Array(32), 1791200527n, null)).toContain(
      'revision 1 was certified at 2026-10-05T11:42:07Z. A token file',
    );
  });

  describe('pending revision notes', () => {
    const note = {
      digest: TEST_DIGEST,
      journalFile: '/docs/.doc.lineage.pending',
      nextProducer: next,
      revision: 3n,
      tokenId: new Uint8Array(32).fill(0xaa),
    };
    const id = 'aa'.repeat(32);

    it('lists the revision, its journal and how to recover it before it is submitted', () => {
      expect(pendingRevisionLines(note, 'submitting')).toEqual(
        [
          `Submitting revision 3 of lineage ${id}:`,
          `  Stamped        SHA-256 ${TEST_DIGEST_HEX}`,
          `  Next producer  ${HexConverter.encode(next)}`,
          '  Journal        /docs/.doc.lineage.pending',
          'If this run is interrupted, run stamp-revision on the same token file again to recover the revision;',
          'without the journal, run it with this digest and next producer.',
          '',
        ].join('\n'),
      );
    });

    it('says what a rejected or recovered revision held, without the recovery advice', () => {
      const sealed = { ...note, nextProducer: null };
      expect(pendingRevisionLines(sealed, 'rejected')).toEqual(
        [
          `Revision 3 of lineage ${id}, as this run submitted it (not certified):`,
          `  Stamped        SHA-256 ${TEST_DIGEST_HEX}`,
          '  Next producer  none; the lineage is finalized (sealed and burned)',
          '',
        ].join('\n'),
      );
      expect(pendingRevisionLines(note, 'recovered')).toMatch(
        new RegExp(`^Recovered revision 3 of lineage ${id}, certified by an interrupted run:\n`),
      );
      expect(pendingRevisionLines(note, 'recovered')).not.toContain('Journal');
    });

    it('notes a recovery from the journal', () => {
      expect(recoveredRevisionLine(3n, '/docs/.doc.lineage.pending')).toEqual(
        'Recovered revision 3 from the journal /docs/.doc.lineage.pending of an interrupted run.\n',
      );
    });
  });
});
