import { readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { CertificationResponse } from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import type { IAggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/IAggregatorClient.js';
import { InclusionProofResponse } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProofResponse.js';
import { JsonRpcNetworkError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcNetworkError.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { stampRevisionWith } from '../../src/commands/stampRevision.js';
import { IStampRevisionConfig } from '../../src/config.js';
import { EXIT_USAGE, EXIT_VERIFICATION_FAILED, toExitCode } from '../../src/errors.js';
import { appendRevision, prepareRevision } from '../../src/lib/LineageClient.js';
import { verifyLineage } from '../../src/lib/LineageVerification.js';
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
      network: { gatewayUrl: 'https://gateway.test', preset: 'testnet2', trustBase: aggregator.rootTrustBase },
      privateKey: TEST_PRIVATE_KEY,
      quiet: false,
      recipientKey: bobPublic,
      timeoutMs: 2_000,
      tokenBytes: null,
      tokenFile: path.join(directory, 'doc.lineage'),
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
      journal = path.join(directory, '.doc.lineage.pending');
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
      expect(await readdir(directory)).toEqual(['.doc.lineage.pending', 'doc.lineage']);
      expect(new Uint8Array(await readFile(tokenFile))).toEqual(genesisBytes);
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
      expect(sink.stderr()).toContain(`Journal        ${journal}`);
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
  });

  it('refuses a file that is not a token', async () => {
    const attempt = stampRevisionWith(
      config({ tokenBytes: new TextEncoder().encode('hello') }),
      client,
      testContext().context,
    );
    await expect(attempt).rejects.toThrow(/is not a token/);
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
