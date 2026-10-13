# Unicity Timestamp CLI

Timestamping service on Unicity network. Tokens are standard Unicity tokens produced with the [state transition SDK](https://github.com/unicitynetwork/state-transition-sdk-js).

## Requirements

- Node.js 22 or newer. Nothing else: every dependency is plain JavaScript.
- A Unicity gateway API key for stamping, from <https://sphere.unicity.network/>. Verifying needs no key.

## Installation

```bash
npm install -g @unicitylabs/timestamp-cli
unicity-timestamp --help
```

Or run it without installing:

```bash
npx @unicitylabs/timestamp-cli --help
```

To work from a checkout instead:

```bash
git clone https://github.com/unicitynetwork/timestamp-cli.git
cd timestamp-cli
npm install         # builds through the prepare script
npm link            # optional: puts `unicity-timestamp` on your PATH
```

## Configuration

Arguments are loaded, in order of precedence, from: flags > variables in shell memory > `.env` file in the current directory > hardcoded defaults.

| Variable | Flag | Meaning | Default |
| --- | --- | --- | --- |
| `UNICITY_API_KEY` | `--api-key` | Gateway API key. Needed by `stamp` only. | none |
| `UNICITY_NETWORK` | `--network` | `mainnet` or `testnet2`. Selects the gateway and the bundled trust base for `stamp`. `verify` reads the network from the token; only its `--network` flag overrides that. | `mainnet` |
| `UNICITY_PRIVATE_KEY` | `--key-file` | secp256k1 private key, 64 hex characters. When set, stamps are signed. | none, stamps are anonymous |
| `UNICITY_GATEWAY_URL` | `--gateway` | Override the gateway URL only. | preset gateway |
| `UNICITY_TRUST_BASE` | `--trust-base` | Override the bundled trust base file. **Not** read from an automatically discovered `./.env` — see below. | bundled file |
| `UNICITY_TIMEOUT` | `--timeout` | Seconds to wait for the inclusion proof. At most `2147483`, the longest delay a Node timer can hold. | `60` |
| | `--out` | Where `stamp` writes the token. `-` writes it to stdout, or, with `--json`, puts the JSON object there instead. | `token_<first 16 hex of digest>.cbor` in the current directory |
| | `--dotenv` | Load this env file instead of `./.env`. | `./.env` if present |

A `.env.example` is in the repository.

`UNICITY_TRUST_BASE` is the one exception to the precedence above. It names the
root of trust, which decides what every verification means, so it is ignored when
it comes from a `./.env` that was merely found in the working directory — a token
shipped next to a `.env` would otherwise verify against whatever trust base the
sender chose. When that happens the CLI says so on stderr and uses the bundled
pin. The flag, an explicit `--dotenv`, and a real environment variable all work
as the table says.

## Usage

### Stamp

```bash
unicity-timestamp stamp <sha256-hex>              # hash supplied
unicity-timestamp stamp --file <path>              # hash computed locally
unicity-timestamp stamp --file document.pdf --out document.cbor
unicity-timestamp stamp --file document.pdf --network testnet2
unicity-timestamp stamp --file document.pdf --timeout 120
unicity-timestamp stamp --file document.pdf --json > stamp.json
```

A stamp prints a summary and writes the token to `--out`, by default `token_<first 16 hex characters of the digest>.cbor` in the current directory. The token file is the receipt; keep it with the document.

```
Stamped        SHA-256 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
Network        mainnet (1) via https://gateway.mainnet.unicity.network
Signer         none (anonymous stamp)
Certified at   2026-10-05T11:42:07Z  (reference time 1791200527)
Round          184233  (round timestamp 1791200531, epoch 1)
Token id       321276fcfb19a925b6e5050d5d5de15c82c56dfe7650cc8d0ae6cf7fc336470d
Written        ./token_2cf24dba5fb0a30e.cbor
```

The hash is 64 hex characters, upper or lower case, with or without a `0x` prefix. `--out -` writes the raw token bytes to stdout, and the summary to stderr, so the two can be separated. With `--out - --json` the JSON object goes to stdout instead and the raw bytes are not written: the object already carries the token as hex in `token`. Existing files are not overwritten unless you pass `--force`.

The destination is checked before the request goes out, so a mistyped or
unwritable `--out` fails with exit code 2 while nothing has been spent.

If the inclusion proof does not arrive within the timeout, `stamp` exits with code 3 and nothing is written. The network may still certify the request, but the CLI does not track it: run `stamp` again, or raise `--timeout` on a slow connection. A gateway answer of HTTP 429 means the API key's quota is exhausted for now; that is also exit code 3.

Should the write fail anyway — a full disk, or permissions changing underneath —
the stamp has already been certified and paid for, so the token is printed to
stderr as hex rather than lost. `verify` and `inspect` both accept hex, so saving
that text recovers the stamp in full; there is no need to stamp again.

### Signed stamps

By default a stamp proves only that the hash existed. To also prove that *you* stamped it, sign with a key:

```bash
unicity-timestamp keygen --out my.key                 # once; mode 0600, 64 hex characters
unicity-timestamp stamp --file document.pdf --key-file my.key
```

`keygen --out -` prints the private key to stdout instead of writing a file, as
a bare hex line or, with `--json`, as the object's `privateKey`. That field is
present on this path only: a key written to a file stays in the file, and the
JSON reports its path and public key alone.

Or put `UNICITY_PRIVATE_KEY=<64 hex>` in `.env` and every stamp is signed. Two flags control this explicitly:

- `--sign` fails with exit code 2 unless a key is configured. Use it in scripts that must never produce an anonymous stamp.
- `--anonymous` produces an unsigned stamp even when a key is configured.

The signer's compressed public key is printed on every `stamp` and `verify`, as `Signer`, or `none` for anonymous stamps. Publish your public key wherever people need to recognise it; the key alone does not say who you are.

### Verify

```bash
unicity-timestamp verify document.cbor                      # is this a valid Unicity timestamp?
unicity-timestamp verify document.cbor --file document.pdf  # ...and is it for this file?
unicity-timestamp verify document.cbor --hash 2cf24dba…9824 # ...or for this digest?
cat document.cbor | unicity-timestamp verify -              # from stdin; binary or hex
```

```
Status         OK  (inclusion proof, consensus signatures and payload verified against the bundled mainnet trust base)
Network        mainnet (1)
Trust base     bundled mainnet pin
Hash           SHA-256 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
Expected hash  matches
Signer         031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
Certified at   2026-10-05T11:42:07Z  (reference time 1791200527)
Round          184233  (round timestamp 1791200531, epoch 1)
Token id       321276fcfb19a925b6e5050d5d5de15c82c56dfe7650cc8d0ae6cf7fc336470d
```

Verification is offline. The CLI picks the trust base that matches the token's network, so a testnet2 token verifies without flags. The first line is the verdict: `Status OK` with exit code 0, or `Status FAIL: <reason>` with exit code 1. Without `--file` or `--hash` the token is checked for validity only; the `Expected hash` line reminds you that it was not tied to a document.

The `Trust base` line says which root of trust produced that verdict — `bundled <network> pin`, or the path of an override. It is worth reading: a verdict is only as good as the trust base behind it, and `OK` against someone else's trust base means nothing. For that reason the root of trust is never taken from a `.env` file found in the working directory; pass `--trust-base` to choose one deliberately.

### Inspect

```bash
unicity-timestamp inspect document.cbor
```

Prints the same fields as `verify` without checking anything, under an `UNVERIFIED` banner. Useful for looking at tokens from other networks or other token types.

### Scripting

Every command accepts `--json` and prints one JSON object on stdout; everything else goes to stderr. Large integers are decimal strings. `referenceTimeIso` is null when the token carries a reference time no date can represent; `referenceTime` always holds the raw value.

```bash
unicity-timestamp verify document.cbor --file document.pdf --json | jq -r .referenceTimeIso
```

| Exit code | Meaning |
| --- | --- |
| 0 | Success. For `verify`: valid, and the hash matched if one was given. |
| 1 | Verification failed, hash mismatch, or the input is not a token. |
| 2 | Usage or configuration error. |
| 3 | Network error, aggregator rejection, or timeout. |
| 130 | Interrupted. |

### Testnet and custom gateways

```bash
unicity-timestamp stamp --file document.pdf --network testnet2 --api-key sk_ddc3cfcc001e4a28ac3fad7407f99590
unicity-timestamp stamp --file document.pdf --gateway https://gateway.example --trust-base ./bft-trustbase.json
unicity-timestamp stamp --file document.pdf --gateway http://localhost:3000 --allow-insecure   # local aggregator only
```

The testnet2 key above is the shared public demo key published in the [sphere-sdk README](https://github.com/unicity-sphere/sphere-sdk/blob/main/README.md#api-key), where it is documented as public rather than secret; capacity is shared, so get your own key for sustained use. Trust bases for mainnet and testnet2 ship inside the package. The CLI never downloads a trust base at run time.

## What a stamp proves

A verified token shows that a transaction containing your hash was certified by the Unicity Network in a specific round, and records the round's reference time, which is at or before the consensus-signed round timestamp. If the stamp is signed, it also shows that the holder of the printed key signed the hash, and that this signature existed no later than the certified time.

It does not prove when the aggregator *received* the request. The proof authenticates the time the aggregator recorded; the guarantee that this time is honest rests on the network's consensus layer, the same way a classic timestamp authority's receipt rests on the authority. The protocol specification states this explicitly.

## Development

```bash
npm ci
npm run build
npm test            # builds, then runs the unit suite and the end-to-end suites
npm run lint
```

There are two test layers. Unit tests exercise the library and the CLI logic offline, using the SDK's in-memory aggregator for genuine certified transactions. End-to-end tests run the built binary: an offline suite that always runs, and a network suite that stamps on a real network and **skips itself unless a test key is configured**:

```bash
# .env (gitignored) or the shell. Deliberately not UNICITY_API_KEY, so tests never spend the production key.
UNICITY_TEST_API_KEY=sk_your_test_key
UNICITY_TEST_NETWORK=testnet2            # or mainnet

npm run test:e2e                                   # network suite runs when the key is set
UNICITY_E2E_WRITE_FIXTURES=1 npm run test:e2e      # also refreshes tests/fixtures/<network>-*.cbor
```

CI has no key, so the network suite is skipped there. A free testnet2 key comes from <https://sphere.unicity.network/> or from the gateway's wallet-auth endpoints, `POST /auth/challenge` and `POST /auth/verify`, documented in the [aggregator-subscription](https://github.com/unicitynetwork/aggregator-subscription) repository. Note that the mainnet free plan currently allows no requests at all, so mainnet stamping needs a paid key.

## Design decisions

- **Stamps are not transferable, and nobody owns them.** The token's recipient predicate is the SDK's burn predicate, which no key can ever unlock. A timestamp is an attestation, not an asset; moving it would prove nothing and would only invite wallets to treat it as something owned. Wallets never see these tokens anyway: Unicity has no token discovery, and a burn-locked token fails every wallet's ownership check.
- **Identity is carried in the stamp, not in ownership.** The payload holds the signer's public key and a signature over the hash. `stamp` adds them when a key is configured (`--key-file` or `UNICITY_PRIVATE_KEY`); `--sign` insists on it and `--anonymous` suppresses it. The mint itself is signed by the SDK's universal mint key, so a recipient key alone would prove nothing; the payload signature is what turns "a token exists" into "this key attested this hash".
- **Anonymous by default.** Every established timestamping service, from RFC 3161 authorities to OpenTimestamps, takes a bare hash. Identity, when wanted, is added by signing first and timestamping the signature. This tool does the same.
- **One fixed token type, one payload format.** All timestamps share a token type and a four-element CBOR payload: version, 32-byte digest, optional signer, optional signature. A dedicated issuance verifier checks the payload during the SDK's own token verification, and the verifier registry stays fail-closed.
- **Verification is offline against pinned trust bases.** Trust bases for mainnet and testnet2 ship inside the package and are refreshed by a reviewed script. Fetching the root of trust from the network being verified would defeat the purpose.
- **`stamp` is stateless.** If the proof does not arrive in time, run it again. An abandoned request costs one API call and nothing else. A resume feature was considered and rejected as not worth a stateful CLI.
- **The time reported is the round's reference time.** It is bound into the certified leaf and checked by the SDK against the consensus-signed round timestamp. Both are printed.
- **Thin wrapper, minimal footprint.** Node 22, the SDK and `commander`. No native modules, no dotenv, no runtime downloads. The tool lives in its own repository and depends on the published SDK, exactly as users do.

## Appendix

### Token file format

A token file is the raw CBOR of the SDK's `Token.toCBOR()`, with no wrapper around it. It is the same encoding Sphere wallets use on the wire, so any SDK-based tool reads it with `Token.fromCBOR()`. Outermost first:

```
tag 39040 [ version = 2, genesis, transfers ]
  transfers = []                                 always empty: the token is burn-locked
  genesis   = [ mintTransaction, inclusionProof ]

  mintTransaction = tag 39041 [ version = 2, networkId, recipient, salt, tokenType, justification, data, expiresAt ]
    networkId       1 for mainnet, 4 for testnet2
    recipient       tag 39032 [ engine = 1, code = bstr(02), reason = bstr("unicity-timestamp") ]   burn predicate
    salt            bstr(32), random; the token id is SHA-256(CBOR[salt, networkId])
    tokenType       bstr(32) = SHA-256("unicity-timestamp") = dd671898…1ee16193
    justification   null
    data            bstr holding the timestamp payload, see below
    expiresAt       null, the deadline is assigned by the service

  inclusionProof = tag 39033 [ version = 1, certificationData, referenceTime, inclusionCertificate, unicityCertificate ]
    referenceTime   Unix seconds; the certified time, printed as "Certified at"
    inclusionCertificate         sparse Merkle tree path proving the leaf under the certified root
    unicityCertificate           consensus certificate; its inputRecord.timestamp is the round timestamp,
                                 always >= referenceTime, and its seal carries the validator quorum signatures
```

The timestamp payload, the bytes inside `data`:

```
[ version = 1,     uint
  digest,          bstr(32)   the SHA-256 digest that was stamped
  signer,          bstr(33)   compressed secp256k1 public key, or null
  signature ]      bstr(65)   recoverable secp256k1 signature r‖s‖recovery, or null
```

- `signer` and `signature` are both present or both null. Both null is an anonymous stamp.
- The signature covers `SHA-256(CBOR["unicity-timestamp", 1, digest])`, not the bare digest, so it cannot be mistaken for a signature over the digest in another protocol.
- An anonymous payload for digest `2cf24dba…938b9824` is 38 bytes: `84 01 5820 <32 digest bytes> f6 f6`.

Verification runs the SDK's checks on the genesis: transaction hash and certification data match the proof, `referenceTime` does not exceed the round timestamp, the Merkle path leads to the certified root, the shard matches, the unicity certificate's quorum signatures verify against the pinned trust base, and the mint unlock script is valid. On top of that the CLI's issuance policy requires the burn recipient, no justification, a payload that decodes, which includes a valid signer key, and a verifying signature.

### Deferred decisions

These are recorded here so they are not forgotten; none blocks using the tool.

1. **Token type registration.** The timestamp token type is fixed and deterministic:

   ```
   TIMESTAMP_TOKEN_TYPE = SHA-256("unicity-timestamp")
                        = dd671898ac55e0a3a9e22f07120cef94943d25fdf1dd0485aab077b21ee16193
   ```

   Reproduce it with `printf 'unicity-timestamp' | shasum -a 256`. Registering this id in the [unicity-ids](https://github.com/unicitynetwork/unicity-ids) token registry, so wallets and explorers can label it, is deferred until the format has settled. The id itself does not change when that happens; the payload carries its own version number.
