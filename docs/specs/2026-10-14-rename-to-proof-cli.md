# Rename to @unicitylabs/proof-cli

Date: 2026-10-14
Status: approved, not yet implemented

## Why

The product is being positioned around proofs that software agents produce —
attesting a tool call, a model output, an agent's identity — rather than around
timestamping a document. The current name describes the first use case and not
the direction, so the package, the binary and the repository are renamed.

Agent-specific fields are a later payload version, not part of this change. See
"Out of scope".

## Decision

|             | Before                         | After                      |
| ----------- | ------------------------------ | -------------------------- |
| npm package | `@unicitylabs/timestamp-cli`   | `@unicitylabs/proof-cli`   |
| binary      | `unicity-timestamp`            | `unicity-proof`            |
| repository  | `unicitynetwork/timestamp-cli` | `unicitynetwork/proof-cli` |
| version     | 0.1.2                          | 0.2.0                      |

Subcommands do not change: `stamp`, `verify`, `inspect`, `keygen`. Every
documented invocation and any script a user already has keeps working apart
from the binary name, and the diff stays about the name.

`UNICITY_*` environment variables do not change.

0.2.0 rather than 0.1.3: the install command changes, which is the most
user-visible break the project has had. The project stays on 0.x.

## The identifier that does not move

`TIMESTAMP_TAG = 'unicity-timestamp'` in `src/lib/constants.ts` is the wire
identifier of the token format, not a label. Three things derive from it:

- the token type is its SHA-256, `dd671898ac55e0a3a9e22f07120cef94943d25fdf1dd0485aab077b21ee16193`,
  and the issuance verifier is registered for exactly that type;
- the burn predicate's reason bytes are its UTF-8 encoding, so it determines the
  recipient every timestamp token is locked to;
- it is the domain tag inside the signed message, `SHA-256(CBOR["unicity-timestamp", 1, digest])`.

Changing it produces a different token type, a different recipient and a
different signature domain. Every stamp already certified on mainnet and
testnet2 would stop verifying, with no migration available: those bytes are
final.

**The tag stays `unicity-timestamp` permanently.** The brand and the wire format
therefore disagree on purpose. A reader who renames the constant to match the
product name breaks every existing proof.

The same applies to the two comments in `src/lib/TimestampPayload.ts` that spell
out the signed message. They document bytes that already exist.

## What changes

Brand and user-visible surface:

- `package.json`: `name`, `bin`, `description`, `keywords`, `repository`,
  `homepage`, `bugs`
- `src/cli.ts`: the `.name()` passed to Commander, and the `--out` help text
  naming the default key file
- `src/output.ts`: the recovery hint printed when a certified stamp cannot be
  written. It tells the reader which command recovers the token from the hex on
  stderr, so a stale binary name there costs a paid-for stamp
- `src/commands/keygen.ts`: `DEFAULT_KEY_FILE`
- `.github/workflows/npm.yml`: the registry pre-check, the release-notes URL,
  and the trusted-publisher instructions in the header comment
- `scripts/update-trust-bases.mjs`: the `User-Agent` sent to GitHub
- `.env.example`, `README.md`
- `tests/`: `describe` titles and `tempDir` prefixes

`DEFAULT_KEY_FILE` is safe to change. Nothing reads it; `keygen` only writes it,
and signing resolves a key from `--key-file` or `UNICITY_PRIVATE_KEY`.

## What stays

Internal vocabulary keeps the format's name: the `TIMESTAMP_*` constants,
`TimestampPayload`, `TimestampClient`, `ITimestampDescription`, and the file
names. These identify the format, which is not being renamed.

The convention this establishes: `TIMESTAMP_*` means the wire format and is
frozen; `proof` means the product and is free to change.

## Migration order

1. Rename the repository on GitHub. Requires organisation admin. Web and git
   redirects are permanent; working copies should still have their remote
   updated.
2. Land the rename: code, docs and workflow strings, reviewed as one change.
3. Publish `@unicitylabs/proof-cli@0.2.0` manually. npm's trusted publishing
   cannot create a package name the publisher does not already own, so the first
   publish of a new name cannot come from CI.
4. Configure the new package's trusted publisher: repository
   `unicitynetwork/proof-cli`, workflow `npm.yml`, environment `npm-publish`.
   The binding is per package and per repository name, so nothing from the old
   package's configuration carries over.
5. Cut one release through the workflow to prove step 4.
6. `npm deprecate @unicitylabs/timestamp-cli "Renamed to @unicitylabs/proof-cli"`.
   The old versions stay installable. Unpublishing would break existing
   lockfiles.

Steps 1, 3, 4 and 6 need registry or organisation credentials.

## Verification

The regression that matters is that a token minted by the old CLI still verifies
under the new one. `tests/fixtures/testnet2-*.cbor` were certified before the
rename and carry the frozen tag in their burn reason, so the offline end-to-end
suite already proves it.

**Do not run `UNICITY_E2E_WRITE_FIXTURES=1` as part of this change.** Those
fixtures are the only evidence the tag held. Regenerating them would make the
test agree with whatever the change broke.

Also required:

- the full suite and lint on Node 22 and 24
- `npm pack` on the renamed package, checking the `bin` entry resolves to
  `unicity-proof` and the tarball contents match a dry run
- `unicity-proof verify` against both committed fixtures, and against a token
  stamped by 0.1.2 from the registry

## Out of scope

Agent-specific payload fields — identity, tool-call or model-output references —
are payload version 2. The payload is `[version, digest, signer, signature]`
with its own version field, and the signed message includes that version, so v2
can be added under the same token type and the same frozen tag, and a v2
signature cannot be replayed as v1.

It is sequenced after the rename because the verifier rejects any version but 1:
a v2 token is unverifiable by every installed CLI. Shipping both at once would
make "your install is old" and "the rename broke something" indistinguishable
from the user's side.

## Risks

| Risk                                             | Mitigation                                                                 |
| ------------------------------------------------ | -------------------------------------------------------------------------- |
| The frozen tag is renamed later for consistency  | Documented here and at the constant; the fixtures fail if it moves         |
| Releases break after the repository rename       | Step 4; the old package needs no further release, so its binding can lapse |
| Users on the old package never learn of the move | Step 6's deprecation message appears on install                            |
