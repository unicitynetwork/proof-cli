# Rename to @unicitylabs/proof-cli

Date: 2026-10-14
Status: approved

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

Subcommands (`stamp`, `verify`, `inspect`, `keygen`), flags and `UNICITY_*`
environment variables do not change.

0.2.0 rather than 0.1.3: the install command changes, which is the most
user-visible break the project has had. The project stays on 0.x.

Two things break for users:

- the binary name, `unicity-timestamp` to `unicity-proof`;
- the default key file `keygen` writes when given no `--out`,
  `unicity-timestamp.key` to `unicity-proof.key`. A script that runs `keygen`
  and then passes `--key-file unicity-timestamp.key` fails with "Cannot read key
  file" until it is updated. Nothing in the code reads the default — signing
  resolves a key from `--key-file` or `UNICITY_PRIVATE_KEY` — so the break is
  confined to scripts that hardcode the old name.

## The identifier that does not move

`TIMESTAMP_TAG = 'unicity-timestamp'` in `src/lib/constants.ts` is the wire
identifier of the token format, not a label. Three things derive from it:

- the token type is its SHA-256, `dd671898ac55e0a3a9e22f07120cef94943d25fdf1dd0485aab077b21ee16193`,
  and the issuance verifier is registered for exactly that type;
- the burn predicate's reason bytes are its UTF-8 encoding, so it determines the
  recipient every timestamp token is locked to;
- it is the domain tag inside the signed message,
  `SHA-256(CBOR["unicity-timestamp", 1, digest])`.

Changing it produces a different token type, a different recipient and a
different signature domain. Every stamp already certified on mainnet and
testnet2 would stop verifying, with no migration available: those bytes are
final.

**The tag stays `unicity-timestamp` permanently.** The brand and the wire format
therefore disagree on purpose. A reader who renames the constant to match the
product name breaks every existing proof.

This change adds a sentence to the comment on `TIMESTAMP_TAG` saying so. The
comment currently explains only why the tag carries no version, which is not
what a contributor doing a consistency sweep needs to read.

The same freeze covers every other place the tag appears as a format
description, none of which may be touched by a search and replace:

- `src/lib/TimestampPayload.ts`, the two comments spelling out the signed
  message;
- `README.md` section `### Token file format`, which gives the burn reason as
  `bstr("unicity-timestamp")`, the token type as `SHA-256("unicity-timestamp")`,
  and the signature domain;
- `README.md` section `### Deferred decisions`, which derives the token type
  again and tells the reader to reproduce it with
  `printf 'unicity-timestamp' | shasum -a 256`.

A file-wide replace through the README would leave the appendix documenting a
burn reason, token type and signature domain that no token has.

## What changes

Brand and user-visible surface:

- `package.json`: `name`, `bin`, `description`, `keywords`, `repository`,
  `homepage`, `bugs`
- `package-lock.json`: the package name at the root and in the `""` package entry
- `src/cli.ts`: `.name()`, `.description()` — the sentence `--help` prints — and
  the `--out` help text naming the default key file
- `src/output.ts`: the recovery hint printed when a certified stamp cannot be
  written. It tells the reader which command recovers the token from the hex on
  stderr, so a stale binary name there costs a paid-for stamp
- `src/commands/keygen.ts`: `DEFAULT_KEY_FILE`
- `.github/workflows/npm.yml`: the registry pre-check, the release-notes URL,
  and the trusted-publisher instructions in the header comment
- `scripts/update-trust-bases.mjs`: the `User-Agent` sent to GitHub
- `.env.example`
- `README.md` everywhere except the two frozen sections above
- `tests/`: `describe` titles and `tempDir` prefixes

## What stays

Internal vocabulary keeps the format's name: the `TIMESTAMP_*` constants,
`TimestampPayload`, `TimestampClient`, `ITimestampDescription`, and the file
names. These identify the format, which is not being renamed.

The convention this establishes: `TIMESTAMP_*` means the wire format and is
frozen; `proof` means the product and is free to change.

## Migration

The package rename and the repository rename are separable. The package rename
needs no organisation admin and carries no redirect risk; the repository rename
needs both. The new package needs its own trusted publisher either way — only
its repository value differs — so neither rename avoids that step.

### Package rename

npm's trusted publishing cannot create a package name the publisher does not
already own, so one publish has to happen by hand. That publish is a
prerelease whose only purpose is to make the name exist, which keeps the real
0.2.0 on the audited path.

1. Land the rename. The release workflow owns versions, so the rename commit
   carries no bump and stays at 0.1.2.
2. Bootstrap the name by hand: `npm version 0.2.0-rc1 --no-git-tag-version`,
   which regenerates `src/version.ts` through the `version` lifecycle script and
   keeps `VersionTest` green, then `npm publish --access public --tag next`.
   Discard the local bump afterwards.

   **`--tag next` is required.** npm points `latest` at whatever it publishes,
   prerelease or not, so without it a plain `npm install @unicitylabs/proof-cli`
   would hand everyone a release candidate. The workflow derives the same tag
   from the version itself; this publish is the one that does not go through it.

3. Configure the new package's trusted publisher: the repository as it is named
   at the time, workflow `npm.yml`, environment `npm-publish`.
4. Run the release workflow with `0.2.0` as the explicit version input. It
   bumps, builds, tests, publishes to `latest`, pushes the bump with its tag and
   creates the release.
5. `npm deprecate @unicitylabs/timestamp-cli "Renamed to @unicitylabs/proof-cli"`.
   The old versions stay installable. Unpublishing would break existing
   lockfiles.
6. Optionally `npm dist-tag rm @unicitylabs/proof-cli next` once 0.2.0 is on
   `latest`.

Publishing 0.2.0 from the workflow rather than by hand is what earns it a
provenance attestation: 0.1.2, released through the workflow, carries an SLSA
predicate, and 0.1.0, published by hand to bootstrap the current name, carries
none. Under this order the unattested artifact is a release candidate on a tag
nothing resolves by default.

### Repository rename

7. Rename the repository on GitHub. Requires organisation admin. Update the
   remote in any working copy.
8. Re-point the new package's trusted publisher at the new repository name, if
   step 3 ran before the rename.

GitHub redirects the old paths only until a repository with the old name is
created in the organisation, so the redirect is not a permanent guarantee. Every
published 0.1.x tarball carries `repository`, `homepage` and `bugs` URLs naming
the old repository for as long as anyone installs those versions.

Steps 2, 3, 5, 6, 7 and 8 need registry or organisation credentials.

## Verification

The regression that matters is that a token certified before the rename still
verifies after it. Two layers cover the frozen tag:

- `ConstantsTest` pins the SHA-256 of the tag against the token type hex, the
  burn-reason bytes, and the encoded recipient predicate. A renamed tag fails the
  unit suite before any fixture is read.
- `tests/fixtures/testnet2-*.cbor` were certified before the rename and carry the
  tag in their burn reason, so the offline end-to-end suite proves that real
  tokens minted by the old release still verify.

**Do not run `UNICITY_E2E_WRITE_FIXTURES=1` as part of this change.** It would
replace the pre-rename evidence with tokens minted by the code under test. That
would not hide a renamed tag, since `ConstantsTest` catches it, but it would
discard the only artifacts in the repository that predate the change.

Also required:

- the full suite and lint on Node 22 and 24
- `npm pack` on the renamed package, checking the `bin` entry resolves to
  `unicity-proof` and the tarball contents match a dry run
- `unicity-proof verify` against both committed fixtures, and against a token
  stamped by `@unicitylabs/timestamp-cli@0.1.2` from the registry

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

| Risk                                                     | Mitigation                                                                                                                          |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| The frozen tag is renamed later for consistency          | A sentence at the constant, the frozen-section list above, and `ConstantsTest`                                                      |
| The README appendix is caught by a file-wide replace     | Both sections named as frozen above; review the README diff line by line                                                            |
| `latest` ends up on a release candidate                  | The bootstrap publish passes `--tag next`; 0.2.0 reaches `latest` only through the workflow, which derives the tag from the version |
| Releases break after the repository rename               | Step 8                                                                                                                              |
| Users on the old package never learn of the move         | Step 5's deprecation message appears on install                                                                                     |
| 0.2.0 ships without a provenance attestation             | Only the bootstrap prerelease is published by hand; 0.2.0 comes from the workflow                                                   |
| The old repository name is recreated, breaking redirects | Do not create a repository named `timestamp-cli` in the organisation                                                                |
