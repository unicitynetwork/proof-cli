---
name: unicity-proof
description: Use when stamping a file or digest to prove it existed at a point in time, when verifying or checking an existing proof or .cbor timestamp token, or when generating a signing key for stamps. Covers the hash-binding, exit-code and trust-base traps in the unicity-proof CLI.
---

# Unicity Proof CLI

Stamps a SHA-256 digest into a Unicity token, proving the digest existed at a
certified time. Verification is fully offline. Stamping needs `UNICITY_API_KEY`;
`verify` and `inspect` need nothing.

## Verifying: the mistake that matters

`unicity-proof verify token.cbor` proves the token is a valid timestamp. It does
**not** prove it is a timestamp *of your document*. Whenever you hold the
document, bind the two:

```bash
unicity-proof verify token.cbor --file document.pdf   # or --hash <64 hex>
```

Then read `Expected hash  matches`. Without `--file` or `--hash` that line tells
you the proof was never tied to anything — a bare `Status OK` on its own
establishes nothing about the file in front of you.

A document lineage token (from `stamp-revision`, `Token type  document lineage`)
holds several revisions. With `--file` it passes if **any** revision carries the
file's hash, so read the `Expected hash` line in full: `matches revision 1;
superseded by revision 2` means the file is a genuine but outdated revision.
`matches revision 2 (the final)` means the lineage was finalized with that
revision (`--finalize`); no later revision can exist. `matches revision 2 (the
latest in this file)` does **not** mean the file is current: any older copy of
an unsealed lineage still verifies, and verification is offline, so later
revisions may have been certified since. Only `(the final)` rules them out; if
being current matters, ask whoever holds the lineage for the current file.

A matching hash does not say *which* lineage the file is in: one issuer can
start several certified lineages from the same document. Only the token id
identifies a lineage, so verify with `--token-id <id>`, using the id the
issuer gave you through a channel you trust, and read the `Lineage id` line:
`matches` ties the result to that lineage; `not checked` means the `Issuer`
and `Expected hash` lines are not enough on their own; `differs` means this
is another lineage.

Also read the `Trust base` line. A verdict is only as good as the root of trust
behind it, and `OK` against someone else's trust base means nothing.

## Stamping

The token file **is** the receipt. Default name is
`token_<first 16 hex of the digest>.cbor`; keep it with the document, because
without it the proof is gone.

- **Exit 3 usually cannot tell you whether anything was certified.** `stamp`
  submits the request before it waits for the inclusion proof, so a timeout, a
  dropped connection or an HTTP error can all arrive after the network already
  accepted it — and the CLI does not track the request, so it cannot say.
  Assume it may have been certified: re-running spends quota again and can
  produce a second token over the same digest. The one unambiguous message is
  `Aggregator rejected the certification request`, where the aggregator refused
  outright and nothing was certified. Always fix
  `Gateway refused the API key` before retrying at all.
- **A failed write after certification is recoverable.** The token is printed to
  stderr as hex, and both `verify` and `inspect` accept hex, so save that text.
  Do not re-stamp.
- **An interrupted `stamp-revision` append is recoverable; do not improvise.**
  Run `stamp-revision` again on the same token file: it recovers the revision
  from the `.<name>.pending` journal next to the token file. Never delete that
  journal by hand; until the token file holds the revision, it is the only
  record of what was certified. Exit 1 with `already certified with different
  content` means an earlier run certified something else for this revision:
  only that run's digest and recipient recover it, and they are on stderr from
  when it was submitted.
- **`(existing lineage, recovered)` means no new lineage was created.** The
  same issuer key, document and first producer always give the same lineage.
  If `stamp-revision` exits 1 saying `the lineage has moved on`, later
  revisions exist: get the current token file from whoever holds the lineage
  rather than creating it again.
- `--sign` exits 2 unless a key is configured. Use it in any automated path that
  must never silently produce an anonymous stamp. `--anonymous` forces the
  opposite.

## Stamp before the outcome is known

A stamp is evidence only if it was made before the thing it commits to could be
known. Stamp first and reveal later; stamping after the fact proves nothing
about foresight.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `verify`: valid, and the hash (and, for a lineage, the token id) matched if one was given. |
| `1` | Verification failed, hash or token id mismatch, or the input is not a token. For `stamp-revision`: the revision was already certified with different content, or a recovered genesis's lineage has moved on. |
| `2` | Usage or configuration error. |
| `3` | Network error, aggregator rejection, or timeout. |
| `130` | Interrupted. |

## Machine-readable output

`--json` prints one JSON object on stdout; everything else goes to stderr. Large
integers are decimal strings.

`--out -` writes raw token bytes to stdout with the summary on stderr. With
`--out - --json` the object goes to stdout instead and carries the token as hex
in its `token` field.

## Trust bases

`UNICITY_TRUST_BASE` is deliberately ignored when it comes from a `./.env` that
was merely found in the working directory: a token shipped next to a `.env`
would otherwise verify against whatever root of trust the sender chose. Pass
`--trust-base` explicitly to select one.

Full flag and configuration reference: the project README.
