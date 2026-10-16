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

Also read the `Trust base` line. A verdict is only as good as the root of trust
behind it, and `OK` against someone else's trust base means nothing.

## Stamping

The token file **is** the receipt. Default name is
`token_<first 16 hex of the digest>.cbor`; keep it with the document, because
without it the proof is gone.

- **Exit 3 covers several failures and only one is ambiguous.** A timeout
  waiting for the inclusion proof is the only case that can leave the request
  certified while nothing was written locally; there, re-running spends quota
  again. `Could not reach the gateway`, `Gateway returned HTTP ...`,
  `Gateway rate limit reached`, `Gateway refused the API key` and
  `Aggregator rejected the certification request` all certified nothing — fix
  the cause rather than retrying blind. The stderr message says which happened.
- **A failed write after certification is recoverable.** The token is printed to
  stderr as hex, and both `verify` and `inspect` accept hex, so save that text.
  Do not re-stamp.
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
| `0` | Success. For `verify`: valid, and the hash matched if one was given. |
| `1` | Verification failed, hash mismatch, or the input is not a token. |
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
