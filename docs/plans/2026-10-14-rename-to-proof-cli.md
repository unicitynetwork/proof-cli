# Rename to @unicitylabs/proof-cli Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the package to `@unicitylabs/proof-cli` and the binary to `unicity-proof` without touching the token format's wire identifier.

**Architecture:** Every occurrence of the old name falls into one of three buckets — brand surface that changes, wire-format description that must not, and internal vocabulary that keeps the format's name. The tasks are ordered so each one's deliverable is independently testable, and the three user-visible strings (help output, default key file, recovery hint) get failing tests before they are changed.

**Tech Stack:** TypeScript, Commander, Jest, npm, GitHub Actions.

**Spec:** `docs/specs/2026-10-14-rename-to-proof-cli.md`

## Global Constraints

- `TIMESTAMP_TAG = 'unicity-timestamp'` in `src/lib/constants.ts` never changes. The token type is its SHA-256 (`dd671898ac55e0a3a9e22f07120cef94943d25fdf1dd0485aab077b21ee16193`), the burn predicate's reason bytes are its UTF-8 encoding, and it is the domain tag in `SHA-256(CBOR["unicity-timestamp", 1, digest])`.
- These stay byte-identical: the two comments in `src/lib/TimestampPayload.ts` spelling out the signed message; `README.md` lines 226, 228 and 250 under `### Token file format`; `README.md` lines 262 and 266 under `### Deferred decisions`.
- Internal vocabulary keeps the format's name: the `TIMESTAMP_*` constants, `TimestampPayload`, `TimestampClient`, `ITimestampDescription`, and all file names. Do not rename them.
- The version stays `0.1.2`. Do not run `npm version`; the release workflow owns the bump to 0.2.0.
- Subcommands (`stamp`, `verify`, `inspect`, `keygen`), all flags, and every `UNICITY_*` environment variable are unchanged.
- **Never run `UNICITY_E2E_WRITE_FIXTURES=1`.** `tests/fixtures/testnet2-*.cbor` were certified before the rename and are the only artifacts in the repository that predate it.
- Non-goal: no "renamed from" note in the README. The npm deprecation message covers that.

---

### Task 1: Package identity and the frozen-tag note

**Files:**

- Modify: `package.json` (name, bin, description, keywords, repository, homepage, bugs)
- Modify: `package-lock.json` (name at the root and in the `""` package entry, and the `bin` map inside that entry)
- Modify: `src/lib/constants.ts:6-12` (the comment on `TIMESTAMP_TAG`)

**Interfaces:**

- Consumes: nothing.
- Produces: the installed command name `unicity-proof`, which Task 2 makes the CLI's help agree with.

- [ ] **Step 1: Rewrite the package identity**

In `package.json`, set exactly these values and leave `version` at `0.1.2`:

```json
  "name": "@unicitylabs/proof-cli",
  "description": "Create and verify Unicity proofs: certify a SHA-256 hash on the Unicity Network and verify the token offline",
  "bin": { "unicity-proof": "lib/cli.js" },
  "keywords": ["unicity", "proof", "attestation", "timestamping", "proof-of-existence", "agent", "cli"],
  "repository": { "type": "git", "url": "git+https://github.com/unicitynetwork/proof-cli.git" },
  "homepage": "https://github.com/unicitynetwork/proof-cli#readme",
  "bugs": { "url": "https://github.com/unicitynetwork/proof-cli/issues" },
```

`timestamping` and `proof-of-existence` stay in `keywords` on purpose: they are what people search for, and they are still accurate.

- [ ] **Step 2: Update the lockfile's two name fields**

```bash
node -e '
const fs = require("fs");
const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
lock.name = "@unicitylabs/proof-cli";
lock.packages[""].name = "@unicitylabs/proof-cli";
fs.writeFileSync("package-lock.json", JSON.stringify(lock, null, 2) + "\n");
'
```

Then confirm npm agrees the tree is unchanged apart from the name:

Run: `npm ci && git diff --stat package-lock.json`
Expected: no further modifications to `package-lock.json` beyond the two name fields.

- [ ] **Step 3: Record the freeze at the constant**

Replace the comment above `TIMESTAMP_TAG` in `src/lib/constants.ts` with:

```ts
/**
 * The one seed string of the format. The token type is its SHA-256, the burn
 * reason is its UTF-8 bytes, and it is the domain tag of the payload signature.
 * It carries no version on purpose: the payload has its own version field, so
 * this identifier stays stable while the payload format evolves.
 *
 * It is also not the product name, and must never be changed to match it.
 * Renaming it gives every later stamp a different token type, recipient and
 * signature domain, and nothing already certified would verify. The CLI is
 * `unicity-proof`; the format is `unicity-timestamp` and stays so.
 */
export const TIMESTAMP_TAG = 'unicity-timestamp';
```

- [ ] **Step 4: Verify the tag and the packaged binary**

Run: `npx jest tests/unit/lib/ConstantsTest.ts tests/unit/VersionTest.ts`
Expected: PASS — the tag derivation is untouched and the version still matches the manifest.

Run: `node -p "Object.keys(require('./package.json').bin).join()"`
Expected: `unicity-proof`

Run: `npm pack --dry-run 2>&1 | tail -20`
Expected: the tarball name is `unicitylabs-proof-cli-0.1.2.tgz` and the file list is unchanged.

- [ ] **Step 5: Commit**

```bash
git add package.json package-lock.json src/lib/constants.ts
git commit -m "Rename the package to @unicitylabs/proof-cli"
```

---

### Task 2: The three user-visible strings

**Files:**

- Modify: `tests/e2e/CliOfflineTest.ts:26-29` (help assertions), and add one test for the default key file
- Modify: `tests/unit/StampWriteTest.ts:40` (recovery hint assertion)
- Modify: `src/cli.ts:26-27` (`.name()`, `.description()`) and `src/cli.ts:103` (the `--out` help text)
- Modify: `src/commands/keygen.ts:17` (`DEFAULT_KEY_FILE`)
- Modify: `src/output.ts:148` (the recovery hint)

**Interfaces:**

- Consumes: the `unicity-proof` binary name from Task 1.
- Produces: `DEFAULT_KEY_FILE = 'unicity-proof.key'`, and help output containing `unicity-proof`.

- [ ] **Step 1: Write the failing assertions for help output**

In `tests/e2e/CliOfflineTest.ts`, add to the existing `prints help and version` test, after the `-v, --version` assertion:

```ts
// The installed command name and the name the help prints have to agree, or
// the help tells the reader to run something that is not on their PATH. The
// whole usage line is asserted rather than a substring, so a stale name cannot
// hide in it — and the old name is deliberately absent from this file, because
// Task 4 and Task 5 grep the tree for it.
expect(help.stdout.split('\n')[0]).toEqual('Usage: unicity-proof [options] [command]');
```

The `--out` default is a separate string in a different help screen, so it gets
its own assertion. Add this test next to the one above:

```ts
it(
  'names the default key file in the keygen help',
  async () => {
    const keygenHelp = await runCli(['keygen', '--help'], { cwd });
    expect(keygenHelp.code).toBe(0);
    expect(keygenHelp.stdout).toContain('unicity-proof.key');
  },
  TIMEOUT,
);
```

- [ ] **Step 2: Write the failing test for the default key file**

In `tests/e2e/CliOfflineTest.ts`, add a new test. `readdir` and `tempDir` are already imported:

```ts
it(
  'names the default key file after the command',
  async () => {
    const directory = await tempDir('proof-cli-default-key-');
    const result = await runCli(['keygen'], { cwd: directory });
    expect(result.code).toBe(0);
    expect(await readdir(directory)).toEqual(['unicity-proof.key']);
  },
  TIMEOUT,
);
```

- [ ] **Step 3: Write the failing assertion for the recovery hint**

In `tests/unit/StampWriteTest.ts`, in the test `refuses to clobber without --force, and prints the token so it is not lost`, add after the existing `could not be written` assertion:

```ts
// The hint is the only instruction a user gets for recovering a stamp they
// have already paid for, so it has to name a command that exists.
expect(sink.stderr()).toContain('`unicity-proof verify` accepts hex text');
```

- [ ] **Step 4: Run the three tests to verify they fail**

Run: `npm run build && npx jest tests/e2e/CliOfflineTest.ts -t 'prints help and version'`
Expected: FAIL — equality mismatch: received `Usage: unicity-timestamp [options] [command]`

Run: `npx jest tests/e2e/CliOfflineTest.ts -t 'names the default key file'`
Expected: FAIL — received `["unicity-timestamp.key"]`

Run: `npx jest tests/unit/StampWriteTest.ts -t 'refuses to clobber'`
Expected: FAIL — the hint still names `unicity-timestamp verify`

- [ ] **Step 5: Change the CLI's name and description**

In `src/cli.ts`, lines 26-27:

```ts
  .name('unicity-proof')
  .description('Certify a SHA-256 hash on the Unicity Network and verify the resulting proof offline.')
```

- [ ] **Step 6: Change the default key file and the `--out` help**

In `src/commands/keygen.ts:17`:

```ts
const DEFAULT_KEY_FILE = 'unicity-proof.key';
```

In `src/cli.ts:103`:

```ts
  .option('--out <path>', 'key file; default unicity-proof.key; "-" prints the key to stdout')
```

- [ ] **Step 7: Change the recovery hint**

In `src/output.ts:148`:

```ts
    'Save the token below; `unicity-proof verify` accepts hex text.',
```

- [ ] **Step 8: Run the three tests to verify they pass**

Run: `npm run build && npx jest tests/e2e/CliOfflineTest.ts tests/unit/StampWriteTest.ts`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/cli.ts src/commands/keygen.ts src/output.ts tests/e2e/CliOfflineTest.ts tests/unit/StampWriteTest.ts
git commit -m "Rename the binary to unicity-proof"
```

---

### Task 3: README, with the appendix left alone

**Files:**

- Modify: `README.md` everywhere except `### Token file format` and `### Deferred decisions`

**Interfaces:**

- Consumes: the command name `unicity-proof` and the default key file name from Task 2.
- Produces: nothing other tasks read.

- [ ] **Step 1: Record the frozen lines before editing**

```bash
git show HEAD:README.md | sed -n '226p;228p;250p;262p;266p' | sha256sum
```

Keep that digest. Step 4 compares against it.

- [ ] **Step 2: Replace the name outside the appendix**

Every `unicity-timestamp` occurrence becomes `unicity-proof`, and `@unicitylabs/timestamp-cli` becomes `@unicitylabs/proof-cli`, **except** inside the two frozen sections. The README names no default key file — the keygen example passes `--out my.key` — so nothing there needs that change.

Line 215 starts `### Token file format`, so the edit is confined to lines 1-214.
Two patterns cover every form, in this order:

```bash
sed -i '1,214{s/unicity-timestamp/unicity-proof/g; s/timestamp-cli/proof-cli/g}' README.md
```

The second pattern catches `@unicitylabs/timestamp-cli` (lines 13 and 20),
`unicitynetwork/timestamp-cli` (line 26) and the bare `cd timestamp-cli`
(line 27), which the first does not. Substitution preserves the line count, so
the appendix does not move.

- [ ] **Step 3: Confirm the appendix needed no edit**

The appendix holds exactly five occurrences of the old name, and all five are
format description: the burn reason, the two token-type derivations, the
signature domain, and the `printf 'unicity-timestamp' | shasum -a 256`
reproduction. It contains no product or install reference, so Step 2's
line-ranged edit is complete and nothing in the appendix is to be touched.

Run: `awk 'NR>=215 && /unicity-timestamp|timestamp-cli/ {print NR}' README.md`
Expected: exactly `226`, `228`, `250`, `262`, `266`.

- [ ] **Step 4: Verify the frozen lines are byte-identical**

```bash
sed -n '226p;228p;250p;262p;266p' README.md | sha256sum
```

Expected: the digest from Step 1. If the line numbers moved, the appendix was edited — recover with `git checkout HEAD -- README.md` and redo Step 2.

- [ ] **Step 5: Verify no stale brand references remain outside the appendix**

Run: `head -214 README.md | grep -nI 'unicity-timestamp\|timestamp-cli\|Timestamp CLI\|Unicity Timestamp'`
Expected: no output.

The last two patterns matter: the H1 title reads `# Unicity Timestamp CLI`,
which is Title Case and space-separated, so Step 2's substitutions do not touch
it and a check using only their patterns cannot see it. Change the title to
`# Unicity Proof CLI` as part of Step 2.

Do **not** broaden this to a case-insensitive search for `timestamp`. The README
uses the English word legitimately throughout — "round timestamp", "A timestamp
is an attestation", "classic timestamp authority" — and all of it stays. Only
the product name is being renamed.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "Rename the CLI throughout the README, leaving the format appendix"
```

---

### Task 4: Workflow, environment sample and test titles

**Files:**

- Modify: `.github/workflows/npm.yml` (the header comment's trusted-publisher instructions, the registry pre-check, the release-notes URL)
- Modify: `.env.example:4`
- Modify: `scripts/update-trust-bases.mjs:17` (the `User-Agent`)
- Modify: test `describe` titles and `tempDir` prefixes in `tests/e2e/CliOfflineTest.ts`, `tests/e2e/CliNetworkTest.ts`, `tests/unit/ConfigTest.ts`, `tests/unit/KeygenTest.ts`, `tests/unit/StampWriteTest.ts`, `tests/unit/VerifyTest.ts`, `tests/support/fixtures.ts`

**Interfaces:**

- Consumes: the package name from Task 1.
- Produces: nothing other tasks read.

- [ ] **Step 1: Update the workflow's three references**

In `.github/workflows/npm.yml`, the header comment's prerequisite becomes repository `unicitynetwork/proof-cli`, and both runtime strings become the new package name:

```yaml
if npm view "@unicitylabs/proof-cli@${version}" version >/dev/null 2>&1; then
echo "@unicitylabs/proof-cli@${version} is already on the registry." >&2
```

```yaml
--notes "https://www.npmjs.com/package/@unicitylabs/proof-cli/v/${version}" \
```

- [ ] **Step 2: Update the environment sample and the update script**

`.env.example:4`:

```
# Gateway API key used by `unicity-proof stamp`. Get one at https://sphere.unicity.network/
```

`scripts/update-trust-bases.mjs:17`:

```js
const response = await fetch(url, { headers: { 'User-Agent': 'unicity-proof-cli' } });
```

- [ ] **Step 3: Rename the test titles and temp-dir prefixes**

```bash
sed -i "s/unicity-timestamp (offline)/unicity-proof (offline)/; s/\`unicity-timestamp against /\`unicity-proof against /" tests/e2e/CliOfflineTest.ts tests/e2e/CliNetworkTest.ts
sed -i "s/timestamp-cli-/proof-cli-/g" tests/support/fixtures.ts tests/e2e/CliOfflineTest.ts tests/e2e/CliNetworkTest.ts tests/unit/ConfigTest.ts tests/unit/KeygenTest.ts tests/unit/StampWriteTest.ts tests/unit/VerifyTest.ts
```

- [ ] **Step 4: Verify the workflow still parses and nothing else references the old name**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/npm.yml')); print('yaml ok')"`
Expected: `yaml ok`

Run: `grep -rnI 'timestamp-cli\|unicity-timestamp' .github .env.example scripts tests`
Expected: no output. Two things make that achievable: `-I` skips
`tests/fixtures/*.cbor`, which carry the tag in their burn reason by design and
would otherwise be reported as binary matches; and Task 2's assertions were
written without the old name in them, so no test file contains it. If this grep
returns a hit inside `tests/`, a test embedded the literal — fix the test
rather than loosening this check.

- [ ] **Step 5: Run the suite and lint**

Run: `npm run lint && CI= npm test`
Expected: PASS, same test count as before the rename plus the two new keygen tests.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/npm.yml .env.example scripts/update-trust-bases.mjs tests
git commit -m "Rename the CLI in the workflow, the env sample and the test titles"
```

---

### Task 5: Whole-change verification

**Files:**

- Create: nothing. This task only verifies.

**Interfaces:**

- Consumes: everything above.
- Produces: the evidence the change is safe to publish.

- [ ] **Step 1: Confirm the frozen identifier survived**

Run: `printf 'unicity-timestamp' | sha256sum && node -p "require('./lib/lib/constants.js').TIMESTAMP_TOKEN_TYPE_HEX"`
Expected: both print `dd671898ac55e0a3a9e22f07120cef94943d25fdf1dd0485aab077b21ee16193`.

- [ ] **Step 2: Confirm pre-rename tokens still verify**

```bash
npm run build
node lib/cli.js verify tests/fixtures/testnet2-anonymous.cbor --json | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).status"
node lib/cli.js verify tests/fixtures/testnet2-signed.cbor --json | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).status"
```

Expected: `OK` twice. These tokens were certified before the rename; this is the regression the whole change is judged on.

- [ ] **Step 3: Confirm the old name survives only where it must**

Run: `grep -rlI 'unicity-timestamp\|Timestamp CLI\|Unicity Timestamp' src tests README.md | sort`
Expected exactly these three files:

```
README.md
src/lib/TimestampPayload.ts
src/lib/constants.ts
```

Any other file is a missed rename. `-I` is required: the two
`tests/fixtures/*.cbor` files contain the tag in their burn reason — which is
the whole point of keeping them — and `grep -l` reports binary matches rather
than skipping them, so without `-I` this check can never pass. `-l` also
suppresses line numbers, so `-n` is not used here.

- [ ] **Step 4: Confirm the package would publish correctly**

```bash
npm pack --dry-run 2>&1 | grep -E 'name:|version:|filename:'
```

Expected: name `@unicitylabs/proof-cli`, version `0.1.2`, filename `unicitylabs-proof-cli-0.1.2.tgz`.

- [ ] **Step 5: Optionally verify against a freshly stamped token**

The spec also asks for a token stamped by the published `0.1.2`. That needs a
gateway key and network access, so it is optional and never part of CI:

```bash
npx --yes @unicitylabs/timestamp-cli@0.1.2 stamp --file README.md \
  --network testnet2 --api-key "$UNICITY_TEST_API_KEY" --out ../old-cli.cbor
node lib/cli.js verify ../old-cli.cbor --file README.md
```

Expected: `Status OK` with `Expected hash matches`. Skip this step when no key
is configured; the committed fixtures in Step 2 cover the same regression
offline.

- [ ] **Step 6: Full gate**

Run: `npm run build:check && npm run lint && CI= npm test`
Expected: PASS. Node 22 and 24 are covered by `ci.yml` on the pull request, not
locally.

Run: `codex exec review --base main`
Expected: findings read, and each one fixed or justified, before the PR opens.

- [ ] **Step 7: Open the pull request**

```bash
cat > ../pr-body.md <<'EOF'
Renames the package to `@unicitylabs/proof-cli` and the binary to
`unicity-proof`, per `docs/specs/2026-10-14-rename-to-proof-cli.md`.

The version stays 0.1.2. The release workflow owns the bump to 0.2.0, and the
first publish under the new name is manual because npm's trusted publishing
cannot create a package name the publisher does not already own.

`TIMESTAMP_TAG` is unchanged, and now says why it can never change. The token
type is its SHA-256, the burn predicate's reason bytes are its UTF-8, and it is
the domain tag inside the payload signature, so renaming it would give every
later stamp a different token type, recipient and signature domain, and nothing
already certified would verify. The README's `### Token file format` and
`### Deferred decisions` sections describe those same bytes and are untouched;
the rename is confined to lines 1-214.

Internal vocabulary keeps the format's name: the `TIMESTAMP_*` constants,
`TimestampPayload`, `TimestampClient` and the file names identify the format,
which is not what is being renamed.

Two things change for users: the binary name, and the default key file `keygen`
writes when given no `--out`, now `unicity-proof.key`. Subcommands, flags and
every `UNICITY_*` variable are unchanged.

Verified: both committed fixtures, certified before the rename, verify `OK`
under the new binary; `printf 'unicity-timestamp' | sha256sum` still matches the
pinned token type; and `npm pack --dry-run` reports `@unicitylabs/proof-cli`
at 0.1.2 with the `unicity-proof` bin entry.
EOF
git push -u origin rename/proof-cli
gh pr create --title "Rename the CLI to @unicitylabs/proof-cli" --body-file ../pr-body.md --base main
```

---

## Operator steps

Most of these need registry or organisation credentials; none is part of the
code change. Step 2 is the merge of this branch. **The repository rename comes
first**, because this branch points `repository`, `homepage` and `bugs` at
`unicitynetwork/proof-cli`, and npm requires a package's `repository` to
match, case-sensitively, the repository it publishes from. Publishing from a
repository still named `timestamp-cli` with those URLs in the manifest fails.

1. Rename the repository on GitHub to `proof-cli`. Organisation admin. Update
   the remote in any working copy.
2. Merge this branch.
3. `npm version 0.2.0-rc1 --no-git-tag-version`, then
   `npm publish --access public --tag next`. Discard the local bump.
   **`--tag next` is required** — npm points `latest` at whatever it publishes,
   prerelease or not.
4. Configure the new package's trusted publisher: repository
   `unicitynetwork/proof-cli`, workflow `npm.yml`, environment `npm-publish`,
   and under "Allowed actions" permit direct publishing with `npm publish`.
   Configurations created after 3 September 2026 default to `npm stage publish`
   only, and this workflow publishes directly.
5. Run the release workflow with `0.2.0` as the explicit version input.
   **Within two days of step 4.** A new trusted-publisher configuration has to
   complete its first successful publish inside that window; after it, the
   configuration expires and can no longer be used or edited, and has to be
   recreated. Do not configure the publisher until ready to release.
6. `npm deprecate @unicitylabs/timestamp-cli "Renamed to @unicitylabs/proof-cli"`.
7. Optionally `npm dist-tag rm @unicitylabs/proof-cli next`.
8. Optionally restrict token publishing on the new package — npm Settings,
   Publishing access, "Require two-factor authentication and disallow tokens".
   Configuring a trusted publisher does not do this on its own, and the
   bootstrap token from step 3 keeps working until it is done.

Step 4's binding is to the repository's immutable identity, not its name. npm
does not document what a later rename requires of it; under this ordering the
repository is not renamed again afterwards, so the question is moot.
