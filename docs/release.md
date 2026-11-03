# Release Process

This package is released through the shared Stonyx pipeline in
[`abofs/stonyx-workflows`](https://github.com/abofs/stonyx-workflows). The three workflow files
in this repo (`.github/workflows/ci.yml`, `publish.yml`, `security-audit.yml`) are thin
`workflow_call` wrappers with no release logic of their own — only triggers and inputs.
Everything below is verified against the shared workflow files
(`ci.yml`, `npm-publish.yml`, `security-audit.yml` at `abofs/stonyx-workflows@main`, fetched and
read directly for this document) and against this repo's own `package.json`, not copied from
`stonyx-workflows/docs/release.md` unread. The three workflow files in this repo are byte-for-byte
the same wrappers as `@stonyx/rest-server`'s (same triggers, same `uses:` targets, no `with:`
overrides), so the pipeline mechanics are identical across the two packages; this document covers
what's specific to `@stonyx/oauth`.

**npm package:** `@stonyx/oauth`

## What actually runs

### CI (`.github/workflows/ci.yml` -> `stonyx-workflows/ci.yml@main`)

Triggers on pull requests into `dev`, `main`, or `fix/**`. Steps, read from the shared workflow:

1. Checkout (`persist-credentials: false`).
2. `pnpm install --frozen-lockfile`.
3. `pnpm test` (this repo's script: `pnpm build && NODE_ENV=test node --import tsx/esm --import ./test/setup.ts node_modules/qunit/bin/qunit.js 'test/**/*-test.ts'`).
4. `pnpm run --if-present build` again, so the docs-import check below sees a built `dist/`.
5. A docs-import check: checks out `stonyx-workflows` at the triggering commit SHA, installs its own pinned TypeScript, and verifies every `@stonyx/*` import appearing in this repo's README/docs resolves against real exports.

**Verified directly:** `pnpm install --frozen-lockfile` and `pnpm test` both succeeded locally — see "Build, Run, Test" in [index.md](index.md) (90/90 assertions passing, no lockfile changes). **Not independently verified:** the docs-import check (step 5), which depends on a `stonyx-workflows` checkout and a temp npm registry.

**Note on typechecking:** unlike `pnpm test`'s build step, there is no dedicated type-check of `test/`/`config/` anywhere in this pipeline. `build:test` (`tsc -p tsconfig.test.json`) would do that, but nothing in `ci.yml`, `publish.yml`, or `package.json`'s own scripts calls it, and it fails as run standalone in this environment (see index.md's "Build, Run, Test" for the exact errors — missing `@types/node`-shaped declarations for `node:fs`, `node:path`, `node:url`, `process`, `setImmediate` in `test/`, because this repo hand-rolls ambient types only for what `src/` uses). This is a pre-existing gap, not something introduced here, but a reader should not assume `pnpm test` type-checks the test suite — it only type-checks `src/` (via `pnpm build`) and runs the tests untyped through `tsx`.

### Publish (`.github/workflows/publish.yml` -> `stonyx-workflows/npm-publish.yml@main`)

Same trigger set and channel-selection logic as `@stonyx/rest-server` (see that repo's
`docs/release.md` for the full table): PR -> alpha, push to `dev` or a cascade dispatch -> beta,
push to `main` -> stable, manual `workflow_dispatch` -> patch/minor/major/custom.

After the version bump, the workflow installs, runs `pnpm test` again, then packs the release
artifact and runs `prepublishOnly` explicitly (`pnpm pkg get scripts.prepublishOnly`; this repo
declares `"prepublishOnly": "npm test"`, same script as CI, run via `npm` rather than `pnpm`).
The packed tarball is scanned for any `.git/` entries before `pnpm publish --tag <channel>
--access public --no-git-checks`.

**Verified:** this repo's `files` field is `["dist", "src", "config", "README.md"]`. Unlike
`@stonyx/rest-server`'s `files` (`["dist", "config", "README.md"]`), **this one ships `src/`
alongside `dist/`** — confirmed by reading `package.json` directly. That is deliberate per
`docs/security.md`'s own note ("the package ships `src/` and `config/` alongside `dist/`..., so
source must carry no credentials, test-only code or debug logging") and does not by itself
collide with the shared workflow's `.git`-leak guard, which only denies paths matching
`package/(.*/)?\.git(/|$)` — `src/` is not `.git/` and the guard does not care how wide `files`
is otherwise. **Not verified / out of scope:** actually triggering a publish.

### Security audit (`.github/workflows/security-audit.yml` -> `stonyx-workflows/security-audit.yml@main`)

Daily cron (`0 8 * * *`) plus manual `workflow_dispatch`. `pnpm install --frozen-lockfile`, then
`pnpm audit --audit-level moderate` with `continue-on-error: true` — informational only, does not
fail the job or block anything downstream.

## Discrepancies / things that don't match a naive reading, or can't be verified here

- **pnpm version pin mismatch**, same issue as `@stonyx/rest-server`: the shared workflows
  default `pnpm-version` to `'9'`, none of this repo's three workflow files override it, and
  `package.json` pins no `packageManager`. CI/publish/audit therefore run on pnpm 9 by default
  while this environment's toolchain is pnpm 10.23.0. No incompatibility was observed locally
  (`pnpm install --frozen-lockfile` and `pnpm test` both succeeded under 10.23.0 with no lockfile
  changes), but the gap itself is unresolved by anything in this repo.
- **No `typecheck` script, and the closest equivalent (`build:test`) is broken** as a standalone
  command in this environment — see the CI section above and index.md's "Build, Run, Test" for
  the exact `tsc` errors. This does not affect what CI actually runs (`pnpm test`), but it means
  `test/` and `config/` are not type-checked by anything in this pipeline today.
- **The docs-import CI check and the full publish/version-bump/tag/push sequence were not
  exercised**, per the task boundary excluding infrastructure, secrets, and branch protection.
  The channel-selection logic above is read directly off the shared workflow's conditional logic,
  not observed from a live run.
- The previous version of this file pointed only to `stonyx-workflows/docs/release.md` with no
  repo-specific detail. That external doc remains the canonical cross-package reference
  (versioning scheme, cascade publishing, the `.git`-leak guard, OIDC provenance); this file adds
  what's specific to `@stonyx/oauth` and what was independently checked here rather than taken on
  trust.
