# PR body skeleton — abofs/stonyx-oauth#49 (SCRATCH, deleted before PR opens)

## Summary
<!-- TBD -->

## The correction to the issue's own scope
<!-- issue names 3 lines; 4 assert the false CSRF property; qa:33 is a different defect; sr:26 is a 5th -->

## Raw sweep output (verbatim, unelided)

Command:
```
grep -rniE 'csrf|xsrf|forgery|replay|state token|pendingStates|randomUUID|session id|bearer|constant.time|secret|credential|cookie|entropy|secure' docs/agents/*.md
```

<!-- PASTE LIVE OUTPUT ON MERGED TREE -->

## Per-hit adjudication (22 hits — every one gets a verdict)

| # | Location | Verdict | Reason |
|---|---|---|---|
| 1 | validation-loop-team.md:32 | TBD | |
| 2 | validation-loop-team.md:34 | TBD | |
| 3 | qa-test-engineer.md:21 | TBD | |
| 4 | qa-test-engineer.md:33 | TBD | |
| 5 | qa-test-engineer.md:37 | TBD | |
| 6 | architect.md:22 | TBD | |
| 7 | architect.md:28 | TBD | |
| 8 | architect.md:32 | TBD | |
| 9 | architect.md:38 | TBD | |
| 10 | architect.md:40 | TBD | |
| 11 | security-reviewer.md:10 | TBD | |
| 12 | security-reviewer.md:17 | TBD | |
| 13 | security-reviewer.md:18 | TBD | |
| 14 | security-reviewer.md:19 | TBD | |
| 15 | security-reviewer.md:24 | TBD | |
| 16 | security-reviewer.md:25 | TBD | |
| 17 | security-reviewer.md:26 | TBD | |
| 18 | security-reviewer.md:31 | TBD | |
| 19 | security-reviewer.md:32 | TBD | |
| 20 | security-reviewer.md:35 | TBD | |
| 21 | security-reviewer.md:37 | TBD | |
| 22 | security-reviewer.md:38 | TBD | |

## AC-by-AC evidence
<!-- AC1..AC6 refined; assertions 1-3, 6-9 mechanical -->

## What is untestable, and the gap I am naming
<!-- no SME-template regression harness; no proxy assertion written; no grep-guard committed (stonyx-orm#252) -->

## Test baseline
REST_PORT=2777 pnpm test -> 72 pass / 0 fail at 3b39f52
