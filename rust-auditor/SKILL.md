---
name: rust-auditor
description: Defensive security review of Rust Solana programs (Anchor, native solana-program, Pinocchio, or Steel), with source-unit coverage, independent validation, optional offline regression evidence, and patch review. Use for full-program audits, focused instruction reviews, remediation reviews, or explicit multi-pass scans. Source-only review is the default; it creates no new executable demonstrations and contacts no live chain.
---

# Rust Auditor

Review the exact Rust/Solana source supplied by its owner, produce evidence-backed records, and distinguish reviewed code from gaps. The default is a defensive, source-only review.

## Non-negotiable contract

- Do not create new executable demonstrations, special reproduction harnesses, crafted transaction inputs, persistence, or concealment material.
- In `source-only` mode, do not execute target code, access a network or blockchain, submit transactions, use credentials, or write to the target repository.
- Store run artifacts outside the target. Hash the exact baseline before delegation. A dirty worktree is valid only when staged, unstaged, and untracked content is captured and hashed.
- Optional tools are capability-gated. Never install, update, fetch, log in, add a toolchain/target, or alter project configuration automatically.
- Tool alerts and reviewer hypotheses are candidates, not findings. A fresh source validator must confirm them; another fresh reviewer checks the final record.
- A refusal, abort, timeout, malformed result, or unreviewed empty response is lost coverage. Reassign the same smaller source-only unit once; a second failure stays `lost` and prevents complete wording.
- Runtime evidence uses only predeclared ordinary project checks in a reviewed OS-enforced sandbox. Missing capabilities are `blocked`, never clean.
- Never claim `clean`, `complete`, `verified`, or `runtime passed` unless the corresponding coverage, validation, and freshness gates pass.

Read [mode-contract.md](references/mode-contract.md) before any action. Read only the additional references routed below.

## Modes

Choose the narrowest mode authorized by the request:

| Mode | Target writes | Project execution | Network | Purpose |
| --- | --- | --- | --- | --- |
| `source-only` (default) | none | none | none | Review source and committed artifacts |
| `validate` | none; scratch only | allowlisted existing checks | off | Ordinary regression/runtime evidence for confirmed records or patches |
| `repair` | explicitly authorized files | optional after patch review | off | Apply minimal fixes, then review them independently |
| `ci-evidence` | none | no new execution | none | Normalize existing trusted CI/tool artifacts |
| `fuzz` | scratch/corpus only | existing or independently reviewed harness | none | Explicit bounded invariant campaign; never inferred from an audit request |
| `deployment-verify` | artifacts only | approved verification tools | explicit | Compare release artifacts with a deployment; separate authorization required |

`--validate` selects `validate`. The former `--poc` option is unsupported: explain that Rust Auditor does not generate exploit demonstrations and offer source validation plus ordinary regression checks instead.

## Intake and immutable baseline

1. Resolve the target root, repository identity, exact commit/tree, dirty state, selected paths, submodules, manifests, lockfiles, IDLs, generated clients, and committed binaries.
2. Select an external run root. Prefer an explicit `--output-dir`; otherwise use `${XDG_STATE_HOME:-$HOME/.local/state}/rust-auditor/<repo-id>/<run-id>` when it is outside the target. Stop if no safe external path is writable.
3. Run `scripts/baseline_snapshot.py --target <root> --output <run-root>/baseline.json [--path <path> ...]`. It reads and hashes files; it never writes inside the target.
4. Record the skill version and content hash, model identities, mode, scope, exclusions, authorization, and prior-run paths in `run.json`.
5. If source changes after the baseline, keep the original evidence and create a separate dirty-overlay or patch manifest. Never silently review a moving tree.

Read [baseline-and-artifacts.md](references/baseline-and-artifacts.md) for artifact ownership, schemas, and staleness rules.

## Inventory

Build a deterministic inventory before review:

- Rust workspaces, crates, release profiles, dependency versions, features, and `unsafe` sites.
- Exact Anchor, native Solana, Pinocchio, Steel, SPL Token, and Token-2022 versions.
- Entrypoints/instructions, account parsers, state types, PDAs, admin/deploy paths, CPIs, return-data use, and `remaining_accounts` consumers.
- IDLs, generated clients, committed ELFs, program IDs, release/build recipes, and existing tests/harnesses as context.
- Existing optional tools and offline caches using path/version probes only.

Run `references/account-map.py --target <root> --out <run-root>/account-map.md <selected-rs-files>` when Python 3 is present. Treat every map item as a lead that requires source confirmation. For native or Pinocchio gaps, complete only the named unresolved cells from source.

Read [solana-review.md](references/solana-review.md) for framework-aware checks, the CPI/remaining-accounts map, Token-2022 flow matrix, and release/IDL evidence. Read [tool-landscape.md](references/tool-landscape.md) only when optional tools or broader Rust assurance are requested.

## Coverage plan

A source unit is normally one instruction or entrypoint plus the account parser, state, helpers, CPIs, token operations, clients/IDL, and release artifacts needed to reason about it. Build `source-units.jsonl`, then seed `coverage.jsonl` for each applicable `unit_id × concern_id` cell.

Declare these stable concern IDs in `run.json`, then create the complete source-unit × concern matrix:

1. `account-boundaries` — identity, owner, signer, writable, executable, discriminator, length, aliases;
2. `pda-lifecycle` — seeds/domain/bump, init, realloc, close, rent, revival;
3. `cpi-boundaries` — target, ordered accounts, privilege propagation, signer seeds, callbacks, reload/serialization, return data;
4. `remaining-accounts` — count, grouping, uniqueness, relationships, privilege, and unused trailing entries;
5. `data-layout` — serialization, zero-copy, unsafe, layout, IDL and generated-client agreement;
6. `arithmetic` — casts, decimals, rounding, fee base, slippage, caps and limits;
7. `token-policy` — Token and Token-2022 admission, extensions, native mint, authority and accounting policy;
8. `state-lifecycle` — ordering, replay, freshness, slot/time, liveness and migrations;
9. `economic-invariants` — venue/oracle assumptions and liquidation/settlement;
10. `governance-release` — admin, upgrade, emergency, governance and release provenance.

Use only these coverage states: `planned`, `in_review`, `clean_reviewed`, `candidate`, `validated`, `lost`, `not_run`, `blocked`, `not_applicable`. Reviewer counts are metadata, never coverage.

Read [coverage-and-validation.md](references/coverage-and-validation.md) for the record contracts and coverage critic.

## Delegation pipeline

Use independent roles and unique output directories:

1. **Source reviewer** — receives one bounded source unit, assigned concerns, relevant framework rules, and prior same-source records. Returns schema-valid `clean_reviewed` cells and zero or more candidates. It does not assign final severity.
2. **Coverage critic** — receives the unit map, coverage matrix, candidates, and gaps. It schedules only justified missing cells. Repeat until a fresh critic returns no actionable gap or the run records an explicit limit.
3. **Candidate validator** — did not produce the candidate. Re-reads every cited source path, traces entrypoint to consequence, records all guards and alternate interpretations, and returns `confirmed`, `needs_validation`, or `rejected`.
4. **Final-record reviewer** — did not produce or validate that candidate. Checks fingerprint, root-cause deduplication, locations, assumptions, severity, confidence, fix direction, and validation plan.
5. **Fixer** (`repair` only) — receives confirmed records with non-overlapping file ownership and applies the smallest invariant-enforcing patch.
6. **Patch reviewer** — fresh review of every patch group, including layout/migration, client/IDL, operational effects, unrelated changes, and regression coverage.
7. **Runtime verifier** (`validate` only) — runs the approved existing checks and records exact semantic level and counts.

Every reviewer prompt begins with the defensive contract in [reviewer-prompts.md](references/reviewer-prompts.md). Do not append incident demonstrations or unrelated review material to every packet; route only what the assigned unit needs.

## Candidate and finding rules

A confirmed record needs:

- a lower-trust or correctness-relevant entrypoint;
- exact repository-relative trace and source hashes;
- the strongest visible guards and why they do not prevent the result;
- a violated invariant and concrete affected resource/result;
- necessary conditions and containment;
- an evidence type and provenance;
- a stable fingerprint derived from repository identity, baseline digest, primary location, and normalized defect class;
- a minimal source fix and appropriate regression case.

Use `needs_validation` only when a specific source-grounded path depends on an exact missing runtime, deployment, dependency, or policy fact. It receives no severity. Use `rejected` when source, a visible guard, impossible prerequisites, or missing meaningful impact refutes the claim. Only independently validated `confirmed` records receive severity.

## Optional execution and tools

Before any project execution, read [validation-and-runtime.md](references/validation-and-runtime.md). The parent must approve exact runner bytes and pre-entry health probes before target code runs. The sandbox must provide no external route, an empty allowlisted environment, read-only source/tools, scratch-only writes, explicit CPU/memory/PID/file/disk/wall limits, and bounded no-follow artifact promotion.

Declare every command, input, expected write, tool identity, timeout, limits, and output path before execution. Run with offline flags and already-cached dependencies only. Do not substitute stale SBF/ELF/IDL artifacts for the current baseline.

Normalize optional tool output as leads/evidence. Never treat a scanner, linter, advisory match, proof, fuzzer, or test as broader than its actual target, features, harness, assumptions, and semantic level.

## Reporting and completion

Canonical data lives in JSON/JSONL; Markdown and SARIF are views. Run:

```sh
python3 scripts/validate_run.py <run-root>
python3 scripts/render_report.py <run-root>
python3 scripts/validate_run.py <run-root> --require-fresh-report
```

Machine-readable core schemas are in `schemas/`; cross-file identity, independence, coverage, hash, patch, runtime, and freshness invariants are enforced by `validate_run.py`.

Read [report-contract.md](references/report-contract.md) before rendering. Report confirmed findings, `needs_validation`, rejected-count context, positive patterns, hardening notes, exact coverage states, tool/runtime results, fixes, patch-review state, and exclusions separately.

Set `run_status: complete` only when:

- every applicable coverage cell is terminal and no cell is `planned` or `in_review`;
- every candidate has an independent disposition;
- every retained confirmed/needs-validation record passed final-record review;
- configured patch/runtime gates have truthful terminal results;
- canonical artifacts validate; and
- the report watermark matches the canonical-record digest.

Otherwise set `run_status: incomplete` with an exact reason and list every gap. A complete source review may still contain `needs_validation` and `blocked` optional runtime checks; the report must say what those limits mean.
