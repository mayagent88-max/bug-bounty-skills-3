# Rust Auditor

Rust Auditor is a defensive review skill for Rust Solana programs built with Anchor, native `solana-program`, Pinocchio, or Steel. Version 2 makes source-only review the default and records exactly what was reviewed, independently validated, repaired, and—only when requested—executed offline.

It is designed for repository owners who want a repeatable pre-release review. It does not replace an independent professional audit or prove the absence of defects.

## What version 2 changes

- The default audit reads source and committed context only. It does not build the target, contact an RPC endpoint, install tools, or write into the target repository.
- Audit artifacts live in a separate external run directory and bind to an immutable hash of the exact clean or dirty source state.
- Coverage is an explicit source-unit × concern matrix. Refusals, timeouts, malformed results, and missing capabilities remain visible gaps.
- A different reviewer validates every candidate, and another fresh reviewer checks every retained final record.
- Account/CPI/`remaining_accounts` maps, Token-2022 policy per flow, framework/version differences, IDL/client agreement, and SBF/ELF provenance have dedicated review contracts.
- Existing ordinary tests may run only under explicit `--validate`, with a reviewed offline sandbox and precise semantic labels. The former `--poc` mode is unsupported.
- Repairs are linked to the original immutable findings and need independent patch review. Markdown, JSON, and SARIF reports carry a freshness watermark.

## Usage

Install the skill from this repository using your agent's supported skill installer, then ask for the narrowest operation you need:

```text
run rust auditor on this repository
```

```text
run rust auditor on programs/vault/src and include three independent review waves
```

```text
run rust auditor in repair mode and fix independently confirmed source defects
```

```text
run rust auditor with --validate using only the repository's existing ordinary tests
```

An audit request alone never authorizes target execution, fuzzing, network access, deployment checks, or source changes. Those are separate modes with separate permissions.

## Review model

Rust Auditor inventories each program and creates bounded source units, normally an instruction plus the account parser, state, helpers, CPIs, token operations, clients/IDL, and release context needed to reason about it. Each unit is reviewed across ten concern families:

1. account boundaries;
2. PDA and account lifecycle;
3. CPI boundaries;
4. `remaining_accounts`;
5. data layout, unsafe code, IDL and clients;
6. arithmetic and value limits;
7. Token and Token-2022 policy;
8. state lifecycle and liveness;
9. economic invariants; and
10. governance and release provenance.

The pipeline separates source review, coverage criticism, candidate validation, final-record review, repair, patch review, and runtime evidence. A scanner alert or model hypothesis is never a finding by itself.

## Modes

| Mode | Target writes | Project execution | Network | Use |
| --- | --- | --- | --- | --- |
| `source-only` | no | no | no | Default full or focused review |
| `validate` | no; scratch only | allowlisted existing checks | off | Ordinary regression/runtime evidence |
| `repair` | explicitly authorized files | optional after patch review | off | Minimal source fixes |
| `ci-evidence` | no | no new execution | no | Normalize trusted existing artifacts |
| `fuzz` | scratch/corpus only | explicit reviewed harness | off | Separately requested bounded campaign |
| `deployment-verify` | artifacts only | approved tools | explicit | Read-only release comparison |

Runtime evidence stays specific: native unit, instruction harness (for example Mollusk), emulator transaction (for example LiteSVM), local integration (for example an offline Surfpool snapshot), fuzz, or deployment verification. These labels are not interchangeable.

## Optional tools

Rust Auditor can use already-installed, pinned tools when the selected mode allows execution and their capabilities are declared. It never installs, updates, or fetches them automatically. The maintained decision matrix covers dependency review, static and unsafe-code analysis, dynamic checks, formal tools, fuzz/property/mutation/coverage tools, and Solana-specific runtimes in [references/tool-landscape.md](references/tool-landscape.md).

`references/account-map.py` is a standard-library, read-only inventory helper. Its output is a lead map that still requires source confirmation.

## Artifacts and reports

The skill stores canonical JSON/JSONL outside the target. Core record shapes are documented in `schemas/`; cross-file identity, independence, coverage, patch, runtime, and freshness invariants are checked by:

```sh
python3 scripts/validate_run.py <external-run-root>
python3 scripts/render_report.py <external-run-root>
python3 scripts/validate_run.py <external-run-root> --require-fresh-report
```

The rendered outputs are `REPORT.md`, `report.json`, and `report.sarif`. If canonical records change, the watermark becomes stale and publication/complete wording is blocked until rerendered.

## Development

Run the deterministic offline tests from this repository:

```sh
python3 -m unittest discover -s tests -v
python3 /path/to/skill-creator/scripts/quick_validate.py .
```

The evaluation cases in `evals/` focus on observable v2 behavior: safe default routing, complete coverage accounting, independent hash-bound review, truthful runtime normalization, and report staleness detection.
