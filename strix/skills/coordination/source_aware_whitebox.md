---
name: source-aware-whitebox
description: Coordination playbook for source-aware white-box testing with static triage and dynamic validation
---

# Source-Aware White-Box Coordination

Use this coordination playbook when repository source code is available.

## Objective

Increase white-box coverage by combining source-aware triage with dynamic validation. Source-aware tooling is expected by default when source is available.

## Recommended Workflow

1. Build a quick source map before deep exploitation, including at least one AST-structural pass (`sg` or `tree-sitter`) scoped to relevant paths.
   - For `sg` baseline, derive `sg-targets.txt` from `opengrep.json` scope first (`paths.scanned`, fallback to unique `results[].path`) and run `xargs ... sg run` on that list.
   - Only fall back to path heuristics when opengrep scope is unavailable.
2. Run first-pass static triage to rank high-risk paths.
3. Use triage outputs to prioritize dynamic PoC validation.
4. Keep findings evidence-driven: no report without validation.

## Source-Aware Triage Stack

- `opengrep`: fast security-first triage and custom pattern scans
- `ast-grep` (`sg`): structural pattern hunting and targeted repo mapping
- `tree-sitter`: syntax-aware parsing support for symbol and route extraction
- `gitleaks` + `trufflehog`: complementary secret detection (working tree and history coverage)
- `trivy fs`: dependency, misconfiguration, license, and secret checks
- `relate` (+ `souffle`): optional code graph from opengrep output for call-chain, reachability, and sanitizer-coverage queries (skills `relate_callgraph_ingest`, `relate_datalog`)

Coverage target per repository:
- one `opengrep` pass
- one AST structural pass (`sg` and/or `tree-sitter`)
- one secrets pass (`gitleaks` and/or `trufflehog`)
- one `trivy fs` pass

## Agent Delegation Guidance

- Keep child agents specialized by vulnerability/component as usual.
- For source-heavy subtasks, prefer creating child agents with `source_aware_sast` skill.
- For structural questions (who calls X, which entry points reach this sink, is every path sanitized, dead code), create a child agent with `relate_callgraph_ingest` (build the opengrep call graph in a relate store and query it with Cypher). Add `relate_datalog` when the question needs fixpoint logic Cypher cannot express (sanitizer on every path, mutual recursion, unreachable code). Add `relate` for CLI details. Cross-file taint needs Opengrep >= 2.0 `--enable-interfile` with rules that set `options: interfile: true`.
- Graph results are triage leads: confirm in source and dynamically before reporting.
- Use source findings to shape payloads and endpoint selection for dynamic testing.

## Validation Guardrails

- Static findings are hypotheses until validated.
- Dynamic exploitation evidence is still required before vulnerability reporting.
- Keep scanner output concise, deduplicated, and mapped to concrete code locations.
