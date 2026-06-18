// Package eval is the PORTABLE eval harness — the replatformed academy
// (portable-agent-architecture.md §4), lifted off the deleted legion/campfire
// transport onto the in-process core.
//
// It is the most portable artifact in the project (§4.9): the corpus is the
// value, the substrate is replaceable. This package keeps the corpus, the
// deterministic grader, the median-of-N discipline, the failure classifier, and
// transcript capture — and drops campfire, legion, cf, rd, and the .toml.tmpl
// rendering entirely.
//
// Pipeline:
//
//	Load(repoRoot)         — SHA-pinned, provenance-safe corpus loader. Skips
//	                         leading-underscore paths (files AND dirs). Asserts the
//	                         pinned count + SHA-256; a mismatch HARD-FAILS (the
//	                         eval-as-interlock gate the self-extension loop needs).
//	RunScenario(...)       — runs ONE scenario through core/agent.ResolveFindingWith
//	                         IN-PROCESS via a controllable Client ({base_url,key}
//	                         pivot), capturing a full per-scenario transcript (§4.7).
//	Grade(run)             — DETERMINISTIC structural grader (no LLM in pass/fail).
//	                         chain_action is the only gating axis; the rest are
//	                         reported provenance. Emits per-scenario result JSON.
//	Run(cfg)               — the full driver: load → N passes → median pass-rate
//	                         with the 8pp band → classifier summary.
//
// Two backends share the Client seam: a creds-free cannedbackend MERGE-GATE
// (golden responses → deterministic green; gates harness+grader regressions; NOT
// the accuracy number) and a real DirectClient parity run (WIRED via
// RealClientFromEnv, NOT run without creds).
package eval
