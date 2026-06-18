package eval

// harness_test.go — the end-to-end test of the PORTABLE eval harness
// (portable-agent-architecture.md §4). It proves, against the REAL shipped
// corpus driven through the in-process core with cannedbackend golden responses:
//
//   - the corpus loads with the EXACT pinned count + SHA (the integrity gate);
//   - leading-underscore paths (_schema.yaml, _test/) are SKIPPED;
//   - the harness runs end-to-end, grades deterministically, and the merge-gate
//     is GREEN (golden responses → 100% chain_action);
//   - result JSON + transcripts + a classifier summary + a median over N=3 are
//     produced;
//   - the SHA/count integrity gate HARD-FAILS on a tampered corpus (tested on a
//     temp copy so the shipped tree is untouched);
//   - real-model mode is WIRED but refuses to run without creds.
//
// Determinism: every test pins the repo root via SetRepoRootForTest (NOT the
// MALLCOP_REPO_ROOT env var — that is shadowed by the os.Executable() walk and is
// incompatible with t.Parallel). The suite is built to survive -count=10 + -race:
// the recording client is mutex-guarded, the canned backends bind ephemeral
// ports, and no global state leaks between tests (the override is set+cleared per
// test under a shared lock).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
)

// repoRoot walks up from the test's working dir (the package dir) to the repo
// root that holds exams/scenarios — the deterministic anchor every test pins.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, scenariosRelPath)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to filesystem root without finding exams/scenarios")
		}
		dir = parent
	}
}

// pinShippedRoot pins the harness AND the agent floor at the REAL shipped corpus
// for one test and clears both overrides on cleanup.
//
// TWO roots must be pinned, deterministically:
//   - the EVAL root (SetRepoRootForTest) — locates exams/scenarios for the loader.
//   - the AGENT FLOOR root (agent.SetRepoRootForTest) — locates the
//     escalate-route corpus the PRE-LLM floor reads INSIDE ResolveFindingWith.
//
// The floor walks up from os.Executable(); under `go test` that binary lives in a
// /tmp build dir with NO corpus marker above it, so the floor would FAIL-SAFE and
// force-escalate every finding (the corpus-not-found path). Pinning the floor's
// EXPORTED test seam removes that — exactly the determinism §4 / the flake-fix
// discipline prescribe. Not parallel-safe across goroutines sharing the override;
// no test below runs parallel.
func pinShippedRoot(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	SetRepoRootForTest(root)
	agent.SetRepoRootForTest(root) // pin the floor's escalate-route corpus too
	t.Cleanup(func() {
		SetRepoRootForTest("")
		agent.SetRepoRootForTest("")
	})
	return root
}

// --- 1. CORPUS LOADER: pinned count + SHA gate. --------------------------------

func TestCorpus_LoadsPinnedCountAndSHA(t *testing.T) {
	root := pinShippedRoot(t)

	c, err := Load(root)
	if err != nil {
		t.Fatalf("Load shipped corpus: %v", err)
	}

	pin, err := readPin(filepath.Join(root, pinRelPath))
	if err != nil {
		t.Fatalf("read pin: %v", err)
	}
	if c.Count != pin.Count {
		t.Fatalf("loaded count %d != pinned %d", c.Count, pin.Count)
	}
	if c.SHA != pin.SHA {
		t.Fatalf("loaded sha %s != pinned %s", c.SHA, pin.SHA)
	}
	if c.Count == 0 {
		t.Fatal("corpus loaded 0 scenarios; layout changed?")
	}
	// Re-scanning yields the identical digest (deterministic manifest).
	c2, err := scanCorpus(filepath.Join(root, scenariosRelPath))
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if c2.SHA != c.SHA || c2.Count != c.Count {
		t.Fatalf("non-deterministic scan: (%d,%s) vs (%d,%s)", c.Count, c.SHA, c2.Count, c2.SHA)
	}
}

// --- 2. LEADING-UNDERSCORE PATHS ARE SKIPPED. ----------------------------------

func TestCorpus_SkipsLeadingUnderscorePaths(t *testing.T) {
	root := pinShippedRoot(t)
	c, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// The shipped tree contains _schema.yaml (a FILE) and _test/ (a DIRECTORY).
	// Neither may appear in the loaded set, and the count must exclude both.
	scenariosRoot := filepath.Join(root, scenariosRelPath)
	if _, err := os.Stat(filepath.Join(scenariosRoot, "_schema.yaml")); err != nil {
		t.Fatalf("precondition: expected _schema.yaml to exist in the corpus tree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(scenariosRoot, "_test")); err != nil {
		t.Fatalf("precondition: expected _test/ dir to exist in the corpus tree: %v", err)
	}
	for _, s := range c.Scenarios {
		if hasUnderscoreComponent(s.RelPath) {
			t.Fatalf("underscore path leaked into corpus: %s", s.RelPath)
		}
		if strings.Contains(s.RelPath, "_schema") || strings.HasPrefix(s.RelPath, "_test/") {
			t.Fatalf("forbidden underscore path included: %s", s.RelPath)
		}
	}
	// The directory-skip footgun: prove the walker, scanning the SAME tree with the
	// skip removed, WOULD have included more — by counting raw .yaml files.
	rawYAML := 0
	_ = filepath.Walk(scenariosRoot, func(path string, fi os.FileInfo, _ error) error {
		if fi != nil && !fi.IsDir() && strings.HasSuffix(path, ".yaml") {
			rawYAML++
		}
		return nil
	})
	if rawYAML <= c.Count {
		t.Fatalf("expected raw .yaml count (%d) to EXCEED skipped count (%d) — "+
			"the underscore corpus files must exist to make this assertion meaningful", rawYAML, c.Count)
	}
}

// --- 3. END-TO-END MERGE-GATE: golden responses → GREEN, median over N=3. ------

func TestHarness_MergeGate_GreenWithMedianOfN(t *testing.T) {
	pinShippedRoot(t)

	report, err := Run(context.Background(), RunConfig{Mode: ModeCanned, N: 3})
	if err != nil {
		t.Fatalf("Run merge-gate: %v", err)
	}

	if report.CorpusCount == 0 {
		t.Fatal("report has 0 scenarios")
	}
	if len(report.Runs) != 3 {
		t.Fatalf("median-of-N must run N=3 passes; got %d", len(report.Runs))
	}
	// MERGE-GATE: golden responses make every scenario pass on chain_action.
	if report.MedianPassRate != 1.0 {
		t.Fatalf("merge-gate median pass rate must be 1.0 (golden responses); got %.4f", report.MedianPassRate)
	}
	for _, rr := range report.Runs {
		if rr.Passed != rr.Total {
			// Surface the first failing scenario for diagnosis.
			for _, res := range rr.Results {
				if !res.Pass {
					t.Errorf("merge-gate FAIL run %d: scenario %s expected=%s terminal=%s reason=%q calls=%d",
						rr.Index, res.ScenarioID, res.ExpectedAction, res.TerminalAction, res.TerminalReason, res.ModelCalls)
				}
			}
			t.Fatalf("merge-gate run %d not green: %d/%d", rr.Index, rr.Passed, rr.Total)
		}
	}
	// Golden responses are deterministic → zero variance → within the 8pp band.
	if !report.WithinBand {
		t.Fatalf("golden-response runs must be within the 8pp band (zero variance expected)")
	}
	// The report must STATE it is not the accuracy number.
	if !strings.Contains(report.Note, "NOT") {
		t.Fatalf("merge-gate report must say it is NOT the accuracy number; note=%q", report.Note)
	}

	// CLASSIFIER: under golden responses every scenario PASSES the GATING axis
	// (chain_action). The classifier therefore bins each scenario as either PASS
	// or R_rubric_axis_fail (the latter is a NON-GATING provenance bin: a scenario
	// whose chain_action passed but whose force-escalate floor reason cannot carry
	// the scenario-specific reasoning_must_mention substrings — a known, expected
	// shape for the hard-constraint families). No scenario may land in an
	// algorithm/infra failure bin under golden responses.
	pass := report.Classifier.Counts[BinPass]
	rubric := report.Classifier.Counts[BinRubricAxisFail]
	if pass+rubric != report.CorpusCount {
		t.Fatalf("classifier: PASS(%d)+R_rubric_axis_fail(%d) must equal corpus %d under golden responses; counts=%v",
			pass, rubric, report.CorpusCount, report.Classifier.Counts)
	}
	for _, bad := range []FailBin{BinNoInference, BinChainDrop, BinShouldResolve, BinShouldEscalate} {
		if n := report.Classifier.Counts[bad]; n != 0 {
			t.Fatalf("classifier: golden responses must produce ZERO %s; got %d (counts=%v)", bad, n, report.Classifier.Counts)
		}
	}
	// Every R_rubric_axis_fail scenario must be one whose chain_action still passed
	// (the bin is provenance, never a harness failure).
	for id, bin := range report.Classifier.PerScenario {
		if bin == BinRubricAxisFail {
			if r := findResult(report.Runs, id); r == nil || r.Structural.ChainAction != AxisPass {
				t.Fatalf("R_rubric_axis_fail scenario %s must have chain_action=pass (non-gating bin)", id)
			}
		}
	}

	// TRANSCRIPTS + RESULT JSON + CLASSIFIER persisted (§4.4/§4.7).
	out := t.TempDir()
	written, err := WriteArtifacts(out, report)
	if err != nil {
		t.Fatalf("WriteArtifacts: %v", err)
	}
	if written != report.CorpusCount*len(report.Runs) {
		t.Fatalf("expected %d transcript files (count*runs); wrote %d", report.CorpusCount*len(report.Runs), written)
	}
	mustExist(t, filepath.Join(out, "report.json"))
	mustExist(t, filepath.Join(out, "classifier.json"))
	// Spot-check one scenario's result JSON + transcript carries real chain data.
	// Pick a scenario that actually REACHED the model: a force-escalated finding
	// (e.g. the E-007/E-008 floor routes added in parity-fixes FIX 1) is escalated
	// pre-LLM and correctly has NO model exchange — an empty transcript is the right
	// behavior there, not a capture regression. The §4.7 "every model exchange
	// captured" invariant is meaningful only for a finding that made model calls.
	var sample string
	for _, res := range report.Runs[0].Results {
		if !res.ForceEscalated && res.ModelCalls > 0 {
			sample = res.ScenarioID
			break
		}
	}
	if sample == "" {
		t.Fatal("no non-force-escalated scenario with model calls to spot-check transcript capture")
	}
	mustExist(t, filepath.Join(out, "run-0", sample+".json"))
	trPath := filepath.Join(out, "run-0", sample+".transcript.json")
	mustExist(t, trPath)
	data, _ := os.ReadFile(trPath)
	if len(strings.TrimSpace(string(data))) < 3 {
		t.Fatalf("transcript %s is empty; §4.7 requires every model exchange captured", trPath)
	}
}

// --- 4. TRANSCRIPT capture is non-negotiable: escalate path has the full chain. -

func TestHarness_TranscriptCapturesFullChain(t *testing.T) {
	pinShippedRoot(t)
	report, err := Run(context.Background(), RunConfig{Mode: ModeCanned, N: 1})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	rr := report.Runs[0]

	// A non-force-escalated ESCALATED scenario drives triage→investigate→escalate
	// = 3 model calls, each captured. AF-02 (distributed-spray) is such a case.
	var found bool
	for _, res := range rr.Results {
		if res.ScenarioID == "AF-02-distributed-spray" {
			found = true
			if res.ForceEscalated {
				t.Fatalf("AF-02 should not be force-escalated (auth-failure-burst is not a hard-constraint route)")
			}
			if res.ModelCalls != 3 {
				t.Fatalf("AF-02 escalate chain should be 3 model calls (triage→investigate→escalate); got %d", res.ModelCalls)
			}
			tr := rr.Transcripts[res.ScenarioID]
			if len(tr) != 3 {
				t.Fatalf("AF-02 transcript should have 3 entries; got %d", len(tr))
			}
			// Every entry carries the system prompt + boxed user prompt (audit value).
			for _, e := range tr {
				if e.System == "" || e.UserPrompt == "" {
					t.Fatalf("transcript entry seq %d missing system/user prompt: %+v", e.Seq, e)
				}
				if !strings.Contains(e.UserPrompt, "USER_DATA") {
					t.Fatalf("transcript entry seq %d user prompt not boxed in USER_DATA markers", e.Seq)
				}
			}
		}
		// A force-escalated PE-* scenario makes ZERO model calls (pre-model floor).
		if res.ScenarioID == "PE-02-self-elevation" {
			if !res.ForceEscalated {
				t.Fatalf("PE-02 (priv-escalation) must be force-escalated pre-model")
			}
			if res.ModelCalls != 0 {
				t.Fatalf("force-escalated PE-02 must make 0 model calls; got %d", res.ModelCalls)
			}
			if res.TerminalAction != "escalated" {
				t.Fatalf("PE-02 terminal must be escalated; got %s", res.TerminalAction)
			}
		}
	}
	if !found {
		t.Fatal("AF-02-distributed-spray not in corpus; the transcript assertion needs it")
	}
}

// --- 5. INTEGRITY GATE HARD-FAILS on a tampered corpus (temp copy). ------------

func TestCorpus_IntegrityGate_HardFailsOnTamper(t *testing.T) {
	src := repoRoot(t)

	// Build a temp corpus tree that PASSES, then tamper it.
	tmp := t.TempDir()
	copyTree(t, filepath.Join(src, scenariosRelPath), filepath.Join(tmp, scenariosRelPath))
	// A go.mod marker so RepoRoot-style resolution is consistent (not strictly
	// needed — Load takes an explicit root).
	mustWrite(t, filepath.Join(tmp, "go.mod"), "module tmp\n\ngo 1.25\n")

	// Sanity: the untampered copy loads clean against its own pin.
	if _, err := Load(tmp); err != nil {
		t.Fatalf("untampered temp copy should load clean: %v", err)
	}

	// TAMPER A: edit a scenario's bytes → SHA mismatch → HARD FAIL.
	victim := pickAnyScenario(t, filepath.Join(tmp, scenariosRelPath))
	appendBytes(t, victim, "\n# tamper: an attacker edited this scenario\n")
	_, err := Load(tmp)
	if err == nil {
		t.Fatal("edited scenario must HARD-FAIL the SHA gate; Load returned no error")
	}
	if !strings.Contains(err.Error(), "sha256") && !strings.Contains(err.Error(), "INTEGRITY") {
		t.Fatalf("tamper error should name the SHA integrity gate; got %v", err)
	}

	// Restore by re-copying, then TAMPER B: add a scenario → COUNT mismatch.
	copyTree(t, filepath.Join(src, scenariosRelPath), filepath.Join(tmp, scenariosRelPath))
	if _, err := Load(tmp); err != nil {
		t.Fatalf("re-copied temp corpus should load clean: %v", err)
	}
	mustWrite(t, filepath.Join(tmp, scenariosRelPath, "behavioral", "ZZ-99-injected.yaml"),
		"id: ZZ-99-injected\nfinding:\n  id: fnd_zz\n  detector: unusual-timing\n  title: injected\n")
	_, err = Load(tmp)
	if err == nil {
		t.Fatal("added scenario must HARD-FAIL the COUNT gate; Load returned no error")
	}
	if !strings.Contains(err.Error(), "count") && !strings.Contains(err.Error(), "INTEGRITY") {
		t.Fatalf("count tamper error should name the count integrity gate; got %v", err)
	}
}

// --- 6. REAL-MODEL MODE is WIRED but refuses to run without creds. -------------

func TestRealMode_WiredButRefusesWithoutCreds(t *testing.T) {
	// Ensure the creds are unset for this assertion (restore after).
	for _, k := range []string{"MALLCOP_INFERENCE_URL", "MALLCOP_API_KEY"} {
		old, had := os.LookupEnv(k)
		_ = os.Unsetenv(k)
		if had {
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		}
	}
	if _, err := RealClientFromEnv(); err == nil {
		t.Fatal("RealClientFromEnv must error without MALLCOP_INFERENCE_URL/MALLCOP_API_KEY")
	}

	// The harness ModeReal also refuses a nil client (no creds → no run).
	pinShippedRoot(t)
	_, err := Run(context.Background(), RunConfig{Mode: ModeReal, N: 1, RealClient: nil})
	if err == nil {
		t.Fatal("ModeReal with a nil client must refuse to run (no creds)")
	}
}

// --- helpers -------------------------------------------------------------------

// findResult returns the ScenarioResult for id in the first run that has it.
func findResult(runs []RunResult, id string) *ScenarioResult {
	for i := range runs {
		for j := range runs[i].Results {
			if runs[i].Results[j].ScenarioID == id {
				return &runs[i].Results[j]
			}
		}
	}
	return nil
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected artifact %s: %v", path, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func appendBytes(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open append %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}

// copyTree mirrors src into dst (files + dirs), overwriting dst. Used to build a
// tamperable temp corpus from the shipped one.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	_ = os.RemoveAll(dst)
	err := filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copyTree %s→%s: %v", src, dst, err)
	}
}

// pickAnyScenario returns the path of one included scenario under root (skips
// underscore paths and the pin file).
func pickAnyScenario(t *testing.T, root string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(root, func(path string, fi os.FileInfo, _ error) error {
		if found != "" || fi == nil || fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if hasUnderscoreComponent(filepath.ToSlash(rel)) {
			return nil
		}
		if strings.HasSuffix(path, ".yaml") {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatal("no scenario found to tamper")
	}
	return found
}
