// scenario_tools_test.go — proves the LIVE path gives the agent REAL,
// scenario-specific evidence (portable-agent-architecture.md §3.8, §4.1).
//
// This is the whole point of the parity run: before this wiring, ModeReal's agent
// investigated with NO scenario telemetry (search-events returned nothing, etc.)
// and the parity number was meaningless. These tests drive a scenario through
// RunScenario with a SCRIPTED httptest backend (the same {base_url,key} seam
// core/inference/direct_test.go exercises) and assert the tool transcript that
// REACHES the model is non-empty AND scenario-specific — and that a DIFFERENT
// scenario produces DIFFERENT tool data (per-scenario isolation, not a shared
// runner). Determinism: SetRepoRootForTest pins the corpus + rule root, so
// -count=N -race resolves the same data every run regardless of binary placement.
package eval

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/internal/exam"
)

// repoRootForTest walks up from the test's working directory (the package dir
// under `go test`) to the directory that holds exams/scenarios, then pins it via
// SetRepoRootForTest so the harness + the §3.8 rule fold resolve deterministically.
// Returns the resolved root; the caller defers SetRepoRootForTest("").
func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if fi, err := os.Stat(filepath.Join(dir, scenariosRelPath)); err == nil && fi.IsDir() {
			SetRepoRootForTest(dir)
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no %s found walking up from %s", scenariosRelPath, dir)
		}
		dir = parent
	}
}

// loadScenarioForTest loads a corpus scenario by its repo-relative path under
// exams/scenarios and wraps it as a LoadedScenario the runner consumes.
func loadScenarioForTest(t *testing.T, root, rel string) LoadedScenario {
	t.Helper()
	s, err := exam.Load(filepath.Join(root, scenariosRelPath, rel))
	if err != nil {
		t.Fatalf("load scenario %s: %v", rel, err)
	}
	return LoadedScenario{RelPath: rel, Scenario: s}
}

// recordingHTTPBackend is a scripted Anthropic-compatible httptest server that
// CAPTURES every request body it receives and returns a fixed escalate verdict so
// the cascade terminates. The captured user-prompt text is where the boxed tool
// transcript (search-events / check-baseline / search-findings results) lands —
// the seam this test inspects to prove the model saw real, scenario-specific
// evidence.
type recordingHTTPBackend struct {
	srv    *httptest.Server
	bodies []string
}

func newRecordingHTTPBackend(t *testing.T) *recordingHTTPBackend {
	t.Helper()
	b := &recordingHTTPBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		b.bodies = append(b.bodies, string(buf))
		w.Header().Set("Content-Type", "application/json")
		// A well-formed escalate verdict — terminates triage→investigate→escalate
		// deterministically without needing tool_use turns (the cascade pre-gathers
		// tool evidence via the ToolRunner and boxes it into the prompt; the model
		// only returns the verdict).
		resp := map[string]any{
			"type":        "message",
			"role":        "assistant",
			"stop_reason": "end_turn",
			"content": []map[string]any{
				{"type": "text", "text": `{"action":"escalate","confidence":3,"positive_evidence":false,"strong_evidence":false,"insufficient_data":false,"reason":"escalating for human review"}`},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *recordingHTTPBackend) client() agent.Client {
	return &inference.DirectClient{BaseURL: b.srv.URL, Key: "test-key", Model: "scripted-test"}
}

// firstToolTranscript returns the boxed tools.transcript text from the FIRST
// captured request — the evidence the triage model saw. The cascade boxes the
// tool transcript in USER_DATA markers labelled "tools.transcript"; we return the
// whole first user-prompt text (the transcript is a substring of it).
func (b *recordingHTTPBackend) firstUserPrompt(t *testing.T) string {
	t.Helper()
	if len(b.bodies) == 0 {
		t.Fatal("scripted backend captured zero requests — the cascade never reached the model")
	}
	var req struct {
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(b.bodies[0]), &req); err != nil {
		t.Fatalf("decode captured request: %v\nbody: %s", err, b.bodies[0])
	}
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		for _, c := range m.Content {
			if c.Type == "text" && c.Text != "" {
				return c.Text
			}
		}
	}
	t.Fatalf("no user text block in captured request: %s", b.bodies[0])
	return ""
}

// TestRunScenario_LiveTools_FeedsScenarioSpecificEvidence drives UT-02 through
// RunScenario with liveTools=true and a scripted backend, then asserts the tool
// transcript the model saw is NON-EMPTY and carries THIS scenario's telemetry:
// its event id, its actor, its baseline frequency, and the §3.8 folded rule
// (R-001, which keys on the maintenance_window flag the events carry). This is the
// proof the live agent actually investigates instead of staring at an empty box.
func TestRunScenario_LiveTools_FeedsScenarioSpecificEvidence(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	// The cascade FLOOR (core/agent) resolves the escalate-route corpus through
	// its OWN repo-root seam; pin it too or the floor fails safe (force-escalate,
	// no model call) when it can't locate the corpus from the test binary.
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	be := newRecordingHTTPBackend(t)

	run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
	if run.SeedErr != "" {
		t.Fatalf("live ToolRunner failed to seed: %s", run.SeedErr)
	}

	prompt := be.firstUserPrompt(t)
	mustContain := map[string]string{
		"event id (search-events returned the scenario's events)": "evt_001",
		"actor (the entity under investigation)":                  "deploy-svc",
		"baseline frequency (check-baseline answered routine?)":   "156",
		"folded operator rule (§3.8 matched_rules)":               "R-001",
		"the search-events tool ran":                              "search-events",
		"the check-baseline tool ran":                             "check-baseline",
	}
	for why, want := range mustContain {
		if !strings.Contains(prompt, want) {
			t.Errorf("tool transcript missing %q (%s)\n--- prompt ---\n%s", want, why, prompt)
		}
	}
}

// TestRunScenario_LiveTools_PerScenarioIsolation proves the runner is built PER
// SCENARIO, not shared/static: UT-02 (actor deploy-svc, container_restart) and
// VA-02 (actor batch-processor, database_access) must each see ONLY their own
// telemetry. If a single shared runner leaked across scenarios, VA-02's prompt
// would carry UT-02's actor (or vice versa) — the assertions below forbid that.
func TestRunScenario_LiveTools_PerScenarioIsolation(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	// The cascade FLOOR (core/agent) resolves the escalate-route corpus through
	// its OWN repo-root seam; pin it too or the floor fails safe (force-escalate,
	// no model call) when it can't locate the corpus from the test binary.
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	utLS := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	vaLS := loadScenarioForTest(t, root, "behavioral/VA-02-month-end-batch.yaml")

	utBE := newRecordingHTTPBackend(t)
	vaBE := newRecordingHTTPBackend(t)

	if run := RunScenario(context.Background(), utBE.client(), utLS, agent.CascadeOptions{}, true); run.SeedErr != "" {
		t.Fatalf("UT-02 seed error: %s", run.SeedErr)
	}
	if run := RunScenario(context.Background(), vaBE.client(), vaLS, agent.CascadeOptions{}, true); run.SeedErr != "" {
		t.Fatalf("VA-02 seed error: %s", run.SeedErr)
	}

	utPrompt := utBE.firstUserPrompt(t)
	vaPrompt := vaBE.firstUserPrompt(t)

	// Each scenario sees its OWN actor.
	if !strings.Contains(utPrompt, "deploy-svc") {
		t.Errorf("UT-02 prompt missing its own actor deploy-svc")
	}
	if !strings.Contains(vaPrompt, "batch-processor") {
		t.Errorf("VA-02 prompt missing its own actor batch-processor")
	}
	// Crucially, neither sees the OTHER's actor — no shared/leaked runner.
	if strings.Contains(utPrompt, "batch-processor") {
		t.Errorf("ISOLATION BREACH: UT-02 prompt leaked VA-02 actor batch-processor\n%s", utPrompt)
	}
	if strings.Contains(vaPrompt, "deploy-svc") {
		t.Errorf("ISOLATION BREACH: VA-02 prompt leaked UT-02 actor deploy-svc\n%s", vaPrompt)
	}
	// And the tool data differs (proving distinct per-scenario evidence, not a
	// static fixture echoed for both).
	if utPrompt == vaPrompt {
		t.Errorf("UT-02 and VA-02 saw identical prompts — tool data is not per-scenario")
	}
}

// TestRunScenario_LiveTools_NotSilentlyEmptyOnReal proves the §gap fix's core
// guarantee: with liveTools=true a REAL per-scenario runner is ALWAYS wired even
// when the caller passes a nil opts.Tools. The agent must NOT silently investigate
// with an empty toolbox — the captured prompt carries real tool output, and a
// run with liveTools=false (the merge-gate path) carries NONE of it, proving the
// difference is the live wiring, not the scenario.
func TestRunScenario_LiveTools_NotSilentlyEmptyOnReal(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	// The cascade FLOOR (core/agent) resolves the escalate-route corpus through
	// its OWN repo-root seam; pin it too or the floor fails safe (force-escalate,
	// no model call) when it can't locate the corpus from the test binary.
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")

	// liveTools=true, nil opts.Tools → a real runner is injected.
	liveBE := newRecordingHTTPBackend(t)
	if run := RunScenario(context.Background(), liveBE.client(), ls, agent.CascadeOptions{Tools: nil}, true); run.SeedErr != "" {
		t.Fatalf("live seed error: %s", run.SeedErr)
	}
	livePrompt := liveBE.firstUserPrompt(t)
	if !strings.Contains(livePrompt, "search-events") || !strings.Contains(livePrompt, "evt_001") {
		t.Fatalf("liveTools=true did NOT wire a real ToolRunner — prompt has no scenario tool data:\n%s", livePrompt)
	}

	// liveTools=false, nil opts.Tools → NO tools wired (merge-gate semantics). The
	// prompt must carry no tool transcript at all.
	gateBE := newRecordingHTTPBackend(t)
	if run := RunScenario(context.Background(), gateBE.client(), ls, agent.CascadeOptions{Tools: nil}, false); run.SeedErr != "" {
		t.Fatalf("gate run unexpectedly seeded a runner: %s", run.SeedErr)
	}
	gatePrompt := gateBE.firstUserPrompt(t)
	if strings.Contains(gatePrompt, "search-events") || strings.Contains(gatePrompt, "check-baseline") {
		t.Fatalf("liveTools=false wired tools anyway (should be tool-free merge-gate path):\n%s", gatePrompt)
	}
}

// TestRunScenario_LiveTools_EventTargetActionReachTheModel proves FIX 4 (eval
// fidelity, event side): a scenario event's target + action now reach the model
// prompt. Before the fix the eval projected only "actor did <event_type>" and the
// model was blind to WHAT each event did and to WHAT — the per-event relationship
// detail legion's academy fed its agent. UT-02's evt_001 carries
// action=restart_container and a target under atom-api; both must appear in the
// boxed tool transcript the triage model sees.
func TestRunScenario_LiveTools_EventTargetActionReachTheModel(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	be := newRecordingHTTPBackend(t)

	run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
	if run.SeedErr != "" {
		t.Fatalf("live ToolRunner failed to seed: %s", run.SeedErr)
	}

	prompt := be.firstUserPrompt(t)
	// action= and target= must be present, carrying the scenario's per-event detail.
	if !strings.Contains(prompt, "action=restart_container") {
		t.Errorf("event ACTION did not reach the model prompt (want action=restart_container)\n--- prompt ---\n%s", prompt)
	}
	if !strings.Contains(prompt, "target=") || !strings.Contains(prompt, "atom-api") {
		t.Errorf("event TARGET did not reach the model prompt (want target=...atom-api)\n--- prompt ---\n%s", prompt)
	}
}

// TestRunScenario_LiveTools_RelationshipsReachTheModel proves FIX 4 (eval fidelity,
// baseline side): the scenario's relationships table is reconstructed into
// pkg/baseline and surfaced by check-baseline so it reaches the model prompt — the
// actor↔target history the academy showed its agent. UT-02's baseline records
// deploy-svc↔atom-api with count 89; the boxed check-baseline transcript must carry
// a relationships line citing it.
func TestRunScenario_LiveTools_RelationshipsReachTheModel(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	be := newRecordingHTTPBackend(t)

	run := RunScenario(context.Background(), be.client(), ls, agent.CascadeOptions{}, true)
	if run.SeedErr != "" {
		t.Fatalf("live ToolRunner failed to seed: %s", run.SeedErr)
	}

	prompt := be.firstUserPrompt(t)
	if !strings.Contains(prompt, "relationships:") {
		t.Errorf("the relationships baseline did not reach the model prompt (want a 'relationships:' line)\n--- prompt ---\n%s", prompt)
	}
	if !strings.Contains(prompt, "count=89") {
		t.Errorf("the deploy-svc↔atom-api relationship (count=89) did not reach the model prompt\n--- prompt ---\n%s", prompt)
	}
}

// TestBaselineFromScenario_RelationshipsQueryable proves the relationships table is
// reconstructed into the typed pkg/baseline and is QUERYABLE via RelationshipsFor —
// the queryable-surface half of FIX 4. UT-02's baseline records two deploy-svc
// relationships; a lookup on the actor must return them with their counts.
func TestBaselineFromScenario_RelationshipsQueryable(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	bl := baselineFromScenario(ls.Scenario)
	if bl == nil {
		t.Fatal("baselineFromScenario returned nil for a scenario with a baseline")
	}
	rels := bl.RelationshipsFor("deploy-svc")
	if len(rels) == 0 {
		t.Fatalf("RelationshipsFor(deploy-svc) returned no relationships; the scenario table was not reconstructed\nrelationships=%v", bl.Relationships)
	}
	// The atom-api relationship has count 89 in the corpus.
	found := false
	for k, rel := range rels {
		if strings.Contains(k, "atom-api") && rel.Count == 89 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a deploy-svc↔atom-api relationship with count=89; got %v", rels)
	}
}

// TestScenarioToolRunner_ToolEmptyForeignActor proves the ToolEmpty fail-safe
// signal is real and scenario-scoped: a runner whose search-events filter matches
// NO event (a finding for an actor absent from the scenario's events) reports
// ToolEmpty=true — the cascade force-escalates a resolve built on an empty read
// (§3.4). This guards against a regression where the runner fabricates evidence
// or swallows the empty signal.
func TestScenarioToolRunner_ToolEmptyForeignActor(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	// The cascade FLOOR (core/agent) resolves the escalate-route corpus through
	// its OWN repo-root seam; pin it too or the floor fails safe (force-escalate,
	// no model call) when it can't locate the corpus from the test binary.
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	ls := loadScenarioForTest(t, root, "behavioral/UT-02-maintenance-window.yaml")
	r, err := newScenarioToolRunner(t.TempDir(), root, ls.Scenario)
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	// Force the search filter to an actor that owns no events in this scenario.
	r.actor = "actor-not-in-this-scenario"

	ev, err := r.RunTools(context.Background(), "triage", findingFromScenario(ls.Scenario))
	if err != nil {
		t.Fatalf("RunTools: %v", err)
	}
	if !ev.ToolEmpty {
		t.Errorf("search-events matched no events but ToolEmpty=false: an empty read must be reported so the fail-safe can fire\n%s", ev.Text)
	}
}
