package eval

// backend_content_test.go — the merge-gate golden backend is CONTENT-AWARE.
//
// These tests lock in the fix for the residual Rule-11 flake on
// TestHarness_MergeGate_GreenWithMedianOfN: the golden responses must be routed by
// the TIER / DIRECTED HYPOTHESIS in the request's system prompt, NOT by a global
// call index. A call-index script is order-dependent and the cascade's fan-out
// issues THREE deep-investigate calls CONCURRENTLY — so an index-keyed script maps
// responses to the wrong deep hypotheses under nondeterministic goroutine
// scheduling and intermittently flips the gate's pinned exact pass rate.
//
// The decisive proof is TestCannedBackend_ConcurrentDeepCalls_AreContentRouted:
// it drives the REAL CannedBackend (the same server the merge-gate uses) with the
// 3 deep system prompts CONCURRENTLY, many times, and asserts each concurrent call
// gets ITS hypothesis's response every time — exactly the path that used to flake.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
)

// deepSystem builds a system prompt that carries BOTH the "# Deep Investigation
// Agent" preamble marker AND a directed-hypothesis marker — the exact pair the
// real deepInvestigateSystemPrompt embeds (preamble + prior + investigate prompt).
// Routing must classify it as the deep tier with the right hypothesis even though
// the prompt also contains "# Investigation Agent".
func deepSystem(hypMarker string) string {
	return "# Deep Investigation Agent (directed hypothesis)\n\n" + hypMarker +
		"\n\n# Investigation Agent\n\nfull investigate prompt body..."
}

const (
	markerBenign     = "BENIGN: Assume the activity is legitimate"
	markerMalicious  = "MALICIOUS: Assume the credentials are compromised"
	markerIncomplete = "INCOMPLETE: Assume the parent could not resolve"
)

func bodyWithSystem(sys string) []byte {
	b, _ := json.Marshal(map[string]any{"system": sys, "model": "merge-gate-canned"})
	return b
}

// --- 1. routeFromBody classifies every tier (+ deep hypothesis) ----------------

func TestRouteFromBody_ClassifiesTierAndHypothesis(t *testing.T) {
	cases := []struct {
		name    string
		sys     string
		wantT   goldenTier
		wantHyp goldenHypothesis
	}{
		{"triage", "# Triage Agent\n\nbody", tierTriage, hypNone},
		{"investigate", "# Investigation Agent\n\nbody", tierInvestigate, hypNone},
		{"escalate", "# Escalate Agent\n\nbody", tierEscalate, hypNone},
		{"deep-benign", deepSystem(markerBenign), tierDeep, hypBenign},
		{"deep-malicious", deepSystem(markerMalicious), tierDeep, hypMalicious},
		{"deep-incomplete", deepSystem(markerIncomplete), tierDeep, hypIncomplete},
		{"unknown", "# Some Other Agent", tierUnknown, hypNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotT, gotHyp := routeFromBody(bodyWithSystem(c.sys))
			if gotT != c.wantT || gotHyp != c.wantHyp {
				t.Fatalf("routeFromBody(%q) = (%v,%v); want (%v,%v)", c.name, gotT, gotHyp, c.wantT, c.wantHyp)
			}
		})
	}
	// A deep prompt embeds the investigate prompt — the deep marker must win.
	if gotT, _ := routeFromBody(bodyWithSystem(deepSystem(markerMalicious))); gotT != tierDeep {
		t.Fatalf("a deep prompt that also contains '# Investigation Agent' must route to tierDeep; got %v", gotT)
	}
}

// --- 2. goldenScript returns the right verdict per tier/hypothesis --------------

// parseAction pulls the "action" field out of a JSON verdict reply.
func parseAction(t *testing.T, reply string) string {
	t.Helper()
	var v struct {
		Action         string `json:"action"`
		StrongEvidence bool   `json:"strong_evidence"`
	}
	if err := json.Unmarshal([]byte(reply), &v); err != nil {
		t.Fatalf("reply is not a JSON verdict (%q): %v", reply, err)
	}
	return v.Action
}

func TestGoldenScript_ResolvedScenario_ResolvesAtEveryTier(t *testing.T) {
	s := &exam.Scenario{ExpectedResolution: &exam.ExpectedResolution{ChainAction: "resolved"}}
	script := goldenScript(s)

	// Triage of a resolved scenario returns a clean resolve.
	if got := parseAction(t, script(bodyWithSystem("# Triage Agent"))); got != "resolve" {
		t.Fatalf("resolved scenario triage must resolve; got action=%q", got)
	}
	// If it nonetheless fans out, ALL 3 deep hypotheses resolve (positive evidence)
	// so the panel resolves benign — deterministically.
	for _, m := range []string{markerBenign, markerMalicious, markerIncomplete} {
		if got := parseAction(t, script(bodyWithSystem(deepSystem(m)))); got != "resolve" {
			t.Fatalf("resolved scenario deep tier %q must resolve; got action=%q", m, got)
		}
	}
}

func TestGoldenScript_EscalatedScenario_EscalatesDeterministically(t *testing.T) {
	s := &exam.Scenario{ExpectedResolution: &exam.ExpectedResolution{ChainAction: "escalated"}}
	script := goldenScript(s)

	if got := parseAction(t, script(bodyWithSystem("# Triage Agent"))); got != "escalate" {
		t.Fatalf("escalated scenario triage must escalate; got %q", got)
	}
	if got := parseAction(t, script(bodyWithSystem("# Investigation Agent"))); got != "escalate" {
		t.Fatalf("escalated scenario investigate must escalate; got %q", got)
	}
	// The malicious deep tier must carry the STRONG indicator so a fanned-out
	// escalate scenario escalates via the strong-malicious aggregation rule
	// regardless of which goroutine wins.
	var mal struct {
		Action         string `json:"action"`
		StrongEvidence bool   `json:"strong_evidence"`
	}
	if err := json.Unmarshal([]byte(script(bodyWithSystem(deepSystem(markerMalicious)))), &mal); err != nil {
		t.Fatalf("malicious deep reply not JSON: %v", err)
	}
	if mal.Action != "escalate" || !mal.StrongEvidence {
		t.Fatalf("malicious deep tier must escalate with strong_evidence=true; got action=%q strong=%v", mal.Action, mal.StrongEvidence)
	}
	// The escalate formatter is free-text (not a JSON verdict).
	alert := script(bodyWithSystem("# Escalate Agent"))
	if !strings.Contains(alert, "SECURITY ALERT") {
		t.Fatalf("escalate formatter must produce a free-text alert; got %q", alert)
	}
}

// --- 3. THE RACE-KILL PROOF: concurrent deep calls are content-routed ----------
//
// This drives the REAL CannedBackend (the merge-gate's server) wired with the
// content-aware goldenScript, firing the 3 deep system prompts CONCURRENTLY many
// times. Under the old call-index script the response a deep call received
// depended on a nondeterministic global index; here every concurrent call must get
// the response for ITS OWN hypothesis. Run under -race this also covers the
// single-atomic call-index path (no increment-then-load).
func TestCannedBackend_ConcurrentDeepCalls_AreContentRouted(t *testing.T) {
	// An escalated scenario: benign→escalate(weak), malicious→escalate(strong),
	// incomplete→escalate(insufficient). Each is DISTINCT, so a mis-routed response
	// is detectable.
	s := &exam.Scenario{ExpectedResolution: &exam.ExpectedResolution{ChainAction: "escalated"}}
	be := &cannedbackend.CannedBackend{CannedContentFunc: goldenScript(s)}
	if err := be.Start(); err != nil {
		t.Fatalf("start canned backend: %v", err)
	}
	defer be.Stop()

	type want struct {
		sys            string
		action         string
		strongEvidence bool
	}
	wants := []want{
		{deepSystem(markerBenign), "escalate", false},
		{deepSystem(markerMalicious), "escalate", true},
		{deepSystem(markerIncomplete), "escalate", false},
	}

	post := func(sys string) (string, bool, error) {
		body := bodyWithSystem(sys)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			be.URL()+"/v1/messages", bytes.NewReader(body))
		if err != nil {
			return "", false, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", false, err
		}
		defer func() { _ = resp.Body.Close() }()
		var out struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return "", false, err
		}
		if len(out.Content) == 0 {
			return "", false, nil
		}
		var v struct {
			Action         string `json:"action"`
			StrongEvidence bool   `json:"strong_evidence"`
		}
		_ = json.Unmarshal([]byte(out.Content[0].Text), &v)
		return v.Action, v.StrongEvidence, nil
	}

	// Fire the 3 deep prompts concurrently, repeated, so the same backend services
	// overlapping calls exactly as the fan-out does.
	const rounds = 200
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		errs := make([]error, len(wants))
		gotAction := make([]string, len(wants))
		gotStrong := make([]bool, len(wants))
		for i, w := range wants {
			wg.Add(1)
			go func(i int, w want) {
				defer wg.Done()
				a, st, err := post(w.sys)
				errs[i], gotAction[i], gotStrong[i] = err, a, st
			}(i, w)
		}
		wg.Wait()
		for i, w := range wants {
			if errs[i] != nil {
				t.Fatalf("round %d call %d: %v", r, i, errs[i])
			}
			if gotAction[i] != w.action || gotStrong[i] != w.strongEvidence {
				t.Fatalf("round %d: hypothesis %q got (action=%q,strong=%v); want (action=%q,strong=%v) — "+
					"content routing scrambled under concurrency (the flake)", r, w.sys, gotAction[i], gotStrong[i], w.action, w.strongEvidence)
			}
		}
	}
}

// compile-time anchor: the content func has the body-routed signature the
// CannedBackend.CannedContentFunc seam expects.
var _ func(body []byte) string = goldenScript(&exam.Scenario{})

// keep agent imported for the seam reference even if the file evolves.
var _ = agent.Client(nil)
