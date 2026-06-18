// classifier.go — the ~40-line failure classifier (portable-agent-architecture.md
// §4.8). It bins each scenario into one of: PASS / I*-infra / A1/A2-algorithm /
// R*-rubric. The cluster name names the fix the next iteration needs — the
// classifier output is the to-do list for the loop.
//
// Bins (lifted from §4.8's classifier vocabulary):
//
//	PASS                            — chain_action passed.
//	I3_no_inference                 — 0 model calls AND not a force-escalate route
//	                                  (the model was never reached → infra/wiring bug).
//	I2_chain_drop_no_terminal       — no terminal action recorded (chain dropped).
//	A1_invest_should_resolve_but_escalated — expected resolved, got escalated
//	                                  (over-escalation cluster, §4.3).
//	A2_should_escalate_but_resolved — expected escalated, got resolved
//	                                  (under-escalation cluster — the dangerous tail).
//	R_rubric_axis_fail              — chain_action passed but a non-gating axis
//	                                  (mentions / no_mentions) failed. Reported for
//	                                  provenance; does NOT count as a harness failure.
package eval

// FailBin is a classifier bin name.
type FailBin string

const (
	BinPass           FailBin = "PASS"
	BinNoInference    FailBin = "I3_no_inference"
	BinChainDrop      FailBin = "I2_chain_drop_no_terminal"
	BinShouldResolve  FailBin = "A1_invest_should_resolve_but_escalated"
	BinShouldEscalate FailBin = "A2_should_escalate_but_resolved"
	BinRubricAxisFail FailBin = "R_rubric_axis_fail"
)

// ClassifierSummary aggregates bins across the worst (most-failing) run so the
// loop sees the dominant cluster. Counts is bin → number of scenarios.
type ClassifierSummary struct {
	Counts map[FailBin]int `json:"counts"`
	// PerScenario maps scenario id → its bin, for transcript pull (§4.8 step 3).
	PerScenario map[string]FailBin `json:"per_scenario"`
}

// classifyOne bins a single graded result.
func classifyOne(r ScenarioResult) FailBin {
	if r.Pass {
		// Gating axis passed. Flag a non-gating axis miss for provenance only.
		if r.Structural.Mentions == AxisFail || r.Structural.NoMentions == AxisFail {
			return BinRubricAxisFail
		}
		return BinPass
	}
	if r.TerminalAction == "" {
		return BinChainDrop
	}
	if r.ModelCalls == 0 && !r.ForceEscalated {
		return BinNoInference
	}
	// chain_action failed with a terminal action present: an algorithm miss.
	switch {
	case r.ExpectedAction == "resolved" && r.TerminalAction == "escalated":
		return BinShouldResolve // over-escalation
	case r.ExpectedAction == "escalated" && r.TerminalAction == "resolved":
		return BinShouldEscalate // under-escalation (dangerous)
	default:
		return BinShouldEscalate // any other gating miss → treat as under-handled
	}
}

// Classify bins the run with the LOWEST pass-rate (the worst case names the
// cluster to fix). Median-of-N reports the median rate; the classifier reports
// the worst run's failure shape so the loop targets the real weakness.
func Classify(runs []RunResult) ClassifierSummary {
	sum := ClassifierSummary{
		Counts:      map[FailBin]int{},
		PerScenario: map[string]FailBin{},
	}
	if len(runs) == 0 {
		return sum
	}
	worst := runs[0]
	for _, rr := range runs[1:] {
		if rr.PassRate < worst.PassRate {
			worst = rr
		}
	}
	for _, r := range worst.Results {
		bin := classifyOne(r)
		sum.Counts[bin]++
		sum.PerScenario[r.ScenarioID] = bin
	}
	return sum
}
