// backend.go — the inference-Client backends the harness drives the core with,
// and the per-scenario GOLDEN SCRIPT generator for the creds-free MERGE-GATE.
//
// THE {base_url, key} PIVOT (§4.4, direct.go doc): the harness is parameterized
// over a single agent.Client seam. Two modes share it:
//
//   - MERGE-GATE (mode "canned"): a cannedbackend is scripted, PER SCENARIO, to
//     return that scenario's EXPECTED verdict (golden responses). With golden
//     responses the deterministic grader's chain_action axis PASSES for every
//     scenario — 0 pp of model noise. This gates HARNESS + GRADER regressions: if
//     someone breaks the loader, the runner, the verdict parser, the gate wiring,
//     or the grader, the merge-gate goes RED even though no model ran. It is
//     creds-free (no network beyond localhost) so CI runs it on every push.
//
//     THE MERGE-GATE IS EXPLICITLY NOT THE ACCURACY NUMBER. Golden responses say
//     "if the model returned the right answer, does the pipeline grade it right?"
//     — a pipeline-integrity check. The real accuracy number comes ONLY from the
//     real-model run, where the model decides the verdict and the eval measures
//     how often it is correct. Reporting the merge-gate's 100% as accuracy would
//     be a lie; the doc string and the README field both say so.
//
//   - REAL-MODEL (mode "real"): a core/inference.DirectClient pointed at
//     MALLCOP_INFERENCE_URL with MALLCOP_API_KEY. THIS path is WIRED but DELIBERATELY
//     NOT RUN here (no creds in this environment). RealClientFromEnv builds it; the
//     harness CLI / test refuses to run it without both env vars set.
//
// This file imports core/inference ONLY for the real path — it is the package
// boundary where the network client is allowed (core/eval is a harness, not the
// shipped product runtime; the import-lint guards core/, and a harness that wires
// the DirectClient is exactly the intended seam, mirrored on cmd/ + test/).
package eval

import (
	"fmt"
	"os"
	"strings"

	"github.com/mallcop-app/mallcop/core/agent"
	"github.com/mallcop-app/mallcop/core/inference"
	"github.com/mallcop-app/mallcop/internal/exam"
	"github.com/mallcop-app/mallcop/internal/testutil/cannedbackend"
)

// Mode selects the inference backend.
type Mode string

const (
	// ModeCanned is the creds-free merge-gate: cannedbackend golden responses.
	ModeCanned Mode = "canned"
	// ModeReal is the parity run against a live model via DirectClient. WIRED but
	// not run here (no creds).
	ModeReal Mode = "real"
)

// goldenScript returns the cannedbackend CannedResolutionFunc that makes ONE
// scenario reach its EXPECTED terminal action. The runner drives one scenario per
// backend, so the script is keyed purely on call index within that scenario.
//
// The contract mirrors the cascade (cascade.go / tier.go):
//
//	expected resolved → call 0 (triage) returns a CLEAN resolve:
//	    action=resolve, confidence=5, positive_evidence=true → cleanResolve()==true
//	    → terminal RESOLVED at triage (1 call).
//
//	expected escalated → call 0 (triage) escalate, call 1 (investigate) escalate,
//	    call 2 (escalate-formatter) free-text alert → terminal ESCALATED (3 calls).
//	    The alert text embeds the scenario's reasoning_must_mention substrings so
//	    the (non-gating) Mentions axis also passes under golden responses.
//
// A force-escalated scenario (priv-escalation / injection-probe / log-format-drift)
// makes ZERO model calls — the floor escalates pre-model — so the script is never
// invoked for it; the merge-gate still passes on chain_action via the floor.
func goldenScript(s *exam.Scenario) func(callIndex int) string {
	expectResolved := false
	var mentions []string
	if exp := s.ExpectedResolution; exp != nil {
		expectResolved = strings.EqualFold(exp.ChainAction, "resolved")
		mentions = exp.ReasoningMustMention
	}

	if expectResolved {
		// One clean triage resolve closes the finding benign. Embed the
		// must-mention substrings in the reason so the Mentions axis passes too
		// (the resolve terminal reason is "triage resolved (benign): "+reason).
		reason := "benign: positive evidence of legitimacy in events + baseline. " + mentionTail(mentions)
		resolve := fmt.Sprintf(
			`{"action":"resolve","confidence":5,"positive_evidence":true,"strong_evidence":false,"insufficient_data":false,"reason":%q}`,
			reason)
		return func(callIndex int) string {
			// Only call 0 is expected; any extra call still resolves (defensive).
			return resolve
		}
	}

	// Escalate path: triage → investigate → escalate-formatter.
	escTriage := `{"action":"escalate","confidence":3,"positive_evidence":false,"strong_evidence":false,"insufficient_data":false,"reason":"triage: no positive evidence to clear; escalating for investigation."}`
	escInvestigate := `{"action":"escalate","confidence":4,"positive_evidence":false,"strong_evidence":true,"insufficient_data":false,"reason":"investigate: confirmed suspicious pattern; escalating to a human."}`
	// The escalate formatter returns free-text (no JSON verdict). Embed the
	// must-mention substrings here — this IS the terminal reason for an escalated
	// finding (cascade.escalate uses the formatter's text as the alert).
	alert := "SECURITY ALERT: suspicious activity requires human review. " + mentionTail(mentions)

	return func(callIndex int) string {
		switch callIndex {
		case 0:
			return escTriage
		case 1:
			return escInvestigate
		default:
			// call 2 (escalate formatter) and any deep-panel calls.
			return alert
		}
	}
}

// mentionTail renders the must-mention substrings into a sentence so the golden
// reason/alert contains every required substring verbatim (Mentions axis). When
// there are none it returns "".
func mentionTail(mentions []string) string {
	if len(mentions) == 0 {
		return ""
	}
	return "Evidence cited: " + strings.Join(mentions, "; ") + "."
}

// newCannedClient starts a cannedbackend scripted with the scenario's golden
// responses and returns an agent.Client (a DirectClient pointed at it) plus a
// stop func. The caller MUST call stop when the scenario is done.
func newCannedClient(s *exam.Scenario) (agent.Client, func(), error) {
	be := &cannedbackend.CannedBackend{CannedResolutionFunc: goldenScript(s)}
	if err := be.Start(); err != nil {
		return nil, func() {}, fmt.Errorf("start canned backend: %w", err)
	}
	client := &inference.DirectClient{BaseURL: be.URL(), Model: "merge-gate-canned"}
	return client, be.Stop, nil
}

// RealClientFromEnv builds the real-model DirectClient from the environment. It
// is the {base_url,key} pivot's REAL leg: BaseURL=MALLCOP_INFERENCE_URL,
// Key=MALLCOP_API_KEY, Model=MALLCOP_MODEL (optional). It returns an error when
// either required var is unset — the harness REFUSES to run real mode without
// creds, which is why no real call happens in this environment.
func RealClientFromEnv() (agent.Client, error) {
	url := strings.TrimSpace(os.Getenv("MALLCOP_INFERENCE_URL"))
	key := strings.TrimSpace(os.Getenv("MALLCOP_API_KEY"))
	model := strings.TrimSpace(os.Getenv("MALLCOP_MODEL"))
	if url == "" || key == "" {
		return nil, fmt.Errorf("real-model mode requires MALLCOP_INFERENCE_URL and MALLCOP_API_KEY (both must be set); refusing to run without creds")
	}
	if model == "" {
		model = "glm-5"
	}
	return &inference.DirectClient{BaseURL: url, Key: key, Model: model}, nil
}
