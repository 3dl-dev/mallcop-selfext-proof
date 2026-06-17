// hardconstraints.go — the ONLY gate before any model call.
//
// Ported from the Python per-finding hard-constraint gate
// (src/mallcop/resolution_rules.py: check_hard_constraints + ALWAYS_ESCALATE_
// DETECTORS) and the boundary-violation volume circuit-breaker
// (src/mallcop/budget.py: check_circuit_breaker, surfaced via escalate.py).
//
// These are hard security constraints that models fail to enforce reliably.
// Moving them to deterministic code guarantees 100% compliance: a finding in a
// dangerous family is escalated to a human in code, with no model in the loop
// and no donuts spent. The model literally never sees it.
package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/pkg/finding"
)

// Action is the deterministic disposition the floor assigns a finding.
type Action string

const (
	// ActionEscalated means: surface to a human. The floor only ever emits this.
	ActionEscalated Action = "escalated"
	// ActionProceed means: not hard-constrained; continue to model routing.
	ActionProceed Action = "proceed"
)

// Resolution is the deterministic outcome of the pre-LLM floor for one finding.
// It is the only thing the floor returns; the model is never consulted to build
// it.
type Resolution struct {
	// ForceEscalated is true when a hard constraint fired. When true, Action is
	// always ActionEscalated and Reason explains which family tripped.
	ForceEscalated bool
	Action         Action
	Reason         string
	// Family is the normalized, canonical finding family that matched (or the
	// normalized input family when nothing matched).
	Family string
}

// hardConstraintFamilies is the canonical set of finding families that ALWAYS
// escalate deterministically — no LLM involved. This is the union of the
// Python ALWAYS_ESCALATE_DETECTORS / _NEVER_AUTO_RESOLVE security families that
// apply per-finding, plus secrets-exposure: a leaked secret must never be
// auto-resolved by a model.
//
//   - secrets-exposure  — credential/secret leakage; auditing a leak to a model
//     would itself risk re-exposing it.
//   - priv-escalation   — privilege changes always need human audit.
//   - injection-probe   — prompt-injection attempts; the one thing a model is
//     least able to adjudicate about itself.
//   - boundary-violation — access-boundary breaches; exempt from squelch/budget
//     in Python, always escalated.
//
// log-format-drift from the Python set is intentionally omitted: there is no
// such detector in this Go codebase (the detector registry has no
// log-format-drift), so listing it would be dead config. If that detector lands
// later, add its canonical name here and the floor covers it automatically.
var hardConstraintFamilies = map[string]struct{}{
	"secrets-exposure":   {},
	"priv-escalation":    {},
	"injection-probe":    {},
	"boundary-violation": {},
}

// circuitBreakerFamily marks the synthetic meta-finding emitted by
// CheckCircuitBreaker. It is itself a hard constraint so a tripped breaker is
// surfaced to a human and never routed to the model.
const circuitBreakerFamily = "mallcop-budget"

// familyAliases maps known evasions / aliases of a dangerous signature onto its
// canonical family. This is the BYPASS defense: an attacker (or a sloppy
// detector) that emits "privilege-escalation", "prompt-injection", or
// "secret_exposure" instead of the canonical name still trips the floor. The
// keys are already case-folded and separator-normalized (see normalizeFamily),
// so only the alphanumeric spelling needs listing.
var familyAliases = map[string]string{
	// priv-escalation aliases
	"privilegeescalation": "priv-escalation",
	"privesc":             "priv-escalation",
	"privilegeesc":        "priv-escalation",
	// injection-probe aliases
	"promptinjection":  "injection-probe",
	"injectionattempt": "injection-probe",
	"injection":        "injection-probe",
	// secrets-exposure aliases (singular / "leak" phrasings)
	"secretexposure":  "secrets-exposure",
	"secretsexposure": "secrets-exposure",
	"secretleak":      "secrets-exposure",
	"secretsleak":     "secrets-exposure",
	// boundary-violation aliases
	"boundarybreach": "boundary-violation",
}

// canonicalFamilies maps the case-folded, separator-stripped spelling of each
// canonical family back to the canonical hyphenated form. Built once from
// hardConstraintFamilies so "INJECTION-PROBE", "injection_probe", and
// "injectionprobe" all resolve to "injection-probe".
var canonicalFamilies = func() map[string]string {
	m := make(map[string]string, len(hardConstraintFamilies))
	for fam := range hardConstraintFamilies {
		m[stripSeparators(fam)] = fam
	}
	return m
}()

// normalizeFamily reduces a raw finding family to its canonical hard-constraint
// name when it matches one (directly, by alias, or by separator/case evasion),
// or returns the trimmed lower-cased input otherwise.
//
// This is the BYPASS hardening: case folding, whitespace trimming, and
// separator stripping collapse "  Injection-Probe ", "PRIV-ESCALATION", and
// "secrets_exposure" onto their canonical forms before the membership test.
func normalizeFamily(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	stripped := stripSeparators(trimmed)
	if canon, ok := canonicalFamilies[stripped]; ok {
		return canon
	}
	if canon, ok := familyAliases[stripped]; ok {
		return canon
	}
	return trimmed
}

// stripSeparators removes hyphens, underscores, spaces and tabs and lower-cases
// the rest, so separator/case variants of a family collapse to one key.
func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		switch r {
		case '-', '_', ' ', '\t', '\n', '\r', '.', '/', ':':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// checkHardConstraints is the ONLY gate before any model call. It is the direct
// port of resolution_rules.check_hard_constraints, hardened against family-match
// evasion.
//
// It returns (forceEscalate, resolution):
//   - forceEscalate=true with an escalated Resolution when the finding's family
//     is a hard constraint (or a tripped circuit-breaker meta-finding). The
//     caller MUST NOT call the model in this case.
//   - forceEscalate=false with a proceed Resolution otherwise; the caller may
//     route the finding to the model.
//
// No model involvement, no I/O, no network — pure code enforcement.
func checkHardConstraints(f finding.Finding) (bool, Resolution) {
	fam := normalizeFamily(f.Type)

	if fam == circuitBreakerFamily {
		return true, Resolution{
			ForceEscalated: true,
			Action:         ActionEscalated,
			Family:         fam,
			Reason: "Hard constraint: volume circuit-breaker tripped — too many findings " +
				"for safe autonomous handling; human review required (deterministic, no LLM)",
		}
	}

	if _, ok := hardConstraintFamilies[fam]; ok {
		return true, Resolution{
			ForceEscalated: true,
			Action:         ActionEscalated,
			Family:         fam,
			Reason: fmt.Sprintf(
				"Hard constraint: %s findings always require human review "+
					"(deterministic escalation, no LLM involved)", fam),
		}
	}

	return false, Resolution{
		ForceEscalated: false,
		Action:         ActionProceed,
		Family:         fam,
	}
}

// BudgetConfig carries the single knob the volume circuit-breaker needs: the max
// finding count that may be handled autonomously before the breaker trips.
// Ported from src/mallcop/budget.py BudgetConfig.max_findings_for_actors.
type BudgetConfig struct {
	// MaxFindingsForActors is the inclusive ceiling. A run with strictly MORE
	// findings than this trips the breaker.
	MaxFindingsForActors int
}

// CheckCircuitBreaker ports src/mallcop/budget.py check_circuit_breaker.
//
// When the number of findings exceeds MaxFindingsForActors, it returns a
// synthetic CRITICAL meta-finding (family "mallcop-budget") describing the trip.
// That meta-finding is itself a hard constraint (see checkHardConstraints), so a
// tripped breaker is surfaced to a human and never routed to the model. When the
// count is at or under the threshold it returns nil — no breaker.
//
// The breaker is a volume defense: a flood of findings (e.g. an attacker
// generating noise to drown a real boundary violation) must not be quietly
// auto-handled. It halts autonomous processing and escalates.
func CheckCircuitBreaker(findings []finding.Finding, cfg BudgetConfig) *finding.Finding {
	if len(findings) <= cfg.MaxFindingsForActors {
		return nil
	}

	breakdown := map[string]int{}
	for _, f := range findings {
		breakdown[f.Severity]++
	}
	parts := make([]string, 0, len(breakdown))
	for sev, n := range breakdown {
		parts = append(parts, fmt.Sprintf("%s=%d", sev, n))
	}

	return &finding.Finding{
		ID:        "meta_circuit_breaker",
		Source:    "mallcop-budget",
		Type:      circuitBreakerFamily,
		Severity:  "critical",
		Timestamp: time.Now().UTC(),
		Reason: fmt.Sprintf(
			"Volume circuit breaker triggered: %d findings exceed threshold %d (severity breakdown: %s)",
			len(findings), cfg.MaxFindingsForActors, strings.Join(parts, " ")),
	}
}

// hardConstraintFamiliesForTest exposes the canonical hard-constraint families
// to the package test (RESOLUTION-RULES positive case) without exporting the
// internal map.
func hardConstraintFamiliesForTest() []string {
	out := make([]string, 0, len(hardConstraintFamilies))
	for fam := range hardConstraintFamilies {
		out = append(out, fam)
	}
	return out
}
