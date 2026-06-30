package pipeline

import (
	"strings"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/finding"
)

// findingKey is the STABLE identity a directive Pattern matches a finding by.
// It is "<source>/<type>/<actor>" — the triple that names "this kind of finding
// about this actor from this detector". The CLI derives a suppress Pattern from
// a concrete finding using exactly this key (see cmd/mallcop/feedback.go), so a
// directive written for one finding suppresses every future finding with the
// same source/type/actor — which is the whole point: the operator dismisses a
// CLASS of finding, not a single transient ID.
//
// The key is deterministic and depends only on durable finding fields, never on
// the per-run finding ID (which embeds the event ID and is not stable across
// scans). An empty segment is preserved (kept as "") so the arity is always
// three and a '*' glob in the directive can still match it.
func findingKey(f finding.Finding) string {
	return f.Source + "/" + f.Type + "/" + f.Actor
}

// matchPattern reports whether a directive Pattern matches a finding key. The
// match is segment-wise over the "<source>/<type>/<actor>" triple:
//
//   - The pattern is split on '/' into at most three segments.
//   - A '*' segment matches ANY value for that position (a wildcard).
//   - Any other segment must equal the corresponding key segment exactly.
//   - A pattern with FEWER than three segments matches on the segments it does
//     name (a prefix match) — e.g. "detector:secrets-exposure" matches every
//     finding from that source regardless of type/actor. A pattern with MORE
//     than three segments never matches (it over-specifies the triple).
//
// The matching is deterministic and case-sensitive — directives are written by
// the CLI from real finding fields, so the casing always lines up.
func matchPattern(pattern string, f finding.Finding) bool {
	if pattern == "" {
		return false
	}
	keyParts := []string{f.Source, f.Type, f.Actor}
	patParts := strings.Split(pattern, "/")
	if len(patParts) > len(keyParts) {
		return false
	}
	for i, p := range patParts {
		if p == "*" {
			continue
		}
		if p != keyParts[i] {
			return false
		}
	}
	return true
}

// applyDirectives filters findings against the operator-steering directive
// stream. It is the load-bearing seam that makes persisted feedback INERT no
// longer: a 'suppress' directive written by `mallcop feedback <id> dismiss`
// drops every future finding whose key matches the directive Pattern.
//
// Semantics (deterministic, order-sensitive replay of the append-only stream):
//
//   - suppress   — a finding matching Pattern is DROPPED.
//   - unsuppress — CANCELS a prior suppress for the same Pattern: a later
//     unsuppress wins, so the finding is kept again. (Replay order is the
//     directive stream order — oldest first — so the last word on a Pattern
//     wins.)
//   - focus / mute / anything else — not a drop verb here; left to other
//     consumers (notification muting, prioritization). They never remove a
//     finding, so they are no-ops for this filter.
//
// Returns the kept findings in their original order. A finding is kept unless
// the net effect of all directives that match it is "suppressed".
func applyDirectives(findings []finding.Finding, directives []store.Directive) []finding.Finding {
	if len(directives) == 0 {
		return findings
	}
	kept := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		suppressed := false
		for _, d := range directives {
			if !matchPattern(d.Pattern, f) {
				continue
			}
			switch d.Op {
			case "suppress":
				suppressed = true
			case "unsuppress":
				suppressed = false
			}
		}
		if !suppressed {
			kept = append(kept, f)
		}
	}
	return kept
}
