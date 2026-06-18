// gate.go — shared helpers for the model seam. ResolveFinding (the tiered
// cascade entry point) lives in cascade.go; the floor (checkHardConstraints)
// lives in hardconstraints.go/router.go. This file holds only the small,
// cross-tier helpers that read a model response.
//
// History: this file once held a floor+single-call STUB of ResolveFinding (floor
// then one advisory model call). The cascade wave replaced that stub with the
// real triage → investigate → escalate chain (cascade.go + tier.go). The stub's
// buildResolveRequest is gone — each tier builds its own untrusted-data-safe
// request (buildTierRequest / buildEscalateRequest in tier.go). firstText
// survives here because every tier and the escalate role read the model's first
// text block through it.
package agent

// firstText returns the first non-empty text block of a response, or "" if none.
// Every tier (triage, investigate) and the escalate formatter reads the model's
// reply through this single helper.
func firstText(resp MessagesResponse) string {
	for _, b := range resp.Content {
		if b.Type == "text" && b.Text != "" {
			return b.Text
		}
	}
	return ""
}
