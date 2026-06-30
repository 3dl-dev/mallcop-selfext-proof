// Package notify holds the reusable outbound-notification send paths shared by
// the cmd/notify-* adapter binaries and the scan pipeline's gated emit step.
//
// The Discord path here is the single source of truth for "format a resolution
// and POST it to a Discord incoming webhook." cmd/notify-discord wraps it for
// the stdin→webhook adapter; cmd/mallcop scan calls EmitEscalations directly
// when DISCORD_WEBHOOK_URL is set. Keeping one implementation means the scan
// emit and the standalone adapter can never drift in wire shape.
//
// No bot token is involved. This is the OUTBOUND half only. The inbound Discord
// bot bridge (operator replies auto-converted to `mallcop feedback`) is out of
// scope and requires a bot token — see the repo NOTES.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// FormatDiscord renders a resolution as a Discord message line. Discord uses
// **bold** markdown (Slack uses *bold*), but the field set is identical.
func FormatDiscord(res resolution.Resolution) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**mallcop: %s**\n", strings.ToUpper(res.Action)))
	sb.WriteString(fmt.Sprintf("Finding: %s\n", res.FindingID))
	if res.Actor != "" {
		sb.WriteString(fmt.Sprintf("Actor: %s\n", res.Actor))
	}
	if res.Severity != "" {
		sb.WriteString(fmt.Sprintf("Severity: %s\n", res.Severity))
	}
	if res.Source != "" {
		sb.WriteString(fmt.Sprintf("Source: %s\n", res.Source))
	}
	if res.Reason != "" {
		sb.WriteString(fmt.Sprintf("Reason: %s\n", res.Reason))
	}
	if res.Confidence > 0 {
		sb.WriteString(fmt.Sprintf("Confidence: %.0f%%\n", res.Confidence*100))
	}
	if !res.Timestamp.IsZero() {
		sb.WriteString(fmt.Sprintf("Time: %s\n", res.Timestamp.UTC().Format(time.RFC3339)))
	}
	return sb.String()
}

// SendDiscord POSTs {"content": content} to a Discord incoming webhook. Discord
// returns 204 on success; any 2xx is accepted.
func SendDiscord(ctx context.Context, webhookURL, content string) error {
	payload, err := json.Marshal(map[string]string{"content": content})
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL,
		bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned %d", resp.StatusCode)
	}
	return nil
}

// EmitEscalations is the GATED scan→Discord hook. For each resolution whose
// Action is "escalate", it formats and POSTs the finding to the Discord webhook.
// It is the caller's job to invoke this ONLY when a webhook is configured; the
// scan command gates on DISCORD_WEBHOOK_URL so that with the var unset this is
// never called and scan behaves exactly as before.
//
// It returns the first send error (so a misconfigured webhook surfaces) after
// attempting every escalation, so one transient failure does not silently drop
// the rest. Non-escalated resolutions are skipped.
func EmitEscalations(ctx context.Context, webhookURL string, resolutions []resolution.Resolution) error {
	var firstErr error
	for _, res := range resolutions {
		if res.Action != "escalate" {
			continue
		}
		if err := SendDiscord(ctx, webhookURL, FormatDiscord(res)); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
