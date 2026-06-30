// Command notify-discord is the Discord outbound notification adapter. It mirrors
// cmd/notify-slack: it decodes a resolution.Resolution from stdin, formats a
// human-readable line, and POSTs it to a Discord incoming webhook.
//
// Discord incoming webhooks accept {"content":"..."} (the analog of Slack's
// {"text":"..."}). The adapter is GATED on DISCORD_WEBHOOK_URL: with the env var
// unset it is a no-op (prints a skip notice and exits 0), so wiring it into a
// scan never requires a token. No bot token is involved — this is the outbound
// half only; the inbound bot bridge is out of scope (see repo NOTES).
//
// The format + send logic lives in pkg/notify so this binary and the scan
// command's gated emit step share one implementation and cannot drift.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mallcop-app/mallcop/pkg/notify"
	"github.com/mallcop-app/mallcop/pkg/resolution"
)

func main() {
	webhook := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhook == "" {
		// GATED: no webhook configured → no-op. Drain a token from stdin so a
		// piping caller does not see a broken pipe, then skip cleanly.
		_, _ = json.NewDecoder(os.Stdin).Token()
		fmt.Fprintln(os.Stderr, "notify-discord: DISCORD_WEBHOOK_URL unset; skipping")
		return
	}

	var res resolution.Resolution
	if err := json.NewDecoder(os.Stdin).Decode(&res); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to parse resolution JSON: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := notify.SendDiscord(ctx, webhook, notify.FormatDiscord(res)); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to send Discord message: %v\n", err)
		os.Exit(1)
	}
}
