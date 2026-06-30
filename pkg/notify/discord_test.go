package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mallcop-app/mallcop/pkg/resolution"
)

// TestSendDiscord_PostsContentToWebhook proves SendDiscord POSTs a Discord-shaped
// {"content":"..."} body — no real network, no token.
func TestSendDiscord_PostsContentToWebhook(t *testing.T) {
	var gotBody map[string]string
	var gotContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusNoContent) // Discord returns 204
	}))
	defer srv.Close()

	if err := SendDiscord(context.Background(), srv.URL, "hello discord"); err != nil {
		t.Fatalf("SendDiscord: %v", err)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if gotBody["content"] != "hello discord" {
		t.Fatalf(`content = %q, want "hello discord"`, gotBody["content"])
	}
	if _, hasText := gotBody["text"]; hasText {
		t.Fatal("Discord payload must use 'content', not Slack's 'text'")
	}
}

func TestFormatDiscord_IncludesFindingFields(t *testing.T) {
	res := resolution.Resolution{
		FindingID: "finding-e1-secret-github-pat",
		Action:    "escalate",
		Actor:     "alice",
		Severity:  "critical",
		Source:    "detector:secrets-exposure",
		Reason:    "github pat in payload",
		Timestamp: time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC),
	}
	got := FormatDiscord(res)
	for _, want := range []string{
		"**mallcop: ESCALATE**",
		"finding-e1-secret-github-pat",
		"alice", "critical", "detector:secrets-exposure",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("format missing %q:\n%s", want, got)
		}
	}
}

func TestSendDiscord_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := SendDiscord(context.Background(), srv.URL, "x"); err == nil {
		t.Fatal("expected error on 500")
	}
}

// TestEmitEscalations_OnlyEscalatedFindingsArePosted proves the gated scan→Discord
// hook posts ONLY escalate-action resolutions and skips the rest.
func TestEmitEscalations_OnlyEscalatedFindingsArePosted(t *testing.T) {
	var posts int64
	var lastContent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&posts, 1)
		var body map[string]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		lastContent = body["content"]
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	resolutions := []resolution.Resolution{
		{FindingID: "f1", Action: "escalate", Source: "detector:secrets-exposure"},
		{FindingID: "f2", Action: "resolve", Source: "detector:new-actor"},
		{FindingID: "f3", Action: "escalate", Source: "detector:priv-escalation"},
	}

	if err := EmitEscalations(context.Background(), srv.URL, resolutions); err != nil {
		t.Fatalf("EmitEscalations: %v", err)
	}
	if got := atomic.LoadInt64(&posts); got != 2 {
		t.Fatalf("expected 2 escalation posts, got %d", got)
	}
	if !strings.Contains(lastContent, "f3") {
		t.Fatalf("last post should be f3, got: %s", lastContent)
	}
}
