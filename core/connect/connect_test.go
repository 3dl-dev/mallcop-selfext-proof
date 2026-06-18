package connect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileConnector_FromReader_ParsesJSONL drives the connector over an in-memory
// JSONL source and asserts every event is parsed, in order, with blank lines
// skipped.
func TestFileConnector_FromReader_ParsesJSONL(t *testing.T) {
	src := `{"id":"a","source":"aws","type":"login","actor":"u1"}

{"id":"b","source":"github","type":"push","actor":"u2"}
{"id":"c","source":"aws","type":"logout","actor":"u1"}
`
	c := FromReader(strings.NewReader(src))
	events, err := c.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}
	wantIDs := []string{"a", "b", "c"}
	for i, want := range wantIDs {
		if events[i].ID != want {
			t.Errorf("event[%d].ID = %q, want %q", i, events[i].ID, want)
		}
	}
}

// TestFileConnector_FromPath_ReadsFile asserts the path-based constructor reads
// and parses a file on disk.
func TestFileConnector_FromPath_ReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte(
		`{"id":"x","source":"aws","type":"login","actor":"u"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	events, err := FromPath(path).Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(events) != 1 || events[0].ID != "x" {
		t.Fatalf("got %+v, want one event id=x", events)
	}
}

// TestFileConnector_MalformedLineIsHardError proves a corrupt event source fails
// LOUD rather than silently under-reporting — an operator must not believe a
// record was scanned when it was dropped.
func TestFileConnector_MalformedLineIsHardError(t *testing.T) {
	src := `{"id":"ok","source":"aws","type":"login","actor":"u"}
this is not json
`
	_, err := FromReader(strings.NewReader(src)).Pull(context.Background())
	if err == nil {
		t.Fatal("expected a hard error on a malformed line; got nil")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error should cite the offending line; got %q", err)
	}
}

// TestFileConnector_MissingFileIsError asserts a missing path surfaces an error
// (not an empty clean scan over a file that does not exist).
func TestFileConnector_MissingFileIsError(t *testing.T) {
	_, err := FromPath(filepath.Join(t.TempDir(), "nope.jsonl")).Pull(context.Background())
	if err == nil {
		t.Fatal("expected an error opening a missing file; got nil")
	}
}

// TestFileConnector_EmptySourceIsCleanScan asserts an empty (but valid) source is
// a clean scan over zero events, not a failure.
func TestFileConnector_EmptySourceIsCleanScan(t *testing.T) {
	events, err := FromReader(strings.NewReader("")).Pull(context.Background())
	if err != nil {
		t.Fatalf("empty source should not error; got %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("empty source should yield 0 events; got %d", len(events))
	}
}

// TestFileConnector_HonorsCancellation asserts a cancelled context aborts the
// read instead of materializing the whole source.
func TestFileConnector_HonorsCancellation(t *testing.T) {
	src := strings.Repeat(`{"id":"x","source":"aws","type":"login","actor":"u"}`+"\n", 1000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the read
	_, err := FromReader(strings.NewReader(src)).Pull(ctx)
	if err == nil {
		t.Fatal("expected a cancellation error; got nil")
	}
	if !strings.Contains(err.Error(), "cancel") {
		t.Errorf("error should be a cancellation; got %q", err)
	}
}
