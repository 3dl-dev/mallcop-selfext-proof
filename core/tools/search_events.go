// search_events.go — the search-events pure read tool, reusing pkg/event and
// reading the events stream from core/store.
//
// SearchEvents replays the events stream from a *store.Store and returns the
// typed event.Event records that pass the actor/source/type/time filters. It is
// a PURE read: it opens no channel, runs no inference, and never writes. Its
// only effect is to read committed records from the git-backed store.
package tools

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mallcop-app/mallcop/core/store"
	"github.com/mallcop-app/mallcop/pkg/event"
)

// SearchEventsInput is the filter for SearchEvents. Every field is optional; an
// empty filter returns every event in the stream.
//
// Actor / Source / Type are case-insensitive equality filters on the matching
// event field. Since / Until bound the event timestamp (inclusive). A zero time
// means "unbounded on that side".
type SearchEventsInput struct {
	Actor  string    `json:"actor,omitempty"`
	Source string    `json:"source,omitempty"`
	Type   string    `json:"type,omitempty"`
	Since  time.Time `json:"since,omitempty"`
	Until  time.Time `json:"until,omitempty"`
}

// SearchEvents reads the events stream from the store and returns the events
// matching the filter, oldest first.
//
// Time-filter fallback: if a Since/Until window excludes EVERY event but the
// non-time filters matched some, SearchEvents returns the non-time-filtered set
// instead. A caller-supplied window is frequently anchored to a different
// "now" than the stored fixtures (an LLM hallucinating a date range a year off
// from the data); treating an all-excluding window as a no-op keeps the read
// useful rather than silently empty. The boolean second return reports whether
// this fallback fired, so the caller can annotate the result if it cares.
//
// SearchEvents returns an error only when the store cannot be read or a record
// is not valid event JSON.
func SearchEvents(s *store.Store, in SearchEventsInput) (events []event.Event, timeFilterFellBack bool, err error) {
	if s == nil {
		return nil, false, fmt.Errorf("search-events: nil store")
	}
	raws, err := s.Load(store.KindEvents)
	if err != nil {
		return nil, false, fmt.Errorf("search-events: load events: %w", err)
	}

	all := make([]event.Event, 0, len(raws))
	for i, raw := range raws {
		var ev event.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, false, fmt.Errorf("search-events: decode event %d: %w", i, err)
		}
		all = append(all, ev)
	}

	// Pass 1: non-time filters (always applied).
	preTime := make([]event.Event, 0, len(all))
	for _, ev := range all {
		if in.Actor != "" && !strings.EqualFold(ev.Actor, in.Actor) {
			continue
		}
		if in.Source != "" && !strings.EqualFold(ev.Source, in.Source) {
			continue
		}
		if in.Type != "" && !strings.EqualFold(ev.Type, in.Type) {
			continue
		}
		preTime = append(preTime, ev)
	}

	// Pass 2: time filter (only when a bound is set).
	if in.Since.IsZero() && in.Until.IsZero() {
		return preTime, false, nil
	}
	filtered := make([]event.Event, 0, len(preTime))
	for _, ev := range preTime {
		if ev.Timestamp.IsZero() {
			continue
		}
		if !in.Since.IsZero() && ev.Timestamp.Before(in.Since) {
			continue
		}
		if !in.Until.IsZero() && ev.Timestamp.After(in.Until) {
			continue
		}
		filtered = append(filtered, ev)
	}
	// Fallback: window excluded every event but non-time filters had hits.
	if len(filtered) == 0 && len(preTime) > 0 {
		return preTime, true, nil
	}
	return filtered, false, nil
}
