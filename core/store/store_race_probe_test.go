package store

import (
	"os/exec"
	"sync"
	"testing"
)

// TestProbe_ConcurrentLoad_NeverPartial seeds a store with N records, then reads
// it from many goroutines concurrently (the fan-out's exact pattern) and asserts
// every Load returns the FULL record set — never a transient empty/partial read.
// This isolates whether the git-subprocess read path (rev-parse HEAD + cat-file
// as two separate calls) can observe an inconsistent tree under concurrency.
func TestProbe_ConcurrentLoad_NeverPartial(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const records = 8
	for i := 0; i < records; i++ {
		if _, err := st.Append(KindEvents, map[string]any{"id": i, "actor": "admin-user"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	const goroutines = 96
	var wg sync.WaitGroup
	bad := make([]int, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			recs, err := st.Load(KindEvents)
			if err != nil {
				bad[g] = -1
				return
			}
			bad[g] = len(recs)
		}(g)
	}
	wg.Wait()
	for g, n := range bad {
		if n != records {
			t.Fatalf("goroutine %d observed %d records, want %d (partial/empty read under concurrency)", g, n, records)
		}
	}
}
