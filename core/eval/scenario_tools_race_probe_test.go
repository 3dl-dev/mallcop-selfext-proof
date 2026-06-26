package eval

import (
	"context"
	"sync"
	"testing"

	"github.com/mallcop-app/mallcop/core/agent"
)

// TestProbe_ConcurrentRunTools_PredicateStable hammers a SINGLE scenarioToolRunner
// with many concurrent RunTools calls (the fan-out's exact access pattern) and
// asserts the role-grant / zero-history predicates compute IDENTICALLY on every
// call regardless of goroutine scheduling. This is the probe for the flake class.
func TestProbe_ConcurrentRunTools_PredicateStable(t *testing.T) {
	root := repoRootForTest(t)
	defer SetRepoRootForTest("")
	agent.SetRepoRootForTest(root)
	defer agent.SetRepoRootForTest("")

	for _, rel := range []string{
		"behavioral/UT-01-competing-signals.yaml",
		"cross_cutting/IT-02-baseline-contradicts-reasoning.yaml",
	} {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			ls := loadScenarioForTest(t, root, rel)
			r, err := newScenarioToolRunner(t.TempDir(), root, ls.Scenario)
			if err != nil {
				t.Fatalf("new runner: %v", err)
			}
			f := findingFromScenario(ls.Scenario)

			// Sequential ground truth.
			base, err := r.RunTools(context.Background(), "triage", f)
			if err != nil {
				t.Fatalf("baseline RunTools: %v", err)
			}
			if !base.RoleGrantByActor {
				t.Fatalf("%s: expected RoleGrantByActor=true on the sequential ground-truth call; got false (events=%q)", rel, base.EventsText)
			}

			const goroutines = 64
			var wg sync.WaitGroup
			fails := make([]string, goroutines)
			for g := 0; g < goroutines; g++ {
				wg.Add(1)
				go func(g int) {
					defer wg.Done()
					// Mix triage and the deep-investigate tiers the fan-out actually
					// uses, so the probe exercises the exact concurrent access pattern.
					tier := "triage"
					switch g % 4 {
					case 1:
						tier = "deep-investigate:benign"
					case 2:
						tier = "deep-investigate:malicious"
					case 3:
						tier = "investigate"
					}
					ev, err := r.RunTools(context.Background(), tier, f)
					if err != nil {
						fails[g] = "err: " + err.Error()
						return
					}
					if ev.RoleGrantByActor != base.RoleGrantByActor {
						fails[g] = "RoleGrantByActor flipped"
					}
					if ev.ToolEmpty != base.ToolEmpty {
						fails[g] = "ToolEmpty flipped"
					}
					if ev.ZeroHistoryAccess != base.ZeroHistoryAccess {
						fails[g] = "ZeroHistoryAccess flipped"
					}
					// The events transcript must be byte-identical across calls —
					// the snapshot is immutable, so any divergence means a re-read
					// observed a different (partial) view. (Triage and the deep
					// tiers all render the same events section.)
					if ev.EventsText != base.EventsText {
						fails[g] = "EventsText diverged: " + ev.EventsText
					}
				}(g)
			}
			wg.Wait()
			for g, msg := range fails {
				if msg != "" {
					t.Fatalf("%s: concurrent RunTools call %d diverged: %s", rel, g, msg)
				}
			}
		})
	}
}
