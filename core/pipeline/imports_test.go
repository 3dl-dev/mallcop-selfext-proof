package pipeline

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bannedImportSubstrings are the families core/pipeline must never depend on.
// The orchestrator assembles the other core seams (connect, detect, agent,
// store) but reaches the model ONLY through the core/agent.Client interface
// threaded in by the caller. It must carry NO vendor LLM SDK, NO transport, and
// NO agent-orchestration framework — if this fails, someone wired a framework
// into the orchestrator instead of injecting a Client.
var bannedImportSubstrings = []string{
	"anthropics/",
	"anthropic-sdk",
	"openai/",
	"bedrock",
	"aws-sdk",
	"langchain",
	"autogen",
	"crewai",
	"claude-code",
	"agent-orchestration",
	"campfire",
	"cfexec",
	"internal/cf",
	"3dl-dev/legion",
	// The orchestrator must not import the network seam directly — it consumes
	// the abstract core/agent.Client, never the concrete HTTP client. Keeping
	// core/inference out of the import graph keeps the pivot (BYOK vs Forge) a
	// caller decision, not a pipeline dependency.
	"core/inference",
}

// TestNoForbiddenImports parses every non-test .go file in this package and
// asserts none imports a banned family.
func TestNoForbiddenImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, banned := range bannedImportSubstrings {
				if strings.Contains(p, banned) {
					t.Errorf("%s imports forbidden package %q (matches %q): the orchestrator reaches "+
						"the model only through core/agent.Client — no SDK / transport / framework / "+
						"concrete inference client here", name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}
