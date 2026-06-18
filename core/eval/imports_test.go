package eval

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bannedImportSubstrings are the families core/eval must never depend on. The
// harness is allowed core/inference (the hand-rolled network seam) and
// internal/testutil/cannedbackend (the golden-response merge-gate backend) — both
// are the intended {base_url,key} pivot seams. It must carry NO vendor LLM SDK,
// NO agent-orchestration framework, and NONE of the dropped legion/campfire/cf
// transport (portable-agent-architecture.md §6: drop the entire glue layer). The
// repo-level core/lint gate also enforces this across core/; this per-package
// guard catches the regression at the source file that introduces it.
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
		f, perr := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		checked++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, banned := range bannedImportSubstrings {
				if strings.Contains(p, banned) {
					t.Errorf("%s imports forbidden package %q (matches %q): the eval harness "+
						"must depend on NO vendor SDK / orchestration framework / dropped transport",
						name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 production files in core/eval; layout changed?")
	}
}
