package connect

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// bannedImportSubstrings are the families core/connect must never depend on. The
// input seam is pure stdlib + pkg/event: it reads a file/stdin and unmarshals
// events. It carries NO cloud SDK (a real CloudTrail/GitHub connector lives
// OUTSIDE core/ and adapts to []event.Event before crossing this seam), NO
// vendor LLM SDK, and NO orchestration framework.
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
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, banned := range bannedImportSubstrings {
				if strings.Contains(p, banned) {
					t.Errorf("%s imports forbidden package %q (matches %q): the input seam is "+
						"pure stdlib + pkg/event — a real cloud connector with an SDK lives outside core/",
						name, p, banned)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("import-lint checked 0 source files; package layout changed?")
	}
}
