// artifacts.go — write the harness's per-scenario result JSON, per-scenario
// TRANSCRIPTS, and the classifier summary to disk (§4.4 result JSON, §4.7
// transcript audit). These are the artifacts every iteration tool consumes;
// transcript capture is non-negotiable.
//
// Layout under outDir:
//
//	outDir/
//	  report.json                       — the full HarnessReport (median, band, classifier)
//	  run-<i>/                           — one dir per corpus pass
//	    <scenario_id>.json               — graded ScenarioResult (§4.4)
//	    <scenario_id>.transcript.json    — full transcript: every model call (§4.7)
//	  classifier.json                    — the ClassifierSummary (the loop's to-do list)
package eval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteArtifacts persists the report, per-scenario results, per-scenario
// transcripts, and the classifier summary under outDir. Transcripts are read from
// each RunResult (the single source). Returns the number of transcript files
// written (one per scenario per run) for caller assertions.
func WriteArtifacts(outDir string, report HarnessReport) (int, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	if err := writeJSON(filepath.Join(outDir, "report.json"), report); err != nil {
		return 0, err
	}
	if err := writeJSON(filepath.Join(outDir, "classifier.json"), report.Classifier); err != nil {
		return 0, err
	}

	written := 0
	for _, rr := range report.Runs {
		runDir := filepath.Join(outDir, fmt.Sprintf("run-%d", rr.Index))
		if err := os.MkdirAll(runDir, 0o755); err != nil {
			return written, fmt.Errorf("mkdir %s: %w", runDir, err)
		}
		for _, res := range rr.Results {
			if err := writeJSON(filepath.Join(runDir, res.ScenarioID+".json"), res); err != nil {
				return written, err
			}
		}
		// Transcripts for this run (every model call, input, output — §4.7).
		for id, tr := range rr.Transcripts {
			if err := writeJSON(filepath.Join(runDir, id+".transcript.json"), tr); err != nil {
				return written, err
			}
			written++
		}
	}
	return written, nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
