// Command mallcop-eval runs the portable eval harness over the SHA-pinned
// scenario corpus and prints the report as JSON.
//
//	mallcop-eval -mode canned          # creds-free merge-gate (golden responses)
//	mallcop-eval -mode real -n 3       # parity run vs a live model (needs creds)
//
// ModeReal reads MALLCOP_INFERENCE_URL + MALLCOP_API_KEY (see core/eval
// RealClientFromEnv). The per-tier lane defaults (triage glm-4.7-flash,
// investigate/deep glm-5) come from the cascade; no model flag is needed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/mallcop-app/mallcop/core/eval"
)

func main() {
	mode := flag.String("mode", "canned", "canned | real")
	n := flag.Int("n", 3, "number of full-corpus passes for the median")
	flag.Parse()

	cfg := eval.RunConfig{N: *n}
	switch *mode {
	case "canned":
		cfg.Mode = eval.ModeCanned
	case "real":
		cfg.Mode = eval.ModeReal
		client, err := eval.RealClientFromEnv()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mallcop-eval: %v\n", err)
			os.Exit(2)
		}
		cfg.RealClient = client
	default:
		fmt.Fprintf(os.Stderr, "mallcop-eval: unknown -mode %q (want canned|real)\n", *mode)
		os.Exit(2)
	}

	report, err := eval.Run(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-eval: %v\n", err)
		os.Exit(1)
	}

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mallcop-eval: marshal report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
