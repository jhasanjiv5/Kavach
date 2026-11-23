package selftest

import (
	"context"
	"testing"
)

func TestRedTeamCorpusPassesAllThresholds(t *testing.T) {
	res, err := Run(context.Background(), "") // the corpus built into the binary
	if err != nil {
		t.Fatalf("selftest.Run: %v", err)
	}
	if res.TotalCases < 60 {
		t.Fatalf("expected >= 60 corpus cases, got %d", res.TotalCases)
	}
	if !res.PassedThresholds {
		t.Fatalf("selftest thresholds failed: secrets=%.2f%% risky=%.2f%% inj=%.2f%% fp=%.2f%% p95=%.2fms failures=%v",
			res.SecretsRate*100, res.RiskyCommandsRate*100, res.InjectionRate*100, res.FalsePositiveRate*100, res.OverallP95Ms, res.Failures)
	}
}

// Every category must actually be exercised; an empty category used to report 0% silently.
func TestCorpusCoversEveryCategory(t *testing.T) {
	cases, err := LoadCorpus("")
	if err != nil {
		t.Fatalf("LoadCorpus: %v", err)
	}
	counts := map[string]int{}
	for _, c := range cases {
		counts[c.Category]++
	}
	for _, cat := range []string{"secrets", "pii", "direct_injection", "indirect_injection", "unicode", "risky_command", "benign"} {
		if counts[cat] == 0 {
			t.Errorf("corpus has no %q cases", cat)
		}
	}
}
