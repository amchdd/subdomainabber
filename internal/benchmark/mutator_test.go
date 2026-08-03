package benchmark

import "testing"

func TestControlledMutatorBenchmarkMetrics(t *testing.T) {
	metrics := RunMutatorBenchmark()
	if metrics.FalsePositives != 0 {
		t.Fatalf("false positives = %d", metrics.FalsePositives)
	}
	if metrics.FingerprintsRevealed != 7 {
		t.Fatalf("revealed = %d, want 7", metrics.FingerprintsRevealed)
	}
	if metrics.FalseNegatives != 0 {
		t.Fatalf("false negatives = %d, want 0", metrics.FalseNegatives)
	}
	if metrics.ProbesExecuted != 11 {
		t.Fatalf("probes = %d, want 11", metrics.ProbesExecuted)
	}
}
