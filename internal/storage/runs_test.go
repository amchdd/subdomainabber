package storage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestRunStoresCompleteObservationAndResumeState(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "runs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, err := store.StartRun(&core.ScanProfile{Version: 2}, []string{"a.example", "b.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddTargets(runID, []string{"b.example", "c.example"}); err != nil {
		t.Fatal(err)
	}
	analysis := &core.HostAnalysis{Host: "a.example", Classification: "UNKNOWN", DNS: core.DNSRecordSet{CNAME: []string{"target.example"}}}
	if err := store.SaveObservation(runID, analysis); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTarget(runID, analysis.Host, "DONE", nil); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingTargets(context.Background(), runID)
	if err != nil || len(pending) != 2 || pending[0] != "b.example" || pending[1] != "c.example" {
		t.Fatalf("alvos pendentes inesperados: %v, erro=%v", pending, err)
	}
	observations, err := store.Observations(context.Background(), runID)
	if err != nil || len(observations) != 1 || observations[0].DNS.CNAME[0] != "target.example" {
		t.Fatalf("observação não preservada: %+v, erro=%v", observations, err)
	}
	runs, err := store.Runs(context.Background(), 1)
	if err != nil || len(runs) != 1 || runs[0].TargetCount != 3 {
		t.Fatalf("contagem de alvos inesperada: %+v, erro=%v", runs, err)
	}
	profile, err := store.RunProfile(context.Background(), runID)
	if err != nil || profile == nil || profile.Version != 2 {
		t.Fatalf("perfil inesperado: %+v, erro=%v", profile, err)
	}
}
