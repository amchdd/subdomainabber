package storage_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/discovery"
	"github.com/amchdd/subdomainabber/internal/storage"
)

func TestReconRunPersistsCandidatesAndCheckpoint(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	runID, err := store.StartRecon("example.test", string(discovery.ModeExhaustive))
	if err != nil {
		t.Fatal(err)
	}
	candidates := []discovery.Candidate{{
		Name: "api.example.test", Root: "example.test", Resolved: true,
		DNS:     discovery.DNSRecord{A: []string{"192.0.2.10"}, Status: core.DNSStatusResolved},
		Origins: []discovery.Origin{{Source: "crt.sh", Method: "passive", Depth: 1}},
	}}
	if err := store.SaveReconCandidates(runID, candidates); err != nil {
		t.Fatal(err)
	}
	checkpoint := discovery.Checkpoint{Round: 2, Frontier: []string{"api.example.test"}}
	if err := store.SaveReconCheckpoint(runID, checkpoint); err != nil {
		t.Fatal(err)
	}

	restored, err := store.ReconCheckpoint(context.Background(), runID)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Round != 2 || len(restored.Frontier) != 1 {
		t.Fatalf("checkpoint incompleto: %+v", restored)
	}
	names, err := store.ReconCandidates(context.Background(), "example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0].Name != "api.example.test" || len(names[0].Origins) != 1 {
		t.Fatalf("catálogo de recon incompleto: %+v", names)
	}
	if err := store.FinishRecon(runID, "COMPLETED", 1); err != nil {
		t.Fatal(err)
	}
}

func TestReconRunCanResumeLatestIncompleteRun(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "resume.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	runID, err := store.StartRecon("example.test", string(discovery.ModeStandard))
	if err != nil {
		t.Fatal(err)
	}
	latest, err := store.LatestRecon(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.ID != runID || latest.Status != "RUNNING" {
		t.Fatalf("execução retomável não encontrada: %+v", latest)
	}
}
