package storage_test

import (
	"context"
	"database/sql"
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
	if err := store.FinishRecon(runID, "COMPLETED", 1, false); err != nil {
		t.Fatal(err)
	}
}

func TestReconCatalogSeparatesOverlappingRoots(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "roots.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	name := "dev.api.example.test"
	first, _ := store.StartRecon("example.test", string(discovery.ModeExhaustive))
	second, _ := store.StartRecon("api.example.test", string(discovery.ModeExhaustive))
	for _, current := range []struct {
		runID  string
		root   string
		source string
	}{{first, "example.test", "fonte-raiz"}, {second, "api.example.test", "fonte-filho"}} {
		candidate := discovery.Candidate{
			Name: name, Root: current.root, Resolved: true,
			Origins: []discovery.Origin{{Source: current.source, Method: "passive"}},
		}
		if err := store.SaveReconCandidates(current.runID, []discovery.Candidate{candidate}); err != nil {
			t.Fatal(err)
		}
	}

	firstNames, err := store.ReconRunCandidates(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	secondNames, err := store.ReconRunCandidates(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstNames) != 1 || firstNames[0].Root != "example.test" || firstNames[0].Origins[0].Source != "fonte-raiz" {
		t.Fatalf("raiz principal foi sobrescrita: %+v", firstNames)
	}
	if len(secondNames) != 1 || secondNames[0].Root != "api.example.test" || secondNames[0].Origins[0].Source != "fonte-filho" {
		t.Fatalf("raiz filha foi sobrescrita: %+v", secondNames)
	}
}

func TestReconReconcilesOnlyCompleteRuns(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "active.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := "example.test"

	first, _ := store.StartRecon(root, string(discovery.ModeExhaustive))
	old := discovery.Candidate{Name: "old.example.test", Root: root, Resolved: true}
	if err := store.SaveReconCandidates(first, []discovery.Candidate{old}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRecon(first, "COMPLETED", 1, false); err != nil {
		t.Fatal(err)
	}

	partial, _ := store.StartRecon(root, string(discovery.ModeExhaustive))
	fresh := discovery.Candidate{Name: "fresh.example.test", Root: root, Resolved: true}
	if err := store.SaveReconCandidates(partial, []discovery.Candidate{fresh}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRecon(partial, "COMPLETED", 1, true); err != nil {
		t.Fatal(err)
	}
	active, err := store.ReconCandidates(context.Background(), root, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("execução parcial removeu o catálogo anterior: %+v", active)
	}

	complete, _ := store.StartRecon(root, string(discovery.ModeExhaustive))
	if err := store.SaveReconCandidates(complete, []discovery.Candidate{fresh}); err != nil {
		t.Fatal(err)
	}
	if err := store.FinishRecon(complete, "COMPLETED", 1, false); err != nil {
		t.Fatal(err)
	}
	active, err = store.ReconCandidates(context.Background(), root, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Name != fresh.Name {
		t.Fatalf("catálogo completo não foi reconciliado: %+v", active)
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

func TestReconCatalogMigratesRootlessPrimaryKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`
		CREATE TABLE recon_names (
			name TEXT PRIMARY KEY, root TEXT NOT NULL, resolved INTEGER NOT NULL,
			wildcard INTEGER NOT NULL, status TEXT NOT NULL, a_json TEXT NOT NULL,
			aaaa_json TEXT NOT NULL, cname_json TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX idx_recon_names_root ON recon_names(root, active, name);
		CREATE TABLE recon_origins (
			name TEXT NOT NULL, source TEXT NOT NULL, method TEXT NOT NULL, parent TEXT NOT NULL,
			depth INTEGER NOT NULL, first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(name, source, method, parent)
		);
		CREATE TABLE recon_run_names (run_id TEXT NOT NULL, name TEXT NOT NULL, PRIMARY KEY(run_id, name));
		INSERT INTO recon_names (name, root, resolved, wildcard, status, a_json, aaaa_json, cname_json)
		VALUES ('api.example.test', 'example.test', 1, 0, 'RESOLVED', '[]', '[]', '[]');
		INSERT INTO recon_origins (name, source, method, parent, depth)
		VALUES ('api.example.test', 'legado', 'passive', '', 1);
	`)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := storage.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	names, err := store.ReconCandidates(context.Background(), "example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || len(names[0].Origins) != 1 || names[0].Origins[0].Source != "legado" {
		t.Fatalf("catálogo legado não foi preservado: %+v", names)
	}
}
