package storage_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/amchdd/subdomainabber/internal/platform"
	"github.com/amchdd/subdomainabber/internal/storage"
)

func TestPlatformCatalogPersistsQueueAndTargetLinks(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, err := store.StartPlatformSync([]string{"hackerone"}, true)
	if err != nil {
		t.Fatal(err)
	}
	program := platform.Program{Platform: "hackerone", ID: "p1", Handle: "acme", Name: "Acme", Assets: []platform.Asset{
		{ID: "a1", Value: "*.example.com", Kind: platform.KindWildcard, ReconRoot: "example.com", Eligible: true},
		{ID: "a2", Value: "https://api.example.com", Kind: platform.KindURL, Host: "api.example.com", ReconRoot: "api.example.com", Eligible: true},
	}}
	if err := store.SavePlatformPrograms(runID, "hackerone", []platform.Program{program}); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingPlatformAssets(context.Background(), runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("fila incompleta: %+v", pending)
	}
	for _, work := range pending {
		if work.AssetID == "a1" {
			if err := store.SavePlatformTargets(work, []string{
				"example.com", "dev.example.com", "notexample.com", "invalid host",
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.CompletePlatformAsset(work.ID, "COMPLETED", ""); err != nil {
			t.Fatal(err)
		}
	}
	targets, err := store.PlatformTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0] != "api.example.com" || targets[1] != "dev.example.com" {
		t.Fatalf("catálogo de alvos inesperado: %v", targets)
	}
	if err := store.FinishPlatformSync(runID, "COMPLETED", len(targets), ""); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformSyncDeactivatesAssetsRemovedFromScope(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "removed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first, _ := store.StartPlatformSync([]string{"hackerone"}, true)
	program := platform.Program{Platform: "hackerone", ID: "p1", Assets: []platform.Asset{
		{ID: "a1", Value: "old.example.com", Host: "old.example.com", ReconRoot: "old.example.com", Kind: platform.KindDomain, Eligible: true},
	}}
	if err := store.SavePlatformPrograms(first, "hackerone", []platform.Program{program}); err != nil {
		t.Fatal(err)
	}
	_ = store.FinishPlatformSync(first, "COMPLETED", 1, "")

	second, _ := store.StartPlatformSync([]string{"hackerone"}, false)
	program.Assets = nil
	if err := store.SavePlatformPrograms(second, "hackerone", []platform.Program{program}); err != nil {
		t.Fatal(err)
	}
	targets, err := store.PlatformTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("alvo removido ainda está ativo: %v", targets)
	}
	latest, err := store.LatestPlatformSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.ID != second || latest.Status != "RUNNING" {
		t.Fatalf("execução retomável ausente: %+v", latest)
	}
}
