package cmd

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/discovery"
	"github.com/amchdd/subdomainabber/internal/storage"
)

type reconStub struct {
	resume *discovery.State
	root   string
}

func (stub *reconStub) Discover(_ context.Context, root string, options discovery.Options) (discovery.Result, error) {
	stub.resume = options.Resume
	stub.root = root
	candidate := discovery.Candidate{
		Name: "api." + root, Root: root, Resolved: true,
		DNS:     discovery.DNSRecord{A: []string{"192.0.2.10"}, Status: core.DNSStatusResolved},
		Origins: []discovery.Origin{{Source: "teste", Method: "passive", Depth: 1}},
	}
	if options.Progress != nil {
		if err := options.Progress(discovery.State{
			Candidates: []discovery.Candidate{candidate},
			Checkpoint: discovery.Checkpoint{Round: 2, Frontier: []string{candidate.Name}},
		}); err != nil {
			return discovery.Result{}, err
		}
	}
	return discovery.Result{Root: root, Mode: options.Mode, Names: []discovery.Candidate{candidate}, Rounds: 2}, nil
}

func TestRunReconResumesLatestExecution(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, err := store.StartRecon("example.test", string(discovery.ModeExhaustive))
	if err != nil {
		t.Fatal(err)
	}
	seed := discovery.Candidate{Name: "seed.example.test", Root: "example.test", Resolved: true}
	if err := store.SaveReconCandidates(runID, []discovery.Candidate{seed}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveReconCheckpoint(runID, discovery.Checkpoint{Round: 1, Frontier: []string{seed.Name}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveReconSources(runID, []discovery.SourceRun{{Name: "fonte", Error: "indisponível"}}); err != nil {
		t.Fatal(err)
	}

	stub := &reconStub{}
	result, resumedID, err := runRecon(context.Background(), stub, store, "example.test", discovery.Options{
		Mode: discovery.ModeExhaustive,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if resumedID != runID {
		t.Fatalf("uma nova execução foi criada: %s", resumedID)
	}
	if stub.resume == nil || stub.resume.Checkpoint.Round != 1 || len(stub.resume.Candidates) != 1 || len(stub.resume.Sources) != 1 {
		t.Fatalf("estado persistido não foi restaurado: %+v", stub.resume)
	}
	if len(result.Names) != 1 {
		t.Fatalf("resultado inesperado: %+v", result)
	}
	latest, err := store.LatestRecon(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if latest.Status != "COMPLETED" || latest.DiscoveredCount != 1 {
		t.Fatalf("execução não foi finalizada: %+v", latest)
	}
}

func TestRunReconRestartsEmptyCheckpoint(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, err := store.StartRecon("example.test", string(discovery.ModeExhaustive))
	if err != nil {
		t.Fatal(err)
	}
	stub := &reconStub{}
	_, resumedID, err := runRecon(context.Background(), stub, store, "example.test", discovery.Options{Mode: discovery.ModeExhaustive}, true)
	if err != nil {
		t.Fatal(err)
	}
	if resumedID != runID {
		t.Fatalf("checkpoint vazio criou outra execução: %s", resumedID)
	}
	if stub.resume != nil {
		t.Fatalf("checkpoint vazio pulou a coleta inicial: %+v", stub.resume)
	}
}

func TestRunReconNormalizesRootBeforePersistence(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "normalize.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	stub := &reconStub{}
	if _, _, err := runRecon(context.Background(), stub, store, " Example.TEST. ", discovery.Options{Mode: discovery.ModePassive}, false); err != nil {
		t.Fatal(err)
	}
	if stub.root != "example.test" {
		t.Fatalf("raiz não normalizada: %q", stub.root)
	}
}

func TestReconRoundsDefaultIsSelectedByMode(t *testing.T) {
	flag := reconCmd.Flags().Lookup("max-rounds")
	if flag == nil || flag.DefValue != "0" {
		t.Fatalf("max-rounds deveria delegar o padrão ao modo: %+v", flag)
	}
}

func TestParseReconView(t *testing.T) {
	view, err := parseReconView("sources", []string{"unresolved,wildcards"})
	if err != nil {
		t.Fatal(err)
	}
	if view.format != "sources" || !view.unresolved || !view.wildcards {
		t.Fatalf("configuração de saída inesperada: %+v", view)
	}
}

func TestParseReconViewAll(t *testing.T) {
	view, err := parseReconView("jsonl", []string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	if !view.unresolved || !view.wildcards {
		t.Fatalf("all não incluiu todo o inventário: %+v", view)
	}
}

func TestParseReconViewRejectsUnknownValues(t *testing.T) {
	if _, err := parseReconView("xml", nil); err == nil {
		t.Fatal("formato desconhecido foi aceito")
	}
	if _, err := parseReconView("text", []string{"inactive"}); err == nil {
		t.Fatal("inclusão desconhecida foi aceita")
	}
}

func TestReconKeepsAdvancedFlagsOutOfBasicHelp(t *testing.T) {
	hidden := []string{
		"max-rounds", "max-depth", "max-candidates", "max-tested", "recursive-threshold", "asset-limit",
		"json", "jsonl", "show-unresolved", "show-sources", "show-wildcards",
	}
	for _, name := range hidden {
		flag := reconCmd.Flags().Lookup(name)
		if flag == nil || !flag.Hidden {
			t.Errorf("flag %s deveria permanecer compatível e oculta", name)
		}
	}
	for _, name := range []string{"mode", "wordlist", "concurrency", "resume", "format", "include"} {
		flag := reconCmd.Flags().Lookup(name)
		if flag == nil || flag.Hidden {
			t.Errorf("flag %s deveria aparecer na ajuda", name)
		}
	}
}
