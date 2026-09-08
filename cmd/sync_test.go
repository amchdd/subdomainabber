package cmd

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/discovery"
	"github.com/amchdd/subdomainabber/internal/platform"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/pkg/config"
)

type syncReconStub struct {
	calls   int
	partial bool
}

func (stub *syncReconStub) Discover(_ context.Context, root string, options discovery.Options) (discovery.Result, error) {
	stub.calls++
	names := []discovery.Candidate{
		{Name: root, Root: root, Resolved: true, DNS: discovery.DNSRecord{Status: core.DNSStatusResolved}},
		{Name: "dev." + root, Root: root, Resolved: true, DNS: discovery.DNSRecord{Status: core.DNSStatusResolved}},
	}
	if options.Progress != nil {
		if err := options.Progress(discovery.State{Candidates: names, Checkpoint: discovery.Checkpoint{Round: 1}}); err != nil {
			return discovery.Result{}, err
		}
	}
	result := discovery.Result{Root: root, Mode: options.Mode, Names: names, Rounds: 1, Partial: stub.partial}
	if stub.partial {
		result.Reasons = []string{"fonte passiva indisponível"}
	}
	return result, nil
}

func TestExpandPlatformAssetsReusesReconForSameRoot(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, _ := store.StartPlatformSync([]string{"hackerone"}, true)
	programs := []platform.Program{
		{Platform: "hackerone", ID: "p1", Assets: []platform.Asset{{ID: "a1", Value: "*.example.com", Kind: platform.KindWildcard, ReconRoot: "example.com", Eligible: true}}},
		{Platform: "hackerone", ID: "p2", Assets: []platform.Asset{{ID: "a2", Value: "*.example.com", Kind: platform.KindWildcard, ReconRoot: "example.com", Eligible: true}}},
	}
	if err := store.SavePlatformPrograms(runID, "hackerone", programs); err != nil {
		t.Fatal(err)
	}
	stub := &syncReconStub{}
	notes, err := expandPlatformAssets(context.Background(), stub, store, runID, discovery.Options{Mode: discovery.ModeExhaustive}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Fatalf("recon completo marcado como parcial: %v", notes)
	}
	if stub.calls != 1 {
		t.Fatalf("a mesma raiz foi enumerada %d vezes", stub.calls)
	}
	targets, err := store.PlatformTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "dev.example.com" {
		t.Fatalf("alvos correlacionados incorretamente: %v", targets)
	}
}

func TestExpandPlatformAssetsReportsPartialRecon(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "partial-sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, _ := store.StartPlatformSync([]string{"hackerone"}, true)
	program := platform.Program{Platform: "hackerone", ID: "p1", Assets: []platform.Asset{{
		ID: "a1", Value: "*.example.com", Kind: platform.KindWildcard, ReconRoot: "example.com", Eligible: true,
	}}}
	if err := store.SavePlatformPrograms(runID, "hackerone", []platform.Program{program}); err != nil {
		t.Fatal(err)
	}
	notes, err := expandPlatformAssets(context.Background(), &syncReconStub{partial: true}, store, runID, discovery.Options{Mode: discovery.ModeExhaustive}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "fonte passiva indisponível") {
		t.Fatalf("motivo parcial ausente: %v", notes)
	}
}

func TestPlatformClientsUseOnlyConfiguredCredentials(t *testing.T) {
	cfg := config.Defaults()
	cfg.HackerOneUsername = "pesquisador"
	cfg.HackerOneToken = "segredo"
	clients, missing, err := platformClients(cfg, nil, []string{"all"})
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].Name() != "hackerone" {
		t.Fatalf("clientes inesperados: %+v", clients)
	}
	if len(missing) != 2 {
		t.Fatalf("plataformas sem credencial não foram informadas: %v", missing)
	}
}

func TestScanSessionNotifiesRunStart(t *testing.T) {
	var observed string
	session := &scanSession{OnStart: func(runID string) error {
		observed = runID
		return nil
	}}
	if err := sessionStarted(session, "run-1"); err != nil {
		t.Fatal(err)
	}
	if session.RunID != "run-1" || observed != "run-1" {
		t.Fatalf("sessão não notificou o início: %+v %q", session, observed)
	}
}

func TestRequirementSettingsUseStrictestRateAndTargetHeaders(t *testing.T) {
	requirements := []storage.PlatformRequirement{
		{Target: "api.example.com", Rules: platform.Rules{AutomatedTooling: 8, UserAgent: "Researcher", RequestHeader: "X-Research: yes"}},
		{Target: "www.example.com", Rules: platform.Rules{AutomatedTooling: 3}},
	}
	limit, headers, warnings := requirementSettings(requirements)
	if limit != 3 || len(warnings) != 0 {
		t.Fatalf("limite inesperado: %d %v", limit, warnings)
	}
	if headers["api.example.com"].Get("User-Agent") != "Researcher" || headers["api.example.com"].Get("X-Research") != "yes" {
		t.Fatalf("headers incompletos: %#v", headers)
	}
}

func TestWorkHeadersReportsConflicts(t *testing.T) {
	headers, warnings := workHeaders([]storage.PlatformWork{
		{Root: "example.com", UserAgent: "Researcher-A"},
		{Root: "example.com", UserAgent: "Researcher-B"},
	})
	if headers.Get("User-Agent") != "Researcher-A" || len(warnings) != 1 {
		t.Fatalf("conflito não informado: headers=%v avisos=%v", headers, warnings)
	}
}

func TestFinishPlatformSyncPersistsPartialState(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "finish.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runID, _ := store.StartPlatformSync([]string{"hackerone"}, true)
	if err := finishPlatformSync(store, runID, 4, "example.com: limite atingido", true); err != nil {
		t.Fatal(err)
	}
	latest, err := store.LatestPlatformSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest == nil || latest.Status != "PARTIAL" || latest.TargetCount != 4 || latest.LastError == "" {
		t.Fatalf("estado parcial incompleto: %+v", latest)
	}
}

func TestTargetHeaderTransportOnlyChangesMatchingHost(t *testing.T) {
	transport := targetHeaderTransport{
		base: transportFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Hostname() == "api.example.com" && request.Header.Get("X-Research") != "yes" {
				t.Fatalf("header do alvo ausente")
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: request}, nil
		}),
		headers: map[string]http.Header{"api.example.com": {"X-Research": {"yes"}}},
	}
	request, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
}

func TestSyncReconRoundsDefaultIsSelectedByMode(t *testing.T) {
	flag := syncCmd.Flags().Lookup("recon-rounds")
	if flag == nil || flag.DefValue != "0" {
		t.Fatalf("recon-rounds deveria delegar o padrão ao modo: %+v", flag)
	}
}

func TestSyncKeepsReconTuningOutOfBasicHelp(t *testing.T) {
	for _, name := range []string{"recon-rounds", "recon-depth", "recon-limit", "recursive-threshold"} {
		flag := syncCmd.Flags().Lookup(name)
		if flag == nil || !flag.Hidden || flag.DefValue != "0" {
			t.Errorf("flag %s deveria delegar ao modo e permanecer oculta: %+v", name, flag)
		}
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (function transportFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
