package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
)

type reconSource struct {
	name  string
	names []string
	err   error
	calls *int32
}

func (source reconSource) Name() string { return source.name }

func (source reconSource) Enumerate(ctx context.Context, _ string, output chan<- string) error {
	if source.calls != nil {
		atomic.AddInt32(source.calls, 1)
	}
	for _, name := range source.names {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case output <- name:
		}
	}
	return source.err
}

func TestDiscoverResumesFromCheckpoint(t *testing.T) {
	var calls int32
	engine := &Engine{
		resolver: &reconResolver{records: map[string]DNSRecord{
			"example.test":         {A: []string{"192.0.2.1"}},
			"api.example.test":     {A: []string{"192.0.2.2"}},
			"dev.api.example.test": {A: []string{"192.0.2.3"}},
		}},
		providers: []Source{reconSource{name: "inventário", calls: &calls}},
	}
	state := &State{
		Candidates: []Candidate{{
			Name: "api.example.test", Root: "example.test", Resolved: true,
			DNS:     DNSRecord{A: []string{"192.0.2.2"}, Status: core.DNSStatusResolved},
			Origins: []Origin{{Source: "inventário", Method: "passive", Depth: 1}},
		}},
		Checkpoint: Checkpoint{Round: 1, Frontier: []string{"api.example.test"}},
	}
	var checkpoints []Checkpoint
	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModeExhaustive, Concurrency: 2, Words: []string{"dev"}, MaxRounds: 2,
		MaxDepth: 3, MaxCandidates: 20, RecursiveThreshold: 1, Resume: state,
		Progress: func(state State) error {
			checkpoints = append(checkpoints, state.Checkpoint)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("fontes passivas foram repetidas durante a retomada")
	}
	if _, ok := result.Find("dev.api.example.test"); !ok {
		t.Fatalf("a fronteira persistida não foi retomada: %+v", result.Names)
	}
	if len(checkpoints) != 1 || checkpoints[0].Round != 2 {
		t.Fatalf("checkpoint inesperado após retomada: %+v", checkpoints)
	}
}

type reconResolver struct {
	records  map[string]DNSRecord
	wildcard map[string]dns.WildcardSignature
}

type zoneReconResolver struct {
	*reconResolver
	nameservers []string
	names       []string
}

type ptrReconResolver struct {
	*reconResolver
	names map[string][]string
}

func (resolver *ptrReconResolver) ResolveAddressPTR(_ context.Context, address string) ([]string, error) {
	return append([]string(nil), resolver.names[address]...), nil
}

func (resolver *zoneReconResolver) LookupNS(context.Context, string) ([]string, error) {
	return append([]string(nil), resolver.nameservers...), nil
}

func (resolver *zoneReconResolver) TransferZone(context.Context, string, string) ([]string, error) {
	return append([]string(nil), resolver.names...), nil
}

func (resolver *reconResolver) ResolveA(_ context.Context, name string) ([]string, error) {
	return append([]string(nil), resolver.records[name].A...), nil
}

func (resolver *reconResolver) ResolveAAAA(_ context.Context, name string) ([]string, error) {
	return append([]string(nil), resolver.records[name].AAAA...), nil
}

func (resolver *reconResolver) ResolveCNAME(_ context.Context, name string) ([]string, error) {
	return append([]string(nil), resolver.records[name].CNAME...), nil
}

func (resolver *reconResolver) ResolveAddressStatus(_ context.Context, name string) core.DNSStatus {
	if record, ok := resolver.records[name]; ok && (len(record.A) > 0 || len(record.AAAA) > 0 || len(record.CNAME) > 0) {
		return core.DNSStatusResolved
	}
	return core.DNSStatusNXDomain
}

func (resolver *reconResolver) IsWildcard(_ context.Context, name string) (bool, dns.WildcardSignature, error) {
	signature := resolver.wildcard[name]
	return !signature.Empty(), signature, nil
}

func (resolver *reconResolver) ResolveMX(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (resolver *reconResolver) LookupNS(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (resolver *reconResolver) ResolveSRV(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func TestDiscoverPreservesProvenanceAndSourceFailures(t *testing.T) {
	engine := &Engine{
		resolver: &reconResolver{records: map[string]DNSRecord{
			"example.test":     {A: []string{"192.0.2.1"}},
			"api.example.test": {A: []string{"192.0.2.2"}},
		}},
		providers: []Source{
			reconSource{name: "fonte-a", names: []string{"api.example.test"}},
			reconSource{name: "fonte-b", names: []string{"api.example.test"}, err: errors.New("limite atingido")},
		},
	}

	result, err := engine.Discover(context.Background(), "example.test", Options{Mode: ModePassive, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	candidate, ok := result.Find("api.example.test")
	if !ok {
		t.Fatalf("hostname passivo ausente: %+v", result.Names)
	}
	sources := candidate.SourceNames()
	sort.Strings(sources)
	if len(sources) != 2 || sources[0] != "fonte-a" || sources[1] != "fonte-b" {
		t.Fatalf("proveniência perdida: %v", sources)
	}
	if len(result.Sources) != 2 || result.Sources[1].Error == "" {
		t.Fatalf("falha da fonte não registrada: %+v", result.Sources)
	}
}

func TestDiscoverRecursesAndKeepsIPv6OnlyNames(t *testing.T) {
	resolver := &reconResolver{records: map[string]DNSRecord{
		"example.test":            {A: []string{"192.0.2.1"}},
		"api.example.test":        {A: []string{"192.0.2.2"}},
		"dev.api.example.test":    {AAAA: []string{"2001:db8::10"}},
		"v2.dev.api.example.test": {A: []string{"192.0.2.3"}},
	}}
	engine := &Engine{
		resolver:  resolver,
		providers: []Source{reconSource{name: "inventário", names: []string{"api.example.test"}}},
	}

	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModeExhaustive, Concurrency: 4, Words: []string{"dev", "v2"},
		MaxRounds: 2, MaxDepth: 4, MaxCandidates: 100, RecursiveThreshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dev.api.example.test", "v2.dev.api.example.test"} {
		candidate, ok := result.Find(name)
		if !ok || !candidate.Resolved {
			t.Fatalf("descoberta recursiva ausente para %s: %+v", name, result.Names)
		}
	}
	if candidate, _ := result.Find("dev.api.example.test"); len(candidate.DNS.AAAA) != 1 {
		t.Fatalf("hostname IPv6-only não foi preservado: %+v", candidate)
	}
}

func TestDiscoverFiltersHierarchicalWildcard(t *testing.T) {
	resolver := &reconResolver{
		records: map[string]DNSRecord{
			"example.test":          {A: []string{"192.0.2.1"}},
			"api.example.test":      {A: []string{"192.0.2.2"}},
			"wild.api.example.test": {A: []string{"198.51.100.10"}},
		},
		wildcard: map[string]dns.WildcardSignature{
			"api.example.test": {A: []string{"198.51.100.10"}},
		},
	}
	engine := &Engine{
		resolver:  resolver,
		providers: []Source{reconSource{name: "inventário", names: []string{"api.example.test"}}},
	}

	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModeExhaustive, Concurrency: 2, Words: []string{"wild"},
		MaxRounds: 1, MaxDepth: 3, MaxCandidates: 50, RecursiveThreshold: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Find("wild.api.example.test"); ok {
		t.Fatalf("resposta de wildcard entrou no catálogo: %+v", result.Names)
	}
}

func TestDiscoverKeepsObservedWildcardOutOfTargets(t *testing.T) {
	resolver := &reconResolver{
		records: map[string]DNSRecord{
			"example.test":      {A: []string{"192.0.2.1"}},
			"seen.example.test": {A: []string{"198.51.100.10"}},
		},
		wildcard: map[string]dns.WildcardSignature{
			"example.test": {A: []string{"198.51.100.10"}},
		},
	}
	engine := &Engine{
		resolver:  resolver,
		providers: []Source{reconSource{name: "inventário", names: []string{"seen.example.test"}}},
	}
	result, err := engine.Discover(context.Background(), "example.test", Options{Mode: ModePassive, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	candidate, found := result.Find("seen.example.test")
	if !found || !candidate.Wildcard {
		t.Fatalf("nome observado em wildcard não foi preservado: %+v", result.Names)
	}
	if len(result.Targets()) != 0 || result.Stats.WildcardFiltered != 1 {
		t.Fatalf("wildcard observado entrou nos alvos: targets=%v stats=%+v", result.Targets(), result.Stats)
	}
}

func TestDiscoverHarvestsNamesFromZoneTransfer(t *testing.T) {
	resolver := &zoneReconResolver{
		reconResolver: &reconResolver{records: map[string]DNSRecord{
			"example.test":        {A: []string{"192.0.2.1"}},
			"hidden.example.test": {A: []string{"192.0.2.20"}},
		}},
		nameservers: []string{"ns1.example.net"},
		names:       []string{"example.test", "hidden.example.test"},
	}
	engine := &Engine{resolver: resolver}
	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModeExhaustive, Concurrency: 2, Words: []string{"unused"}, MaxRounds: 1,
		MaxDepth: 3, MaxCandidates: 20, MaxTested: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, found := result.Find("hidden.example.test")
	if !found || !candidate.Resolved {
		t.Fatalf("nome transferido não foi descoberto: %+v", result.Names)
	}
	if len(candidate.Origins) != 1 || candidate.Origins[0].Method != "axfr" {
		t.Fatalf("origem AXFR ausente: %+v", candidate.Origins)
	}
}

func TestDiscoverPivotsPTRBackIntoScope(t *testing.T) {
	resolver := &ptrReconResolver{
		reconResolver: &reconResolver{records: map[string]DNSRecord{
			"example.test":        {A: []string{"192.0.2.1"}},
			"origin.example.test": {A: []string{"192.0.2.1"}},
		}},
		names: map[string][]string{"192.0.2.1": {"origin.example.test", "outside.invalid"}},
	}
	engine := &Engine{resolver: resolver}
	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModeStandard, Concurrency: 2, Words: []string{"unused"}, MaxRounds: 1,
		MaxDepth: 3, MaxCandidates: 20, MaxTested: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, found := result.Find("origin.example.test")
	if !found || !candidate.Resolved {
		t.Fatalf("nome PTR interno não foi descoberto: %+v", result.Names)
	}
	if _, found := result.Find("outside.invalid"); found {
		t.Fatalf("PTR externo entrou no escopo: %+v", result.Names)
	}
	if len(candidate.Origins) != 1 || candidate.Origins[0].Method != "ptr" {
		t.Fatalf("origem PTR ausente: %+v", candidate.Origins)
	}
}

func TestResultTargetsKeepsOnlyResolvedSubdomains(t *testing.T) {
	result := Result{Root: "example.test", Names: []Candidate{
		{Name: "example.test", Resolved: true},
		{Name: "api.example.test", Resolved: true},
		{Name: "old.example.test", Resolved: false},
		{Name: "wild.example.test", Resolved: true, Wildcard: true},
	}}
	targets := result.Targets()
	if len(targets) != 1 || targets[0] != "api.example.test" {
		t.Fatalf("alvos acionáveis incorretos: %v", targets)
	}
	inventory := result.Inventory()
	if len(inventory) != 2 || inventory[0] != "api.example.test" || inventory[1] != "old.example.test" {
		t.Fatalf("inventário incompleto: %v", inventory)
	}
}

func TestValidateOptionsRejectsInvalidMode(t *testing.T) {
	err := ValidateOptions(Options{Mode: Mode("unknown")})
	if err == nil || !strings.Contains(err.Error(), "modo de recon inválido") {
		t.Fatalf("modo inválido aceito: %v", err)
	}
}

func TestValidateOptionsRejectsInvalidTestLimit(t *testing.T) {
	err := ValidateOptions(Options{Mode: ModeStandard, MaxTested: 20000001})
	if err == nil || !strings.Contains(err.Error(), "max-tested") {
		t.Fatalf("limite inválido aceito: %v", err)
	}
}

func TestModeLimits(t *testing.T) {
	tests := []struct {
		mode       Mode
		rounds     int
		depth      int
		candidates int
		tested     int
		recursive  int
		assets     int
	}{
		{mode: ModePassive, rounds: 0, depth: 20, candidates: 250000, tested: 250000, recursive: 2, assets: 4},
		{mode: ModeStandard, rounds: 1, depth: 6, candidates: 250000, tested: 250000, recursive: 3, assets: 4},
		{mode: ModeExhaustive, rounds: 4, depth: 12, candidates: 1000000, tested: 1000000, recursive: 2, assets: 12},
	}
	for _, test := range tests {
		got, err := (Options{Mode: test.mode}).normalized()
		if err != nil {
			t.Fatal(err)
		}
		if got.MaxRounds != test.rounds || got.MaxDepth != test.depth || got.MaxCandidates != test.candidates ||
			got.MaxTested != test.tested || got.RecursiveThreshold != test.recursive || got.AssetLimit != test.assets {
			t.Errorf("perfil %s inesperado: %+v", test.mode, got)
		}
	}
}

func TestDiscoverMarksTruncatedPassiveInventoryAsPartial(t *testing.T) {
	names := []string{"a.example.test", "b.example.test", "c.example.test", "d.example.test"}
	records := map[string]DNSRecord{"example.test": {A: []string{"192.0.2.1"}}}
	for index, name := range names {
		records[name] = DNSRecord{A: []string{fmt.Sprintf("192.0.2.%d", index+2)}}
	}
	engine := &Engine{
		resolver:  &reconResolver{records: records},
		providers: []Source{reconSource{name: "inventário", names: names}},
	}
	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModePassive, Concurrency: 2, MaxCandidates: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Partial || len(result.Sources) != 1 || !result.Sources[0].Truncated || result.Sources[0].Count != 4 {
		t.Fatalf("truncamento passivo não foi sinalizado: %+v", result)
	}
	if len(result.Names) != 3 {
		t.Fatalf("limite global ignorado: %d", len(result.Names))
	}
}

func TestGenerateSeedsSkipsAttemptedBeforeLimit(t *testing.T) {
	attempted := map[string]struct{}{"a.example.test": {}}
	seeds := generateSeeds(
		"example.test", nil, map[string]Candidate{}, attempted,
		[]string{"a", "b", "c"}, Options{MaxDepth: 3}, 2,
	)
	if len(seeds) != 2 || seeds[0].name != "b.example.test" || seeds[1].name != "c.example.test" {
		t.Fatalf("orçamento foi consumido por nomes repetidos: %+v", seeds)
	}
}

func TestGenerateSeedsDistributesWordsAcrossZones(t *testing.T) {
	attempted := map[string]struct{}{
		"api.example.test": {},
		"dev.example.test": {},
	}
	frontier := []Candidate{
		{Name: "one.example.test", Root: "example.test", Resolved: true},
		{Name: "two.example.test", Root: "example.test", Resolved: true},
	}
	catalog := map[string]Candidate{
		"one.example.test": frontier[0],
		"two.example.test": frontier[1],
	}
	seeds := generateSeeds(
		"example.test", frontier, catalog, attempted, []string{"api", "dev"},
		Options{MaxDepth: 3, RecursiveThreshold: 1}, 2,
	)
	if len(seeds) != 2 || seeds[0].name != "api.one.example.test" || seeds[1].name != "api.two.example.test" {
		t.Fatalf("zonas não receberam o mesmo termo antes do próximo: %+v", seeds)
	}
}

func TestScrapeSeedsSkipsUnresolvedNames(t *testing.T) {
	var requests atomic.Int32
	engine := &Engine{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("requisição inesperada")
	})}}
	seeds := engine.scrapeSeeds(context.Background(), "example.test", []Candidate{{
		Name: "old.example.test", Root: "example.test", Resolved: false,
	}}, Options{Concurrency: 1, ScrapeLimit: 10}, 10)
	if len(seeds) != 0 || requests.Load() != 0 {
		t.Fatalf("hostname não resolvido foi consultado: sementes=%d requisições=%d", len(seeds), requests.Load())
	}
}

func TestPassiveSeedsDoNotSpendBudgetOnDuplicates(t *testing.T) {
	engine := &Engine{providers: []Source{
		reconSource{name: "fonte-a", names: []string{"a.example.test", "a.example.test", "b.example.test"}},
		reconSource{name: "fonte-b", names: []string{"a.example.test", "c.example.test"}},
	}}
	seeds, runs := engine.passiveSeeds(context.Background(), "example.test", 2)
	if len(seeds) != 3 {
		t.Fatalf("proveniência ou orçamento incorretos: %+v", seeds)
	}
	if runs[0].Count != 2 || !runs[0].Truncated || runs[1].Count != 2 || runs[1].Truncated {
		t.Fatalf("contagem das fontes incorreta: %+v", runs)
	}
}

func TestPassiveSeedsDistributeBudgetAcrossSources(t *testing.T) {
	engine := &Engine{providers: []Source{
		reconSource{name: "fonte-a", names: []string{"a.example.test", "b.example.test", "c.example.test"}},
		reconSource{name: "fonte-b", names: []string{"x.example.test"}},
	}}
	seeds, runs := engine.passiveSeeds(context.Background(), "example.test", 2)
	if len(seeds) != 2 || seeds[0].name != "a.example.test" || seeds[1].name != "x.example.test" {
		t.Fatalf("orçamento não distribuído: %+v", seeds)
	}
	if !runs[0].Truncated || runs[1].Truncated {
		t.Fatalf("truncamento incorreto: %+v", runs)
	}
}

func TestCheckpointPersistsAttemptedNames(t *testing.T) {
	engine := &Engine{
		resolver: &reconResolver{records: map[string]DNSRecord{
			"example.test":     {A: []string{"192.0.2.1"}},
			"api.example.test": {A: []string{"192.0.2.2"}},
		}},
		providers: []Source{reconSource{name: "inventário", names: []string{"api.example.test", "old.example.test"}}},
	}
	var checkpoint Checkpoint
	_, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModePassive, Concurrency: 2, MaxCandidates: 10, MaxTested: 10,
		Progress: func(state State) error {
			checkpoint = state.Checkpoint
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(checkpoint.Attempted, ",")
	for _, name := range []string{"api.example.test", "example.test", "old.example.test"} {
		if !strings.Contains(joined, name) {
			t.Fatalf("nome testado ausente do checkpoint: %s em %v", name, checkpoint.Attempted)
		}
	}
}

func TestDefaultWordsProvideContextualCoverage(t *testing.T) {
	standard := DefaultWords(ModeStandard)
	exhaustive := DefaultWords(ModeExhaustive)
	if len(standard) < 100 || len(exhaustive) <= len(standard) {
		t.Fatalf("cobertura insuficiente: standard=%d exhaustive=%d", len(standard), len(exhaustive))
	}
	joined := "," + strings.Join(exhaustive, ",") + ","
	for _, word := range []string{"api-staging", "staging-api", "api-sa-east-1"} {
		if !strings.Contains(joined, ","+word+",") {
			t.Fatalf("combinação contextual ausente: %s", word)
		}
	}
}

func TestGenerateMutationsFlipsEnvironmentAndRegion(t *testing.T) {
	names := GenerateMutations("example.test", "api-dev.example.test", []string{"internal"})
	names = append(names, GenerateMutations("example.test", "api.dev.example.test", []string{"internal"})...)
	joined := "," + strings.Join(names, ",") + ","
	for _, name := range []string{"api-prod.example.test", "api-dev.internal.example.test", "internal-api-dev.example.test", "api.prod.example.test"} {
		if !strings.Contains(joined, ","+name+",") {
			t.Fatalf("alteração ausente: %s em %v", name, names)
		}
	}
}
