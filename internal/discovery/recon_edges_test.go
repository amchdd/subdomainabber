package discovery

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/amchdd/subdomainabber/internal/dns"
)

func TestReconPermutesLeaf(t *testing.T) {
	engine := &Engine{
		resolver: &reconResolver{records: map[string]DNSRecord{
			"app-dev.example.test":  {A: []string{"192.0.2.1"}},
			"app-prod.example.test": {A: []string{"192.0.2.2"}},
		}},
		providers: []Source{reconSource{name: "fonte", names: []string{"app-dev.example.test"}}},
	}
	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModeExhaustive, Words: []string{"unused"}, MaxRounds: 1, MaxTested: 2000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(result.Targets(), "app-prod.example.test") {
		t.Fatal("o hostname observado sem filhos não recebeu permutação")
	}
}

func TestReconExpandsParentWithoutAddress(t *testing.T) {
	frontier := []Candidate{
		{Name: "api.dev.example.test", Root: "example.test", Resolved: true},
		{Name: "web.dev.example.test", Root: "example.test", Resolved: true},
	}
	catalog := map[string]Candidate{frontier[0].Name: frontier[0], frontier[1].Name: frontier[1]}
	seeds := generateSeeds("example.test", frontier, catalog, nil, []string{"portal"}, Options{
		Mode: ModeExhaustive, MaxDepth: 4, RecursiveThreshold: 2,
	}, 2000)
	if !slices.ContainsFunc(seeds, func(item seed) bool {
		return item.name == "portal.dev.example.test" && item.origin.Method == "recursão"
	}) {
		t.Fatal("a zona intermediária sem A/AAAA não recebeu expansão")
	}
}

func TestReconScrapesLargeInventory(t *testing.T) {
	var calls atomic.Int32
	engine := &Engine{
		resolver: &reconResolver{records: map[string]DNSRecord{
			"example.test":        {A: []string{"192.0.2.1"}},
			"old.example.test":    {},
			"web.example.test":    {A: []string{"192.0.2.2"}},
			"hidden.example.test": {A: []string{"192.0.2.3"}},
		}},
		providers: []Source{reconSource{name: "fonte", names: []string{"old.example.test", "web.example.test"}}},
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("hidden.example.test")), Request: request}, nil
		})},
	}
	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModeStandard, Words: []string{"unused"}, ScrapeLimit: 1, MaxTested: 2000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(result.Targets(), "hidden.example.test") || calls.Load() != 2 {
		t.Fatalf("coleta não respeitou o limite de páginas: alvos=%v chamadas=%d", result.Targets(), calls.Load())
	}
}

func TestReconAXFROverridesObservedWildcard(t *testing.T) {
	resolver := &zoneReconResolver{
		reconResolver: &reconResolver{
			records:  map[string]DNSRecord{"seen.example.test": {A: []string{"192.0.2.1"}}},
			wildcard: map[string]dns.WildcardSignature{"example.test": {A: []string{"192.0.2.1"}}},
		},
		nameservers: []string{"ns.example.test"}, names: []string{"seen.example.test"},
	}
	engine := &Engine{resolver: resolver, providers: []Source{reconSource{name: "fonte", names: resolver.names}}}
	result, err := engine.Discover(context.Background(), "example.test", Options{
		Mode: ModeExhaustive, Words: []string{"unused"}, MaxRounds: 1, MaxTested: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(result.Targets(), "seen.example.test") {
		t.Fatal("nome explícito na transferência de zona permaneceu filtrado por wildcard")
	}
}

func TestPassiveIgnoresGenerationRounds(t *testing.T) {
	engine := &Engine{resolver: &reconResolver{records: map[string]DNSRecord{
		"example.test": {A: []string{"192.0.2.1"}}, "generated.example.test": {A: []string{"192.0.2.2"}},
	}}}
	result, err := engine.Discover(context.Background(), "example.test", Options{Mode: ModePassive, MaxRounds: 3, Words: []string{"generated"}})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(result.Targets(), "generated.example.test") || result.Rounds != 0 {
		t.Fatal("o modo passivo gerou nomes com o ajuste legado de rodadas")
	}
}

func TestScraperRejectsHostnameSuffix(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Request: request,
			Body: io.NopCloser(strings.NewReader("https://api.example.test.evil.invalid https://valid.example.test/v1"))}, nil
	})}
	names, err := ScrapePage(context.Background(), "https://example.test", "example.test", client)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"valid.example.test"}) {
		t.Fatalf("um prefixo de hostname externo virou candidato: %v", names)
	}
}
