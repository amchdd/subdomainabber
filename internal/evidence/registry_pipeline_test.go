package evidence

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

type recordingCollector struct {
	phase   CollectorPhase
	name    string
	mu      *sync.Mutex
	order   *[]string
	collect func(*core.HostAnalysis) error
}

func (collector recordingCollector) Phase() CollectorPhase { return collector.phase }
func (collector recordingCollector) Collect(_ context.Context, analysis *core.HostAnalysis) error {
	collector.mu.Lock()
	*collector.order = append(*collector.order, collector.name)
	collector.mu.Unlock()
	if collector.collect != nil {
		return collector.collect(analysis)
	}
	return nil
}

func TestRegistryRunsDeterministicMutationPipeline(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		var mu sync.Mutex
		var order []string
		analysis := &core.HostAnalysis{Host: "example.com"}
		collectors := []Collector{
			recordingCollector{phase: PhaseHTTPMutation, name: "mutation", mu: &mu, order: &order, collect: func(analysis *core.HostAnalysis) error {
				if _, exists := analysis.HTTPObservation("http"); !exists {
					t.Fatal("mutation phase ran before baseline was stored")
				}
				return nil
			}},
			recordingCollector{phase: PhaseIndependent, name: "independent", mu: &mu, order: &order},
			recordingCollector{phase: PhaseImpact, name: "impact", mu: &mu, order: &order},
			recordingCollector{phase: PhaseHTTPBaseline, name: "baseline", mu: &mu, order: &order, collect: func(analysis *core.HostAnalysis) error {
				analysis.SetHTTPObservation("http", newHTTPObservation("http", 403, make(http.Header), []byte("blocked"), true, 0, "", ""))
				return nil
			}},
			recordingCollector{phase: PhaseProviderDiscovery, name: "provider", mu: &mu, order: &order},
		}
		if err := NewRegistry(collectors).Run(context.Background(), analysis); err != nil {
			t.Fatalf("Run: %v", err)
		}
		want := []string{"provider", "baseline", "independent", "mutation", "impact"}
		if !reflect.DeepEqual(order, want) {
			t.Fatalf("pipeline order = %#v, want %#v", order, want)
		}
	}
}

func TestRegistryWithoutMutatorDoesNotExecuteMutationTransport(t *testing.T) {
	transport := &scriptedRawTransport{}
	analysis := mutationAnalysis(t, true, []byte("Access denied"))
	registry := NewRegistry([]Collector{
		recordingCollector{phase: PhaseIndependent, name: "independent", mu: &sync.Mutex{}, order: &[]string{}},
	})
	if err := registry.Run(context.Background(), analysis); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if transport.callCount() != 0 || len(analysis.MutationResults) != 0 {
		t.Fatalf("disabled mutator executed: calls=%d results=%d", transport.callCount(), len(analysis.MutationResults))
	}
}
