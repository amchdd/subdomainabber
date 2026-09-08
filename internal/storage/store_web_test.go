package storage

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestStorePreservesHTTPDecision(t *testing.T) {
	store, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	analysis := &core.HostAnalysis{
		Host: "app.example.test", Classification: "MISCONFIGURED", ResultState: core.ResultCandidate,
		HTTPObservations: map[string]core.HTTPObservation{"http": {Scheme: "http", StatusCode: 200, BodyHash: "abc", Complete: true}},
		HTTPCorrelation:  &core.HTTPCorrelation{HTTPStatus: 200, TransportPriority: 6},
		Redirects:        map[string]core.RedirectChain{"http": {Scheme: "http", FinalURL: "http://app.example.test/"}},
		Inferences:       []core.Inference{{Rule: "PLAINTEXT_WEB_CONTENT", State: core.ResultCandidate}},
		Decision:         &core.Decision{State: core.ResultCandidate, Rule: "PLAINTEXT_WEB_CONTENT"},
	}
	if err := store.SaveAnalysis(analysis); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.GetHost(context.Background(), analysis.Host)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.ResultState != core.ResultCandidate || loaded.Decision == nil || loaded.Decision.Rule != "PLAINTEXT_WEB_CONTENT" {
		t.Fatalf("decisão não foi preservada: %+v", loaded)
	}
	if loaded.HTTPCorrelation == nil || loaded.HTTPCorrelation.TransportPriority != 6 || loaded.HTTPObservations["http"].BodyHash != "abc" {
		t.Fatalf("contexto HTTP não foi preservado: %+v", loaded)
	}
}
