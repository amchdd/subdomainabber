package discovery

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/pkg/config"
)

func TestBelongsToDomainRequiresDNSBoundary(t *testing.T) {
	for _, host := range []string{"example.com", "api.example.com", "API.EXAMPLE.COM."} {
		if !belongsToDomain(host, "example.com") {
			t.Fatalf("expected %q to be in scope", host)
		}
	}
	for _, host := range []string{"notexample.com", "example.com.attacker.test", "bad..example.com"} {
		if belongsToDomain(host, "example.com") {
			t.Fatalf("out-of-scope hostname accepted: %q", host)
		}
	}
}

func TestEnumerateRejectsInvalidConcurrencyBeforeStartingWorkers(t *testing.T) {
	engine := &Engine{}
	for _, concurrency := range []int{0, -1, config.MaximumEnumerationConcurrency + 1} {
		if _, err := engine.Enumerate(context.Background(), "example.com", "", concurrency); err == nil {
			t.Fatalf("a concorrência inválida %d foi aceita", concurrency)
		}
	}
}
