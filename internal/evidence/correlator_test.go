package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestCorrelatorDoesNotCombineDifferentProviders(t *testing.T) {
	analysis := &core.HostAnalysis{
		Evidences: []core.Evidence{
			{Type: "CNAME_PROVIDER_MATCH", Source: "GitHub Pages"},
			{Type: "HTTP_BODY_MATCH", Source: "Cargo"},
			{Type: "TLS_PROVIDER_MATCH", Source: "Cloudflare"},
		},
	}

	if err := NewCorrelator().Collect(context.Background(), analysis); err != nil {
		t.Fatalf("Collect returned an unexpected error: %v", err)
	}
	for _, evidence := range analysis.Evidences {
		if evidence.Type == "CORRELATED_PROVIDER_CONFIRMATION" {
			t.Fatal("evidence from different providers must not be correlated")
		}
	}
}

func TestCorrelatorKeepsSameProviderCorrelation(t *testing.T) {
	analysis := &core.HostAnalysis{
		Evidences: []core.Evidence{
			{Type: "CNAME_PROVIDER_MATCH", Source: "GitHub Pages", Metadata: map[string]string{"provider_id": "github_pages", "matched_cname": "user.github.io"}},
			{Type: "HTTP_BODY_MATCH", Source: "GitHub Pages", Metadata: map[string]string{"provider_id": "github_pages", "matched_cname": "user.github.io", "rule_id": "github-pages-missing", "matched_fingerprint": "There isn't a GitHub Pages site here."}},
			{Type: "TLS_PROVIDER_MATCH", Source: "GitHub Pages"},
		},
	}

	if err := NewCorrelator().Collect(context.Background(), analysis); err != nil {
		t.Fatalf("Collect returned an unexpected error: %v", err)
	}
	for _, evidence := range analysis.Evidences {
		if evidence.Type == "CORRELATED_PROVIDER_CONFIRMATION" {
			return
		}
	}
	t.Fatal("compatible evidence from the same provider should still correlate")
}

func TestCorrelatorDoesNotSynthesizeAdministrativeDNSFindingsAsTakeover(t *testing.T) {
	analysis := &core.HostAnalysis{Evidences: []core.Evidence{
		{Type: "DNS_AXFR_ALLOWED"},
		{Type: "NS_ALL_DEAD"},
		{Type: "NS_ORPHANED"},
		{Type: "MX_DANGLING"},
		{Type: "SRV_DANGLING"},
	}}
	if err := NewCorrelator().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	for _, evidence := range analysis.Evidences {
		if evidence.Type == "CORRELATED_FULL_DNS_TAKEOVER" || evidence.Type == "CORRELATED_NS_TAKEOVER" || evidence.Type == "CORRELATED_MX_TAKEOVER" || evidence.Type == "CORRELATED_SRV_TAKEOVER" {
			t.Fatalf("administrative DNS finding was synthesized as takeover: %#v", evidence)
		}
	}
}
