package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestTXTOwnerTokens(t *testing.T) {
	tests := []struct {
		host     string
		provider string
	}{
		{"_github-pages-challenge-owner.example.com", "GitHub"},
		{"asuid.app.example.com", "Microsoft Azure"},
	}
	for _, test := range tests {
		analysis := &core.HostAnalysis{Host: test.host, DNS: core.DNSRecordSet{TXT: []string{"token"}}}
		if err := NewTXTCollector(nil).Collect(context.Background(), analysis); err != nil {
			t.Fatal(err)
		}
		if len(analysis.TXTCandidates) != 1 || analysis.TXTCandidates[0].Provider != test.provider {
			t.Fatalf("token de %s não detectado: %+v", test.provider, analysis.TXTCandidates)
		}
	}
}

func TestTXTResidualCorrelation(t *testing.T) {
	analysis := &core.HostAnalysis{TXTCandidates: []core.TXTVerificationCandidate{{Provider: "GitHub"}}}
	if err := NewTXTResidualCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.TXTCandidates[0].State != "POSSIBLY_RESIDUAL" || !hasEvidenceType(analysis.Evidences, "TXT_OWNERSHIP_TOKEN_RESIDUAL") {
		t.Fatalf("token residual não classificado: %+v", analysis)
	}

	linked := &core.HostAnalysis{TXTCandidates: []core.TXTVerificationCandidate{{Provider: "GitHub"}}}
	linked.AddProviderCandidate(core.ProviderCandidate{ProviderID: providerID("GitHub Pages"), Vector: "CNAME"})
	if err := NewTXTResidualCollector().Collect(context.Background(), linked); err != nil {
		t.Fatal(err)
	}
	if linked.TXTCandidates[0].State != "RELATED_PROVIDER_PRESENT" || hasEvidenceType(linked.Evidences, "TXT_OWNERSHIP_TOKEN_RESIDUAL") {
		t.Fatalf("token vinculado foi marcado como residual: %+v", linked)
	}
}
