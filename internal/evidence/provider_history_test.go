package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestProviderMigration(t *testing.T) {
	analysis := &core.HostAnalysis{
		ScanProfile:       &core.ScanProfile{Version: 2},
		PreviousEvidences: []core.Evidence{{Type: "CNAME_PROVIDER_MATCH", Source: "CloudFront"}},
		Evidences:         []core.Evidence{{Type: "CNAME_PROVIDER_MATCH", Source: "Fastly"}},
	}
	if err := NewProviderHistoryCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "PROVIDER_MIGRATION_DETECTED") {
		t.Fatalf("migração não detectada: %+v", analysis.Evidences)
	}
}

func TestProviderStaleReference(t *testing.T) {
	analysis := &core.HostAnalysis{
		ScanProfile:       &core.ScanProfile{Version: 2},
		PreviousEvidences: []core.Evidence{{Type: "CNAME_PROVIDER_MATCH", Source: "CloudFront"}},
		Evidences: []core.Evidence{
			{Type: "CNAME_PROVIDER_MATCH", Source: "CloudFront"},
			{Type: "CNAME_PROVIDER_MATCH", Source: "Fastly"},
		},
	}
	if err := NewProviderHistoryCollector().Collect(context.Background(), analysis); err != nil {
		t.Fatal(err)
	}
	if !hasEvidenceType(analysis.Evidences, "PROVIDER_MIGRATION_STALE_REFERENCE") {
		t.Fatalf("referência antiga não detectada: %+v", analysis.Evidences)
	}
}
