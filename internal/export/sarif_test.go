package export

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestSARIFContainsOnlyPrioritizedResults(t *testing.T) {
	document := buildSARIF([]core.HostAnalysis{
		{Host: "healthy.example", Classification: "HEALTHY"},
		{Host: "orphan.example", Classification: "ORPHANED"},
		{Host: "blocked.example", Classification: "MISCONFIGURED", ResultState: core.ResultSuppressed},
	})
	if len(document.Runs) != 1 || len(document.Runs[0].Results) != 1 {
		t.Fatalf("documento inesperado: %+v", document)
	}
	if document.Runs[0].Results[0].RuleID != "ORPHANED" || document.Runs[0].Results[0].Level != "note" {
		t.Fatalf("resultado inesperado: %+v", document.Runs[0].Results[0])
	}
}
