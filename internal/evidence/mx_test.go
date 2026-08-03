package evidence

import (
	"context"
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestMXCollectorTreatsNullMXAsIntentionalPolicy(t *testing.T) {
	collector := NewMXCollector(nil, nil)
	analysis := &core.HostAnalysis{Host: "example.com", DNS: core.DNSRecordSet{MX: []string{"."}}}
	if err := collector.Collect(context.Background(), analysis); err != nil {
		t.Fatalf("a coleta de Null MX falhou: %v", err)
	}
	if _, found := findEvidence(analysis, "NULL_MX_PRESENT"); !found {
		t.Fatalf("a política Null MX não foi registrada: %#v", analysis.Evidences)
	}
	for _, evidenceType := range []string{"MX_BROKEN", "MX_DANGLING", "MX_UNRESOLVABLE"} {
		if _, found := findEvidence(analysis, evidenceType); found {
			t.Fatalf("Null MX foi classificado como %s", evidenceType)
		}
	}
	if len(analysis.MXCandidates) != 0 {
		t.Fatalf("Null MX criou candidato de takeover: %#v", analysis.MXCandidates)
	}
}
