package cmd

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestCompareRunsReportsClassificationAndEvidence(t *testing.T) {
	left := []core.HostAnalysis{{Host: "app.example", Classification: "UNKNOWN", Evidences: []core.Evidence{{Type: "A", Source: "DNS"}}}}
	right := []core.HostAnalysis{{Host: "app.example", Classification: "ORPHANED", Evidences: []core.Evidence{{Type: "B", Source: "HTTP"}}}}
	changes := compareRuns(left, right)
	if len(changes) != 1 || changes[0].Before != "UNKNOWN" || changes[0].After != "ORPHANED" {
		t.Fatalf("comparação inesperada: %+v", changes)
	}
	if len(changes[0].AddedEvidence) != 1 || len(changes[0].RemovedEvidence) != 1 {
		t.Fatalf("diferença de evidências incompleta: %+v", changes[0])
	}
}

func TestCompareRunsDetectsEvidenceMetadataChange(t *testing.T) {
	left := []core.HostAnalysis{{Host: "app.example", Classification: "ORPHANED", Evidences: []core.Evidence{{Type: "DNS", Source: "DNS", Metadata: map[string]string{"status": "NXDOMAIN"}}}}}
	right := []core.HostAnalysis{{Host: "app.example", Classification: "ORPHANED", Evidences: []core.Evidence{{Type: "DNS", Source: "DNS", Metadata: map[string]string{"status": "NO_DATA"}}}}}
	changes := compareRuns(left, right)
	if len(changes) != 1 || len(changes[0].AddedEvidence) != 1 || len(changes[0].RemovedEvidence) != 1 {
		t.Fatalf("mudança de metadados não detectada: %+v", changes)
	}
}
