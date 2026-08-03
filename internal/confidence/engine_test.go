package confidence

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestCalculateDoesNotAssignGenericConfidenceWithoutScoredEvidence(t *testing.T) {
	analysis := &core.HostAnalysis{
		Classification: "UNKNOWN",
		TestedVectors:  []string{"DNS", "HTTP"},
		Evidences:      []core.Evidence{{Type: "HTTP_RESPONSE", Weight: 0}},
	}
	verdict := Calculate(analysis)
	if verdict.Percentage != 0 || verdict.Label != "0.0%" {
		t.Fatalf("a confiança foi inventada sem evidência pontuada: %#v", verdict)
	}
	if analysis.CoverageScore != 40 || analysis.KnowledgeScore != 0 {
		t.Fatalf("as métricas calculadas não foram persistidas na análise: cobertura=%.1f conhecimento=%.1f", analysis.CoverageScore, analysis.KnowledgeScore)
	}
}

func TestCoverageIsRelativeToRequestedProfile(t *testing.T) {
	baselineVectors := []string{"DNS", "HTTP", "TLS", "MX", "TXT", "SRV", "A_AAAA_ASN", "CAA"}
	baseline := &core.HostAnalysis{TestedVectors: baselineVectors, ScanProfile: &core.ScanProfile{Version: 1}}
	if got := Calculate(baseline).CoverageScore; got != 100 {
		t.Fatalf("cobertura da varredura padrão completa = %.1f; esperado 100", got)
	}

	withNS := &core.HostAnalysis{TestedVectors: baselineVectors, ScanProfile: &core.ScanProfile{Version: 1, CheckNS: true}}
	if got := Calculate(withNS).CoverageScore; got >= 100 {
		t.Fatalf("o módulo NS solicitado e ausente não reduziu a cobertura: %.1f", got)
	}
	withNS.TestedVectors = append(withNS.TestedVectors, "NS_DELEGATION")
	if got := Calculate(withNS).CoverageScore; got != 100 {
		t.Fatalf("cobertura com NS concluído = %.1f; esperado 100", got)
	}
}
