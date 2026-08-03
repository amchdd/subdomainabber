package classification

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestAuxiliaryHeaderAndShadowITSignalsDoNotBecomeFindings(t *testing.T) {
	for _, evidenceType := range []string{"HTTP_HSTS_MISSING", "HTTP_CSP_MISSING", "SHADOW_IT_DETECTED", "EMAIL_SPF_MISSING", "EMAIL_DMARC_MISSING"} {
		analysis := &core.HostAnalysis{Evidences: []core.Evidence{{Type: evidenceType, Confidence: 100}}}
		if got := Classify(analysis); got != LevelInsufficientEvidence {
			t.Fatalf("%s foi promovido para %s", evidenceType, got)
		}
		CalculateScores(analysis)
		if analysis.RiskScore != 0 || analysis.MitigationScore != 0 || analysis.ConfidenceScore != 0 {
			t.Fatalf("%s alterou pontuações: %#v", evidenceType, analysis)
		}
	}
}
