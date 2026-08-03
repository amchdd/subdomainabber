package classification

import (
	"testing"

	"github.com/amchdd/subdomainabber/internal/core"
)

func TestCalculateScoresIgnoresNeutralEvidenceInConfidence(t *testing.T) {
	analysis := &core.HostAnalysis{Evidences: []core.Evidence{
		{Type: "HTTP_RESPONSE", Source: "https", Weight: 0, Confidence: 100},
		{Type: "HTTP_BODY_MATCH", Source: "aws_s3", Weight: 50, Confidence: 80},
	}}
	CalculateScores(analysis)
	if analysis.ConfidenceScore != 80 {
		t.Fatalf("a observação neutra alterou a confiança: obtido=%d esperado=80", analysis.ConfidenceScore)
	}
}

func TestCalculateScoresDoesNotInventConfidenceFromOnlyNeutralEvidence(t *testing.T) {
	analysis := &core.HostAnalysis{Evidences: []core.Evidence{{
		Type: "HTTP_RESPONSE", Source: "https", Weight: 0, Confidence: 100,
	}}}
	CalculateScores(analysis)
	if analysis.ConfidenceScore != 0 || analysis.RiskScore != 0 {
		t.Fatalf("a observação neutra gerou pontuação: confiança=%d risco=%d", analysis.ConfidenceScore, analysis.RiskScore)
	}
}
