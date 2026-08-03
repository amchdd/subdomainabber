package classification

import "github.com/amchdd/subdomainabber/internal/core"

// EvidenceWeights define o impacto bruto (0-100) de cada tipo de evidência.
var EvidenceWeights = map[string]int{
	"HTTP_BODY_MATCH":   50,
	"NS_REFUSED":        40,
	"NS_SERVFAIL":       30,
	"NS_TIMEOUT":        10,
	"CNAME_MATCH":       20,
	"HTTP_STATUS_404":   10,
	"NXDOMAIN_EXPECTED": 10,
	// Evidências sem peso específico usam o valor configurado pela assinatura.
	"LEGACY_MATCH": 20,
}

// CalculateScores computa as pontuações de risco, mitigação e confiança.
func CalculateScores(analysis *core.HostAnalysis) {
	risk := 0
	mitigation := 0
	confidenceSum := 0
	confidenceCount := 0

	seen := make(map[string]bool)

	for _, ev := range analysis.Evidences {
		weight, exists := EvidenceWeights[ev.Type]
		if !exists {
			weight = ev.Weight
		}

		if !seen[ev.Type+"|"+ev.Source] {
			conf := ev.Confidence
			if conf == 0 {
				conf = 100
			}

			if ev.IsNegative {
				mitigation += (weight * conf) / 100
			} else {
				risk += (weight * conf) / 100
				// Observações neutras (peso zero) enriquecem o relatório, mas não
				// podem aumentar artificialmente a confiança da classificação.
				if weight > 0 {
					confidenceSum += conf
					confidenceCount++
				}
			}

			seen[ev.Type+"|"+ev.Source] = true
		}
	}

	if risk > 100 {
		risk = 100
	}
	if mitigation > 100 {
		mitigation = 100
	}

	confAvg := 0
	if confidenceCount > 0 {
		confAvg = confidenceSum / confidenceCount
	}

	analysis.RiskScore = risk
	analysis.MitigationScore = mitigation
	analysis.ConfidenceScore = confAvg
}
