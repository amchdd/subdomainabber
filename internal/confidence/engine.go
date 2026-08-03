package confidence

import (
	"fmt"
	"math"

	"github.com/amchdd/subdomainabber/internal/core"
)

// Verdict descreve a confiança calculada para a classificação do host.
type Verdict struct {
	Percentage    float64
	Label         string
	Reasons       []string
	CoverageScore float64
}

// Calculate combina cobertura, qualidade do conhecimento e evidências para estimar
// a confiança da classificação.
func Calculate(analysis *core.HostAnalysis) Verdict {
	v := Verdict{
		Percentage:    0.0,
		CoverageScore: calculateCoverage(analysis.TestedVectors, analysis.ScanProfile),
	}

	analysis.CoverageScore = v.CoverageScore
	analysis.KnowledgeScore = calculateKnowledge(analysis.Evidences)

	var computed float64

	if analysis.Classification == "TAKEN_OVER" || analysis.Classification == "ZONE_CONTROL_CONFIRMED" {
		v.Percentage = 100.0
		v.Label = "100.0%"
		v.Reasons = append(v.Reasons, "PROVEN_CLAIM_SUCCESS")
		return v
	}

	if analysis.Classification == "INSUFFICIENT_EVIDENCE" {
		v.Label = "0.0%"
		v.Reasons = append(v.Reasons, "NO_POSITIVE_HEALTH_OR_RISK_SIGNAL")
		return v
	}

	if analysis.Classification == "HEALTHY" {
		// Uma resposta saudável parte de 80% e recebe o reforço das mitigações.
		computed = 80.0

		bonus := float64(analysis.MitigationScore) * 0.2
		computed += bonus

		if computed > 99.9 {
			computed = 99.9 // Reserva 100% para uma prova ativa de controle.
		}

		v.Percentage = math.Min(computed, v.CoverageScore)

		// Um provedor desconhecido limita a confiança mesmo com boa cobertura.
		if v.CoverageScore >= 80.0 && analysis.KnowledgeScore <= 30.0 && analysis.UnknownProvider != nil {
			if v.Percentage > 45.0 {
				v.Percentage = 45.0
			}
			v.Reasons = append(v.Reasons, "UNKNOWN_PROVIDER (confiança limitada)")
		}

		v.Label = fmt.Sprintf("%.1f%%", v.Percentage)
		v.Reasons = append(v.Reasons, "Nenhum indicador de recurso órfão encontrado")
		v.Reasons = append(v.Reasons, "Nenhum indicador de takeover encontrado")
		for _, ev := range analysis.Evidences {
			if ev.IsNegative {
				v.Reasons = append(v.Reasons, ev.Type)
			}
		}
		return v
	}

	// As demais classificações partem da confiança bruta das evidências.
	base := float64(analysis.ConfidenceScore)

	// A persistência temporal e a correlação do provedor reforçam a observação.
	multiplier := 1.0
	for _, ev := range analysis.Evidences {
		if ev.Type == "LONG_LIVED_ORPHAN" {
			multiplier = 1.15
			v.Reasons = append(v.Reasons, "Observado por um período prolongado")
		} else if ev.Type == "CORRELATED_PROVIDER_CONFIRMATION" {
			multiplier = 1.20
		}

		if !ev.IsNegative {
			// Limita os motivos para manter o relatório legível.
			if len(v.Reasons) < 4 {
				v.Reasons = append(v.Reasons, ev.Type)
			}
		}
	}

	computed = math.Min(base*multiplier, 99.9)

	// Sinais related-domain descrevem impacto potencial depois que o controle é
	// comprovado. Eles não aumentam a certeza de que o recurso é reivindicável.
	if analysis.Classification == "TAKEOVERABLE" && analysis.ParentCookieScope {
		v.Reasons = append(v.Reasons, "Impacto potencial: cookie emitido para o domínio registrável")
	}
	if analysis.Classification == "TAKEOVERABLE" && analysis.ParentCORSWildcard {
		v.Reasons = append(v.Reasons, "Impacto potencial: origem candidata refletida com credenciais em CORS")
	}

	v.Percentage = math.Min(computed, v.CoverageScore)
	v.Label = fmt.Sprintf("%.1f%%", v.Percentage)
	if computed == 0 {
		v.Reasons = append(v.Reasons, "Nenhuma evidência pontuada sustenta uma confiança diferente de zero")
	}

	return v
}

func calculateCoverage(tested []string, profile *core.ScanProfile) float64 {
	weights := map[string]float64{
		"DNS":              20,
		"HTTP":             20,
		"TLS":              15,
		"MX":               10,
		"TXT":              10,
		"SRV":              10,
		"A_AAAA_ASN":       10,
		"CAA":              5,
		"NS_DELEGATION":    20,
		"EMAIL":            10,
		"SEC_HEADERS":      5,
		"OPEN_REDIRECT":    5,
		"AXFR":             10,
		"DNSSEC":           5,
		"SHADOW_IT":        5,
		"CLOUD":            10,
		"HTTP_MUTATOR":     10,
		"HTTP_FRAMING_LAB": 10,
	}
	expected := map[string]bool{
		"DNS": true, "HTTP": true, "TLS": true, "MX": true,
		"TXT": true, "SRV": true, "A_AAAA_ASN": true, "CAA": true,
	}
	if profile != nil {
		expected["NS_DELEGATION"] = profile.CheckNS
		expected["EMAIL"] = profile.CheckEmail
		expected["SEC_HEADERS"] = profile.CheckHeaders
		expected["OPEN_REDIRECT"] = profile.CheckRedirects
		expected["AXFR"] = profile.CheckAXFR
		expected["DNSSEC"] = profile.CheckDNSSEC
		expected["SHADOW_IT"] = profile.CheckShadowIT
		expected["CLOUD"] = profile.CheckCloud
		expected["HTTP_MUTATOR"] = profile.CheckEvasion
		expected["HTTP_FRAMING_LAB"] = profile.CheckFraming
	}

	testedSet := make(map[string]bool, len(tested))
	for _, vector := range tested {
		switch vector {
		case "NS":
			vector = "NS_DELEGATION"
		case "ASN":
			vector = "A_AAAA_ASN"
		}
		testedSet[vector] = true
	}

	var completedWeight, expectedWeight float64
	for vector, enabled := range expected {
		if !enabled {
			continue
		}
		weight := weights[vector]
		expectedWeight += weight
		if testedSet[vector] {
			completedWeight += weight
		}
	}
	if expectedWeight == 0 {
		return 0
	}
	return math.Min(completedWeight/expectedWeight*100, 100)
}

// calculateKnowledge pondera a proveniência das evidências.
func calculateKnowledge(evidences []core.Evidence) float64 {
	var score float64
	seen := make(map[string]bool)

	for _, ev := range evidences {
		if seen[ev.Type] {
			continue
		}
		seen[ev.Type] = true

		switch ev.Type {
		// Conhecimento direto (x1.0).
		case "CNAME_PROVIDER_MATCH", "NS_PROVIDER_MATCH", "MX_PROVIDER_MATCH":
			score += 40.0 * 1.0
		case "HTTP_BODY_MATCH":
			score += 15.0 * 1.0
		case "VERIFIER_CONFIRMED":
			score += 10.0 * 1.0

		// Conhecimento semidireto (x0.5).
		case "TLS_PROVIDER_MATCH":
			score += 20.0 * 0.5

		// Conhecimento indireto (x0.25).
		case "CLOUD_PROVIDER_MATCH", "ASN_PROVIDER_MATCH", "CLOUD_IP_CONTEXT":
			score += 15.0 * 0.25
		}
	}

	if score > 100.0 {
		score = 100.0
	}
	return score
}
