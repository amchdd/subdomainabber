package classification

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/amchdd/subdomainabber/internal/core"
)

// Classify aplica regras semânticas em ordem de prioridade para evitar que uma
// pontuação isolada produza uma classificação indevida.
func Classify(analysis *core.HostAnalysis) string {
	has := func(evType string) bool {
		for _, e := range analysis.Evidences {
			if e.Type == evType {
				return true
			}
		}
		return false
	}
	hasHealthyHTTPResponse := func() bool {
		for _, evidence := range analysis.Evidences {
			if evidence.Type != "HTTP_RESPONSE" {
				continue
			}
			status, err := strconv.Atoi(evidence.Metadata["status"])
			if err == nil && status >= 200 && status < 400 {
				return true
			}
		}
		return false
	}

	providerBoundHTTPFingerprint := func(cnameEv, bodyEv core.Evidence) bool {
		return bodyEv.Type == "HTTP_BODY_MATCH" && bodyEv.Source == cnameEv.Source &&
			cnameEv.Metadata["provider_id"] != "" && bodyEv.Metadata["provider_id"] == cnameEv.Metadata["provider_id"] &&
			bodyEv.Metadata["matched_cname"] == cnameEv.Metadata["matched_cname"] && bodyEv.Metadata["rule_id"] != "" &&
			!genericFingerprintText(bodyEv.Metadata["matched_fingerprint"])
	}
	hasProviderBoundMutationFingerprint := func() bool {
		for _, cnameEvidence := range analysis.Evidences {
			if cnameEvidence.Type != "CNAME_PROVIDER_MATCH" || cnameEvidence.Source == "" {
				continue
			}
			for _, mutationEvidence := range analysis.Evidences {
				if mutationEvidence.Type == "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT" &&
					mutationEvidence.Source == cnameEvidence.Source &&
					cnameEvidence.Metadata["provider_id"] != "" &&
					mutationEvidence.Metadata["provider_id"] == cnameEvidence.Metadata["provider_id"] &&
					mutationEvidence.Metadata["cname"] == cnameEvidence.Metadata["matched_cname"] &&
					mutationEvidence.Metadata["rule_id"] != "" &&
					!genericFingerprintText(mutationEvidence.Metadata["matched_fingerprint"]) &&
					mutationEvidence.Metadata["confirmations"] == "2" {
					return true
				}
			}
		}
		return false
	}
	hasProviderBoundHTTPFingerprint := func() bool {
		for _, cnameEvidence := range analysis.Evidences {
			if cnameEvidence.Type != "CNAME_PROVIDER_MATCH" || cnameEvidence.Source == "" {
				continue
			}
			for _, httpEvidence := range analysis.Evidences {
				if providerBoundHTTPFingerprint(cnameEvidence, httpEvidence) {
					return true
				}
			}
		}
		return false
	}

	// Controle comprovado por uma reivindicação ativa tem a maior prioridade.
	if has("ZONE_CONTROL_CONFIRMED") {
		return LevelZoneControlConfirmed
	}
	if has("CLAIM_SUCCESS") {
		return LevelTakenOver
	}

	// A verificação ativa exige um resultado positivo estruturado;
	// uma pontuação numérica isolada nunca constitui prova.
	if analysis.VerificationScore == 100 && analysis.ActiveVerification != nil && analysis.ActiveVerification.Verified &&
		analysis.ActiveVerification.ControlProven && analysis.ActiveVerification.Confidence == 100 {
		return LevelConfirmed
	}

	// LIKELY_TAKEOVERABLE exige uma assinatura HTTP específica e vinculada ao provedor.
	// TLS fortalece a observação, mas não promove isoladamente. O Mutator também
	// exige duas confirmações reproduzíveis.
	if hasProviderBoundMutationFingerprint() || hasProviderBoundHTTPFingerprint() {
		return LevelLikelyTakeoverable
	}

	// Achados de delegação usam uma máquina de estados própria. Uma correspondência
	// de provedor com delegação pai quebrada continua candidata até que a
	// reivindicabilidade seja comprovada.
	if has("DELEGATION_CLAIMABILITY_VERIFIED") {
		return LevelDelegationClaimabilityVerified
	}
	if has("DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED") {
		return LevelDelegationBroken
	}
	if has("DELEGATION_TAKEOVER_CANDIDATE") {
		return LevelDelegationTakeoverCandidate
	}
	if has("DELEGATION_BROKEN") {
		return LevelDelegationBroken
	}

	// Exposições de dados ou de configurações em nuvem não comprovam takeover.
	if has("CLOUD_S3_LISTABLE") || has("CLOUD_S3_WRITABLE") || has("CLOUD_AZURE_BLOB_LISTABLE") || has("CLOUD_GCS_LISTABLE") || has("DNS_AXFR_ALLOWED") {
		return LevelExposed
	}

	// ORPHANED exige um sinal concreto de abandono do recurso.
	if has("CNAME_DANGLING") {
		return LevelOrphaned
	}

	// Problemas estruturais de DNS, zonas, e-mail ou redirecionamento são
	// classificados como configuração incorreta.
	if has("NS_REFUSED") || has("NS_SERVFAIL") || has("NS_ALL_DEAD") || has("NS_ORPHANED") || has("LAME_DELEGATION") || has("MX_UNRESOLVABLE") || has("NS_SOA_MISMATCH") ||
		has("MX_BROKEN") || has("SRV_BROKEN") || has("MX_DANGLING") || has("SRV_DANGLING") || has("SPF_BROKEN_INCLUDE") || has("SPF_DANGLING_TAKEOVER") || has("SPF_INCLUDE_WITHOUT_POLICY") || has("SPF_INCLUDE_CYCLE") || has("SPF_LOOKUP_LIMIT_EXCEEDED") ||
		has("EMAIL_SPF_PERMISSIVE") || has("HTTP_OPEN_REDIRECT") {
		return LevelMisconfigured
	}

	// HEALTHY exige, além de uma resposta HTTP bem-sucedida, um sinal
	// independente de tecnologia ou CDN. A correspondência SAN é apenas contexto,
	// pois o coletor TLS tolerante não valida a cadeia de confiança.
	if hasHealthyHTTPResponse() && (has("CDN_DETECTED") || has("TECHNOLOGY_DETECTED")) {
		if !has("HTTP_STATUS_404") && !has("CNAME_DANGLING") && !has("NXDOMAIN") {
			return LevelHealthy
		}
	}

	// Evidências apenas contextuais são insuficientes; outros indícios isolados
	// permanecem em UNKNOWN para revisão.
	if len(analysis.Evidences) > 0 {
		if hasOnlyContextEvidence(analysis.Evidences) {
			return LevelInsufficientEvidence
		}
		return LevelUnknown
	}

	// Ausência de evidência não comprova que o host esteja saudável.
	return LevelInsufficientEvidence
}

func hasOnlyContextEvidence(evidences []core.Evidence) bool {
	if len(evidences) == 0 {
		return false
	}
	contextTypes := map[string]struct{}{
		"ASN_MATCH":                 {},
		"CAA_RECORD_PRESENT":        {},
		"CDN_DETECTED":              {},
		"CLOUD_IP_CONTEXT":          {},
		"CNAME_PROVIDER_MATCH":      {},
		"DNSSEC_ARTIFACTS_OBSERVED": {},
		"EMAIL_DMARC_MISSING":       {},
		"EMAIL_SPF_MISSING":         {},
		"HTTP_OK_ACTIVE":            {},
		"HTTP_RESPONSE":             {},
		"HTTP_HSTS_MISSING":         {},
		"HTTP_CSP_MISSING":          {},
		"MX_PROVIDER_MATCH":         {},
		"NULL_MX_PRESENT":           {},
		"NS_PROVIDER_MATCH":         {},
		"NXDOMAIN_EXPECTED":         {},
		"SRV_PROVIDER_MATCH":        {},
		"SHADOW_IT_DETECTED":        {},
		"TLS_PROVIDER_MATCH":        {},
		"TLS_SAN_MATCH":             {},
		"TXT_VERIFICATION_TOKEN":    {},
	}
	for _, evidence := range evidences {
		if _, ok := contextTypes[evidence.Type]; !ok {
			return false
		}
	}
	return true
}

func genericFingerprintText(value string) bool {
	normalized := strings.Join(strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }), " ")
	switch normalized {
	case "not found", "404 not found", "page not found", "site not found":
		return true
	default:
		allowed := map[string]struct{}{"404": {}, "error": {}, "page": {}, "site": {}, "not": {}, "found": {}}
		fields := strings.Fields(normalized)
		if len(fields) == 0 {
			return true
		}
		for _, field := range fields {
			if _, ok := allowed[field]; !ok {
				return false
			}
		}
		return strings.Contains(" "+normalized+" ", " not ") && strings.Contains(" "+normalized+" ", " found ")
	}
}
