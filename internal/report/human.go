package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/finding"
	"github.com/amchdd/subdomainabber/internal/presentation"
	"github.com/amchdd/subdomainabber/pkg/color"
)

type Options struct {
	Color              bool
	SuppressDelegation bool
}

type humanFinding struct {
	rank int
	body string
}

type fieldLine struct {
	label string
	value string
}

func Human(analysis *core.HostAnalysis, confidence string) string {
	return HumanWithOptions(analysis, confidence, Options{})
}

// HumanWithOptions renderiza todas as constatações causais por impacto.
// IDs/campos estruturados permanecem estáveis e nunca recebem sequências ANSI.
func HumanWithOptions(analysis *core.HostAnalysis, confidence string, options Options) string {
	if analysis == nil {
		return ""
	}
	confidence = presentation.Confidence(confidence)

	var findings []humanFinding
	if proof := analysis.ActiveVerification; proof != nil && proof.Verified && proof.ControlProven &&
		!strings.EqualFold(proof.Vector, "CNAME") && !strings.EqualFold(proof.Vector, "NS") {
		findings = append(findings, humanFinding{rank: 110, body: activeVectorFinding(analysis, proof, confidence, options)})
	}
	if hasCNAMEFinding(analysis) {
		rank := 65
		switch {
		case cnameClaimed(analysis):
			rank = 110
		case hasAny(analysis, "HTTP_BODY_MATCH", "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"):
			rank = 100
		case analysis.Classification == classification.LevelOrphaned:
			rank = 80
		}
		findings = append(findings, humanFinding{rank: rank, body: cnameFinding(analysis, confidence, options)})
	}
	if !options.SuppressDelegation && analysis.Delegation != nil &&
		hasAny(analysis, "DELEGATION_BROKEN", "DELEGATION_TAKEOVER_CANDIDATE",
			"DELEGATION_CLAIMABILITY_VERIFIED", "DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED",
			"ZONE_CONTROL_CONFIRMED") {
		rank := 75
		if hasAny(analysis, "ZONE_CONTROL_CONFIRMED") {
			rank = 110
		} else if hasAny(analysis, "DELEGATION_TAKEOVER_CANDIDATE", "DELEGATION_CLAIMABILITY_VERIFIED") {
			rank = 90
		}
		findings = append(findings, humanFinding{rank: rank, body: delegationFinding(analysis, confidence, options)})
	}
	for _, candidate := range brokenMXs(analysis) {
		findings = append(findings, humanFinding{rank: 45, body: mxFinding(analysis, candidate, confidence, options)})
	}
	for _, candidate := range brokenSRVs(analysis) {
		findings = append(findings, humanFinding{rank: 40, body: srvFinding(analysis, candidate, confidence, options)})
	}
	for _, candidate := range analysis.SPFCandidates {
		findings = append(findings, humanFinding{rank: 45, body: spfFinding(analysis, candidate, confidence, options)})
	}
	if candidate, ok := staleIP(analysis); ok {
		findings = append(findings, humanFinding{rank: 50, body: ipFinding(analysis, candidate, confidence, options)})
	}
	if hasAny(analysis, "DNS_AXFR_ALLOWED") {
		findings = append(findings, humanFinding{rank: 70, body: axfrFinding(analysis, confidence, options)})
	}
	if len(findings) == 0 {
		if options.SuppressDelegation && analysis.Delegation != nil &&
			hasAny(analysis, "DELEGATION_BROKEN", "DELEGATION_TAKEOVER_CANDIDATE",
				"DELEGATION_CLAIMABILITY_VERIFIED", "DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED",
				"ZONE_CONTROL_CONFIRMED") {
			return ""
		}
		return fallbackFinding(analysis, confidence, options)
	}

	sort.SliceStable(findings, func(left, right int) bool { return findings[left].rank > findings[right].rank })
	blocks := make([]string, 0, len(findings))
	for _, item := range findings {
		blocks = append(blocks, strings.TrimSpace(item.body))
	}
	return strings.Join(blocks, "\n\n") + "\n"
}

func fallbackFinding(analysis *core.HostAnalysis, confidence string, options Options) string {
	primary := finding.Primary(analysis)
	evidence := primary.Evidence.Type
	description := presentation.EvidenceDescription(primary.Evidence)
	if description != "" {
		evidence += " — " + description
	}
	return renderBlock(
		presentation.Classification(analysis.Classification),
		valueOr(primary.Resource, analysis.Host),
		toneForClassification(analysis.Classification),
		[]fieldLine{
			{"Categoria", category(analysis.Classification)},
			{"Vetor", primary.Vector},
			{"Evidência principal", evidence},
			{"Confiança da análise", confidence},
			{"Próximo passo", "inspecione as evidências estruturadas com --explain-json"},
		},
		options,
	)
}

func delegationFinding(analysis *core.HostAnalysis, confidence string, options Options) string {
	candidate := analysis.Delegation
	label, tone := "DELEGAÇÃO QUEBRADA", color.ToneLow
	claimability := candidate.Claimability
	if hasAny(analysis, "ZONE_CONTROL_CONFIRMED") {
		label, tone = "CONTROLE DA ZONA CONFIRMADO", color.ToneCritical
		claimability = core.ClaimabilityControlConfirmed
	} else if hasAny(analysis, "DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED") {
		label = "DELEGAÇÃO NÃO REIVINDICÁVEL"
	} else if hasAny(analysis, "DELEGATION_TAKEOVER_CANDIDATE") {
		label, tone = "REVISÃO DE DELEGAÇÃO", color.ToneMedium
	}

	failed, conclusivelyFailed := delegationFailureCounts(analysis, candidate)
	provider := valueOr(candidate.Provider, "desconhecido")
	dsStatus := "desconhecido"
	if candidate.ParentDSChecked {
		dsStatus = "ausente"
		if candidate.ParentHasDS {
			dsStatus = "presente"
		}
	}

	nextStep := "valide a recriação da zona e o conjunto exato de NS dentro do escopo do programa"
	if hasAny(analysis, "DELEGATION_CLAIMABILITY_NOT_DEMONSTRATED") {
		nextStep = "não reporte como takeover; a tentativa autorizada retornou um conjunto de NS diferente"
	}
	impact := fmt.Sprintf(
		"o controle poderia alcançar *.%s somente após prova de reivindicabilidade",
		candidate.Zone,
	)

	return renderBlock(label, candidate.Zone, tone, []fieldLine{
		{"Vetor", "delegação NS"},
		{"Zona", zoneWithParent(candidate.Zone, candidate.ParentZone)},
		{"Servidores NS", fmt.Sprint(len(candidate.DelegatedNameservers))},
		{"Sem resposta saudável", fmt.Sprintf("%d/%d servidores NS únicos", failed, len(candidate.DelegatedNameservers))},
		{"Falhas conclusivas", fmt.Sprintf("%d/%d servidores NS únicos", conclusivelyFailed, len(candidate.DelegatedNameservers))},
		{"Provedor", provider},
		{"DS na zona pai", dsStatus},
		{"Impacto na zona", impact},
		{"Reivindicabilidade", presentation.Value(string(claimability))},
		{"Confiança da análise", confidence},
		{"Próximo passo", nextStep},
	}, options)
}

func delegationFailureCounts(analysis *core.HostAnalysis, candidate *core.DelegationCandidate) (int, int) {
	if candidate == nil {
		return 0, 0
	}
	failed := make(map[string]struct{})
	for _, observation := range candidate.Nameservers {
		if observation.Status != core.DNSStatusResolved {
			failed[strings.ToLower(strings.TrimSuffix(observation.Nameserver, "."))] = struct{}{}
		}
	}
	if len(candidate.Nameservers) == 0 {
		for _, nameserver := range append(append([]string(nil), candidate.Lame...), candidate.Unresolvable...) {
			failed[strings.ToLower(strings.TrimSuffix(nameserver, "."))] = struct{}{}
		}
	}

	conclusive := make(map[string]struct{})
	for _, evidence := range analysis.Evidences {
		switch evidence.Type {
		case "LAME_DELEGATION", "NS_NXDOMAIN", "NS_ORPHANED":
			if evidence.Source != "" {
				conclusive[strings.ToLower(strings.TrimSuffix(evidence.Source, "."))] = struct{}{}
			}
		case "NS_ALL_DEAD":
			if count, err := strconv.Atoi(evidence.Metadata["failed_unique"]); err == nil && count > len(conclusive) {
				return len(failed), count
			}
		}
	}
	return len(failed), len(conclusive)
}

func mxFinding(analysis *core.HostAnalysis, candidate core.MXCandidate, confidence string, options Options) string {
	return renderBlock("MX QUEBRADO", analysis.Host, color.ToneLow, []fieldLine{
		{"Vetor", "MX"},
		{"Destino", candidate.Target},
		{"Resultado DNS", presentation.Value(string(candidate.DNSStatus))},
		{"Provedor", valueOr(candidate.Provider, "desconhecido")},
		{"Propriedade", valueOr(presentation.Value(candidate.Ownership), "desconhecida")},
		{"Registrabilidade", resourceStatus(candidate.RegistrableDomain, candidate.RegistrationStatus)},
		{"Reivindicabilidade", presentation.Value(string(candidate.Claimability))},
		{"Impacto", "interceptação de e-mail somente após prova de registro ou vínculo no provedor"},
		{"Confiança da análise", confidence},
		{"Próximo passo", "valide propriedade, disponibilidade de registro e controle de entrega"},
	}, options)
}

func srvFinding(analysis *core.HostAnalysis, candidate core.SRVCandidate, confidence string, options Options) string {
	subject := valueOr(candidate.Record.Owner, analysis.Host)
	return renderBlock("SRV QUEBRADO", subject, color.ToneLow, []fieldLine{
		{"Vetor", "SRV"},
		{"Nome proprietário DNS", candidate.Record.Owner},
		{"Destino", fmt.Sprintf("%s:%d", candidate.Record.Target, candidate.Record.Port)},
		{"Resultado DNS", presentation.Value(string(candidate.DNSStatus))},
		{"Dados do serviço", fmt.Sprintf("prioridade: %d; peso: %d", candidate.Record.Priority, candidate.Record.Weight)},
		{"Propriedade", valueOr(presentation.Value(candidate.Ownership), "desconhecida")},
		{"Reivindicabilidade", presentation.Value(string(candidate.Claimability))},
		{"Confiança da análise", confidence},
		{"Próximo passo", "valide a propriedade do destino e o impacto específico do protocolo"},
	}, options)
}

func spfFinding(analysis *core.HostAnalysis, candidate core.SPFCandidate, confidence string, options Options) string {
	subject := analysis.Host
	if len(candidate.Chain) > 0 {
		subject = candidate.Chain[0]
	}
	return renderBlock("SPF QUEBRADO", subject, color.ToneLow, []fieldLine{
		{"Vetor", "SPF " + candidate.Mechanism},
		{"Destino", candidate.Domain},
		{"Cadeia", strings.Join(candidate.Chain, " → ")},
		{"Resultado DNS", presentation.Value(string(candidate.DNSStatus))},
		{"Propriedade", valueOr(presentation.Value(candidate.Ownership), "desconhecida")},
		{"Registrabilidade", resourceStatus(candidate.RegistrableDomain, candidate.RegistrationStatus)},
		{"Reivindicabilidade", presentation.Value(string(candidate.Claimability))},
		{"Confiança da análise", confidence},
		{"Próximo passo", "valide a registrabilidade e se um e-mail controlado passaria pelo SPF"},
	}, options)
}

func ipFinding(analysis *core.HostAnalysis, candidate core.CloudIPCandidate, confidence string, options Options) string {
	return renderBlock("REVISÃO DE IP EM NUVEM", analysis.Host, color.ToneLow, []fieldLine{
		{"Vetor", candidate.RecordType + "/ASN"},
		{"Endereço", candidate.IP},
		{"Provedor", fmt.Sprintf("%s (ASN %s)", candidate.Provider, candidate.ASN)},
		{"Alcançabilidade", presentation.Value(candidate.Reachability)},
		{"Reivindicabilidade", presentation.Value(string(candidate.Claimability))},
		{"Confiança da análise", confidence},
		{"Próximo passo", "inspecione o histórico e a viabilidade de alocação; silêncio de rede não é prova"},
	}, options)
}

func axfrFinding(analysis *core.HostAnalysis, confidence string, options Options) string {
	evidence := firstEvidence(analysis, "DNS_AXFR_ALLOWED")
	return renderBlock("EXPOSIÇÃO DNS", analysis.Host, color.ToneMedium, []fieldLine{
		{"Vetor", "AXFR"},
		{"Zona", evidence.Metadata["zone"]},
		{"Servidor NS", evidence.Metadata["nameserver"]},
		{"Impacto", "exposição dos registros da zona; isso não representa controle da zona"},
		{"Confiança da análise", confidence},
		{"Próximo passo", "restrinja transferências aos servidores secundários autorizados"},
	}, options)
}

func cnameFinding(analysis *core.HostAnalysis, confidence string, options Options) string {
	label, tone := "REVISÃO CNAME", color.ToneLow
	if cnameClaimed(analysis) {
		label, tone = "CONTROLE DO RECURSO COMPROVADO", color.ToneCritical
	} else if hasAny(analysis, "HTTP_BODY_MATCH", "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT") {
		label, tone = "TAKEOVER PROVÁVEL", color.ToneMedium
	} else if hasAny(analysis, "CNAME_DANGLING") {
		label = "RECURSO ÓRFÃO"
	}

	provider := "desconhecido"
	for _, candidate := range analysis.ProviderCandidates {
		if strings.EqualFold(candidate.Vector, "CNAME") || candidate.CNAME != "" {
			provider = valueOr(candidate.Service, provider)
			break
		}
	}

	chain := append([]string{analysis.Host}, analysis.DNS.CNAME...)
	fingerprint := "não observado"
	source := "DNS"
	status := "desconhecido"
	claimed := false
	hasHTTPObservation := false
	if proof := analysis.ActiveVerification; proof != nil && proof.Verified && proof.ControlProven && strings.EqualFold(proof.Vector, "CNAME") {
		fingerprint = valueOr(proof.Evidence, "prova de controle do provedor")
		source = "reivindicação autorizada com criação, prova e liberação"
		status, claimed = presentation.Value("CONTROLLED"), true
		hasHTTPObservation = true
	}
	if !claimed {
		if evidence := firstEvidence(analysis, "HTTP_BODY_MATCH"); evidence.Type != "" {
			fingerprint = quote(evidence.Metadata["matched_fingerprint"])
			provider = valueOr(evidence.Source, provider)
			source = "linha de base HTTP"
			hasHTTPObservation = true
		}
		if evidence := firstEvidence(analysis, "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT"); evidence.Type != "" {
			fingerprint = quote(evidence.Metadata["matched_fingerprint"])
			provider = valueOr(evidence.Source, provider)
			source = fmt.Sprintf(
				"revelado por %s (%s/%s confirmações)",
				evidence.Metadata["mutation"],
				evidence.Metadata["confirmations"],
				evidence.Metadata["attempts"],
			)
			status = evidence.Metadata["mutated_status"]
			hasHTTPObservation = true
		} else if evidence := firstEvidence(analysis, "HTTP_RESPONSE"); evidence.Type != "" {
			status = evidence.Metadata["status"]
			source = "linha de base HTTP"
			hasHTTPObservation = true
		}
	}
	evidenceSummary := "DNS — destino final da cadeia sem registros A/AAAA"
	if hasHTTPObservation {
		evidenceSummary = fmt.Sprintf("HTTP %s — %s", status, fingerprint)
	}

	nextStep := "valide o vínculo do recurso no provedor dentro do escopo do programa"
	if claimed {
		nextStep = "revise o recibo de auditoria e o estado confirmado da liberação"
	}

	return renderBlock(label, analysis.Host, tone, []fieldLine{
		{"Vetor", "CNAME"},
		{"Cadeia", strings.Join(unique(chain), " → ")},
		{"Provedor", provider},
		{"Evidência", evidenceSummary},
		{"Fonte", source},
		{"Confiança da análise", confidence},
		{"Próximo passo", nextStep},
	}, options)
}

func activeVectorFinding(analysis *core.HostAnalysis, proof *core.VerificationResult, confidence string, options Options) string {
	cleanup := "estado da liberação indisponível"
	if hasAny(analysis, "CLAIM_RELEASE_SUCCEEDED") {
		cleanup = "liberação concluída pelo fluxo auditado"
	} else if hasAny(analysis, "CLAIM_RELEASE_FAILED") {
		cleanup = "FALHOU; revise a auditoria e reconcilie imediatamente"
	}

	return renderBlock("CONTROLE CONFIRMADO", analysis.Host, color.ToneCritical, []fieldLine{
		{"Vetor", valueOr(proof.Vector, "desconhecido")},
		{"Recurso", valueOr(proof.Resource, analysis.Host)},
		{"Provedor", valueOr(proof.Provider, "desconhecido")},
		{"Prova", valueOr(proof.Evidence, "prova positiva de controle do provedor")},
		{"Confiança da análise", confidence},
		{"Limpeza", cleanup},
	}, options)
}

func renderBlock(label, subject string, tone color.Tone, fields []fieldLine, options Options) string {
	header := color.ToneText(fmt.Sprintf("[%s] %s", label, subject), tone, options.Color)
	var builder strings.Builder
	builder.WriteString(header)
	builder.WriteByte('\n')
	for _, field := range fields {
		if strings.TrimSpace(field.value) == "" {
			continue
		}
		builder.WriteString("  ")
		builder.WriteString(color.Field(field.label, options.Color))
		builder.WriteString(": ")
		builder.WriteString(field.value)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func category(level string) string {
	switch level {
	case classification.LevelTakenOver,
		classification.LevelConfirmed,
		classification.LevelTakeoverable,
		classification.LevelLikelyTakeoverable,
		classification.LevelZoneControlConfirmed,
		classification.LevelDelegationClaimabilityVerified,
		classification.LevelDelegationTakeoverCandidate:
		return "takeover"
	case classification.LevelExposed:
		return "exposição"
	case classification.LevelMisconfigured, classification.LevelDelegationBroken:
		return "configuração incorreta"
	case classification.LevelOrphaned:
		return "recurso órfão"
	case classification.LevelHealthy:
		return "saudável"
	case classification.LevelInsufficientEvidence:
		return "evidência insuficiente"
	default:
		return "revisão"
	}
}

func toneForClassification(level string) color.Tone {
	switch classificationSeverityRank(level) {
	case 5:
		return color.ToneCritical
	case 4:
		return color.ToneHigh
	case 3:
		return color.ToneMedium
	case 2:
		return color.ToneLow
	case 1:
		return color.ToneInfo
	default:
		return color.ToneMuted
	}
}

func classificationSeverityRank(level string) int {
	switch level {
	case classification.LevelTakenOver, classification.LevelZoneControlConfirmed:
		return 5
	case classification.LevelConfirmed, classification.LevelDelegationClaimabilityVerified, classification.LevelTakeoverable:
		return 4
	case classification.LevelLikelyTakeoverable, classification.LevelDelegationTakeoverCandidate, classification.LevelExposed:
		return 3
	case classification.LevelOrphaned, classification.LevelDelegationBroken, classification.LevelMisconfigured:
		return 2
	case classification.LevelHealthy:
		return 1
	default:
		return 0
	}
}

func hasCNAMEFinding(analysis *core.HostAnalysis) bool {
	return cnameClaimed(analysis) ||
		hasAny(analysis, "CNAME_DANGLING", "HTTP_BODY_MATCH", "HTTP_MUTATION_REVEALED_PROVIDER_FINGERPRINT")
}

func cnameClaimed(analysis *core.HostAnalysis) bool {
	evidence := firstEvidence(analysis, "CLAIM_SUCCESS")
	return evidence.Type != "" && strings.EqualFold(evidence.Metadata["vector"], "CNAME")
}

func brokenMXs(analysis *core.HostAnalysis) []core.MXCandidate {
	var result []core.MXCandidate
	for _, candidate := range analysis.MXCandidates {
		if candidate.DNSStatus == core.DNSStatusNXDomain || candidate.DNSStatus == core.DNSStatusNoData {
			result = append(result, candidate)
		}
	}
	return result
}

func brokenSRVs(analysis *core.HostAnalysis) []core.SRVCandidate {
	var result []core.SRVCandidate
	for _, candidate := range analysis.SRVCandidates {
		if candidate.DNSStatus == core.DNSStatusNXDomain || candidate.DNSStatus == core.DNSStatusNoData {
			result = append(result, candidate)
		}
	}
	return result
}

func staleIP(analysis *core.HostAnalysis) (core.CloudIPCandidate, bool) {
	if !hasAny(analysis, "STALE_CLOUD_IP_CANDIDATE") {
		return core.CloudIPCandidate{}, false
	}
	for _, candidate := range analysis.CloudIPCandidates {
		if candidate.ProviderID != "" {
			return candidate, true
		}
	}
	return core.CloudIPCandidate{}, false
}

func firstEvidence(analysis *core.HostAnalysis, evidenceType string) core.Evidence {
	for _, evidence := range analysis.Evidences {
		if evidence.Type == evidenceType {
			return evidence
		}
	}
	return core.Evidence{}
}

func hasAny(analysis *core.HostAnalysis, types ...string) bool {
	for _, evidenceType := range types {
		if firstEvidence(analysis, evidenceType).Type != "" {
			return true
		}
	}
	return false
}

func resourceStatus(resource, status string) string {
	resource = strings.TrimSpace(resource)
	status = presentation.Value(status)
	switch {
	case resource == "":
		return status
	case status == "":
		return resource
	default:
		return fmt.Sprintf("%s (%s)", resource, status)
	}
}

func zoneWithParent(zone, parent string) string {
	if strings.TrimSpace(parent) == "" {
		return zone
	}
	return fmt.Sprintf("%s (zona pai: %s)", zone, parent)
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func quote(value string) string {
	if value == "" {
		return "não observado"
	}
	return fmt.Sprintf("%q", value)
}

func unique(values []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, value := range values {
		value = strings.TrimSuffix(strings.TrimSpace(value), ".")
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
