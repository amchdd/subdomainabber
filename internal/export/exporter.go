package export

import (
	"context"
	"fmt"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/core"
)

// Exporter define o contrato para exportar resultados de análise.
type Exporter interface {
	Export(ctx context.Context, hosts []core.HostAnalysis) error
}

// Summary representa o resumo executivo de uma exportação.
type Summary struct {
	GeneratedAt        string `json:"generated_at"`
	TotalHosts         int    `json:"total_hosts"`
	Takeoverable       int    `json:"takeoverable"`
	LikelyTakeoverable int    `json:"likely_takeoverable"`
	Misconfigured      int    `json:"misconfigured"`
	Confirmed          int    `json:"confirmed"`
	Candidates         int    `json:"candidates"`
	Observations       int    `json:"observations"`
	Suppressed         int    `json:"suppressed"`
	Inconclusive       int    `json:"inconclusive"`
	Healthy            int    `json:"healthy"`
}

func BuildSummary(hosts []core.HostAnalysis, generatedAt string) *Summary {
	s := &Summary{
		GeneratedAt: generatedAt,
		TotalHosts:  len(hosts),
	}

	for _, h := range hosts {
		switch exportResultState(h) {
		case core.ResultConfirmed:
			s.Confirmed++
		case core.ResultCandidate:
			s.Candidates++
		case core.ResultObservation:
			s.Observations++
		case core.ResultSuppressed:
			s.Suppressed++
		case core.ResultHealthy:
			s.Healthy++
		default:
			s.Inconclusive++
		}
		switch h.Classification {
		case "TAKEOVERABLE":
			s.Takeoverable++
		case "LIKELY_TAKEOVERABLE":
			s.LikelyTakeoverable++
		case "MISCONFIGURED":
			s.Misconfigured++
		}
	}

	return s
}

func exportResultState(host core.HostAnalysis) core.ResultState {
	if host.ResultState != "" {
		return host.ResultState
	}
	switch host.Classification {
	case classification.LevelTakenOver, classification.LevelConfirmed, classification.LevelZoneControlConfirmed,
		classification.LevelDelegationClaimabilityVerified, classification.LevelExposed:
		return core.ResultConfirmed
	case classification.LevelTakeoverable, classification.LevelLikelyTakeoverable, classification.LevelDelegationTakeoverCandidate,
		classification.LevelDelegationBroken, classification.LevelOrphaned, classification.LevelMisconfigured:
		return core.ResultCandidate
	case classification.LevelHealthy:
		return core.ResultHealthy
	default:
		return core.ResultInconclusive
	}
}

func PrintSummary(s *Summary) {
	fmt.Printf("\n--- Resumo executivo ---\n")
	fmt.Printf("Gerado em:                              %s\n", s.GeneratedAt)
	fmt.Printf("Total de hosts:                         %d\n", s.TotalHosts)
	fmt.Printf("Confirmados:                            %d\n", s.Confirmed)
	fmt.Printf("Candidatos:                             %d\n", s.Candidates)
	fmt.Printf("Observações:                            %d\n", s.Observations)
	fmt.Printf("Suprimidos:                             %d\n", s.Suppressed)
	fmt.Printf("Saudáveis:                              %d\n", s.Healthy)
	fmt.Printf("Inconclusivos:                          %d\n", s.Inconclusive)
	fmt.Printf("Reivindicáveis (TAKEOVERABLE):          %d\n", s.Takeoverable)
	fmt.Printf("Prováveis (LIKELY_TAKEOVERABLE):        %d\n", s.LikelyTakeoverable)
	fmt.Printf("Configuração incorreta (MISCONFIGURED): %d\n", s.Misconfigured)
}
