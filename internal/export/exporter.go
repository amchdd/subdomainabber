package export

import (
	"context"
	"fmt"

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
}

func BuildSummary(hosts []core.HostAnalysis, generatedAt string) *Summary {
	s := &Summary{
		GeneratedAt: generatedAt,
		TotalHosts:  len(hosts),
	}

	for _, h := range hosts {
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

func PrintSummary(s *Summary) {
	fmt.Printf("\n--- Resumo executivo ---\n")
	fmt.Printf("Gerado em:                              %s\n", s.GeneratedAt)
	fmt.Printf("Total de hosts:                         %d\n", s.TotalHosts)
	fmt.Printf("Reivindicáveis (TAKEOVERABLE):          %d\n", s.Takeoverable)
	fmt.Printf("Prováveis (LIKELY_TAKEOVERABLE):        %d\n", s.LikelyTakeoverable)
	fmt.Printf("Configuração incorreta (MISCONFIGURED): %d\n", s.Misconfigured)
}
