package discovery

import (
	"context"
	"fmt"
	"sort"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/presentation"
	"github.com/amchdd/subdomainabber/internal/storage"
)

type ProviderCandidate struct {
	core.UnknownProviderEvidence
	DiscoveryScore float64
}

// CalculateDiscoveryScore calcula a prioridade de revisão de um provedor desconhecido.
func CalculateDiscoveryScore(ev core.UnknownProviderEvidence) float64 {
	// Ocorrências repetidas aumentam a prioridade.
	freqWeight := float64(ev.Frequency) * 1.5

	// A severidade possui peso decrescente: HIGH, MEDIUM e LOW.
	sevWeight := 0.0
	switch ev.Severity {
	case "HIGH":
		sevWeight = 500.0
	case "MEDIUM":
		sevWeight = 200.0
	case "LOW":
		sevWeight = 10.0
	}

	// A persistência é medida pelo intervalo entre a primeira e a última observação.
	growthDays := ev.LastSeen.Sub(ev.FirstSeen).Hours() / 24.0
	growthWeight := growthDays * 5.0 // Quanto mais tempo ativo no radar, mais forte a relevância

	return freqWeight + sevWeight + growthWeight
}

// Mine reúne e ordena os provedores desconhecidos observados.
func Mine(ctx context.Context, store *storage.Store) ([]ProviderCandidate, error) {
	evidences, err := store.GetAllUnknownProviders(ctx)
	if err != nil {
		return nil, err
	}

	var candidates []ProviderCandidate
	for _, ev := range evidences {
		score := CalculateDiscoveryScore(ev)

		// Guarda a pontuação para comparar a tendência na próxima execução.
		if err := store.UpdateDiscoveryScore(ctx, ev.RootDomain, score); err != nil {
			return nil, fmt.Errorf("atualizando a pontuação de descoberta de %s: %w", ev.RootDomain, err)
		}

		candidates = append(candidates, ProviderCandidate{
			UnknownProviderEvidence: ev,
			DiscoveryScore:          score,
		})
	}

	// Apresenta primeiro os candidatos com maior prioridade.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].DiscoveryScore > candidates[j].DiscoveryScore
	})

	return candidates, nil
}

// PrintSuggestionEngine apresenta os provedores que merecem revisão manual.
func PrintSuggestionEngine(candidates []ProviderCandidate, suggest bool) {
	if len(candidates) == 0 {
		fmt.Println("Nenhum provedor desconhecido descoberto até o momento.")
		return
	}

	fmt.Println("Análise de provedores desconhecidos")
	fmt.Println("=====================================")

	for _, c := range candidates {
		fmt.Printf("\nProvedor candidato: %s\n", c.RootDomain)
		fmt.Printf("Pontuação de descoberta: %.1f\n", c.DiscoveryScore)
		fmt.Printf("Ocorrências: %d\n", c.Frequency)
		fmt.Printf("Visto primeiro em: %s\n", c.FirstSeen.Format("2006-01-02"))
		fmt.Printf("Visto por último em: %s\n", c.LastSeen.Format("2006-01-02"))
		fmt.Printf("Severidade: %s\n", presentation.Severity(c.Severity))

		if c.LastDiscoveryScore > 0 && c.DiscoveryScore > (c.LastDiscoveryScore*1.5) {
			fmt.Printf("Tendência: crescimento rápido (de %.1f para %.1f)\n", c.LastDiscoveryScore, c.DiscoveryScore)
		} else if c.LastDiscoveryScore > 0 {
			fmt.Printf("Tendência: estável (anterior: %.1f)\n", c.LastDiscoveryScore)
		}

		if len(c.ExampleHosts) > 0 {
			fmt.Println("Hosts de exemplo:")
			for _, h := range c.ExampleHosts {
				fmt.Printf("  - %s\n", h)
			}
		}

		if suggest {
			fmt.Println()
			fmt.Println("  Candidato para revisão manual")
			fmt.Println("  ------------------------------")
			fmt.Println("  Evidência:")
			fmt.Printf("    Ocorrências de CNAME: %d\n\n", c.Frequency)
			fmt.Println("  Regra sugerida:")
			fmt.Printf("    Serviço: %s\n", c.RootDomain)
			fmt.Printf("    CNAMEs:  [\"%s\"]\n\n", c.RootDomain)
			fmt.Println("  Confiança automática: não atribuída")
		}
		fmt.Println("----------------------------------------")
	}
}
