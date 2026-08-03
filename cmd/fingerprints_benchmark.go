package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/storage"
)

var (
	benchService  string
	benchEvidence string
)

var benchmarkFingerprintsCmd = &cobra.Command{
	Use:   "fingerprints",
	Short: "Mede a qualidade das assinaturas com base na conversão para estados vulneráveis",
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		cfg, err := loadCommandConfigWithError()
		if err != nil {
			return fmt.Errorf("erro ao carregar a configuração do benchmark de assinaturas: %w", err)
		}
		if cfg.DBPath == "" {
			cfg.DBPath = "subdomainabber.db"
		}

		db, err := storage.New(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("erro ao abrir o banco de dados para o benchmark de assinaturas: %w", err)
		}
		defer closeStoreWithError(db, &runErr)

		hosts, err := db.GetAllHosts(cmd.Context(), storage.QueryOptions{})
		if err != nil {
			return fmt.Errorf("erro ao buscar hosts para o benchmark de assinaturas: %w", err)
		}

		if len(hosts) == 0 {
			fmt.Println("Nenhum host no banco de dados para analisar.")
			return nil
		}

		type Stat struct {
			Source       string
			Type         string
			Total        int
			Relevant     int
			ManualReview int
		}

		statsMap := make(map[string]*Stat)

		for _, h := range hosts {
			isRelevant := h.Classification == classification.LevelTakeoverable ||
				h.Classification == classification.LevelLikelyTakeoverable ||
				h.Classification == classification.LevelOrphaned

			isManualReview := h.Classification == classification.LevelLikelyTakeoverable

			for _, ev := range h.Evidences {
				if benchService != "" && !strings.EqualFold(ev.Source, benchService) {
					continue
				}
				if benchEvidence != "" && !strings.EqualFold(ev.Type, benchEvidence) {
					continue
				}

				key := fmt.Sprintf("%s|%s", ev.Source, ev.Type)
				if _, exists := statsMap[key]; !exists {
					statsMap[key] = &Stat{Source: ev.Source, Type: ev.Type}
				}

				statsMap[key].Total++
				if isRelevant {
					statsMap[key].Relevant++
				}
				if isManualReview {
					statsMap[key].ManualReview++
				}
			}
		}

		var results []*Stat
		for _, s := range statsMap {
			results = append(results, s)
		}

		// Exibe primeiro as assinaturas com mais ocorrências.
		sort.Slice(results, func(i, j int) bool {
			return results[i].Total > results[j].Total
		})

		fmt.Printf("Avaliação de assinaturas (baseada em %d hosts)\n", len(hosts))
		fmt.Println("======================================================================================")
		fmt.Printf("%-25s | %-18s | %-8s | %-10s | %-8s | %-12s\n", "Fonte", "Tipo de evidência", "Disparos", "Conversões", "Revisão", "Nota")
		fmt.Println("--------------------------------------------------------------------------------------")

		for _, r := range results {
			score := float64(r.Relevant) / float64(r.Total) * 100

			grade := "Não confiável"
			if score >= 90 {
				grade = "Excelente"
			} else if score >= 75 {
				grade = "Bom"
			} else if score >= 50 {
				grade = "Razoável"
			} else if score >= 25 {
				grade = "Fraco"
			}

			fmt.Printf("%-25s | %-18s | %-8d | %-10d | %-8d | %-12s (%.1f%%)\n",
				r.Source, r.Type, r.Total, r.Relevant, r.ManualReview, grade, score)
		}
		return nil
	},
}

func init() {
	benchmarkCmd.AddCommand(benchmarkFingerprintsCmd)
	benchmarkFingerprintsCmd.Flags().StringVarP(&benchService, "service", "s", "", "Filtra métricas de conversão para um serviço específico (ex.: 'GitHub Pages')")
	benchmarkFingerprintsCmd.Flags().StringVarP(&benchEvidence, "evidence", "e", "", "Filtra por tipo de evidência (ex.: 'CNAME_PROVIDER_MATCH')")
}
