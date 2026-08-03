package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/amchdd/subdomainabber/internal/classification"
	"github.com/amchdd/subdomainabber/internal/export"
	"github.com/amchdd/subdomainabber/internal/presentation"
	"github.com/amchdd/subdomainabber/internal/stats"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/internal/verify"
)

var (
	statsJSON bool
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Interage com o banco de dados do SubdomainAbber",
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Exibe estatísticas operacionais do banco de dados",
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		cfg, err := loadCommandConfigWithError()
		if err != nil {
			return fmt.Errorf("erro ao carregar a configuração das estatísticas: %w", err)
		}
		if cfg.DBPath == "" {
			cfg.DBPath = "subdomainabber.db"
		}

		db, err := storage.New(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("erro ao abrir o banco de dados para obter estatísticas: %w", err)
		}
		defer closeStoreWithError(db, &runErr)

		svc := stats.NewService(db.DB())

		dbStats, err := svc.GetStats(cmd.Context())
		if err != nil {
			return fmt.Errorf("erro ao calcular as estatísticas do banco de dados: %w", err)
		}

		if statsJSON {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(dbStats); err != nil {
				return fmt.Errorf("erro ao gerar as estatísticas em JSON: %w", err)
			}
			return nil
		}

		printTextStats(dbStats)
		return nil
	},
}

func printTextStats(dbStats *stats.DBStats) {
	fmt.Println("=====================================")
	fmt.Println("       Estatísticas do banco         ")
	fmt.Println("=====================================")
	fmt.Printf("\nTotal de hosts: %d\n\n", dbStats.TotalHosts)

	// Ordem preferencial de classificação
	order := []string{
		classification.LevelHealthy,
		classification.LevelInsufficientEvidence,
		classification.LevelUnknown,
		classification.LevelMisconfigured,
		classification.LevelExposed,
		classification.LevelOrphaned,
		classification.LevelDelegationBroken,
		classification.LevelLikelyTakeoverable,
		classification.LevelDelegationTakeoverCandidate,
		classification.LevelTakeoverable,
		classification.LevelConfirmed,
		classification.LevelDelegationClaimabilityVerified,
		classification.LevelZoneControlConfirmed,
		classification.LevelTakenOver,
	}

	for _, k := range order {
		v := dbStats.ClassificationCounts[k]
		fmt.Printf("%-42s %d\n", presentation.Classification(k)+":", v)
	}

	fmt.Println("\n--- Mudanças de estado ---")
	states := []verify.StateChange{verify.Fixed, verify.Improved, verify.Regressed, verify.Changed, verify.Unchanged}
	for _, s := range states {
		v := dbStats.StateChangeCounts[string(s)]
		fmt.Printf("%-20s %d\n", presentation.StateChange(s)+":", v)
	}

	if len(dbStats.TopEvidenceTypes) > 0 {
		fmt.Println("\n--- Tipos de evidência mais frequentes ---")
		for _, ev := range dbStats.TopEvidenceTypes {
			fmt.Printf("%-25s %d\n", ev.Type, ev.Count)
		}
	}
	fmt.Println("")
}

var (
	exportFormat    string
	exportOut       string
	exportClass     string
	exportOnlyRisky bool
	exportChanged   time.Duration
	exportSummary   bool
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Exporta os dados do banco para JSON ou CSV",
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		cfg, err := loadCommandConfigWithError()
		if err != nil {
			return fmt.Errorf("erro ao carregar a configuração da exportação: %w", err)
		}
		if cfg.DBPath == "" {
			cfg.DBPath = "subdomainabber.db"
		}

		db, err := storage.New(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("erro ao abrir o banco de dados para exportação: %w", err)
		}
		defer closeStoreWithError(db, &runErr)

		opts := storage.QueryOptions{
			OnlyRisky:      exportOnlyRisky,
			Classification: exportClass,
			ChangedSince:   exportChanged,
		}

		hosts, err := db.GetAllHosts(cmd.Context(), opts)
		if err != nil {
			return fmt.Errorf("erro ao buscar hosts para exportação: %w", err)
		}

		if exportSummary {
			sum := export.BuildSummary(hosts, time.Now().UTC().Format(time.RFC3339))
			if exportFormat == "json" {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				if err := encoder.Encode(sum); err != nil {
					return fmt.Errorf("erro ao gerar o resumo da exportação em JSON: %w", err)
				}
			} else {
				export.PrintSummary(sum)
			}
			return nil
		}

		var exporter export.Exporter
		switch exportFormat {
		case "json":
			exporter = export.NewJSONExporter(exportOut)
		case "csv":
			exporter = export.NewCSVExporter(exportOut)
		default:
			return fmt.Errorf("formato de exportação %q não suportado; use json ou csv", exportFormat)
		}

		if err := exporter.Export(cmd.Context(), hosts); err != nil {
			return fmt.Errorf("erro ao exportar os dados: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(dbCmd)
	dbCmd.AddCommand(statsCmd)
	dbCmd.AddCommand(exportCmd)

	statsCmd.Flags().BoolVar(&statsJSON, "json", false, "Saída em formato JSON")

	exportCmd.Flags().StringVarP(&exportFormat, "format", "f", "json", "Formato de exportação (json, csv)")
	exportCmd.Flags().StringVarP(&exportOut, "out", "o", "", "Arquivo de saída (por padrão, usa stdout)")
	exportCmd.Flags().StringVar(&exportClass, "classification", "", "Filtrar por classificação")
	exportCmd.Flags().BoolVar(&exportOnlyRisky, "only-risky", false, "Exportar apenas vulneráveis ou problemáticos")
	exportCmd.Flags().DurationVar(&exportChanged, "changed-since", 0, "Exportar apenas hosts alterados recentemente (ex.: 24h, 7d)")
	exportCmd.Flags().BoolVar(&exportSummary, "summary", false, "Imprimir apenas um resumo executivo")
}
