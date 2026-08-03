package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/amchdd/subdomainabber/internal/learning"
	"github.com/amchdd/subdomainabber/internal/storage"
)

var (
	learnMinHosts int
)

var learnCmd = &cobra.Command{
	Use:   "learn",
	Short: "Detecta padrões repetidos de hosts órfãos para sugerir novas assinaturas",
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		cfg, err := loadCommandConfigWithError()
		if err != nil {
			return fmt.Errorf("erro ao carregar a configuração do aprendizado: %w", err)
		}
		if cfg.DBPath == "" {
			cfg.DBPath = "subdomainabber.db"
		}

		db, err := storage.New(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("erro ao abrir o banco de dados para aprendizado: %w", err)
		}
		defer closeStoreWithError(db, &runErr)

		fmt.Println("[*] Analisando padrões recorrentes...")
		engine := learning.NewEngine(db.DB())

		candidates, err := engine.Discover(cmd.Context(), learnMinHosts)
		if err != nil {
			return fmt.Errorf("falha ao analisar os padrões recorrentes: %w", err)
		}

		if len(candidates) == 0 {
			fmt.Println("[*] Nenhum padrão recorrente atende ao limite configurado.")
			return nil
		}

		fmt.Printf("[+] Padrões candidatos identificados: %d\n", len(candidates))
		fmt.Println("================================================================")

		for _, cand := range candidates {
			fmt.Printf("Nova assinatura potencial (ocorrências: %d)\n", cand.ObservedHosts)
			fmt.Printf("Base do provedor: %s\n", cand.TargetCNAME)
			fmt.Printf("Status HTTP:      %s\n", cand.StatusCode)
			fmt.Printf("Título da página: %s\n", cand.PageTitle)
			fmt.Println("----------------------------------------------------------------")
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(learnCmd)
	learnCmd.Flags().IntVarP(&learnMinHosts, "min-hosts", "m", 5, "Número mínimo de ocorrências do padrão para sugeri-lo como assinatura")
}
