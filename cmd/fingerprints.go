package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/amchdd/subdomainabber/internal/discovery"
	"github.com/amchdd/subdomainabber/internal/fingerprint"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/pkg/signatures"
)

var (
	validateStrict  bool
	listJSON        bool
	listService     string
	discoverSuggest bool
)

var fingerprintsCmd = &cobra.Command{
	Use:   "fingerprints",
	Short: "Gerencia e valida o catálogo de assinaturas",
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Valida a integridade, a sintaxe e as regras do catálogo de assinaturas",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadCommandConfigWithError()
		if err != nil {
			return fmt.Errorf("erro ao carregar a configuração das assinaturas: %w", err)
		}

		fmt.Println("[*] Carregando o catálogo de assinaturas...")
		allSignatures, err := loadConfiguredSignatures(cfg.SigsFile, cfg.SigsDir)
		if err != nil {
			return err
		}

		if len(allSignatures) == 0 {
			return fmt.Errorf("nenhuma assinatura foi carregada para validação")
		}

		// A validação é feita antes da mesclagem para detectar duplicatas no banco original
		report := fingerprint.Validate(allSignatures)
		report.Print(validateStrict)

		if report.HasFatalErrors() || (validateStrict && len(report.Warnings) > 0) {
			return fmt.Errorf("o catálogo de assinaturas não passou na validação")
		}
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Lista as assinaturas carregadas",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadCommandConfigWithError()
		if err != nil {
			return fmt.Errorf("erro ao carregar a configuração das assinaturas: %w", err)
		}
		allSignatures, err := loadConfiguredSignatures(cfg.SigsFile, cfg.SigsDir)
		if err != nil {
			return err
		}

		allSignatures = signatures.MergeSignatures(allSignatures)

		var filtered []signatures.Fingerprint
		for _, sig := range allSignatures {
			if listService != "" && !strings.EqualFold(sig.Service, listService) {
				continue
			}
			filtered = append(filtered, sig)
		}

		if listJSON {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(filtered); err != nil {
				return fmt.Errorf("erro ao gerar a listagem JSON de assinaturas: %w", err)
			}
			return nil
		}

		fmt.Printf("Total de serviços carregados: %d\n", len(filtered))
		fmt.Println("--------------------------------------------------")
		for _, sig := range filtered {
			fmt.Printf("Serviço: %s\n", sig.Service)
			if sig.CheckType != "" {
				fmt.Printf("  Tipo:              %s\n", sig.CheckType)
			}
			if len(sig.CNames) > 0 {
				fmt.Printf("  CNAMEs:            %s\n", strings.Join(sig.CNames, ", "))
			}
			if sig.Fingerprint != "" {
				fmt.Printf("  Regra de correspondência: %s\n", sig.Fingerprint)
			}
			if sig.ActiveVerifier != "" {
				fmt.Printf("  Prova ativa:       %s\n", sig.ActiveVerifier)
			}
			if len(sig.ProofRequirements) > 0 {
				fmt.Printf("  Requisitos de prova: %s\n", strings.Join(sig.ProofRequirements, " -> "))
			}
			fmt.Println()
		}
		return nil
	},
}

var coverageCmd = &cobra.Command{
	Use:   "coverage",
	Short: "Exibe o relatório de cobertura de provedores por vetor (KPI)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadCommandConfigWithError()
		if err != nil {
			return fmt.Errorf("erro ao carregar a configuração das assinaturas: %w", err)
		}

		allSignatures, err := loadConfiguredSignatures(cfg.SigsFile, cfg.SigsDir)
		if err != nil {
			return err
		}

		cnameSet := make(map[string]bool)
		mxSet := make(map[string]bool)
		nsSet := make(map[string]bool)
		txtSet := make(map[string]bool)
		tlsSet := make(map[string]bool)
		asnSet := make(map[string]bool)
		srvSet := make(map[string]bool)
		spfSet := make(map[string]bool)

		for _, sig := range allSignatures {
			if len(sig.CNames) > 0 {
				cnameSet[sig.Service] = true
			}
			if len(sig.MXFingerprints) > 0 {
				mxSet[sig.Service] = true
			}
			if len(sig.NSFingerprints) > 0 {
				nsSet[sig.Service] = true
			}
			if len(sig.TXTFingerprints) > 0 {
				txtSet[sig.Service] = true
			}
			if len(sig.TLSFingerprints) > 0 {
				tlsSet[sig.Service] = true
			}
			if len(sig.ASNFingerprints) > 0 {
				asnSet[sig.Service] = true
			}
			if len(sig.SRVFingerprints) > 0 {
				srvSet[sig.Service] = true
			}
			if len(sig.SPFFingerprints) > 0 {
				spfSet[sig.Service] = true
			}
		}

		fmt.Println("Relatório de cobertura")
		fmt.Println("")
		fmt.Printf("CNAME: %d provedores\n", len(cnameSet))
		fmt.Printf("MX: %d provedores\n", len(mxSet))
		fmt.Printf("NS: %d provedores\n", len(nsSet))
		fmt.Printf("TXT: %d provedores\n", len(txtSet))
		fmt.Printf("TLS: %d provedores\n", len(tlsSet))
		fmt.Printf("ASN: %d provedores\n", len(asnSet))
		fmt.Printf("SRV: %d provedores\n", len(srvSet))
		fmt.Printf("SPF: %d provedores\n", len(spfSet))
		return nil
	},
}

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Minera provedores desconhecidos do banco de dados e sugere novas assinaturas",
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		cfg, err := loadCommandConfigWithError()
		if err != nil {
			return fmt.Errorf("erro ao carregar a configuração da descoberta: %w", err)
		}

		db, err := storage.New(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("erro ao abrir o banco de dados para descoberta: %w", err)
		}
		defer closeStoreWithError(db, &runErr)

		candidates, err := discovery.Mine(cmd.Context(), db)
		if err != nil {
			return fmt.Errorf("erro ao minerar provedores desconhecidos: %w", err)
		}

		discovery.PrintSuggestionEngine(candidates, discoverSuggest)
		return nil
	},
}

func loadConfiguredSignatures(file, dir string) ([]signatures.Fingerprint, error) {
	embedded, err := signatures.LoadEmbedded()
	if err != nil {
		return nil, fmt.Errorf("erro ao carregar o catálogo de assinaturas embutido: %w", err)
	}
	all := append([]signatures.Fingerprint(nil), embedded...)

	if file != "" {
		local, err := signatures.LoadFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("erro ao carregar o arquivo de assinaturas %q: %w", file, err)
		}
		all = append(all, local...)
	}
	if dir != "" {
		fromDir, err := signatures.LoadFromDir(dir)
		if err != nil {
			return nil, fmt.Errorf("erro ao carregar o diretório de assinaturas %q: %w", dir, err)
		}
		all = append(all, fromDir...)
	}

	return all, nil
}

func init() {
	rootCmd.AddCommand(fingerprintsCmd)
	fingerprintsCmd.AddCommand(validateCmd)
	fingerprintsCmd.AddCommand(listCmd)
	fingerprintsCmd.AddCommand(coverageCmd)
	fingerprintsCmd.AddCommand(discoverCmd)

	validateCmd.Flags().BoolVar(&validateStrict, "strict", false, "Falha a validação também em caso de avisos (ideal para CI/CD)")

	listCmd.Flags().BoolVar(&listJSON, "json", false, "Exibir listagem em formato JSON")
	listCmd.Flags().StringVar(&listService, "service", "", "Filtrar por nome do serviço")

	discoverCmd.Flags().BoolVar(&discoverSuggest, "suggest", false, "Gera sugestões de assinaturas prontas (não confiáveis automaticamente)")
}
