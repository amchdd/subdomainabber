package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/amchdd/subdomainabber/internal/discovery"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/netclient"
	"github.com/amchdd/subdomainabber/pkg/config"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
	"github.com/spf13/cobra"
)

var (
	enumDomain      string
	enumWordlist    string
	enumConcurrency int
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumera subdomínios passivamente e ativamente",
	RunE: func(cmd *cobra.Command, args []string) error {
		if enumDomain == "" {
			return fmt.Errorf("é necessário especificar um domínio com -d")
		}

		cfg, err := loadRuntimeCommandConfig()
		if err != nil {
			return fmt.Errorf("configuração de execução inválida: %w", err)
		}
		if err := config.ValidateEnumerationConcurrency(enumConcurrency); err != nil {
			return fmt.Errorf("configuração de enumeração inválida: %w", err)
		}
		limiter := ratelimit.New(cfg.RateLimit)
		var customResolvers []string
		if cfg.ResolversFile != "" {
			customResolvers, err = dns.LoadResolversFromFile(cfg.ResolversFile)
			if err != nil {
				return fmt.Errorf("erro ao carregar resolvedores: %w", err)
			}
		}
		res := dns.New(customResolvers)
		res.SetTimeout(time.Duration(cfg.Timeout) * time.Second)
		res.SetRequestLimiter(limiter)
		res.SetWildcardFiltering(!cfg.NoWildcardFilter)
		if err := configureResolverDoH(res, cfg); err != nil {
			return err
		}
		client, err := netclient.NewScopedClient(time.Duration(cfg.Timeout)*time.Second, cfg.Proxy, limiter)
		if err != nil {
			return fmt.Errorf("erro ao configurar o cliente compartilhado: %w", err)
		}
		engine := discovery.NewEngineWithClient(res, cfg, client)

		ctx := commandContext(cmd)
		subdomains, err := engine.Enumerate(ctx, enumDomain, enumWordlist, enumConcurrency)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ctx.Err()) {
				return nil
			}
			return fmt.Errorf("erro na enumeração: %w", err)
		}

		for _, sub := range subdomains {
			fmt.Println(sub)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(enumCmd)

	enumCmd.Flags().StringVarP(&enumDomain, "domain", "d", "", "Domínio alvo (ex.: example.com)")
	enumCmd.Flags().StringVarP(&enumWordlist, "wordlist", "w", "", "Caminho para lista de palavras de força bruta (opcional)")
	enumCmd.Flags().IntVarP(&enumConcurrency, "concurrency", "c", 50, "Número de consultas simultâneas na força bruta (entre 1 e 1000)")
}
