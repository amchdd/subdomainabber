package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/netclient"
	"github.com/amchdd/subdomainabber/internal/presentation"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/internal/verify"
	"github.com/amchdd/subdomainabber/pkg/color"
	"github.com/amchdd/subdomainabber/pkg/notify"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
)

var (
	verifyOnlyRisky   bool
	verifyClassFilter string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Revalida hosts previamente analisados para detectar mudanças de estado",
	RunE: func(cmd *cobra.Command, args []string) (runErr error) {
		cfg, err := loadRuntimeCommandConfig()
		if err != nil {
			return fmt.Errorf("configuração de execução inválida: %w", err)
		}
		useColor := !cfg.NoColor && color.Enabled(os.Stdout)
		if cfg.DBPath == "" {
			cfg.DBPath = "subdomainabber.db"
		}

		db, err := storage.New(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("erro no banco de dados: %w", err)
		}
		defer closeStoreWithError(db, &runErr)

		fmt.Printf("[*] Carregando hosts do banco %s...\n", cfg.DBPath)
		ctx := commandContext(cmd)
		hosts, err := db.GetAllHosts(ctx, storage.QueryOptions{
			OnlyRisky:      verifyOnlyRisky,
			Classification: verifyClassFilter,
		})
		if err != nil {
			return fmt.Errorf("erro ao recuperar hosts: %w", err)
		}

		if len(hosts) == 0 {
			fmt.Println("[*] Nenhum host encontrado para os critérios selecionados.")
			return nil
		}

		fmt.Printf("[*] %d hosts carregados. Iniciando verificação contínua...\n\n", len(hosts))

		// Instanciar dependências do motor
		var customResolvers []string
		if cfg.ResolversFile != "" {
			customResolvers, err = dns.LoadResolversFromFile(cfg.ResolversFile)
			if err != nil {
				return fmt.Errorf("erro ao carregar resolvedores: %w", err)
			}
		}
		res := dns.New(customResolvers)
		res.SetTimeout(time.Duration(cfg.Timeout) * time.Second)
		res.SetWildcardFiltering(!cfg.NoWildcardFilter)
		if err := configureResolverDoH(res, cfg); err != nil {
			return err
		}
		limiter := ratelimit.New(cfg.RateLimit)
		res.SetRequestLimiter(limiter)
		sharedClient, clientErr := netclient.NewScopedClient(time.Duration(cfg.Timeout)*time.Second, cfg.Proxy, limiter)
		if clientErr != nil {
			return fmt.Errorf("configuração inválida do cliente HTTP: %w", clientErr)
		}

		baseSignatures, err := loadVerificationSignatureBase(cfg)
		if err != nil {
			return fmt.Errorf("carregando assinaturas para revalidação: %w", err)
		}
		runtimes, err := buildVerificationRuntimes(hosts, res, cfg, limiter, sharedClient, baseSignatures, db)
		if err != nil {
			return err
		}

		dispatcher, err := notify.NewDispatcherWithOptions(notify.DispatcherConfig{
			Workers: 3, DiscordWebhook: cfg.DiscordWebhook, TelegramConfig: cfg.TelegramConfig,
			MinimumSeverity: cfg.DiscordMinSeverity,
		})
		if err != nil {
			return fmt.Errorf("configuração de notificação inválida: %w", err)
		}
		defer dispatcher.Flush()

		changedCount := 0

		concurrencyLimit := effectiveHostConcurrency(cfg.Concurrency, cfg.RateLimit)

		type verifyResult struct {
			host    core.HostAnalysis
			resDiff *verify.Result
			err     error
		}

		hostChan := make(chan core.HostAnalysis, concurrencyLimit)

		go func() {
			defer close(hostChan)
			for _, h := range hosts {
				select {
				case <-ctx.Done():
					return
				case hostChan <- h:
				}
			}
		}()

		// O buffer permite que os workers terminem a coleta enquanto o goroutine
		// principal persiste e apresenta os resultados em ordem de chegada.
		resultsChan := make(chan verifyResult, len(hosts))
		var wg sync.WaitGroup

		for i := 0; i < concurrencyLimit; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for h := range hostChan {
					runtime := runtimes[verificationProfileKey(h.ScanProfile)]
					resDiff, err := runtime.engine.Verify(ctx, &h)
					select {
					case <-ctx.Done():
						return
					case resultsChan <- verifyResult{host: h, resDiff: resDiff, err: err}:
					}
				}
			}()
		}

		go func() {
			wg.Wait()
			close(resultsChan)
		}()

		var persistenceErrors []error
		processedCount := 0
		for res := range resultsChan {
			processedCount++
			if res.err != nil {
				if ctx.Err() != nil || errors.Is(res.err, ctx.Err()) {
					continue
				}
				fmt.Fprintf(os.Stderr, "[-] Erro ao verificar %s: %v\n", res.host.Host, res.err)
				continue
			}
			if res.resDiff == nil {
				fmt.Fprintf(os.Stderr, "[-] A revalidação de %s não retornou resultado.\n", res.host.Host)
				continue
			}
			if res.resDiff.State == verify.Incomplete {
				fmt.Printf("[REVALIDAÇÃO INCONCLUSIVA] %s\n", res.resDiff.Host)
				fmt.Printf("  Motivo: %s\n", res.resDiff.Reason)
				if len(res.resDiff.MissingVectors) > 0 {
					fmt.Printf("  Módulos ausentes: %s\n", strings.Join(res.resDiff.MissingVectors, ", "))
				}
				if len(res.resDiff.UnexpectedVectors) > 0 {
					fmt.Printf("  Módulos adicionais: %s\n", strings.Join(res.resDiff.UnexpectedVectors, ", "))
				}
				fmt.Println("  Próximo passo: execute novamente o comando scan para criar uma referência compatível.")
				fmt.Println()
				continue
			}

			if err := persistVerifiedAnalysis(db, res.resDiff); err != nil {
				persistenceErrors = append(persistenceErrors, err)
				fmt.Fprintf(os.Stderr, "[-] Falha ao persistir a revalidação de %s: %v\n", res.resDiff.Host, err)
				continue
			}

			if res.resDiff.State != verify.Unchanged {
				changedCount++

				severity := verify.GetTransitionSeverity(res.resDiff.OldClassification, res.resDiff.NewClassification)

				if severity == "NONE" {
					continue
				}

				fmt.Printf("[%s] %s (Severidade: %s)\n",
					presentation.StateChange(res.resDiff.State),
					res.resDiff.Host,
					presentation.Severity(severity),
				)
				fmt.Printf("  Transição: %s -> %s\n",
					color.ColorizeClassificationLabelWith(res.resDiff.OldClassification, presentation.Classification(res.resDiff.OldClassification), useColor),
					color.ColorizeClassificationLabelWith(res.resDiff.NewClassification, presentation.Classification(res.resDiff.NewClassification), useColor))

				snapshots, err := db.GetHostSnapshots(ctx, res.resDiff.Host)
				if err == nil && len(snapshots) > 0 {
					fmt.Printf("  Linha do tempo:\n")
					firstSeen := snapshots[0].ObservedAt
					for _, snap := range snapshots {
						fmt.Printf("    - %s: %s (Conhecimento: %d, Cobertura: %d)\n", snap.ObservedAt.Format("2006-01-02"),
							color.ColorizeClassificationLabelWith(snap.Classification, presentation.Classification(snap.Classification), useColor), snap.KnowledgeScore, snap.CoverageScore)
					}
					exposureAge := time.Since(firstSeen).Hours() / 24.0
					fmt.Printf("  Tempo de exposição: %.0f dias\n", exposureAge)
				}
				fmt.Println()

				dispatcher.Dispatch(res.resDiff)
			}
		}

		if ctx.Err() != nil {
			fmt.Printf("[*] Revalidação interrompida. %d de %d hosts processados; %d mudanças persistidas.\n", processedCount, len(hosts), changedCount)
		} else {
			fmt.Printf("[*] Verificação concluída. %d hosts mudaram de estado.\n", changedCount)
		}
		return errors.Join(persistenceErrors...)
	},
}

func persistVerifiedAnalysis(db *storage.Store, result *verify.Result) error {
	if db == nil {
		return fmt.Errorf("banco de dados ausente")
	}
	if result == nil || result.NewAnalysis == nil {
		return fmt.Errorf("resultado de revalidação incompleto")
	}
	if err := db.SaveAnalysis(result.NewAnalysis); err != nil {
		return fmt.Errorf("salvando a análise de %s: %w", result.Host, err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().BoolVar(&verifyOnlyRisky, "only-risky", false, "Verifica apenas hosts que não são HEALTHY, UNKNOWN ou INSUFFICIENT_EVIDENCE")
	verifyCmd.Flags().StringVar(&verifyClassFilter, "classification", "", "Verifica apenas hosts com uma classificação específica")
}
