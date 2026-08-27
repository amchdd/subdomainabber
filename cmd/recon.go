package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/amchdd/subdomainabber/internal/discovery"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/internal/netclient"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/pkg/config"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
	"github.com/spf13/cobra"
)

var (
	reconDomain             string
	reconMode               string
	reconWordlist           string
	reconConcurrency        int
	reconRounds             int
	reconDepth              int
	reconLimit              int
	reconRecursiveThreshold int
	reconResume             bool
	reconJSON               bool
	reconShowUnresolved     bool
)

type reconRunner interface {
	Discover(context.Context, string, discovery.Options) (discovery.Result, error)
}

var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Descobre e mantém um inventário amplo de subdomínios",
	RunE: func(command *cobra.Command, _ []string) error {
		if reconDomain == "" {
			return fmt.Errorf("é necessário especificar um domínio com -d")
		}
		cfg, err := loadRuntimeCommandConfig()
		if err != nil {
			return fmt.Errorf("configuração de execução inválida: %w", err)
		}
		words, err := discovery.LoadWords(reconWordlist)
		if err != nil {
			return err
		}
		engine, err := newReconEngine(cfg)
		if err != nil {
			return err
		}
		store, err := storage.New(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("abrindo catálogo SQLite: %w", err)
		}
		defer store.Close()
		result, runID, err := runRecon(commandContext(command), engine, store, reconDomain, discovery.Options{
			Mode:               discovery.Mode(reconMode),
			Concurrency:        reconConcurrency,
			Words:              words,
			MaxRounds:          reconRounds,
			MaxDepth:           reconDepth,
			MaxCandidates:      reconLimit,
			RecursiveThreshold: reconRecursiveThreshold,
		}, reconResume)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return err
		}
		if result.Partial && !cfg.Silent {
			fmt.Fprintln(os.Stderr, "recon parcial; o catálogo anterior não será desativado")
			for _, reason := range result.Reasons {
				fmt.Fprintf(os.Stderr, "- %s\n", reason)
			}
		}
		if reconJSON || cfg.JSONOutput {
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		names := result.Targets()
		if reconShowUnresolved {
			names = result.Inventory()
		}
		for _, name := range names {
			fmt.Println(name)
		}
		if cfg.Verbose && !cfg.Silent {
			unresolved := len(result.Inventory()) - len(result.Targets())
			fmt.Fprintf(os.Stderr, "recon %s concluído: %d alvos resolvidos, %d nomes não resolvidos em %d rodada(s)\n", runID, len(result.Targets()), unresolved, result.Rounds)
			for _, source := range result.Sources {
				if source.Error != "" {
					fmt.Fprintf(os.Stderr, "fonte %s: %s\n", source.Name, source.Error)
				}
			}
		}
		return nil
	},
}

func newReconEngine(cfg *config.Config) (*discovery.Engine, error) {
	limiter := ratelimit.New(cfg.RateLimit)
	var servers []string
	var err error
	if cfg.ResolversFile != "" {
		servers, err = dns.LoadResolversFromFile(cfg.ResolversFile)
		if err != nil {
			return nil, fmt.Errorf("carregando resolvedores: %w", err)
		}
	}
	resolver := dns.New(servers)
	resolver.SetTimeout(time.Duration(cfg.Timeout) * time.Second)
	resolver.SetRequestLimiter(limiter)
	resolver.SetWildcardFiltering(!cfg.NoWildcardFilter)
	if err := configureResolverDoH(resolver, cfg); err != nil {
		return nil, err
	}
	client, err := netclient.NewScopedClient(time.Duration(cfg.Timeout)*time.Second, cfg.Proxy, limiter)
	if err != nil {
		return nil, fmt.Errorf("configurando cliente HTTP: %w", err)
	}
	return discovery.NewEngineWithClient(resolver, cfg, client), nil
}

func runRecon(ctx context.Context, runner reconRunner, store *storage.Store, root string, options discovery.Options, resume bool) (discovery.Result, string, error) {
	root, err := domainutil.NormalizeHostname(root)
	if err != nil {
		return discovery.Result{}, "", fmt.Errorf("domínio de recon inválido: %w", err)
	}
	var runID string
	if resume {
		latest, err := store.LatestRecon(ctx, root)
		if err != nil {
			return discovery.Result{}, "", err
		}
		if latest != nil && latest.Status == "RUNNING" && latest.Mode == string(options.Mode) {
			runID = latest.ID
			checkpoint, err := store.ReconCheckpoint(ctx, runID)
			if err != nil {
				return discovery.Result{}, "", err
			}
			candidates, err := store.ReconRunCandidates(ctx, runID)
			if err != nil {
				return discovery.Result{}, "", err
			}
			sources, err := store.ReconSources(ctx, runID)
			if err != nil {
				return discovery.Result{}, "", err
			}
			options.Resume = &discovery.State{Candidates: candidates, Checkpoint: checkpoint, Sources: sources}
		}
	}
	if runID == "" {
		var err error
		runID, err = store.StartRecon(root, string(options.Mode))
		if err != nil {
			return discovery.Result{}, "", err
		}
	}
	previousProgress := options.Progress
	options.Progress = func(state discovery.State) error {
		if previousProgress != nil {
			if err := previousProgress(state); err != nil {
				return err
			}
		}
		if err := store.SaveReconCandidates(runID, state.Candidates); err != nil {
			return err
		}
		if err := store.SaveReconCheckpoint(runID, state.Checkpoint); err != nil {
			return err
		}
		return store.SaveReconSources(runID, state.Sources)
	}
	result, err := runner.Discover(ctx, root, options)
	if err != nil {
		if ctx.Err() == nil {
			_ = store.FinishRecon(runID, "FAILED", 0, true)
		}
		return discovery.Result{}, runID, err
	}
	if err := store.SaveReconCandidates(runID, result.Names); err != nil {
		return discovery.Result{}, runID, err
	}
	if err := store.FinishRecon(runID, "COMPLETED", len(result.Names), result.Partial); err != nil {
		return discovery.Result{}, runID, err
	}
	return result, runID, nil
}

func init() {
	rootCmd.AddCommand(reconCmd)
	reconCmd.Flags().StringVarP(&reconDomain, "domain", "d", "", "Domínio raiz")
	reconCmd.Flags().StringVar(&reconMode, "mode", string(discovery.ModeExhaustive), "Modo: passive, standard ou exhaustive")
	reconCmd.Flags().StringVarP(&reconWordlist, "wordlist", "w", "", "Wordlist adicional")
	reconCmd.Flags().IntVarP(&reconConcurrency, "concurrency", "c", 50, "Consultas DNS simultâneas")
	reconCmd.Flags().IntVar(&reconRounds, "max-rounds", 4, "Máximo de rodadas recursivas")
	reconCmd.Flags().IntVar(&reconDepth, "max-depth", 5, "Profundidade máxima de labels")
	reconCmd.Flags().IntVar(&reconLimit, "max-candidates", 250000, "Limite de nomes no catálogo")
	reconCmd.Flags().IntVar(&reconRecursiveThreshold, "recursive-threshold", 2, "Densidade mínima para expansão recursiva")
	reconCmd.Flags().BoolVar(&reconResume, "resume", true, "Retomar a última execução interrompida")
	reconCmd.Flags().BoolVar(&reconJSON, "json", false, "Exibir resultado em JSON")
	reconCmd.Flags().BoolVar(&reconShowUnresolved, "show-unresolved", false, "Incluir nomes observados que não resolvem no momento")
}
