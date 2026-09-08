package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
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
	reconTestLimit          int
	reconRecursiveThreshold int
	reconAssetLimit         int
	reconResume             bool
	reconFormat             string
	reconInclude            []string
	reconJSON               bool
	reconJSONL              bool
	reconShowUnresolved     bool
	reconShowSources        bool
	reconShowWildcards      bool
)

type reconRunner interface {
	Discover(context.Context, string, discovery.Options) (discovery.Result, error)
}

type reconView struct {
	format     string
	unresolved bool
	wildcards  bool
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
		view, err := selectReconView(command, cfg.JSONOutput)
		if err != nil {
			return err
		}
		words, err := discovery.LoadWords(reconWordlist)
		if err != nil {
			return err
		}
		if len(words) > 0 {
			words = append(words, discovery.DefaultWords(discovery.Mode(reconMode))...)
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
			MaxTested:          reconTestLimit,
			RecursiveThreshold: reconRecursiveThreshold,
			AssetLimit:         reconAssetLimit,
			Progress:           reconProgress(cfg.Silent, reconDomain),
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
		if view.format == "json" {
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		if view.format == "jsonl" {
			encoder := json.NewEncoder(os.Stdout)
			for _, candidate := range result.Names {
				if candidate.Name == result.Root || (candidate.Wildcard && !view.wildcards) || (!view.unresolved && !candidate.Resolved) {
					continue
				}
				if err := encoder.Encode(candidate); err != nil {
					return err
				}
			}
			return nil
		}
		for _, candidate := range result.Names {
			if candidate.Name == result.Root || (candidate.Wildcard && !view.wildcards) || (!candidate.Resolved && !view.unresolved) {
				continue
			}
			if view.format != "sources" {
				if _, err := fmt.Fprintln(os.Stdout, candidate.Name); err != nil {
					return err
				}
				continue
			}
			if _, err := fmt.Fprintf(os.Stdout, "%s\t%s\n", candidate.Name, strings.Join(candidate.SourceNames(), ",")); err != nil {
				return err
			}
		}
		if cfg.Verbose && !cfg.Silent {
			unresolved := len(result.Inventory()) - len(result.Targets())
			fmt.Fprintf(
				os.Stderr,
				"recon %s concluído: %d alvos resolvidos, %d nomes não resolvidos, %d nomes testados e %d wildcards filtrados em %d rodada(s)\n",
				runID,
				len(result.Targets()),
				unresolved,
				result.Stats.NamesTested,
				result.Stats.WildcardFiltered,
				result.Rounds,
			)
			for _, source := range result.Sources {
				if source.Error != "" {
					fmt.Fprintf(os.Stderr, "fonte %s: %s\n", source.Name, source.Error)
				}
			}
		}
		return nil
	},
}

func selectReconView(command *cobra.Command, configJSON bool) (reconView, error) {
	view, err := parseReconView(reconFormat, reconInclude)
	if err != nil {
		return reconView{}, err
	}
	if !command.Flags().Changed("format") {
		switch {
		case reconJSON || configJSON:
			view.format = "json"
		case reconJSONL:
			view.format = "jsonl"
		case reconShowSources:
			view.format = "sources"
		}
	}
	view.unresolved = view.unresolved || reconShowUnresolved
	view.wildcards = view.wildcards || reconShowWildcards
	return view, nil
}

func parseReconView(format string, include []string) (reconView, error) {
	view := reconView{format: strings.ToLower(strings.TrimSpace(format))}
	if view.format == "" {
		view.format = "text"
	}
	switch view.format {
	case "text", "sources", "json", "jsonl":
	default:
		return reconView{}, fmt.Errorf("formato de recon inválido %q; use text, sources, json ou jsonl", format)
	}
	for _, value := range include {
		for _, item := range strings.Split(value, ",") {
			switch strings.ToLower(strings.TrimSpace(item)) {
			case "":
				continue
			case "unresolved":
				view.unresolved = true
			case "wildcards":
				view.wildcards = true
			case "all":
				view.unresolved = true
				view.wildcards = true
			default:
				return reconView{}, fmt.Errorf("inclusão de recon inválida %q; use unresolved, wildcards ou all", item)
			}
		}
	}
	return view, nil
}

func reconProgress(silent bool, root string) func(discovery.State) error {
	if silent {
		return nil
	}
	return func(state discovery.State) error {
		stage := fmt.Sprintf("rodada %d", state.Checkpoint.Round)
		if state.Checkpoint.Round == 0 {
			stage = "coleta inicial"
		}
		fmt.Fprintf(
			os.Stderr,
			"recon %s: %s, %d nomes no catálogo, %d na fronteira e %d testados\n",
			root,
			stage,
			len(state.Candidates),
			len(state.Checkpoint.Frontier),
			len(state.Checkpoint.Attempted),
		)
		return nil
	}
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
	if err := discovery.ValidateOptions(options); err != nil {
		return discovery.Result{}, "", err
	}
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
			if len(candidates) > 0 {
				options.Resume = &discovery.State{Candidates: candidates, Checkpoint: checkpoint, Sources: sources}
			}
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
		return store.SaveReconProgress(runID, state.Candidates, state.Checkpoint, state.Sources)
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
	reconCmd.Flags().IntVar(&reconRounds, "max-rounds", 0, "Máximo de rodadas recursivas; zero usa o padrão do modo")
	reconCmd.Flags().IntVar(&reconDepth, "max-depth", 0, "Profundidade máxima de labels; zero usa o padrão do modo")
	reconCmd.Flags().IntVar(&reconLimit, "max-candidates", 0, "Limite de nomes no catálogo; zero usa o padrão do modo")
	reconCmd.Flags().IntVar(&reconTestLimit, "max-tested", 0, "Limite de nomes testados por DNS; zero usa 250000 ou 1000000 no modo exaustivo")
	reconCmd.Flags().IntVar(&reconRecursiveThreshold, "recursive-threshold", 0, "Densidade mínima para expansão recursiva; zero usa o padrão do modo")
	reconCmd.Flags().IntVar(&reconAssetLimit, "asset-limit", 0, "Assets da mesma origem por página; zero usa 4 ou 12 no modo exaustivo")
	reconCmd.Flags().BoolVar(&reconResume, "resume", true, "Retomar a última execução interrompida")
	reconCmd.Flags().StringVar(&reconFormat, "format", "text", "Formato: text, sources, json ou jsonl")
	reconCmd.Flags().StringSliceVar(&reconInclude, "include", nil, "Incluir unresolved, wildcards ou all")
	reconCmd.Flags().BoolVar(&reconJSON, "json", false, "Exibir resultado em JSON")
	reconCmd.Flags().BoolVar(&reconJSONL, "jsonl", false, "Exibir um candidato JSON por linha")
	reconCmd.Flags().BoolVar(&reconShowUnresolved, "show-unresolved", false, "Incluir nomes observados que não resolvem no momento")
	reconCmd.Flags().BoolVar(&reconShowSources, "show-sources", false, "Acrescentar as fontes à saída textual")
	reconCmd.Flags().BoolVar(&reconShowWildcards, "show-wildcards", false, "Incluir nomes observados que coincidem com wildcard DNS")
	for _, name := range []string{
		"max-rounds", "max-depth", "max-candidates", "max-tested", "recursive-threshold", "asset-limit",
		"json", "jsonl", "show-unresolved", "show-sources", "show-wildcards",
	} {
		if err := reconCmd.Flags().MarkHidden(name); err != nil {
			panic(err)
		}
	}
}
