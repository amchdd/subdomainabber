package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/amchdd/subdomainabber/internal/discovery"
	"github.com/amchdd/subdomainabber/internal/netclient"
	"github.com/amchdd/subdomainabber/internal/platform"
	"github.com/amchdd/subdomainabber/internal/storage"
	"github.com/amchdd/subdomainabber/pkg/config"
	"github.com/amchdd/subdomainabber/pkg/ratelimit"
	"github.com/spf13/cobra"
)

const (
	hackerOneAPI = "https://api.hackerone.com"
	intigritiAPI = "https://api.intigriti.com/external/researcher"
	bugcrowdAPI  = "https://api.bugcrowd.com"
)

var (
	syncPlatforms          []string
	syncIncremental        bool
	syncResume             bool
	syncScan               bool
	syncReconMode          string
	syncReconConcurrency   int
	syncReconRounds        int
	syncReconDepth         int
	syncReconLimit         int
	syncRecursiveThreshold int
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sincroniza programas, expande escopos e varre o catálogo local",
	RunE: func(command *cobra.Command, _ []string) error {
		cfg, err := loadRuntimeCommandConfig()
		if err != nil {
			return fmt.Errorf("configuração de execução inválida: %w", err)
		}
		ctx := commandContext(command)
		store, err := storage.New(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("abrindo catálogo SQLite: %w", err)
		}
		defer store.Close()

		latest, err := store.LatestPlatformSync(ctx)
		if err != nil {
			return err
		}
		var runID, stage string
		var syncNote string
		full := !syncIncremental
		selected := append([]string(nil), syncPlatforms...)
		if syncResume && latest != nil && latest.Status == "RUNNING" {
			runID, stage, full = latest.ID, latest.Stage, latest.Full
			syncNote = latest.LastError
			selected = append([]string(nil), latest.Platforms...)
			if !cfg.Silent {
				fmt.Fprintf(os.Stderr, "retomando sincronização %s na etapa %s\n", runID, strings.ToLower(stage))
			}
		}

		if runID == "" || stage == "CATALOG" {
			syncLog(cfg.Silent, "atualizando catálogo das plataformas")
			apiLimiter := ratelimit.New(cfg.RateLimit)
			apiHTTP, err := netclient.NewScopedClient(time.Duration(cfg.Timeout)*time.Second, cfg.Proxy, apiLimiter)
			if err != nil {
				return fmt.Errorf("configurando cliente das plataformas: %w", err)
			}
			clients, missing, err := platformClients(cfg, apiHTTP, selected)
			if err != nil {
				return err
			}
			if len(clients) == 0 {
				return fmt.Errorf("nenhuma plataforma possui credenciais configuradas")
			}
			if !cfg.Silent && len(missing) > 0 {
				fmt.Fprintf(os.Stderr, "plataformas ignoradas por falta de credenciais: %s\n", strings.Join(missing, ", "))
			}
			if runID == "" {
				names := make([]string, 0, len(clients))
				for _, client := range clients {
					names = append(names, client.Name())
				}
				runID, err = store.StartPlatformSync(names, full)
				if err != nil {
					return err
				}
			}
			if err := syncPrograms(ctx, store, runID, clients); err != nil {
				return err
			}
			syncLog(cfg.Silent, "catálogo atualizado")
			if err := store.SetPlatformSyncStage(runID, "RECON", ""); err != nil {
				return err
			}
			stage = "RECON"
		}

		if stage == "RECON" {
			requirements, err := store.ActivePlatformRules(ctx)
			if err != nil {
				return err
			}
			limit, _, warnings := requirementSettings(requirements)
			for _, warning := range warnings {
				if !cfg.Silent {
					fmt.Fprintln(os.Stderr, warning)
				}
			}
			reconConfig := *cfg
			if limit > 0 && limit < reconConfig.RateLimit {
				reconConfig.RateLimit = limit
			}
			options := discovery.Options{
				Mode:               discovery.Mode(syncReconMode),
				Concurrency:        syncReconConcurrency,
				MaxRounds:          syncReconRounds,
				MaxDepth:           syncReconDepth,
				MaxCandidates:      syncReconLimit,
				RecursiveThreshold: syncRecursiveThreshold,
			}
			if err := discovery.ValidateOptions(options); err != nil {
				return err
			}
			recon, err := newReconEngine(&reconConfig)
			if err != nil {
				return err
			}
			notes, err := expandPlatformAssets(ctx, recon, store, runID, options, cfg.Silent)
			if err != nil {
				return err
			}
			syncNote = strings.Join(notes, "\n")
			if err := store.SetPlatformSyncNote(runID, syncNote); err != nil {
				return err
			}
			if err := store.SetPlatformSyncStage(runID, "SCAN", ""); err != nil {
				return err
			}
			stage = "SCAN"
		}

		targets, err := store.PlatformTargets(ctx)
		if err != nil {
			return err
		}
		if !syncScan || len(targets) == 0 {
			return finishPlatformSync(store, runID, len(targets), syncNote, cfg.Silent)
		}
		syncLog(cfg.Silent, "iniciando varredura de %d alvo(s)", len(targets))
		if err := runPlatformScan(ctx, store, runID, latest, targets, cfg.Silent); err != nil {
			if ctx.Err() == nil {
				_ = store.FinishPlatformSync(runID, "FAILED", len(targets), err.Error())
			}
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		return finishPlatformSync(store, runID, len(targets), syncNote, cfg.Silent)
	},
}

func platformClients(cfg *config.Config, httpClient *http.Client, selected []string) ([]platform.Client, []string, error) {
	requested := make(map[string]struct{})
	all := len(selected) == 0
	for _, name := range selected {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "all" {
			all = true
			continue
		}
		if name != "hackerone" && name != "intigriti" && name != "bugcrowd" {
			return nil, nil, fmt.Errorf("plataforma desconhecida: %s", name)
		}
		requested[name] = struct{}{}
	}
	wanted := func(name string) bool {
		_, found := requested[name]
		return all || found
	}
	var clients []platform.Client
	var missing []string
	if wanted("hackerone") {
		if cfg.HackerOneUsername != "" && cfg.HackerOneToken != "" {
			clients = append(clients, platform.NewHackerOne(httpClient, hackerOneAPI, cfg.HackerOneUsername, cfg.HackerOneToken))
		} else {
			missing = append(missing, "hackerone")
		}
	}
	if wanted("intigriti") {
		if cfg.IntigritiToken != "" {
			clients = append(clients, platform.NewIntigriti(httpClient, intigritiAPI, cfg.IntigritiToken))
		} else {
			missing = append(missing, "intigriti")
		}
	}
	if wanted("bugcrowd") {
		if cfg.BugcrowdToken != "" {
			clients = append(clients, platform.NewBugcrowd(httpClient, bugcrowdAPI, cfg.BugcrowdToken))
		} else {
			missing = append(missing, "bugcrowd")
		}
	}
	return clients, missing, nil
}

func syncPrograms(ctx context.Context, store *storage.Store, runID string, clients []platform.Client) error {
	type result struct {
		name     string
		programs []platform.Program
		err      error
	}
	results := make(chan result, len(clients))
	var group sync.WaitGroup
	for _, client := range clients {
		group.Add(1)
		go func(client platform.Client) {
			defer group.Done()
			programs, err := client.Programs(ctx)
			results <- result{name: client.Name(), programs: programs, err: err}
		}(client)
	}
	group.Wait()
	close(results)
	var loaded []result
	for item := range results {
		if item.err != nil {
			return fmt.Errorf("sincronizando %s: %w", item.name, item.err)
		}
		loaded = append(loaded, item)
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].name < loaded[j].name })
	for _, item := range loaded {
		if err := store.SavePlatformPrograms(runID, item.name, item.programs); err != nil {
			return err
		}
	}
	return nil
}

func expandPlatformAssets(ctx context.Context, runner reconRunner, store *storage.Store, runID string, options discovery.Options, silent bool) ([]string, error) {
	works, err := store.PendingPlatformAssets(ctx, runID)
	if err != nil {
		return nil, err
	}
	groups := make(map[string][]storage.PlatformWork)
	var roots []string
	for _, work := range works {
		if _, found := groups[work.Root]; !found {
			roots = append(roots, work.Root)
		}
		groups[work.Root] = append(groups[work.Root], work)
	}
	sort.Strings(roots)
	var notes []string
	for index, root := range roots {
		syncLog(silent, "recon %d/%d: %s", index+1, len(roots), root)
		for _, work := range groups[root] {
			_ = store.CompletePlatformAsset(work.ID, "RUNNING", "")
		}
		rootOptions := options
		var warnings []string
		rootOptions.Headers, warnings = workHeaders(groups[root])
		for _, warning := range warnings {
			syncLog(silent, "%s", warning)
		}
		result, _, err := runRecon(ctx, runner, store, root, rootOptions, true)
		if err != nil {
			for _, work := range groups[root] {
				_ = store.CompletePlatformAsset(work.ID, "FAILED", err.Error())
			}
			return notes, fmt.Errorf("recon de %s: %w", root, err)
		}
		if result.Partial {
			reason := strings.Join(result.Reasons, "; ")
			if reason == "" {
				reason = "resultado incompleto"
			}
			notes = append(notes, fmt.Sprintf("%s: %s", root, reason))
			syncLog(silent, "recon parcial de %s: %s", root, reason)
		}
		for _, work := range groups[root] {
			if err := store.SavePlatformTargets(work, result.Targets(), result.Partial); err != nil {
				return notes, err
			}
			if err := store.CompletePlatformAsset(work.ID, "COMPLETED", ""); err != nil {
				return notes, err
			}
		}
	}
	return notes, nil
}

func runPlatformScan(ctx context.Context, store *storage.Store, runID string, latest *storage.PlatformSync, targets []string, silent bool) error {
	requirements, err := store.PlatformTargetRules(ctx)
	if err != nil {
		return err
	}
	limit, headers, warnings := requirementSettings(requirements)
	for _, warning := range warnings {
		syncLog(silent, "%s", warning)
	}
	session := &scanSession{RateLimit: limit, TargetHeaders: headers}
	if latest != nil && latest.ID == runID && latest.Stage == "SCAN" && latest.ScanRunID != "" {
		pending, err := store.PendingTargets(ctx, latest.ScanRunID)
		if err != nil {
			return err
		}
		if len(pending) == 0 {
			return nil
		}
		session.RunID = latest.ScanRunID
		session.Resume = true
	} else {
		session.OnStart = func(scanRunID string) error {
			return store.SetPlatformSyncStage(runID, "SCAN", scanRunID)
		}
	}
	previousCheckAll := checkAll
	checkAll = true
	defer func() { checkAll = previousCheckAll }()
	err = runScan(ctx, targets, nil, session)
	return finishScanSession(ctx, session, err)
}

func workHeaders(works []storage.PlatformWork) (http.Header, []string) {
	if len(works) == 0 {
		return nil, nil
	}
	var requirements []storage.PlatformRequirement
	for _, work := range works {
		requirements = append(requirements, storage.PlatformRequirement{
			Target: work.Root,
			Rules: platform.Rules{
				AutomatedTooling: work.AutomatedTooling,
				UserAgent:        work.UserAgent,
				RequestHeader:    work.RequestHeader,
			},
		})
	}
	_, headers, warnings := requirementSettings(requirements)
	return headers[works[0].Root], warnings
}

func finishPlatformSync(store *storage.Store, runID string, count int, note string, silent bool) error {
	status := "COMPLETED"
	description := "concluída"
	if note != "" {
		status = "PARTIAL"
		description = "concluída parcialmente"
	}
	if err := store.FinishPlatformSync(runID, status, count, note); err != nil {
		return err
	}
	syncLog(silent, "sincronização %s %s: %d alvo(s) ativos", runID, description, count)
	return nil
}

func syncLog(silent bool, format string, arguments ...any) {
	if !silent {
		fmt.Fprintf(os.Stderr, format+"\n", arguments...)
	}
}

func requirementSettings(requirements []storage.PlatformRequirement) (int, map[string]http.Header, []string) {
	limit := 0
	headers := make(map[string]http.Header)
	var warnings []string
	for _, requirement := range requirements {
		rules := requirement.Rules
		if rules.AutomatedTooling > 0 && (limit == 0 || rules.AutomatedTooling < limit) {
			limit = rules.AutomatedTooling
		}
		if requirement.Target == "" {
			continue
		}
		target := strings.ToLower(requirement.Target)
		if headers[target] == nil {
			headers[target] = make(http.Header)
		}
		if value := strings.TrimSpace(rules.UserAgent); value != "" {
			if current := headers[target].Get("User-Agent"); current != "" && current != value {
				warnings = append(warnings, fmt.Sprintf("requisitos de User-Agent conflitantes para %s; usando o primeiro valor", target))
			} else {
				headers[target].Set("User-Agent", value)
			}
		}
		for _, line := range strings.Split(strings.ReplaceAll(rules.RequestHeader, "\r\n", "\n"), "\n") {
			name, value, found := strings.Cut(line, ":")
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if !found || name == "" || value == "" {
				if strings.TrimSpace(line) != "" {
					warnings = append(warnings, fmt.Sprintf("header obrigatório inválido para %s: %q", target, strings.TrimSpace(line)))
				}
				continue
			}
			if current := headers[target].Get(name); current != "" && current != value {
				warnings = append(warnings, fmt.Sprintf("valores conflitantes de %s para %s; usando o primeiro", http.CanonicalHeaderKey(name), target))
				continue
			}
			headers[target].Set(name, value)
		}
	}
	return limit, headers, warnings
}

type targetHeaderTransport struct {
	base    http.RoundTripper
	headers map[string]http.Header
}

func (transport targetHeaderTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := transport.base
	if base == nil {
		base = http.DefaultTransport
	}
	values := transport.headers[strings.ToLower(request.URL.Hostname())]
	if values == nil {
		return base.RoundTrip(request)
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	for name, entries := range values {
		clone.Header.Del(name)
		for _, value := range entries {
			clone.Header.Add(name, value)
		}
	}
	return base.RoundTrip(clone)
}

func setTargetHeaders(client *http.Client, session *scanSession) {
	if client == nil || session == nil || len(session.TargetHeaders) == 0 {
		return
	}
	client.Transport = targetHeaderTransport{base: client.Transport, headers: session.TargetHeaders}
}

func init() {
	rootCmd.AddCommand(syncCmd)
	syncCmd.Flags().StringSliceVar(&syncPlatforms, "platform", []string{"all"}, "Plataformas: hackerone, intigriti, bugcrowd ou all")
	syncCmd.Flags().BoolVar(&syncIncremental, "incremental", false, "Expandir somente escopos novos ou alterados")
	syncCmd.Flags().BoolVar(&syncResume, "resume", true, "Retomar a sincronização interrompida")
	syncCmd.Flags().BoolVar(&syncScan, "scan", true, "Executar a varredura completa após sincronizar")
	syncCmd.Flags().StringVar(&syncReconMode, "recon-mode", string(discovery.ModeExhaustive), "Modo de recon: passive, standard ou exhaustive")
	syncCmd.Flags().IntVar(&syncReconConcurrency, "recon-concurrency", 50, "Consultas DNS simultâneas no recon")
	syncCmd.Flags().IntVar(&syncReconRounds, "recon-rounds", 4, "Máximo de rodadas recursivas")
	syncCmd.Flags().IntVar(&syncReconDepth, "recon-depth", 5, "Profundidade máxima de labels")
	syncCmd.Flags().IntVar(&syncReconLimit, "recon-limit", 250000, "Limite de nomes por raiz")
	syncCmd.Flags().IntVar(&syncRecursiveThreshold, "recursive-threshold", 2, "Densidade mínima para expansão recursiva")
}
