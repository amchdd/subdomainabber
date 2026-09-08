package discovery

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/amchdd/subdomainabber/internal/core"
	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/config"
	"github.com/amchdd/subdomainabber/pkg/passive"
)

type Mode string

const (
	ModePassive    Mode = "passive"
	ModeStandard   Mode = "standard"
	ModeExhaustive Mode = "exhaustive"
)

type Source = passive.Provider
type Candidate = core.ReconCandidate
type Origin = core.ReconOrigin
type DNSRecord = core.ReconDNSRecord
type Checkpoint = core.ReconCheckpoint

type SourceRun = core.ReconSourceRun

type Result struct {
	Root       string      `json:"root"`
	Mode       Mode        `json:"mode"`
	Names      []Candidate `json:"names"`
	Sources    []SourceRun `json:"sources"`
	Rounds     int         `json:"rounds"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
	Partial    bool        `json:"partial,omitempty"`
	Reasons    []string    `json:"partial_reasons,omitempty"`
	Stats      Stats       `json:"stats"`
}

type Stats struct {
	Observed         int            `json:"observed"`
	NamesTested      int            `json:"names_tested"`
	Resolved         int            `json:"resolved"`
	Unresolved       int            `json:"unresolved"`
	WildcardFiltered int            `json:"wildcard_filtered"`
	Methods          map[string]int `json:"methods,omitempty"`
}

type State struct {
	Candidates []Candidate `json:"candidates"`
	Checkpoint Checkpoint  `json:"checkpoint"`
	Sources    []SourceRun `json:"sources,omitempty"`
}

func (result Result) Find(name string) (Candidate, bool) {
	name = normalizeName(name)
	for _, candidate := range result.Names {
		if candidate.Name == name {
			return candidate, true
		}
	}
	return Candidate{}, false
}

func (result Result) Targets() []string {
	targets := make([]string, 0, len(result.Names))
	for _, candidate := range result.Names {
		if candidate.Name != result.Root && candidate.Resolved && !candidate.Wildcard {
			targets = append(targets, candidate.Name)
		}
	}
	return targets
}

func (result Result) Inventory() []string {
	names := make([]string, 0, len(result.Names))
	for _, candidate := range result.Names {
		if candidate.Name != result.Root && !candidate.Wildcard {
			names = append(names, candidate.Name)
		}
	}
	return names
}

type Options struct {
	Mode               Mode
	Concurrency        int
	Words              []string
	MaxRounds          int
	MaxDepth           int
	MaxCandidates      int
	MaxTested          int
	RecursiveThreshold int
	ScrapeLimit        int
	AssetLimit         int
	Resume             *State
	Progress           func(State) error
	Headers            http.Header
}

type dnsLookup interface {
	ResolveA(context.Context, string) ([]string, error)
	ResolveAAAA(context.Context, string) ([]string, error)
	ResolveCNAME(context.Context, string) ([]string, error)
	ResolveAddressStatus(context.Context, string) core.DNSStatus
	IsWildcard(context.Context, string) (bool, dns.WildcardSignature, error)
	ResolveMX(context.Context, string) ([]string, error)
	LookupNS(context.Context, string) ([]string, error)
	ResolveSRV(context.Context, string) ([]string, error)
}

type zoneLookup interface {
	TransferZone(context.Context, string, string) ([]string, error)
}

type ptrLookup interface {
	ResolveAddressPTR(context.Context, string) ([]string, error)
}

type seed struct {
	name   string
	origin Origin
	keep   bool
}

type ptrAddress struct {
	address string
	parents []string
}

type modeLimits struct {
	rounds     int
	depth      int
	candidates int
	tested     int
	recursive  int
	assets     int
}

func limitsFor(mode Mode) modeLimits {
	switch mode {
	case ModePassive:
		return modeLimits{depth: 20, candidates: 250000, tested: 250000, recursive: 2, assets: 4}
	case ModeExhaustive:
		return modeLimits{rounds: 4, depth: 12, candidates: 1000000, tested: 1000000, recursive: 2, assets: 12}
	default:
		return modeLimits{rounds: 1, depth: 6, candidates: 250000, tested: 250000, recursive: 3, assets: 4}
	}
}

func (options Options) normalized() (Options, error) {
	if options.Mode == "" {
		options.Mode = ModeStandard
	}
	if options.Mode != ModePassive && options.Mode != ModeStandard && options.Mode != ModeExhaustive {
		return options, fmt.Errorf("modo de recon inválido: %s", options.Mode)
	}
	if options.Concurrency == 0 {
		options.Concurrency = 50
	}
	if err := config.ValidateEnumerationConcurrency(options.Concurrency); err != nil {
		return options, err
	}
	limits := limitsFor(options.Mode)
	if options.MaxRounds == 0 {
		options.MaxRounds = limits.rounds
	}
	if options.MaxRounds < 0 || options.MaxRounds > 12 {
		return options, fmt.Errorf("max-rounds deve estar entre 0 e 12")
	}
	if options.Mode == ModePassive {
		options.MaxRounds = 0
	}
	if options.MaxDepth == 0 {
		options.MaxDepth = limits.depth
	}
	if options.MaxDepth < 1 || options.MaxDepth > 20 {
		return options, fmt.Errorf("max-depth deve estar entre 1 e 20")
	}
	if options.MaxCandidates == 0 {
		options.MaxCandidates = limits.candidates
	}
	if options.MaxCandidates < 1 || options.MaxCandidates > 5000000 {
		return options, fmt.Errorf("max-candidates deve estar entre 1 e 5000000")
	}
	if options.MaxTested == 0 {
		options.MaxTested = limits.tested
	}
	if options.MaxTested < 1 || options.MaxTested > 20000000 {
		return options, fmt.Errorf("max-tested deve estar entre 1 e 20000000")
	}
	if options.RecursiveThreshold == 0 {
		options.RecursiveThreshold = limits.recursive
	}
	if options.RecursiveThreshold < 1 || options.RecursiveThreshold > 1000 {
		return options, fmt.Errorf("recursive-threshold deve estar entre 1 e 1000")
	}
	if options.ScrapeLimit == 0 {
		options.ScrapeLimit = 2000
	}
	if options.ScrapeLimit < 0 {
		return options, fmt.Errorf("o limite de páginas não pode ser negativo")
	}
	if options.AssetLimit == 0 {
		options.AssetLimit = limits.assets
	}
	if options.AssetLimit < 0 || options.AssetLimit > 64 {
		return options, fmt.Errorf("asset-limit deve estar entre 0 e 64")
	}
	if len(options.Words) == 0 {
		options.Words = DefaultWords(options.Mode)
	}
	options.Words = cleanWords(options.Words)
	return options, nil
}

func ValidateOptions(options Options) error {
	_, err := options.normalized()
	return err
}

func (engine *Engine) Discover(ctx context.Context, root string, options Options) (Result, error) {
	started := time.Now().UTC()
	root, err := domainutil.NormalizeHostname(root)
	if err != nil {
		return Result{}, fmt.Errorf("domínio de recon inválido: %w", err)
	}
	options, err = options.normalized()
	if err != nil {
		return Result{}, err
	}
	result := Result{Root: root, Mode: options.Mode, StartedAt: started}
	candidates := make(map[string]Candidate)
	wildcards := make(map[string]dns.WildcardSignature)
	attempted := make(map[string]struct{})
	wildcardFiltered := 0
	var frontier []Candidate
	startRound := 1
	if options.Resume != nil {
		mergeCandidates(candidates, options.Resume.Candidates, options.MaxCandidates)
		for _, name := range options.Resume.Checkpoint.Attempted {
			if name = normalizeName(name); name != "" {
				attempted[name] = struct{}{}
			}
		}
		for name := range candidates {
			attempted[name] = struct{}{}
		}
		frontier = restoreFrontier(candidates, options.Resume.Checkpoint.Frontier)
		result.Sources = append([]SourceRun(nil), options.Resume.Sources...)
		result.Rounds = options.Resume.Checkpoint.Round
		startRound = result.Rounds + 1
	} else {
		limit := minInt(options.MaxCandidates-1, options.MaxTested-1)
		seeds, sources := engine.passiveSeeds(ctx, root, limit)
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		result.Sources = sources
		seeds = append([]seed{{name: root, keep: true, origin: Origin{Source: "escopo", Method: "seed"}}}, seeds...)
		markSeeds(attempted, seeds, root, options.MaxDepth)
		initial, filtered := engine.resolveSeeds(ctx, root, seeds, options, wildcards)
		wildcardFiltered += filtered
		frontier = mergeCandidates(candidates, initial, options.MaxCandidates)
		wildcardFiltered += engine.addDNSSeeds(ctx, root, candidates, &frontier, attempted, options, wildcards)
		wildcardFiltered += engine.addZoneSeeds(ctx, root, candidates, &frontier, attempted, options, wildcards)
		wildcardFiltered += engine.addPTRSeeds(ctx, root, candidates, &frontier, attempted, options, wildcards)
		if err := reportProgress(options.Progress, candidates, attempted, 0, frontier, result.Sources); err != nil {
			return Result{}, err
		}
	}

	for round := startRound; round <= options.MaxRounds && len(frontier) > 0 && len(candidates) < options.MaxCandidates && len(attempted) < options.MaxTested; round++ {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		words := append([]string(nil), options.Words...)
		if options.Mode == ModeExhaustive {
			words = cleanWords(append(words, learnedWords(candidates)...))
		}
		budget := minInt(options.MaxCandidates-len(candidates), options.MaxTested-len(attempted))
		var generated []seed
		if options.Mode != ModePassive && engine.client != nil {
			generated = engine.scrapeSeeds(ctx, root, frontier, options, budget)
			mergeSeedOrigins(candidates, generated)
			generated = unseenSeeds(generated, attempted, budget, root, options.MaxDepth)
		}
		remaining := budget - len(generated)
		if remaining > 0 {
			seeds := generateSeeds(root, frontier, candidates, attempted, words, options, remaining)
			generated = append(generated, unseenSeeds(seeds, attempted, remaining, root, options.MaxDepth)...)
		}
		resolved, filtered := engine.resolveSeeds(ctx, root, generated, options, wildcards)
		wildcardFiltered += filtered
		frontier = mergeCandidates(candidates, resolved, options.MaxCandidates)
		wildcardFiltered += engine.addCNAMESeeds(ctx, root, candidates, &frontier, attempted, options, wildcards)
		wildcardFiltered += engine.addPTRSeeds(ctx, root, candidates, &frontier, attempted, options, wildcards)
		result.Rounds = round
		if err := reportProgress(options.Progress, candidates, attempted, round, frontier, result.Sources); err != nil {
			return Result{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	result.Names = sortedCandidates(candidates)
	result.Stats = reconStats(result, len(attempted), wildcardFiltered)
	result.Reasons = partialReasons(result.Sources, len(result.Names), options.MaxCandidates, len(attempted), options.MaxTested)
	result.Partial = len(result.Reasons) > 0
	result.FinishedAt = time.Now().UTC()
	return result, nil
}

func restoreFrontier(catalog map[string]Candidate, names []string) []Candidate {
	frontier := make([]Candidate, 0, len(names))
	for _, name := range names {
		if candidate, found := catalog[normalizeName(name)]; found {
			frontier = append(frontier, candidate)
		}
	}
	return frontier
}

func unseenSeeds(seeds []seed, attempted map[string]struct{}, limit int, root string, maxDepth int) []seed {
	result := make([]seed, 0, len(seeds))
	for _, item := range seeds {
		if len(result) >= limit {
			break
		}
		name := normalizeName(item.name)
		if name == "" || !belongsToDomain(name, root) || nameDepth(name, root) > maxDepth {
			continue
		}
		if _, found := attempted[name]; found {
			continue
		}
		attempted[name] = struct{}{}
		result = append(result, item)
	}
	return result
}

func markSeeds(attempted map[string]struct{}, seeds []seed, root string, maxDepth int) {
	for _, item := range seeds {
		if name := normalizeName(item.name); name != "" && belongsToDomain(name, root) && nameDepth(name, root) <= maxDepth {
			attempted[name] = struct{}{}
		}
	}
}

func mergeSeedOrigins(catalog map[string]Candidate, seeds []seed) {
	for _, item := range seeds {
		name := normalizeName(item.name)
		candidate, found := catalog[name]
		if !found {
			continue
		}
		candidate.Origins = appendOrigin(candidate.Origins, item.origin)
		if item.origin.Method == "axfr" {
			candidate.Wildcard = false
		}
		catalog[name] = candidate
	}
}

func reportProgress(callback func(State) error, catalog map[string]Candidate, attempted map[string]struct{}, round int, frontier []Candidate, sources []SourceRun) error {
	if callback == nil {
		return nil
	}
	names := make([]string, 0, len(frontier))
	for _, candidate := range frontier {
		names = append(names, candidate.Name)
	}
	sort.Strings(names)
	tested := make([]string, 0, len(attempted))
	for name := range attempted {
		tested = append(tested, name)
	}
	sort.Strings(tested)
	state := State{
		Candidates: sortedCandidates(catalog),
		Checkpoint: Checkpoint{Round: round, Frontier: names, Attempted: tested},
		Sources:    append([]SourceRun(nil), sources...),
	}
	if err := callback(state); err != nil {
		return fmt.Errorf("persistindo progresso do recon: %w", err)
	}
	return nil
}

func (engine *Engine) passiveSeeds(ctx context.Context, root string, limit int) ([]seed, []SourceRun) {
	if len(engine.providers) == 0 {
		return nil, nil
	}
	if limit < 0 {
		limit = 0
	}
	type stream struct {
		provider Source
		names    chan string
		errors   chan error
	}
	streams := make([]stream, 0, len(engine.providers))
	for _, provider := range engine.providers {
		current := stream{provider: provider, names: make(chan string, 256), errors: make(chan error, 1)}
		streams = append(streams, current)
		go func(current stream) {
			current.errors <- current.provider.Enumerate(ctx, root, current.names)
			close(current.names)
		}(current)
	}

	type sourceSeeds struct {
		run   SourceRun
		items []seed
	}
	collected := make([]sourceSeeds, 0, len(streams))
	for _, current := range streams {
		run := SourceRun{Name: current.provider.Name()}
		seen := make(map[string]struct{})
		var items []seed
		for name := range current.names {
			name = normalizeName(name)
			if !belongsToDomain(name, root) {
				continue
			}
			if _, found := seen[name]; found {
				continue
			}
			seen[name] = struct{}{}
			run.Count++
			items = append(items, seed{
				name:   name,
				keep:   true,
				origin: Origin{Source: current.provider.Name(), Method: "passive", Depth: nameDepth(name, root)},
			})
		}
		if err := <-current.errors; err != nil {
			run.Error = err.Error()
		}
		collected = append(collected, sourceSeeds{run: run, items: items})
	}

	selected := make(map[string]struct{}, limit)
	positions := make([]int, len(collected))
	for len(selected) < limit {
		progressed := false
		for index := range collected {
			for positions[index] < len(collected[index].items) {
				item := collected[index].items[positions[index]]
				positions[index]++
				if _, found := selected[item.name]; found {
					continue
				}
				selected[item.name] = struct{}{}
				progressed = true
				break
			}
			if len(selected) >= limit {
				break
			}
		}
		if !progressed {
			break
		}
	}

	runs := make([]SourceRun, 0, len(collected))
	var seeds []seed
	for _, source := range collected {
		for _, item := range source.items {
			if _, found := selected[item.name]; found {
				seeds = append(seeds, item)
			} else {
				source.run.Truncated = true
			}
		}
		runs = append(runs, source.run)
	}
	return seeds, runs
}

func partialReasons(sources []SourceRun, count, limit, tested, queryLimit int) []string {
	var reasons []string
	for _, source := range sources {
		if source.Error != "" {
			reasons = append(reasons, "falha na fonte "+source.Name)
		}
		if source.Truncated {
			reasons = append(reasons, "limite atingido na fonte "+source.Name)
		}
	}
	if limit > 0 && count >= limit {
		reasons = append(reasons, fmt.Sprintf("limite global de %d nomes atingido", limit))
	}
	if queryLimit > 0 && tested >= queryLimit {
		reasons = append(reasons, fmt.Sprintf("limite de %d nomes testados atingido", queryLimit))
	}
	return reasons
}

func reconStats(result Result, tested, filtered int) Stats {
	stats := Stats{
		NamesTested:      tested,
		WildcardFiltered: filtered,
		Methods:          make(map[string]int),
	}
	for _, candidate := range result.Names {
		if candidate.Name != result.Root {
			stats.Observed++
			if candidate.Resolved {
				stats.Resolved++
			} else {
				stats.Unresolved++
			}
		}
		seen := make(map[string]struct{})
		for _, origin := range candidate.Origins {
			if origin.Method == "" {
				continue
			}
			if _, found := seen[origin.Method]; found {
				continue
			}
			seen[origin.Method] = struct{}{}
			stats.Methods[origin.Method]++
		}
	}
	return stats
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func (engine *Engine) resolveSeeds(ctx context.Context, root string, seeds []seed, options Options, wildcards map[string]dns.WildcardSignature) ([]Candidate, int) {
	grouped := make(map[string][]seed)
	for _, item := range seeds {
		name := normalizeName(item.name)
		if name == "" || !belongsToDomain(name, root) || nameDepth(name, root) > options.MaxDepth {
			continue
		}
		item.name = name
		grouped[name] = append(grouped[name], item)
	}
	if len(grouped) == 0 || engine.resolver == nil {
		return nil, 0
	}

	type resolution struct {
		candidate *Candidate
		wildcard  bool
	}
	jobs := make(chan string)
	results := make(chan resolution, options.Concurrency)
	var group sync.WaitGroup
	var wildcardMu sync.Mutex
	for worker := 0; worker < options.Concurrency; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for name := range jobs {
				record := engine.resolve(ctx, name)
				resolved := len(record.A) > 0 || len(record.AAAA) > 0 || len(record.CNAME) > 0 || record.Status == core.DNSStatusResolved
				wildcard := resolved && engine.matchesWildcard(ctx, root, name, record, wildcards, &wildcardMu)
				keep := false
				explicit := false
				origins := make([]Origin, 0, len(grouped[name]))
				for _, item := range grouped[name] {
					keep = keep || item.keep
					explicit = explicit || item.origin.Method == "axfr"
					origins = appendOrigin(origins, item.origin)
				}
				if wildcard {
					if keep {
						candidate := Candidate{
							Name: name, Root: root, Resolved: true, Wildcard: !explicit, DNS: record, Origins: origins,
						}
						results <- resolution{candidate: &candidate, wildcard: !explicit}
					} else {
						results <- resolution{wildcard: true}
					}
				} else if resolved || keep {
					candidate := Candidate{Name: name, Root: root, Resolved: resolved, DNS: record, Origins: origins}
					results <- resolution{candidate: &candidate}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for name := range grouped {
			select {
			case <-ctx.Done():
				return
			case jobs <- name:
			}
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()

	candidates := make([]Candidate, 0, len(grouped))
	filtered := 0
	for result := range results {
		if result.wildcard {
			filtered++
		}
		if result.candidate != nil {
			candidates = append(candidates, *result.candidate)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	return candidates, filtered
}

func (engine *Engine) resolve(ctx context.Context, name string) DNSRecord {
	a, _ := engine.resolver.ResolveA(ctx, name)
	aaaa, _ := engine.resolver.ResolveAAAA(ctx, name)
	cnames, _ := engine.resolver.ResolveCNAME(ctx, name)
	return DNSRecord{
		A:      uniqueSorted(a),
		AAAA:   uniqueSorted(aaaa),
		CNAME:  normalizeNames(cnames),
		Status: engine.resolver.ResolveAddressStatus(ctx, name),
	}
}

func (engine *Engine) matchesWildcard(ctx context.Context, root, name string, record DNSRecord, cache map[string]dns.WildcardSignature, mu *sync.Mutex) bool {
	if engine.noWildcardFilter {
		return false
	}
	for parent := parentName(name); parent != "" && belongsToDomain(parent, root); parent = parentName(parent) {
		mu.Lock()
		signature, found := cache[parent]
		mu.Unlock()
		if !found {
			_, signature, _ = engine.resolver.IsWildcard(ctx, parent)
			mu.Lock()
			cache[parent] = signature
			mu.Unlock()
		}
		if matchesSignature(record, signature) {
			return true
		}
		if parent == root {
			break
		}
	}
	return false
}

func matchesSignature(record DNSRecord, signature dns.WildcardSignature) bool {
	if signature.Empty() {
		return false
	}
	matched := false
	if len(record.A) > 0 {
		matched = true
		if !signature.MatchesA(record.A) {
			return false
		}
	}
	if len(record.AAAA) > 0 {
		matched = true
		if !signature.MatchesAAAA(record.AAAA) {
			return false
		}
	}
	if len(record.CNAME) > 0 {
		matched = true
		if !signature.MatchesCNAME(record.CNAME) {
			return false
		}
	}
	return matched
}

func mergeCandidates(catalog map[string]Candidate, incoming []Candidate, limit int) []Candidate {
	var added []Candidate
	for _, candidate := range incoming {
		if current, found := catalog[candidate.Name]; found {
			becameResolved := !current.Resolved && candidate.Resolved
			if !current.Resolved {
				current.Wildcard = candidate.Wildcard
			} else if candidate.Resolved {
				current.Wildcard = current.Wildcard && candidate.Wildcard
			}
			current.Resolved = current.Resolved || candidate.Resolved
			current.DNS = mergeRecords(current.DNS, candidate.DNS)
			for _, origin := range candidate.Origins {
				current.Origins = appendOrigin(current.Origins, origin)
			}
			catalog[candidate.Name] = current
			if becameResolved {
				added = append(added, current)
			}
			continue
		}
		if len(catalog) >= limit {
			break
		}
		catalog[candidate.Name] = candidate
		added = append(added, candidate)
	}
	return added
}

func mergeRecords(left, right DNSRecord) DNSRecord {
	left.A = uniqueSorted(append(left.A, right.A...))
	left.AAAA = uniqueSorted(append(left.AAAA, right.AAAA...))
	left.CNAME = normalizeNames(append(left.CNAME, right.CNAME...))
	if left.Status == "" || right.Status == core.DNSStatusResolved {
		left.Status = right.Status
	}
	return left
}

func appendOrigin(origins []Origin, origin Origin) []Origin {
	for _, current := range origins {
		if current == origin {
			return origins
		}
	}
	return append(origins, origin)
}

func (engine *Engine) addDNSSeeds(ctx context.Context, root string, catalog map[string]Candidate, frontier *[]Candidate, attempted map[string]struct{}, options Options, wildcards map[string]dns.WildcardSignature) int {
	if options.Mode == ModePassive || engine.resolver == nil {
		return 0
	}
	var seeds []seed
	if names, err := engine.resolver.ResolveMX(ctx, root); err == nil {
		for _, name := range names {
			seeds = append(seeds, dnsSeed(name, root, "mx"))
		}
	}
	if names, err := engine.resolver.LookupNS(ctx, root); err == nil {
		for _, name := range names {
			seeds = append(seeds, dnsSeed(name, root, "ns"))
		}
	}
	for _, service := range commonServices {
		owner := service + "." + root
		values, err := engine.resolver.ResolveSRV(ctx, owner)
		if err != nil {
			continue
		}
		for _, value := range values {
			name := value
			if index := strings.LastIndex(value, ":"); index > 0 {
				name = value[:index]
			}
			seeds = append(seeds, dnsSeed(name, root, "srv"))
		}
	}
	limit := minInt(options.MaxCandidates-len(catalog), options.MaxTested-len(attempted))
	mergeSeedOrigins(catalog, seeds)
	seeds = unseenSeeds(seeds, attempted, limit, root, options.MaxDepth)
	resolved, filtered := engine.resolveSeeds(ctx, root, seeds, options, wildcards)
	*frontier = append(*frontier, mergeCandidates(catalog, resolved, options.MaxCandidates)...)
	return filtered
}

func dnsSeed(name, root, method string) seed {
	name = normalizeName(name)
	return seed{
		name:   name,
		keep:   true,
		origin: Origin{Source: "dns", Method: method, Parent: root, Depth: nameDepth(name, root)},
	}
}

func (engine *Engine) addZoneSeeds(ctx context.Context, root string, catalog map[string]Candidate, frontier *[]Candidate, attempted map[string]struct{}, options Options, wildcards map[string]dns.WildcardSignature) int {
	transfer, supported := engine.resolver.(zoneLookup)
	if !supported || options.Mode != ModeExhaustive {
		return 0
	}
	nameservers, err := engine.resolver.LookupNS(ctx, root)
	if err != nil {
		return 0
	}
	var seeds []seed
	for _, nameserver := range nameservers {
		names, transferErr := transfer.TransferZone(ctx, root, nameserver)
		if transferErr != nil || len(names) == 0 {
			continue
		}
		for _, name := range names {
			seeds = append(seeds, seed{
				name: name,
				keep: true,
				origin: Origin{
					Source: "dns", Method: "axfr", Parent: normalizeName(nameserver), Depth: nameDepth(name, root),
				},
			})
		}
		break
	}
	limit := minInt(options.MaxCandidates-len(catalog), options.MaxTested-len(attempted))
	mergeSeedOrigins(catalog, seeds)
	seeds = unseenSeeds(seeds, attempted, limit, root, options.MaxDepth)
	resolved, filtered := engine.resolveSeeds(ctx, root, seeds, options, wildcards)
	*frontier = append(*frontier, mergeCandidates(catalog, resolved, options.MaxCandidates)...)
	return filtered
}

func (engine *Engine) addCNAMESeeds(ctx context.Context, root string, catalog map[string]Candidate, frontier *[]Candidate, attempted map[string]struct{}, options Options, wildcards map[string]dns.WildcardSignature) int {
	var seeds []seed
	for _, candidate := range *frontier {
		for _, target := range candidate.DNS.CNAME {
			if belongsToDomain(target, root) {
				seeds = append(seeds, seed{
					name:   target,
					keep:   true,
					origin: Origin{Source: "dns", Method: "cname", Parent: candidate.Name, Depth: nameDepth(target, root)},
				})
			}
		}
	}
	limit := minInt(options.MaxCandidates-len(catalog), options.MaxTested-len(attempted))
	mergeSeedOrigins(catalog, seeds)
	seeds = unseenSeeds(seeds, attempted, limit, root, options.MaxDepth)
	resolved, filtered := engine.resolveSeeds(ctx, root, seeds, options, wildcards)
	*frontier = append(*frontier, mergeCandidates(catalog, resolved, options.MaxCandidates)...)
	return filtered
}

func (engine *Engine) addPTRSeeds(ctx context.Context, root string, catalog map[string]Candidate, frontier *[]Candidate, attempted map[string]struct{}, options Options, wildcards map[string]dns.WildcardSignature) int {
	lookup, supported := engine.resolver.(ptrLookup)
	if !supported || options.Mode == ModePassive || len(*frontier) == 0 {
		return 0
	}
	seeds := ptrSeeds(ctx, lookup, root, ptrAddresses(*frontier), options.Concurrency)
	limit := minInt(options.MaxCandidates-len(catalog), options.MaxTested-len(attempted))
	mergeSeedOrigins(catalog, seeds)
	seeds = unseenSeeds(seeds, attempted, limit, root, options.MaxDepth)
	resolved, filtered := engine.resolveSeeds(ctx, root, seeds, options, wildcards)
	*frontier = append(*frontier, mergeCandidates(catalog, resolved, options.MaxCandidates)...)
	return filtered
}

func ptrAddresses(frontier []Candidate) []ptrAddress {
	positions := make(map[string]int)
	var addresses []ptrAddress
	for _, candidate := range frontier {
		for _, address := range append(append([]string(nil), candidate.DNS.A...), candidate.DNS.AAAA...) {
			if index, found := positions[address]; found {
				addresses[index].parents = append(addresses[index].parents, candidate.Name)
				continue
			}
			positions[address] = len(addresses)
			addresses = append(addresses, ptrAddress{address: address, parents: []string{candidate.Name}})
		}
	}
	return addresses
}

func ptrSeeds(ctx context.Context, lookup ptrLookup, root string, addresses []ptrAddress, concurrency int) []seed {
	jobs := make(chan ptrAddress)
	results := make(chan seed, concurrency)
	var group sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for item := range jobs {
				names, err := lookup.ResolveAddressPTR(ctx, item.address)
				if err != nil {
					continue
				}
				for _, name := range names {
					for _, parent := range item.parents {
						select {
						case <-ctx.Done():
							return
						case results <- seed{
							name: name, keep: true,
							origin: Origin{Source: "dns", Method: "ptr", Parent: parent, Depth: nameDepth(name, root)},
						}:
						}
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, item := range addresses {
			select {
			case <-ctx.Done():
				return
			case jobs <- item:
			}
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()
	var seeds []seed
	for item := range results {
		seeds = append(seeds, item)
	}
	return seeds
}

func generateSeeds(root string, frontier []Candidate, catalog map[string]Candidate, attempted map[string]struct{}, words []string, options Options, limit int) []seed {
	if limit <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	seeds := make([]seed, 0, len(words))
	add := func(name, method, parent string) {
		if len(seeds) >= limit {
			return
		}
		name = normalizeName(name)
		if name == "" || !belongsToDomain(name, root) || nameDepth(name, root) > options.MaxDepth {
			return
		}
		if _, found := catalog[name]; found {
			return
		}
		if _, found := attempted[name]; found {
			return
		}
		if _, found := seen[name]; found {
			return
		}
		seen[name] = struct{}{}
		seeds = append(seeds, seed{
			name:   name,
			origin: Origin{Source: "recon", Method: method, Parent: parent, Depth: nameDepth(name, root)},
		})
	}

	for _, word := range words {
		add(word+"."+root, "wordlist", root)
		if len(seeds) >= limit {
			return seeds
		}
	}
	recursive := recursiveZones(root, frontier, catalog, options.RecursiveThreshold)
	for _, word := range words {
		for _, zone := range recursive {
			add(word+"."+zone, "recursão", zone)
			if len(seeds) >= limit {
				return seeds
			}
		}
	}
	alterations := wordsForAlteration(words, learnedWords(catalog))
	for _, candidate := range frontier {
		if candidate.Name == root || candidate.Wildcard {
			continue
		}
		for _, name := range numericNames(candidate.Name) {
			add(name, "sequência", candidate.Name)
		}
		for _, name := range GenerateMutations(root, candidate.Name, alterations) {
			add(name, "alteração", candidate.Name)
			if len(seeds) >= limit {
				return seeds
			}
		}
	}
	return seeds
}

func recursiveZones(root string, frontier []Candidate, catalog map[string]Candidate, threshold int) []string {
	children := make(map[string]int)
	for name, candidate := range catalog {
		if !candidate.Wildcard {
			children[parentName(name)]++
		}
	}
	seen := make(map[string]struct{})
	var zones []string
	for _, candidate := range frontier {
		if candidate.Wildcard {
			continue
		}
		for zone := candidate.Name; zone != root && belongsToDomain(zone, root); zone = parentName(zone) {
			if _, found := seen[zone]; found {
				continue
			}
			if children[zone] < threshold && !(threshold == 1 && zone == candidate.Name) {
				continue
			}
			seen[zone] = struct{}{}
			zones = append(zones, zone)
		}
	}
	sort.Strings(zones)
	return zones
}

func numericNames(name string) []string {
	label, parent := firstLabel(name)
	index := len(label)
	for index > 0 && label[index-1] >= '0' && label[index-1] <= '9' {
		index--
	}
	if index == len(label) {
		return []string{
			label + "1." + parent,
			label + "2." + parent,
			label + "-1." + parent,
			label + "-2." + parent,
		}
	}
	if index == 0 {
		return nil
	}
	number, err := strconv.Atoi(label[index:])
	if err != nil {
		return nil
	}
	prefix := label[:index]
	width := len(label[index:])
	values := []int{number - 2, number - 1, number + 1, number + 2, 0, 1, 2, 3, 5, 10}
	seen := make(map[int]struct{})
	names := []string{strings.TrimSuffix(prefix, "-") + "." + parent}
	for _, next := range values {
		if next >= 0 {
			if _, found := seen[next]; found || next == number {
				continue
			}
			seen[next] = struct{}{}
			names = append(names, prefix+fmt.Sprintf("%0*d", width, next)+"."+parent)
		}
	}
	return names
}

func (engine *Engine) scrapeSeeds(ctx context.Context, root string, frontier []Candidate, options Options, limit int) []seed {
	if engine.client == nil || len(frontier) == 0 || limit <= 0 {
		return nil
	}
	jobs := make(chan string)
	results := make(chan seed, options.Concurrency)
	var group sync.WaitGroup
	for worker := 0; worker < options.Concurrency; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for name := range jobs {
				for _, scheme := range []string{"https", "http"} {
					found, err := crawlReferences(ctx, scheme+"://"+name, root, options.Headers, options.AssetLimit, engine.client)
					if err != nil {
						continue
					}
					for _, reference := range found {
						source := "html"
						method := "referência"
						switch reference.method {
						case "san":
							source = "tls"
							method = "san"
						case "script":
							method = "script"
						}
						select {
						case <-ctx.Done():
							return
						case results <- seed{
							name:   reference.name,
							keep:   true,
							origin: Origin{Source: source, Method: method, Parent: name, Depth: nameDepth(reference.name, root)},
						}:
						}
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		queued := 0
		for _, candidate := range frontier {
			if queued >= options.ScrapeLimit {
				break
			}
			if !candidate.Resolved || candidate.Wildcard {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case jobs <- candidate.Name:
				queued++
			}
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()

	seeds := make([]seed, 0, limit)
	seen := make(map[string]struct{}, limit)
	for item := range results {
		if len(seeds) >= limit {
			continue
		}
		name := normalizeName(item.name)
		if name == "" {
			continue
		}
		if _, found := seen[name]; found {
			continue
		}
		seen[name] = struct{}{}
		item.name = name
		seeds = append(seeds, item)
	}
	return seeds
}

func learnedWords(catalog map[string]Candidate) []string {
	var words []string
	for name, candidate := range catalog {
		if name == candidate.Root {
			continue
		}
		relative := strings.TrimSuffix(name, "."+candidate.Root)
		for _, part := range strings.FieldsFunc(relative, func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
			if validWord(part) {
				words = append(words, part)
			}
		}
		for _, cname := range candidate.DNS.CNAME {
			label, _ := firstLabel(cname)
			if validWord(label) {
				words = append(words, label)
			}
		}
	}
	words = cleanWords(words)
	sort.Strings(words)
	return words
}

func sortedCandidates(catalog map[string]Candidate) []Candidate {
	result := make([]Candidate, 0, len(catalog))
	for _, candidate := range catalog {
		sort.Slice(candidate.Origins, func(i, j int) bool {
			left := candidate.Origins[i]
			right := candidate.Origins[j]
			if left.Source != right.Source {
				return left.Source < right.Source
			}
			if left.Method != right.Method {
				return left.Method < right.Method
			}
			return left.Parent < right.Parent
		})
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func cleanWords(words []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(words))
	for _, word := range words {
		word = strings.ToLower(strings.TrimSpace(word))
		if !validWord(word) {
			continue
		}
		if _, found := seen[word]; found {
			continue
		}
		seen[word] = struct{}{}
		result = append(result, word)
	}
	return result
}

func validWord(word string) bool {
	if len(word) < 1 || len(word) > 63 || word[0] == '-' || word[len(word)-1] == '-' {
		return false
	}
	for _, character := range word {
		if !unicode.IsLower(character) && !unicode.IsDigit(character) && character != '-' {
			return false
		}
	}
	return true
}

func normalizeName(name string) string {
	name = strings.TrimPrefix(strings.TrimSpace(name), "*.")
	normalized, err := domainutil.NormalizeHostname(name)
	if err != nil {
		return ""
	}
	return normalized
}

func normalizeNames(names []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(names))
	for _, name := range names {
		name = normalizeName(name)
		if name == "" {
			continue
		}
		if _, found := seen[name]; found {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func nameDepth(name, root string) int {
	name = normalizeName(name)
	root = normalizeName(root)
	if name == "" || root == "" || name == root {
		return 0
	}
	prefix := strings.TrimSuffix(name, "."+root)
	if prefix == name {
		return 0
	}
	return len(strings.Split(prefix, "."))
}

func parentName(name string) string {
	if index := strings.IndexByte(name, '.'); index >= 0 && index+1 < len(name) {
		return name[index+1:]
	}
	return ""
}

func firstLabel(name string) (string, string) {
	if index := strings.IndexByte(name, '.'); index >= 0 {
		return name[:index], name[index+1:]
	}
	return name, ""
}

var commonServices = []string{
	"_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp", "_imap._tcp", "_imaps._tcp",
	"_pop3._tcp", "_pop3s._tcp", "_sip._tcp", "_sip._udp", "_smtp._tcp", "_xmpp-client._tcp",
}
