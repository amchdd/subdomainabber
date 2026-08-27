package discovery

import (
	"context"
	"fmt"
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

type SourceRun struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

type Result struct {
	Root       string      `json:"root"`
	Mode       Mode        `json:"mode"`
	Names      []Candidate `json:"names"`
	Sources    []SourceRun `json:"sources"`
	Rounds     int         `json:"rounds"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
}

type State struct {
	Candidates []Candidate `json:"candidates"`
	Checkpoint Checkpoint  `json:"checkpoint"`
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
		if !candidate.Wildcard {
			targets = append(targets, candidate.Name)
		}
	}
	return targets
}

type Options struct {
	Mode               Mode
	Concurrency        int
	Words              []string
	MaxRounds          int
	MaxDepth           int
	MaxCandidates      int
	RecursiveThreshold int
	ScrapeLimit        int
	Resume             *State
	Progress           func(State) error
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

type seed struct {
	name   string
	origin Origin
	keep   bool
}

type sourceHit struct {
	name   string
	source string
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
	if options.MaxRounds == 0 {
		switch options.Mode {
		case ModePassive:
			options.MaxRounds = 0
		case ModeStandard:
			options.MaxRounds = 1
		case ModeExhaustive:
			options.MaxRounds = 4
		}
	}
	if options.MaxRounds < 0 || options.MaxRounds > 12 {
		return options, fmt.Errorf("max-rounds deve estar entre 0 e 12")
	}
	if options.MaxDepth == 0 {
		options.MaxDepth = 5
	}
	if options.MaxDepth < 1 || options.MaxDepth > 20 {
		return options, fmt.Errorf("max-depth deve estar entre 1 e 20")
	}
	if options.MaxCandidates == 0 {
		options.MaxCandidates = 250000
	}
	if options.MaxCandidates < 1 || options.MaxCandidates > 5000000 {
		return options, fmt.Errorf("max-candidates deve estar entre 1 e 5000000")
	}
	if options.RecursiveThreshold == 0 {
		options.RecursiveThreshold = 2
	}
	if options.RecursiveThreshold < 1 || options.RecursiveThreshold > 1000 {
		return options, fmt.Errorf("recursive-threshold deve estar entre 1 e 1000")
	}
	if options.ScrapeLimit == 0 {
		options.ScrapeLimit = 2000
	}
	if len(options.Words) == 0 {
		options.Words = append([]string(nil), defaultReconWords...)
	}
	options.Words = cleanWords(options.Words)
	return options, nil
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
	var frontier []Candidate
	startRound := 1
	if options.Resume != nil {
		mergeCandidates(candidates, options.Resume.Candidates, options.MaxCandidates)
		frontier = restoreFrontier(candidates, options.Resume.Checkpoint.Frontier)
		result.Rounds = options.Resume.Checkpoint.Round
		startRound = result.Rounds + 1
	} else {
		seeds, sources := engine.passiveSeeds(ctx, root)
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		result.Sources = sources
		seeds = append(seeds, seed{name: root, keep: true, origin: Origin{Source: "escopo", Method: "seed"}})
		initial := engine.resolveSeeds(ctx, root, seeds, options, wildcards)
		frontier = mergeCandidates(candidates, initial, options.MaxCandidates)
		engine.addDNSSeeds(ctx, root, candidates, &frontier, options, wildcards)
		if err := reportProgress(options.Progress, candidates, 0, frontier); err != nil {
			return Result{}, err
		}
	}
	attempted := make(map[string]struct{}, len(candidates))
	for name := range candidates {
		attempted[name] = struct{}{}
	}

	for round := startRound; round <= options.MaxRounds && len(frontier) > 0 && len(candidates) < options.MaxCandidates; round++ {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		words := append([]string(nil), options.Words...)
		if options.Mode == ModeExhaustive {
			words = cleanWords(append(words, learnedWords(candidates)...))
		}
		generated := generateSeeds(root, frontier, candidates, words, options)
		if options.Mode != ModePassive && engine.client != nil && len(candidates) < options.ScrapeLimit {
			generated = append(generated, engine.scrapeSeeds(ctx, root, frontier, options)...)
		}
		generated = unseenSeeds(generated, attempted)
		resolved := engine.resolveSeeds(ctx, root, generated, options, wildcards)
		frontier = mergeCandidates(candidates, resolved, options.MaxCandidates)
		engine.addCNAMESeeds(ctx, root, candidates, &frontier, options, wildcards)
		result.Rounds = round
		if err := reportProgress(options.Progress, candidates, round, frontier); err != nil {
			return Result{}, err
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	result.Names = sortedCandidates(candidates)
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

func unseenSeeds(seeds []seed, attempted map[string]struct{}) []seed {
	result := make([]seed, 0, len(seeds))
	for _, item := range seeds {
		name := normalizeName(item.name)
		if name == "" {
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

func reportProgress(callback func(State) error, catalog map[string]Candidate, round int, frontier []Candidate) error {
	if callback == nil {
		return nil
	}
	names := make([]string, 0, len(frontier))
	for _, candidate := range frontier {
		names = append(names, candidate.Name)
	}
	sort.Strings(names)
	state := State{
		Candidates: sortedCandidates(catalog),
		Checkpoint: Checkpoint{Round: round, Frontier: names},
	}
	if err := callback(state); err != nil {
		return fmt.Errorf("persistindo progresso do recon: %w", err)
	}
	return nil
}

type sourceBatch struct {
	index int
	run   SourceRun
	hits  []sourceHit
}

func (engine *Engine) passiveSeeds(ctx context.Context, root string) ([]seed, []SourceRun) {
	if len(engine.providers) == 0 {
		return nil, nil
	}
	batches := make(chan sourceBatch, len(engine.providers))
	var group sync.WaitGroup
	for index, provider := range engine.providers {
		group.Add(1)
		go func(index int, provider Source) {
			defer group.Done()
			names := make(chan string, 256)
			errors := make(chan error, 1)
			go func() {
				errors <- provider.Enumerate(ctx, root, names)
				close(names)
			}()
			batch := sourceBatch{index: index, run: SourceRun{Name: provider.Name()}}
			for name := range names {
				if normalized := normalizeName(name); belongsToDomain(normalized, root) {
					batch.hits = append(batch.hits, sourceHit{name: normalized, source: provider.Name()})
				}
			}
			if err := <-errors; err != nil {
				batch.run.Error = err.Error()
			}
			batch.run.Count = len(batch.hits)
			batches <- batch
		}(index, provider)
	}
	go func() {
		group.Wait()
		close(batches)
	}()

	runs := make([]SourceRun, len(engine.providers))
	var seeds []seed
	for batch := range batches {
		runs[batch.index] = batch.run
		for _, hit := range batch.hits {
			seeds = append(seeds, seed{
				name:   hit.name,
				keep:   true,
				origin: Origin{Source: hit.source, Method: "passive", Depth: nameDepth(hit.name, root)},
			})
		}
	}
	return seeds, runs
}

func (engine *Engine) resolveSeeds(ctx context.Context, root string, seeds []seed, options Options, wildcards map[string]dns.WildcardSignature) []Candidate {
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
		return nil
	}

	jobs := make(chan string)
	results := make(chan Candidate, options.Concurrency)
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
				origins := make([]Origin, 0, len(grouped[name]))
				for _, item := range grouped[name] {
					keep = keep || item.keep
					origins = appendOrigin(origins, item.origin)
				}
				if (resolved || keep) && !wildcard {
					results <- Candidate{Name: name, Root: root, Resolved: resolved, DNS: record, Origins: origins}
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
	for candidate := range results {
		candidates = append(candidates, candidate)
	}
	return candidates
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

func (engine *Engine) addDNSSeeds(ctx context.Context, root string, catalog map[string]Candidate, frontier *[]Candidate, options Options, wildcards map[string]dns.WildcardSignature) {
	if options.Mode == ModePassive || engine.resolver == nil {
		return
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
	resolved := engine.resolveSeeds(ctx, root, seeds, options, wildcards)
	*frontier = append(*frontier, mergeCandidates(catalog, resolved, options.MaxCandidates)...)
}

func dnsSeed(name, root, method string) seed {
	name = normalizeName(name)
	return seed{
		name:   name,
		keep:   true,
		origin: Origin{Source: "dns", Method: method, Parent: root, Depth: nameDepth(name, root)},
	}
}

func (engine *Engine) addCNAMESeeds(ctx context.Context, root string, catalog map[string]Candidate, frontier *[]Candidate, options Options, wildcards map[string]dns.WildcardSignature) {
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
	resolved := engine.resolveSeeds(ctx, root, seeds, options, wildcards)
	*frontier = append(*frontier, mergeCandidates(catalog, resolved, options.MaxCandidates)...)
}

func generateSeeds(root string, frontier []Candidate, catalog map[string]Candidate, words []string, options Options) []seed {
	seen := make(map[string]struct{})
	seeds := make([]seed, 0, len(words))
	add := func(name, method, parent string) {
		name = normalizeName(name)
		if name == "" || !belongsToDomain(name, root) || nameDepth(name, root) > options.MaxDepth {
			return
		}
		if _, found := catalog[name]; found {
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
	}
	for _, candidate := range frontier {
		if candidate.Name == root || !shouldRecurse(candidate, catalog, root, options.RecursiveThreshold) {
			continue
		}
		for _, word := range words {
			add(word+"."+candidate.Name, "recursão", candidate.Name)
		}
		label, parent := firstLabel(candidate.Name)
		for _, word := range words {
			add(label+"-"+word+"."+parent, "alteração", candidate.Name)
			add(word+"-"+label+"."+parent, "alteração", candidate.Name)
		}
		for _, name := range numericNames(candidate.Name) {
			add(name, "sequência", candidate.Name)
		}
	}
	return seeds
}

func shouldRecurse(candidate Candidate, catalog map[string]Candidate, root string, threshold int) bool {
	for _, origin := range candidate.Origins {
		if origin.Method == "passive" || origin.Method == "cname" || origin.Method == "srv" {
			return true
		}
	}
	children := 0
	for name := range catalog {
		if parentName(name) == candidate.Name {
			children++
		}
	}
	return children >= threshold || (candidate.Name != root && threshold == 1)
}

func numericNames(name string) []string {
	label, parent := firstLabel(name)
	index := len(label)
	for index > 0 && label[index-1] >= '0' && label[index-1] <= '9' {
		index--
	}
	if index == len(label) || index == 0 {
		return nil
	}
	number, err := strconv.Atoi(label[index:])
	if err != nil {
		return nil
	}
	prefix := label[:index]
	width := len(label[index:])
	var names []string
	for _, next := range []int{number - 1, number + 1} {
		if next >= 0 {
			names = append(names, prefix+fmt.Sprintf("%0*d", width, next)+"."+parent)
		}
	}
	return names
}

func (engine *Engine) scrapeSeeds(ctx context.Context, root string, frontier []Candidate, options Options) []seed {
	if engine.client == nil || len(frontier) == 0 {
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
					found, err := ScrapePage(ctx, scheme+"://"+name, root, engine.client)
					if err != nil {
						continue
					}
					for _, target := range found {
						select {
						case <-ctx.Done():
							return
						case results <- seed{
							name:   target,
							origin: Origin{Source: "html", Method: "referência", Parent: name, Depth: nameDepth(target, root)},
						}:
						}
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		limit := len(frontier)
		if limit > options.ScrapeLimit {
			limit = options.ScrapeLimit
		}
		for _, candidate := range frontier[:limit] {
			select {
			case <-ctx.Done():
				return
			case jobs <- candidate.Name:
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

func learnedWords(catalog map[string]Candidate) []string {
	var words []string
	for name, candidate := range catalog {
		label, _ := firstLabel(name)
		for _, part := range strings.FieldsFunc(label, func(r rune) bool { return r == '-' || r == '_' }) {
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
	return cleanWords(words)
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
	sort.Strings(result)
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

var defaultReconWords = []string{
	"admin", "api", "app", "assets", "auth", "beta", "cdn", "dev", "docs", "files",
	"git", "internal", "login", "mail", "mobile", "old", "portal", "prod", "sandbox", "stage",
	"staging", "static", "status", "test", "uat", "vpn", "web", "www",
}

var commonServices = []string{
	"_autodiscover._tcp", "_caldav._tcp", "_carddav._tcp", "_imap._tcp", "_imaps._tcp",
	"_pop3._tcp", "_pop3s._tcp", "_sip._tcp", "_sip._udp", "_smtp._tcp", "_xmpp-client._tcp",
}
