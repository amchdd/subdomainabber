package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/config"
	"github.com/amchdd/subdomainabber/pkg/passive"
)

type Engine struct {
	resolver         dnsLookup
	providers        []passive.Provider
	noWildcardFilter bool
	client           *http.Client
}

func NewEngine(resolver *dns.Resolver, cfg *config.Config) *Engine {
	return NewEngineWithClient(resolver, cfg, nil)
}

func NewEngineWithClient(resolver *dns.Resolver, cfg *config.Config, client *http.Client) *Engine {
	if cfg == nil {
		cfg = config.Defaults()
	}
	return &Engine{
		resolver: resolver,
		providers: []passive.Provider{
			&passive.CrtshProvider{Client: client},
			&passive.WaybackProvider{Client: client},
			&passive.WaybackCDXProvider{Client: client},
			&passive.AlienVaultProvider{Client: client, Token: cfg.AlienVaultToken},
			&passive.CertSpotterProvider{Client: client, Token: cfg.CertSpotterToken},
			&passive.URLScanProvider{Client: client, Token: cfg.UrlscanToken},
		},
		noWildcardFilter: cfg.NoWildcardFilter,
		client:           scraperClient(client),
	}
}

func (engine *Engine) Enumerate(ctx context.Context, domain, wordlist string, concurrency int) ([]string, error) {
	if err := config.ValidateEnumerationConcurrency(concurrency); err != nil {
		return nil, err
	}
	words, err := LoadWords(wordlist)
	if err != nil {
		return nil, err
	}
	result, err := engine.Discover(ctx, domain, Options{
		Mode:        ModeStandard,
		Concurrency: concurrency,
		Words:       words,
	})
	if err != nil {
		return nil, err
	}
	return result.Targets(), nil
}

func LoadWords(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("abrindo wordlist %q: %w", path, err)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("lendo wordlist %q: %w", path, err)
	}
	return words, nil
}

func belongsToDomain(host, domain string) bool {
	return domainutil.MatchDNSName(host, domain)
}
