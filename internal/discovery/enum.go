package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/amchdd/subdomainabber/internal/dns"
	"github.com/amchdd/subdomainabber/internal/domainutil"
	"github.com/amchdd/subdomainabber/pkg/config"
	"github.com/amchdd/subdomainabber/pkg/passive"
)

type Engine struct {
	resolver          *dns.Resolver
	providers         []passive.Provider
	wildcardFiltering bool
	client            *http.Client
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
		wildcardFiltering: !cfg.NoWildcardFilter,
		client:            scraperClient(client),
	}
}

func (e *Engine) Enumerate(ctx context.Context, domain string, wordlist string, concurrency int) ([]string, error) {
	if err := config.ValidateEnumerationConcurrency(concurrency); err != nil {
		return nil, err
	}

	var wildcardSignature dns.WildcardSignature
	if e.wildcardFiltering {
		_, wildcardSignature, _ = e.resolver.IsWildcard(ctx, domain)
	}

	var wg sync.WaitGroup
	results := make(chan string, 1000)

	for _, provider := range e.providers {
		wg.Add(1)
		p := provider
		go func() {
			defer wg.Done()
			p.Enumerate(ctx, domain, results)
		}()
	}

	if wordlist != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.queryBrute(ctx, domain, wordlist, concurrency, results, wildcardSignature)
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	unique := make(map[string]bool)
	var list []string
	for sub := range results {
		sub = strings.ToLower(strings.TrimSpace(sub))
		sub = strings.TrimPrefix(sub, "*.")
		if belongsToDomain(sub, domain) && !unique[sub] {
			unique[sub] = true
			list = append(list, sub)
		}
	}

	// Gera variações dos nomes encontrados pelas fontes iniciais.
	if len(list) > 0 {
		var mutWg sync.WaitGroup
		mutResults := make(chan string, 1000)

		mutWg.Add(1)
		go func() {
			defer mutWg.Done()
			e.queryMutations(ctx, domain, list, concurrency, mutResults, wildcardSignature)
		}()

		go func() {
			mutWg.Wait()
			close(mutResults)
		}()

		for sub := range mutResults {
			if !unique[sub] {
				unique[sub] = true
				list = append(list, sub)
			}
		}
	}

	// Examina as páginas dos nomes encontrados em busca de novas referências.
	if len(list) > 0 {
		var scrapeWg sync.WaitGroup
		scrapeResults := make(chan string, 1000)

		scrapeWg.Add(1)
		go func() {
			defer scrapeWg.Done()
			e.runScraper(ctx, domain, list, concurrency, scrapeResults, wildcardSignature)
		}()

		go func() {
			scrapeWg.Wait()
			close(scrapeResults)
		}()

		for sub := range scrapeResults {
			if !unique[sub] {
				unique[sub] = true
				list = append(list, sub)
			}
		}
	}

	return list, nil
}

func belongsToDomain(host, domain string) bool {
	return domainutil.MatchDNSName(host, domain)
}

func (e *Engine) runScraper(ctx context.Context, domain string, validSubs []string, concurrency int, out chan<- string, wildcardSignature dns.WildcardSignature) {
	urls := make(chan string, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urls {
				found, err := ScrapePage(ctx, u, domain, e.client)
				if err == nil {
					for _, sub := range found {
						// Mantém somente nomes que resolvem e não pertencem ao curinga.
						if ips, _ := e.resolver.ResolveA(ctx, sub); len(ips) > 0 {
							if wildcardSignature.MatchesA(ips) {
								continue
							}
							out <- sub
						} else if cnames, _ := e.resolver.ResolveCNAME(ctx, sub); len(cnames) > 0 {
							if wildcardSignature.MatchesCNAME(cnames) {
								continue
							}
							out <- sub
						}
					}
				}
			}
		}()
	}

Loop:
	for _, sub := range validSubs {
		select {
		case <-ctx.Done():
			break Loop
		case urls <- fmt.Sprintf("http://%s", sub):
		}
		select {
		case <-ctx.Done():
			break Loop
		case urls <- fmt.Sprintf("https://%s", sub):
		}
	}
	close(urls)
	wg.Wait()
}

func (e *Engine) queryMutations(ctx context.Context, domain string, validSubs []string, concurrency int, out chan<- string, wildcardSignature dns.WildcardSignature) {
	mutations := make(chan string, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for mut := range mutations {
				if ips, _ := e.resolver.ResolveA(ctx, mut); len(ips) > 0 {
					if wildcardSignature.MatchesA(ips) {
						continue
					}
					out <- mut
				} else if cnames, _ := e.resolver.ResolveCNAME(ctx, mut); len(cnames) > 0 {
					if wildcardSignature.MatchesCNAME(cnames) {
						continue
					}
					out <- mut
				}
			}
		}()
	}

Loop:
	for _, sub := range validSubs {
		muts := GenerateMutations(domain, sub, nil)
		for _, m := range muts {
			select {
			case <-ctx.Done():
				break Loop
			case mutations <- m:
			}
		}
	}
	close(mutations)
	wg.Wait()
}

func (e *Engine) queryBrute(ctx context.Context, domain string, wordlist string, concurrency int, out chan<- string, wildcardSignature dns.WildcardSignature) {
	f, err := os.Open(wordlist)
	if err != nil {
		return
	}
	defer f.Close()

	words := make(chan string, concurrency*2)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range words {
				sub := fmt.Sprintf("%s.%s", w, domain)
				// Mantém somente nomes que resolvem e não pertencem ao curinga.
				if ips, _ := e.resolver.ResolveA(ctx, sub); len(ips) > 0 {
					if wildcardSignature.MatchesA(ips) {
						continue
					}
					out <- sub
				} else if cnames, _ := e.resolver.ResolveCNAME(ctx, sub); len(cnames) > 0 {
					if wildcardSignature.MatchesCNAME(cnames) {
						continue
					}
					out <- sub
				}
			}
		}()
	}

	scanner := bufio.NewScanner(f)
Loop:
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			select {
			case <-ctx.Done():
				break Loop // Interrompe explicitamente o laço identificado por Loop.
			case words <- word:
			}
		}
	}
	close(words)
	wg.Wait()
}
