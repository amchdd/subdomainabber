package passive

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const maxCommonCrawlResults = 10000

type CommonCrawlProvider struct {
	Client   *http.Client
	IndexURL string
}

func (p *CommonCrawlProvider) Name() string {
	return "Common Crawl"
}

func (p *CommonCrawlProvider) Enumerate(ctx context.Context, domain string, out chan<- string) error {
	client := passiveHTTPClient(p.Client)
	endpoint := strings.TrimSpace(p.IndexURL)
	if endpoint == "" {
		var err error
		endpoint, err = currentCommonCrawlIndex(ctx, client)
		if err != nil {
			return err
		}
	}

	query := url.Values{}
	query.Set("url", domain)
	query.Set("matchType", "domain")
	query.Set("output", "json")
	query.Set("fl", "url")
	query.Set("filter", "status:200")
	query.Set("collapse", "urlkey")
	query.Set("limit", fmt.Sprint(maxCommonCrawlResults))
	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}
	request, err := newGETRequest(ctx, endpoint+separator+query.Encode(), "Common Crawl")
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "SubdomainAbber recon")
	body, err := fetchLimited(client, request, "Common Crawl", maxPassiveAPIResponseBytes)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return fmt.Errorf("decodificando resposta do Common Crawl: %w", err)
		}
		parsed, err := url.Parse(record.URL)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		count++
		if err := emit(ctx, out, parsed.Hostname()); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("lendo resposta do Common Crawl: %w", err)
	}
	if count >= maxCommonCrawlResults {
		return fmt.Errorf("o Common Crawl atingiu o limite de %d resultados", maxCommonCrawlResults)
	}
	return nil
}

func currentCommonCrawlIndex(ctx context.Context, client *http.Client) (string, error) {
	request, err := newGETRequest(ctx, "https://index.commoncrawl.org/collinfo.json", "catálogo do Common Crawl")
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "SubdomainAbber recon")
	body, err := fetchLimited(client, request, "catálogo do Common Crawl", 1<<20)
	if err != nil {
		return "", err
	}
	var indexes []struct {
		API string `json:"cdx-api"`
	}
	if err := json.Unmarshal(body, &indexes); err != nil {
		return "", fmt.Errorf("decodificando catálogo do Common Crawl: %w", err)
	}
	if len(indexes) == 0 || indexes[0].API == "" {
		return "", fmt.Errorf("o catálogo do Common Crawl não informou um índice")
	}
	endpoint, err := url.Parse(indexes[0].API)
	if err != nil || endpoint.Scheme != "https" || !strings.EqualFold(endpoint.Hostname(), "index.commoncrawl.org") {
		return "", fmt.Errorf("o catálogo do Common Crawl retornou um índice inválido")
	}
	return endpoint.String(), nil
}
