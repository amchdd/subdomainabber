package discovery

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/domainutil"
	"golang.org/x/net/html"
)

func SubdomainRegex(baseDomain string) *regexp.Regexp {
	normalized, err := domainutil.NormalizeHostname(baseDomain)
	if err != nil {
		return regexp.MustCompile(`a^`)
	}
	label := `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	pattern := `(?i)(?:` + label + `\.)+` + regexp.QuoteMeta(normalized) + `\.?`
	return regexp.MustCompile(pattern)
}

func ScrapePage(ctx context.Context, url string, baseDomain string, clients ...*http.Client) ([]string, error) {
	return ScrapePageWithHeaders(ctx, url, baseDomain, nil, clients...)
}

func ScrapePageWithHeaders(ctx context.Context, url string, baseDomain string, headers http.Header, clients ...*http.Client) ([]string, error) {
	references, err := scrapeReferences(ctx, url, baseDomain, headers, clients...)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(references))
	seen := make(map[string]struct{})
	for _, reference := range references {
		if _, found := seen[reference.name]; found {
			continue
		}
		seen[reference.name] = struct{}{}
		names = append(names, reference.name)
	}
	return names, nil
}

type pageReference struct {
	name   string
	method string
}

func scrapeReferences(ctx context.Context, rawURL string, baseDomain string, headers http.Header, clients ...*http.Client) ([]pageReference, error) {
	client := scraperClient(clients...)
	references, _, err := fetchReferences(ctx, client, rawURL, baseDomain, headers, "html", 0)
	return references, err
}

func crawlReferences(ctx context.Context, rawURL string, baseDomain string, headers http.Header, assetLimit int, clients ...*http.Client) ([]pageReference, error) {
	client := scraperClient(clients...)
	references, assets, err := fetchReferences(ctx, client, rawURL, baseDomain, headers, "html", assetLimit)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, reference := range references {
		seen[reference.method+"\x00"+reference.name] = struct{}{}
	}
	assetClient := *client
	assetClient.CheckRedirect = func(request *http.Request, previous []*http.Request) error {
		if len(previous) == 0 || len(previous) >= 10 || !samePageOrigin(previous[0].URL, request.URL) {
			return http.ErrUseLastResponse
		}
		if client.CheckRedirect != nil {
			return client.CheckRedirect(request, previous)
		}
		return nil
	}
	for _, asset := range assets {
		found, _, fetchErr := fetchReferences(ctx, &assetClient, asset, baseDomain, headers, "script", 0)
		if fetchErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		for _, reference := range found {
			key := reference.method + "\x00" + reference.name
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			references = append(references, reference)
		}
	}
	return references, nil
}

func fetchReferences(ctx context.Context, client *http.Client, rawURL, baseDomain string, headers http.Header, bodyMethod string, assetLimit int) ([]pageReference, []string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	seen := make(map[string]struct{})
	var references []pageReference
	add := func(name, method string) {
		if strings.HasPrefix(strings.TrimSpace(name), "*.") {
			return
		}
		name = normalizeName(name)
		if name == "" || !belongsToDomain(name, baseDomain) {
			return
		}
		key := method + "\x00" + name
		if _, found := seen[key]; found {
			return
		}
		seen[key] = struct{}{}
		references = append(references, pageReference{name: name, method: method})
	}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		for _, name := range resp.TLS.PeerCertificates[0].DNSNames {
			add(name, "san")
		}
	}
	if resp.StatusCode != 200 {
		return references, nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, nil, err
	}

	re := SubdomainRegex(baseDomain)
	for _, match := range re.FindAllIndex(body, -1) {
		start, end := match[0], match[1]
		if (start > 0 && hostByte(body[start-1])) || (end < len(body) && hostByte(body[end])) {
			continue
		}
		add(string(body[start:end]), bodyMethod)
	}
	base := req.URL
	if resp.Request != nil && resp.Request.URL != nil {
		base = resp.Request.URL
	}
	return references, pageAssets(body, base, assetLimit), nil
}

func hostByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '.' || value == '-' || value == '_' || value >= 128
}

func pageAssets(body []byte, base *url.URL, limit int) []string {
	if limit <= 0 || base == nil {
		return nil
	}
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	seen := make(map[string]struct{})
	var assets []string
	for len(assets) < limit {
		token := tokenizer.Next()
		if token == html.ErrorToken {
			break
		}
		if token != html.StartTagToken && token != html.SelfClosingTagToken {
			continue
		}
		current := tokenizer.Token()
		attribute := ""
		switch current.Data {
		case "script":
			attribute = "src"
		case "link":
			attribute = "href"
		default:
			continue
		}
		value := ""
		for _, item := range current.Attr {
			if strings.EqualFold(item.Key, attribute) {
				value = strings.TrimSpace(item.Val)
				break
			}
		}
		if value == "" {
			continue
		}
		reference, err := url.Parse(value)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(reference)
		if !samePageOrigin(base, resolved) || !assetPath(resolved.Path) {
			continue
		}
		key := resolved.String()
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		assets = append(assets, key)
	}
	return assets
}

func samePageOrigin(left, right *url.URL) bool {
	return left != nil && right != nil &&
		strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func assetPath(value string) bool {
	switch strings.ToLower(path.Ext(value)) {
	case ".js", ".mjs", ".css", ".json", ".map":
		return true
	default:
		return false
	}
}

func scraperClient(clients ...*http.Client) *http.Client {
	if len(clients) > 0 && clients[0] != nil {
		return clients[0]
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			if len(previous) >= 10 {
				return http.ErrUseLastResponse
			}
			if len(previous) == 0 || !strings.EqualFold(request.URL.Hostname(), previous[0].URL.Hostname()) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
