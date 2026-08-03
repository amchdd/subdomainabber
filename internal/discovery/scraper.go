package discovery

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/domainutil"
)

// SubdomainRegex corresponde aos formatos comuns de subdomínio de um domínio base.
func SubdomainRegex(baseDomain string) *regexp.Regexp {
	normalized, err := domainutil.NormalizeHostname(baseDomain)
	if err != nil {
		return regexp.MustCompile(`a^`)
	}
	label := `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?`
	pattern := `(?i)(?:` + label + `\.)+` + regexp.QuoteMeta(normalized) + `\.?`
	return regexp.MustCompile(pattern)
}

// ScrapePage obtém uma página HTTP e extrai os subdomínios correspondentes ao domínio base.
func ScrapePage(ctx context.Context, url string, baseDomain string, clients ...*http.Client) ([]string, error) {
	client := scraperClient(clients...)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil // Processa somente páginas obtidas com sucesso.
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // Limite de 2 MB.
	if err != nil {
		return nil, err
	}

	re := SubdomainRegex(baseDomain)
	matches := re.FindAllString(string(body), -1)

	var unique []string
	seen := make(map[string]bool)
	for _, m := range matches {
		m = strings.TrimSuffix(strings.ToLower(m), ".")
		if !seen[m] {
			seen[m] = true
			unique = append(unique, m)
		}
	}

	return unique, nil
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
