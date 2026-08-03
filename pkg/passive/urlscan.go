package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// URLScanProvider implementa a interface Provider para o urlscan.io.
type URLScanProvider struct {
	Client *http.Client
	Token  string
}

func (p *URLScanProvider) Name() string {
	return "URLScan"
}

func (p *URLScanProvider) Enumerate(ctx context.Context, domain string, out chan<- string) error {
	client := passiveHTTPClient(p.Client)

	searchAfter := ""
	seenSearchAfter := make(map[string]struct{})
	for page := 0; page < maxURLScanPages; page++ {
		query := url.Values{}
		query.Set("q", "domain:"+domain)
		if searchAfter != "" {
			query.Set("search_after", searchAfter)
		}
		request, err := newGETRequest(ctx, "https://urlscan.io/api/v1/search/?"+query.Encode(), "urlscan.io")
		if err != nil {
			return err
		}

		if p.Token != "" {
			request.Header.Set("API-Key", p.Token)
		}
		body, err := fetchLimited(client, request, "urlscan.io", maxPassiveAPIResponseBytes)
		if err != nil {
			return err
		}

		var data struct {
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
				} `json:"page"`
				Sort []interface{} `json:"sort"`
			} `json:"results"`
			HasMore bool `json:"has_more"`
		}

		if err := json.Unmarshal(body, &data); err != nil {
			return fmt.Errorf("decodificando resposta do urlscan.io: %w", err)
		}

		if len(data.Results) == 0 {
			return nil
		}

		for _, result := range data.Results {
			if result.Page.Domain != "" {
				if err := emit(ctx, out, result.Page.Domain); err != nil {
					return err
				}
			}
		}

		if !data.HasMore {
			return nil
		}

		lastSort := data.Results[len(data.Results)-1].Sort
		if len(lastSort) > 0 {
			parts := make([]string, 0, len(lastSort))
			for _, value := range lastSort {
				parts = append(parts, fmt.Sprint(value))
			}
			searchAfter = strings.Join(parts, ",")
			if _, repeated := seenSearchAfter[searchAfter]; repeated {
				return fmt.Errorf("o urlscan.io repetiu o cursor de paginação %q", searchAfter)
			}
			seenSearchAfter[searchAfter] = struct{}{}
		} else {
			return nil
		}
	}
	return fmt.Errorf("a consulta ao urlscan.io atingiu o limite de %d páginas", maxURLScanPages)
}
