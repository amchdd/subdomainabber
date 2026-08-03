package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Provider representa uma fonte de enumeração passiva.
type Provider interface {
	Name() string
	Enumerate(ctx context.Context, domain string, out chan<- string) error
}

// CrtshProvider implementa a interface Provider para o crt.sh.
type CrtshProvider struct {
	Client *http.Client
}

func (p *CrtshProvider) Name() string {
	return "crt.sh"
}

func (p *CrtshProvider) Enumerate(ctx context.Context, domain string, out chan<- string) error {
	query := url.Values{}
	query.Set("q", "%."+domain)
	query.Set("output", "json")
	request, err := newGETRequest(ctx, "https://crt.sh/?"+query.Encode(), "crt.sh")
	if err != nil {
		return err
	}
	body, err := fetchLimited(passiveHTTPClient(p.Client), request, "crt.sh", maxPassiveAPIResponseBytes)
	if err != nil {
		return err
	}

	var data []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("decodificando resposta do crt.sh: %w", err)
	}
	for _, entry := range data {
		for _, sub := range strings.Split(entry.NameValue, "\n") {
			if sub == "" {
				continue
			}
			if err := emit(ctx, out, sub); err != nil {
				return err
			}
		}
	}
	return nil
}

// WaybackProvider implementa a interface Provider para o Wayback Machine.
type WaybackProvider struct {
	Client *http.Client
}

func (p *WaybackProvider) Name() string {
	return "Wayback Machine"
}

func (p *WaybackProvider) Enumerate(ctx context.Context, domain string, out chan<- string) error {
	query := url.Values{}
	query.Set("url", "*."+domain+"/*")
	query.Set("output", "json")
	query.Set("collapse", "urlkey")
	request, err := newGETRequest(ctx, "https://web.archive.org/cdx/search/cdx?"+query.Encode(), "Wayback Machine")
	if err != nil {
		return err
	}
	body, err := fetchLimited(passiveHTTPClient(p.Client), request, "Wayback Machine", maxPassiveAPIResponseBytes)
	if err != nil {
		return err
	}

	var data [][]string
	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("decodificando resposta da Wayback Machine: %w", err)
	}
	for i, row := range data {
		if i == 0 || len(row) < 3 {
			continue
		}
		original, err := url.Parse(row[2])
		if err != nil || (original.Scheme != "http" && original.Scheme != "https") {
			continue
		}
		host := original.Hostname()
		if host == "" {
			continue
		}
		if err := emit(ctx, out, host); err != nil {
			return err
		}
	}
	return nil
}
