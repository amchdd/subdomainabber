package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// CertSpotterProvider implementa a interface Provider para o CertSpotter.
type CertSpotterProvider struct {
	Client *http.Client
	Token  string
}

func (p *CertSpotterProvider) Name() string {
	return "CertSpotter"
}

func (p *CertSpotterProvider) Enumerate(ctx context.Context, domain string, out chan<- string) error {
	query := url.Values{}
	query.Set("domain", domain)
	query.Set("include_subdomains", "true")
	query.Set("expand", "dns_names")
	request, err := newGETRequest(ctx, "https://api.certspotter.com/v1/issuances?"+query.Encode(), "CertSpotter")
	if err != nil {
		return err
	}

	if p.Token != "" {
		request.Header.Set("Authorization", "Bearer "+p.Token)
	}
	body, err := fetchLimited(passiveHTTPClient(p.Client), request, "CertSpotter", maxPassiveAPIResponseBytes)
	if err != nil {
		return err
	}

	var data []struct {
		DNSNames []string `json:"dns_names"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("decodificando resposta do CertSpotter: %w", err)
	}
	for _, entry := range data {
		for _, name := range entry.DNSNames {
			if name == "" {
				continue
			}
			if err := emit(ctx, out, name); err != nil {
				return err
			}
		}
	}
	return nil
}
