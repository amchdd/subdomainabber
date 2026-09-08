package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type SecurityTrailsProvider struct {
	Client  *http.Client
	Token   string
	BaseURL string
}

func (p *SecurityTrailsProvider) Name() string {
	return "SecurityTrails"
}

func (p *SecurityTrailsProvider) Enumerate(ctx context.Context, domain string, out chan<- string) error {
	base := strings.TrimSuffix(strings.TrimSpace(p.BaseURL), "/")
	if base == "" {
		base = "https://api.securitytrails.com/v1"
	}
	request, err := newGETRequest(ctx, base+"/domain/"+url.PathEscape(domain)+"/subdomains", "SecurityTrails")
	if err != nil {
		return err
	}
	request.Header.Set("APIKEY", p.Token)
	body, err := fetchLimited(passiveHTTPClient(p.Client), request, "SecurityTrails", maxPassiveAPIResponseBytes)
	if err != nil {
		return err
	}
	var response struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("decodificando resposta do SecurityTrails: %w", err)
	}
	for _, name := range response.Subdomains {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" {
			continue
		}
		if name != domain && !strings.HasSuffix(name, "."+domain) {
			name += "." + domain
		}
		if err := emit(ctx, out, name); err != nil {
			return err
		}
	}
	return nil
}
