package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// AlienVaultProvider implementa a interface Provider para o AlienVault OTX.
type AlienVaultProvider struct {
	Client *http.Client
	Token  string
}

func (p *AlienVaultProvider) Name() string {
	return "AlienVault OTX"
}

func (p *AlienVaultProvider) Enumerate(ctx context.Context, domain string, out chan<- string) error {
	endpoint := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.PathEscape(domain))
	request, err := newGETRequest(ctx, endpoint, "AlienVault OTX")
	if err != nil {
		return err
	}

	if p.Token != "" {
		request.Header.Set("X-OTX-API-KEY", p.Token)
	}
	body, err := fetchLimited(passiveHTTPClient(p.Client), request, "AlienVault OTX", maxPassiveAPIResponseBytes)
	if err != nil {
		return err
	}

	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return fmt.Errorf("decodificando resposta do AlienVault OTX: %w", err)
	}
	for _, entry := range data.PassiveDNS {
		if entry.Hostname == "" {
			continue
		}
		if err := emit(ctx, out, entry.Hostname); err != nil {
			return err
		}
	}
	return nil
}
