package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type ZendeskVerifier struct {
	client *http.Client
}

func NewZendeskVerifier(cfg Config) *ZendeskVerifier {
	return &ZendeskVerifier{client: cfg.Client}
}

func (v *ZendeskVerifier) Name() string {
	return "Zendesk"
}

func (v *ZendeskVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	if !hasProviderCNAME(analysis, "zendesk.com") {
		return nil, nil
	}

	client := v.client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		req, _ = http.NewRequestWithContext(ctx, "GET", "https://"+analysis.Host, nil)
		resp, err = client.Do(req)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyStr := string(body)

	if strings.Contains(bodyStr, "Help Center Closed") {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "A Zendesk retornou 'Help Center Closed'; a possibilidade de registrar ou vincular o subdomínio não foi comprovada.",
		}, nil
	}

	return nil, nil
}
