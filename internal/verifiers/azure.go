package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type AzureVerifier struct {
	client *http.Client
}

func NewAzureVerifier(cfg Config) *AzureVerifier {
	return &AzureVerifier{client: cfg.Client}
}

func (v *AzureVerifier) Name() string {
	return "Azure"
}

func (v *AzureVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	if !hasProviderCNAME(analysis, "azurewebsites.net", "cloudapp.net", "trafficmanager.net") {
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

	if resp.StatusCode == 404 && (strings.Contains(bodyStr, "404 Web Site not found") || strings.Contains(bodyStr, "The specified bucket does not exist")) {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "O Azure retornou uma assinatura de recurso ausente; a possibilidade de criação não foi comprovada.",
		}, nil
	}

	return nil, nil
}
