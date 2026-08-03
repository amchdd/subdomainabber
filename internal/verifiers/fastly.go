package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type FastlyVerifier struct {
	client *http.Client
}

func NewFastlyVerifier(cfg Config) *FastlyVerifier {
	return &FastlyVerifier{client: cfg.Client}
}

func (v *FastlyVerifier) Name() string {
	return "Fastly"
}

func (v *FastlyVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	if !hasProviderCNAME(analysis, "fastly.net") {
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

	if resp.StatusCode == 500 && strings.Contains(bodyStr, "Fastly error: unknown domain") {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "A Fastly retornou 'unknown domain'; a vinculação do domínio a uma nova conta não foi comprovada.",
		}, nil
	}

	return nil, nil
}
