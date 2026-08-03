package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type VercelVerifier struct {
	client *http.Client
}

func NewVercelVerifier(cfg Config) *VercelVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &VercelVerifier{
		client: client,
	}
}

func (v *VercelVerifier) Name() string {
	return "Vercel"
}

func (v *VercelVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+analysis.Host, nil)
	if err != nil {
		return nil, err
	}

	resp, err := v.client.Do(req)
	if err != nil {
		req, _ = http.NewRequestWithContext(ctx, "GET", "https://"+analysis.Host, nil)
		resp, err = v.client.Do(req)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyStr := string(bodyBytes)

	if resp.StatusCode == 404 && (strings.Contains(bodyStr, "The deployment could not be found") || strings.Contains(bodyStr, "DEPLOYMENT_NOT_FOUND")) {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "A Vercel retornou uma assinatura de projeto ausente; a possibilidade de reivindicação não foi comprovada.",
		}, nil
	}

	return nil, nil
}
