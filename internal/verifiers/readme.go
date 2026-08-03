package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type ReadmeVerifier struct {
	client *http.Client
}

func NewReadmeVerifier(cfg Config) *ReadmeVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &ReadmeVerifier{
		client: client,
	}
}

func (v *ReadmeVerifier) Name() string {
	return "Readme.io"
}

func (v *ReadmeVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
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

	if resp.StatusCode == 404 && (strings.Contains(bodyStr, "Project doesnt exist") || providerRedirectMatches(resp.Header.Get("Location"), "/signup", "readme.io")) {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 95,
			Evidence:   "A ReadMe retornou uma assinatura de projeto ausente; a possibilidade de reivindicação não foi comprovada.",
		}, nil
	}

	return nil, nil
}
