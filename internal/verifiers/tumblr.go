package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type TumblrVerifier struct {
	client *http.Client
}

func NewTumblrVerifier(cfg Config) *TumblrVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &TumblrVerifier{
		client: client,
	}
}

func (v *TumblrVerifier) Name() string {
	return "Tumblr"
}

func (v *TumblrVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
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

	if resp.StatusCode == 404 && (strings.Contains(bodyStr, "There's nothing here.") || strings.Contains(bodyStr, "Whatever you were looking for doesn't currently exist at this address.")) {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "O Tumblr retornou uma assinatura de blog ausente; a possibilidade de reivindicação não foi comprovada.",
		}, nil
	}

	return nil, nil
}
