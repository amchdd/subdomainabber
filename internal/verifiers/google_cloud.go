package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type GoogleCloudVerifier struct {
	client *http.Client
}

func NewGoogleCloudVerifier(cfg Config) *GoogleCloudVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &GoogleCloudVerifier{
		client: client,
	}
}

func (v *GoogleCloudVerifier) Name() string {
	return "Google Cloud"
}

func (v *GoogleCloudVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
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

	if resp.StatusCode == 404 && strings.Contains(bodyStr, "<Code>NoSuchBucket</Code>") {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "O Google Cloud Storage retornou uma assinatura de bucket ausente; a disponibilidade do nome não foi comprovada.",
		}, nil
	}

	return nil, nil
}
