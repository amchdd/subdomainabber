package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type HerokuVerifier struct {
	client *http.Client
}

func NewHerokuVerifier(cfg Config) *HerokuVerifier {
	return &HerokuVerifier{client: cfg.Client}
}

func (v *HerokuVerifier) Name() string {
	return "Heroku"
}

func (v *HerokuVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
	if !hasProviderCNAME(analysis, "herokuapp.com", "herokudns.com") {
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

	if resp.StatusCode == 404 && strings.Contains(bodyStr, "No such app") {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "A Heroku retornou 'No such app'; a disponibilidade do nome e a possibilidade de vinculação não foram comprovadas.",
		}, nil
	}

	return nil, nil
}
