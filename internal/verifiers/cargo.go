package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type CargoVerifier struct {
	client *http.Client
}

func NewCargoVerifier(cfg Config) *CargoVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &CargoVerifier{
		client: client,
	}
}

func (v *CargoVerifier) Name() string {
	return "Cargo Collective"
}

func (v *CargoVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
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

	if resp.StatusCode == 404 && strings.Contains(bodyStr, "404 Not Found") {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 90,
			Evidence:   "O Cargo retornou uma assinatura de recurso ausente; a possibilidade de reivindicação não foi comprovada.",
		}, nil
	}

	return nil, nil
}
