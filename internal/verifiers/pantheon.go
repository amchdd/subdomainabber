package verifiers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/amchdd/subdomainabber/internal/core"
)

type PantheonVerifier struct {
	client *http.Client
}

func NewPantheonVerifier(cfg Config) *PantheonVerifier {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &PantheonVerifier{
		client: client,
	}
}

func (v *PantheonVerifier) Name() string {
	return "Pantheon"
}

func (v *PantheonVerifier) Verify(ctx context.Context, analysis *core.HostAnalysis) (*core.VerificationResult, error) {
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

	if resp.StatusCode == 404 && (strings.Contains(bodyStr, "The gods are wise") || strings.Contains(bodyStr, "404 Site Unknown")) {
		return &core.VerificationResult{
			Provider:   v.Name(),
			Verified:   true,
			Confidence: 100,
			Evidence:   "O Pantheon retornou uma assinatura de site ausente; a possibilidade de reivindicação não foi comprovada.",
		}, nil
	}

	return nil, nil
}
